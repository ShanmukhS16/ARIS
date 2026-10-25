"""Sigma vs ML vs Hybrid detection comparison.

Ingests sample data, runs both detection layers, and reports overlap.
This script demonstrates the value of the hybrid approach.

Usage:
    cd backend
    python -m scripts.compare
"""

from __future__ import annotations

from app.parsers.sysmon import parse_sysmon_file
from app.parsers.authlog import parse_authlog_file
from app.sigma_engine.engine import run_rules
from app.ml.anomaly import train_model, score_event, is_anomaly
from app.config import settings


def main():
    # Load sample data
    with open("sample_data/sysmon_sample.jsonl") as f:
        sysmon_events = list(parse_sysmon_file(f.read()))
    with open("sample_data/auth_log_sample.log") as f:
        auth_events = list(parse_authlog_file(f.read()))

    events = sysmon_events + auth_events
    print(f"Loaded {len(events)} events ({len(sysmon_events)} sysmon, {len(auth_events)} authlog)")

    # Sigma pass
    sigma_flags = set()
    sigma_details = {}
    for i, ev in enumerate(events):
        dets = run_rules(ev)
        if dets:
            sigma_flags.add(i)
            sigma_details[i] = [(d.rule_id, d.rule_title) for d in dets]

    print(f"\nSigma detections: {len(sigma_flags)}")
    for i in sorted(sigma_flags):
        ev = events[i]
        rules = ", ".join(r[0] for r in sigma_details[i])
        print(f"  [{i:2d}] {ev.host:10s} {(ev.process or 'N/A')[:60]:60s} -> {rules}")

    # ML pass
    print("\nTraining IsolationForest...")
    train_model(events)
    ml_flags = set()
    ml_scores = {}
    for i, ev in enumerate(events):
        score = score_event(ev)
        ml_scores[i] = score
        if is_anomaly(score):
            ml_flags.add(i)

    print(f"ML anomalies (threshold {settings.ml_anomaly_threshold}): {len(ml_flags)}")
    for i in sorted(ml_flags):
        ev = events[i]
        print(f"  [{i:2d}] {ev.host:10s} {(ev.process or 'N/A')[:60]:60s} score={ml_scores[i]:.4f}")

    # Comparison
    hybrid = sigma_flags | ml_flags
    both = sigma_flags & ml_flags
    sigma_only = sigma_flags - ml_flags
    ml_only = ml_flags - sigma_flags

    print(f"\n{'='*60}")
    print(f"Sigma-only:  {len(sigma_only)}")
    print(f"ML-only:     {len(ml_only)}")
    print(f"Both:        {len(both)}")
    print(f"Hybrid:      {len(hybrid)}")
    print(f"{'='*60}")

    if ml_only:
        print("\nML-only detections (Sigma gaps):")
        for i in sorted(ml_only):
            ev = events[i]
            print(f"  [{i:2d}] {ev.host} | {(ev.process or 'N/A')[:80]} | score={ml_scores[i]:.4f}")

    # Pseudo-F1 using Sigma as ground truth
    if sigma_flags:
        tp = len(both)
        fp = len(ml_only)
        fn = len(sigma_only)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        print(f"\nML vs Sigma pseudo-labels: P={precision:.3f} R={recall:.3f} F1={f1:.3f}")
        print("(These are pseudo-labels. Real metrics require OpTC ground truth.)")


if __name__ == "__main__":
    main()
