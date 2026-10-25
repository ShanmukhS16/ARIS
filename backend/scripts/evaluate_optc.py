"""Evaluate ARIS detection on OpTC dataset.

Full pipeline: load eCAR data, run Sigma + ML, label against ground truth,
compute precision/recall/F1 for Sigma-only, ML-only, and Hybrid detection,
then break down results per MITRE technique.

Usage:
  python -m scripts.evaluate_optc --sample                    # included 10-event test
  python -m scripts.evaluate_optc --data-dir ./optc_data/ecar/ # real dataset
  python -m scripts.evaluate_optc --data-dir ./optc_data/ecar/ --max-events 10000
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

from app.parsers.optc import parse_optc_file, parse_optc_gzip, parse_optc_gzip_strided
from app.parsers.optc_labels import label_event, summary as gt_summary
from app.sigma_engine.engine import run_rules
from app.ml.anomaly import train_model, score_event, is_anomaly

SAMPLE_DIR = Path(__file__).parent.parent / "sample_data"


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate ARIS on OpTC dataset")
    parser.add_argument("--data-dir", type=str, help="Path to OpTC eCAR directory")
    parser.add_argument("--max-events", type=int, default=None, help="Limit events for dev")
    parser.add_argument("--sample", action="store_true", help="Use included sample eCAR data")
    parser.add_argument("--threshold", type=float, default=0.5, help="ML anomaly threshold")
    return parser.parse_args()


def load_events(data_dir, use_sample, max_events):
    """Load events from data directory.

    When max_events is set, uses strided sampling: estimates total event
    count, then reads every Nth event to get uniform coverage across the
    full time range. This ensures malicious events (which occur mid-day)
    are included even with a small cap.
    """
    events = []

    if use_sample:
        content = (SAMPLE_DIR / "optc_ecar_sample.jsonl").read_text()
        events = list(parse_optc_file(content))
    elif data_dir:
        data_path = Path(data_dir)
        gz_files = sorted(data_path.glob("*.json.gz"))
        jsonl_files = sorted(data_path.glob("*.jsonl"))

        if not max_events:
            for gz_file in gz_files:
                for ev in parse_optc_gzip(str(gz_file)):
                    events.append(ev)
            for jsonl_file in jsonl_files:
                content = jsonl_file.read_text()
                for ev in parse_optc_file(content):
                    events.append(ev)
        else:
            # Estimate total lines: sample first 1000 lines to get avg
            # compressed bytes per line, then extrapolate from file sizes
            total_estimate = _estimate_total_lines(gz_files, jsonl_files)
            stride = max(1, total_estimate // max_events)
            print(f"Strided sampling: ~{total_estimate:,} total events, "
                  f"stride={stride}, target={max_events:,}")

            line_idx = 0
            for gz_file in gz_files:
                for ev in parse_optc_gzip_strided(str(gz_file), stride, offset=line_idx):
                    events.append(ev)
                    if len(events) >= max_events:
                        print(f"  Loaded {len(events):,} events (strided)")
                        return events
                # Count actual lines in this file for offset tracking
                # (stride handles the math internally via enumerate offset)
                import gzip as _gzip
                with _gzip.open(str(gz_file), "rt") as _f:
                    file_lines = sum(1 for _ in _f)
                line_idx += file_lines
            for jsonl_file in jsonl_files:
                content = jsonl_file.read_text()
                for ev in parse_optc_file(content):
                    if line_idx % stride == 0:
                        events.append(ev)
                        if len(events) >= max_events:
                            return events
                    line_idx += 1

            print(f"  Loaded {len(events):,} events "
                  f"(sampled from {line_idx:,} scanned)")

    return events


def _estimate_total_lines(gz_files, jsonl_files):
    """Estimate total line count by sampling first gz file."""
    import gzip
    total = 0

    if gz_files:
        # Sample: read first 2000 lines, measure compressed bytes consumed
        first_gz = str(gz_files[0])
        sample_lines = 0
        with gzip.open(first_gz, "rt", encoding="utf-8") as f:
            for _ in f:
                sample_lines += 1
                if sample_lines >= 2000:
                    break
        # Estimate: file_size_compressed / (compressed_bytes_for_2000_lines)
        # Simpler: assume ~equal events per file (they're generated that way)
        gz_size = sum(f.stat().st_size for f in gz_files)
        first_size = gz_files[0].stat().st_size
        if sample_lines > 0:
            # Rough: total_lines_in_first_file * num_files
            # Better: use ratio of file sizes
            est_per_file = int(first_size / (first_size / max(sample_lines * 4, 1)))
            # Very rough but fast: each file has similar count
            total = est_per_file * len(gz_files)
            # Sanity: at least sample_lines * num_files
            total = max(total, sample_lines * len(gz_files))

    for jf in jsonl_files:
        total += sum(1 for _ in jf.open())

    return total

    return events


def evaluate(events, threshold):
    print(f"\n{gt_summary()}\n")
    print(f"Events loaded: {len(events)}")

    # Label events
    labels = []
    truth_set = set()
    technique_events = defaultdict(list)
    for i, ev in enumerate(events):
        lbl = label_event(ev.timestamp, ev.host)
        labels.append(lbl)
        if lbl["is_malicious"]:
            truth_set.add(i)
            for tech in lbl["techniques"]:
                technique_events[tech].append(i)

    print(f"Malicious (ground truth): {len(truth_set)}")
    print(f"Benign (ground truth): {len(events) - len(truth_set)}")

    # Sigma pass
    sigma_flags = set()
    for i, ev in enumerate(events):
        dets = run_rules(ev)
        if dets:
            sigma_flags.add(i)

    # ML pass
    print("\nTraining IsolationForest...")
    train_model(events)
    ml_flags = set()
    ml_scores = {}
    for i, ev in enumerate(events):
        score = score_event(ev)
        ml_scores[i] = score
        if is_anomaly(score, threshold):
            ml_flags.add(i)

    hybrid_flags = sigma_flags | ml_flags

    # Metrics
    def metrics(detected, ground_truth):
        tp = len(detected & ground_truth)
        fp = len(detected - ground_truth)
        fn = len(ground_truth - detected)
        p = tp / (tp + fp) if (tp + fp) > 0 else 0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
        return p, r, f1

    sp, sr, sf1 = metrics(sigma_flags, truth_set)
    mp, mr, mf1 = metrics(ml_flags, truth_set)
    hp, hr, hf1 = metrics(hybrid_flags, truth_set)

    print(f"\n{'Layer':<12s} {'Precision':>10s} {'Recall':>10s} {'F1':>10s} {'Flagged':>10s}")
    print("-" * 55)
    print(f"{'Sigma':<12s} {sp:>10.3f} {sr:>10.3f} {sf1:>10.3f} {len(sigma_flags):>10d}")
    print(f"{'ML':<12s} {mp:>10.3f} {mr:>10.3f} {mf1:>10.3f} {len(ml_flags):>10d}")
    print(f"{'Hybrid':<12s} {hp:>10.3f} {hr:>10.3f} {hf1:>10.3f} {len(hybrid_flags):>10d}")

    # Per-technique breakdown
    if technique_events:
        print(f"\n--- Per-Technique Detection ---")
        for tech in sorted(technique_events.keys()):
            event_indices = technique_events[tech]
            sigma_caught = sum(1 for idx in event_indices if idx in sigma_flags)
            ml_caught = sum(1 for idx in event_indices if idx in ml_flags)
            hybrid_caught = sum(1 for idx in event_indices if idx in hybrid_flags)
            total = len(event_indices)
            print(f"  {tech}: {hybrid_caught}/{total} hybrid ({sigma_caught} sigma, {ml_caught} ml)")

    # Overlap analysis
    sigma_only = sigma_flags - ml_flags
    ml_only = ml_flags - sigma_flags
    overlap = sigma_flags & ml_flags

    print(f"\n--- Detection Overlap ---")
    print(f"  Sigma-only:  {len(sigma_only)}")
    print(f"  ML-only:     {len(ml_only)}")
    print(f"  Both:        {len(overlap)}")
    print(f"  Union:       {len(hybrid_flags)}")

    # ML-only findings on malicious events
    ml_only_malicious = ml_only & truth_set
    if ml_only_malicious:
        print(f"\n--- ML-Only Findings on Malicious Events ---")
        for i in sorted(ml_only_malicious):
            ev = events[i]
            lbl = labels[i]
            print(f"  Event {i}: host={ev.host} process={(ev.process or 'N/A')[:60]}")
            print(f"    Score: {ml_scores[i]:.4f}")
            print(f"    GT: Day {lbl['day']}, {lbl['campaign']}")
            print(f"    Techniques: {', '.join(lbl['techniques'])}")


def main():
    args = parse_args()
    events = load_events(args.data_dir, args.sample, args.max_events)
    if not events:
        print("No events loaded.")
        sys.exit(1)
    evaluate(events, args.threshold)


if __name__ == "__main__":
    main()
