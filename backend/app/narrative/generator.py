"""Incident narrative generator.

Two modes:
  1. LLM (Claude API): ATT&CK-grounded structured prompt, JSON output with
     kill chain steps, severity, visibility gaps, and recommendations.
  2. Offline fallback: Rule-based narrative from Sigma detections and ML
     anomaly scores. Works without any external dependencies.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from app.config import settings
from app.narrative.attack_kb import get_techniques_context

logger = logging.getLogger(__name__)


async def generate_narrative(
    events: list[dict],
    detections: list[dict],
    technique_ids: list[str],
) -> dict[str, Any]:
    """Generate an incident narrative from events and detections.

    Tries the LLM path first if an API key is configured, otherwise
    falls back to the offline rule-based generator.
    """
    if settings.anthropic_api_key:
        try:
            return await _generate_llm_narrative(events, detections, technique_ids)
        except Exception as e:
            logger.warning(f"LLM narrative failed, falling back to offline: {e}")

    return _generate_offline_narrative(events, detections, technique_ids)


async def _generate_llm_narrative(
    events: list[dict],
    detections: list[dict],
    technique_ids: list[str],
) -> dict[str, Any]:
    """Call Claude API with ATT&CK-grounded prompt."""
    import httpx

    attack_context = get_techniques_context(technique_ids)

    # Build the event listing
    event_lines = []
    for i, ev in enumerate(events):
        det_strs = [
            d["rule_title"] for d in detections if d.get("event_index") == i
        ]
        score_str = ""
        if ev.get("anomaly_score") is not None:
            score_str = f" [ML score: {ev['anomaly_score']:.3f}]"
        det_line = f"  Detections: {', '.join(det_strs)}" if det_strs else ""
        event_lines.append(
            f"[{i}] {ev.get('timestamp', 'N/A')} | {ev.get('host', '?')} | "
            f"user={ev.get('user', 'N/A')} | {(ev.get('process') or 'N/A')[:120]}"
            f"{score_str}\n{det_line}"
        )

    system_prompt = (
        "You are a senior SOC analyst writing an incident narrative. "
        "Your output must be valid JSON with these fields:\n"
        '  "summary": one-paragraph incident summary\n'
        '  "severity": "critical", "high", "medium", or "low"\n'
        '  "kill_chain": array of objects with "step", "timestamp", '
        '"technique_id", "technique_name", "description", "evidence"\n'
        '  "visibility_gaps": array of strings describing detection blind spots\n'
        '  "recommendations": array of actionable remediation steps\n\n'
        "Ground every technique reference in the ATT&CK descriptions provided. "
        "Do not invent techniques not present in the evidence."
    )

    user_prompt = (
        f"MITRE ATT&CK Reference:\n{attack_context}\n\n"
        f"Events ({len(events)} total):\n" + "\n".join(event_lines) + "\n\n"
        f"Detections ({len(detections)} total):\n"
        + json.dumps(detections, indent=2, default=str)
        + "\n\nGenerate the incident narrative JSON."
    )

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.anthropic_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": settings.anthropic_model,
                "max_tokens": 2048,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            },
        )
        resp.raise_for_status()
        data = resp.json()

    # Extract text content
    text = ""
    for block in data.get("content", []):
        if block.get("type") == "text":
            text += block["text"]

    # Parse JSON from response (handle markdown fences)
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    narrative = json.loads(text)
    narrative["_source"] = "llm"
    narrative["_model"] = settings.anthropic_model
    return narrative


def _generate_offline_narrative(
    events: list[dict],
    detections: list[dict],
    technique_ids: list[str],
) -> dict[str, Any]:
    """Rule-based fallback narrative from detections and scores."""
    from app.narrative.attack_kb import get_technique

    # Build kill chain from detections (ordered by event index)
    kill_chain = []
    seen_techniques = set()

    sorted_dets = sorted(detections, key=lambda d: d.get("event_index", 0))
    step_num = 0

    for det in sorted_dets:
        tech_id = det.get("mitre_attack_id", "")
        if tech_id and tech_id in seen_techniques:
            continue
        seen_techniques.add(tech_id)
        step_num += 1

        tech_info = get_technique(tech_id) if tech_id else None
        ev_idx = det.get("event_index", 0)
        ev = events[ev_idx] if ev_idx < len(events) else {}

        kill_chain.append({
            "step": step_num,
            "timestamp": ev.get("timestamp", "unknown"),
            "technique_id": tech_id or "N/A",
            "technique_name": tech_info["name"] if tech_info else det.get("rule_title", "Unknown"),
            "description": (
                f"{det.get('rule_title', 'Detection')} triggered on "
                f"{ev.get('host', 'unknown')} by {ev.get('user', 'unknown')}"
            ),
            "evidence": (ev.get("process") or "N/A")[:200],
        })

    # Add ML-only anomalies that did not match any Sigma rule
    det_event_indices = {d.get("event_index") for d in detections}
    for i, ev in enumerate(events):
        if i in det_event_indices:
            continue
        score = ev.get("anomaly_score")
        if score is not None and score >= 0.5:
            step_num += 1
            kill_chain.append({
                "step": step_num,
                "timestamp": ev.get("timestamp", "unknown"),
                "technique_id": "ML_ANOMALY",
                "technique_name": "ML-Detected Anomaly (no Sigma rule)",
                "description": (
                    f"IsolationForest flagged anomalous activity on "
                    f"{ev.get('host', 'unknown')} (score: {score:.3f})"
                ),
                "evidence": (ev.get("process") or "N/A")[:200],
            })

    # Assess severity
    severities = [d.get("severity", "medium") for d in detections]
    if "critical" in severities:
        severity = "critical"
    elif "high" in severities:
        severity = "high"
    elif len(detections) >= 5:
        severity = "high"
    else:
        severity = "medium"

    # Identify visibility gaps
    gaps = []
    covered = {d.get("mitre_attack_id") for d in detections if d.get("mitre_attack_id")}
    known = {"T1033", "T1547.001", "T1059.001", "T1110.001", "T1003.008"}
    uncovered_common = {"T1012", "T1082", "T1021.001", "T1105", "T1027"} - covered
    if uncovered_common:
        gaps.append(
            f"No Sigma rules for: {', '.join(sorted(uncovered_common))}. "
            "ML may partially cover these techniques."
        )
    if any(ev.get("anomaly_score") is None for ev in events):
        gaps.append("Some events lack ML scores. Run 'python -m app.ml.train' to backfill.")

    # Recommendations
    recommendations = [
        "Review and triage all high/critical detections within 1 hour.",
        "Isolate affected hosts if lateral movement is confirmed.",
        "Check registry Run keys on flagged hosts for unauthorized persistence entries.",
        "Rotate credentials for any accounts involved in brute force detections.",
    ]
    if uncovered_common:
        recommendations.append(
            f"Add Sigma rules for techniques {', '.join(sorted(uncovered_common))} "
            "to reduce reliance on ML-only detection."
        )

    summary_parts = [
        f"Incident involving {len(set(ev.get('host','') for ev in events))} host(s) "
        f"with {len(detections)} Sigma detection(s) across {len(seen_techniques)} "
        f"MITRE ATT&CK technique(s).",
    ]
    ml_anomalies = sum(1 for ev in events if (ev.get("anomaly_score") or 0) >= 0.5)
    if ml_anomalies:
        sigma_only = len(det_event_indices)
        ml_only = ml_anomalies - len(det_event_indices & {
            i for i, ev in enumerate(events) if (ev.get("anomaly_score") or 0) >= 0.5
        })
        summary_parts.append(
            f"ML layer flagged {ml_anomalies} anomalies, {ml_only} of which were not "
            "caught by Sigma rules."
        )

    return {
        "summary": " ".join(summary_parts),
        "severity": severity,
        "kill_chain": kill_chain,
        "visibility_gaps": gaps,
        "recommendations": recommendations,
        "_source": "offline",
    }
