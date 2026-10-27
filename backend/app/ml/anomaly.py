"""IsolationForest anomaly detection for ARIS.

Uses structured feature engineering instead of raw text hashing.
Features are designed to capture behavioral signals that distinguish
attacker activity from normal endpoint telemetry:

  - Command line length and entropy (encoded payloads are long + high entropy)
  - Presence of known suspicious indicators (encoded flags, tool names)
  - Process rarity within the corpus
  - User-process combination rarity
  - Network destination unusualness
  - Registry target sensitivity

Scoring standardises the raw IsolationForest decision_function f(x)
with the training mean and std, then applies a sigmoid with the sign
flipped (lower f = more anomalous): s = 1 / (1 + exp((f - mu) / sigma)).
Any event with f below the training mean scores above 0.5, so the share
of events above a threshold depends on the skew of f; it is not fixed.
contamination shifts f by a constant that cancels in (f - mu), so it does
not affect s. The threshold should be tuned against ground truth labels.
"""

from __future__ import annotations

import json
import math
import pickle
import re
from collections import Counter
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.config import settings

_MODEL_DIR = Path(__file__).parent
_MODEL_PATH = _MODEL_DIR / "model.pkl"
_SCALER_PATH = _MODEL_DIR / "scaler.pkl"
_STATS_PATH = _MODEL_DIR / "score_stats.pkl"

_model: IsolationForest | None = None
_scaler: StandardScaler | None = None
_score_stats: dict | None = None  # percentiles for normalization

# -----------------------------------------------------------------------
# Suspicious indicators (things that are rare in normal telemetry)
# -----------------------------------------------------------------------
SUSPICIOUS_CMD = [
    "-enc", "-encodedcommand", "-w hidden", "-nop", "-ep bypass",
    "downloadstring", "downloadfile", "iex(", "invoke-expression",
    "frombase64string", "minidump", "comsvcs", "lsass",
    "whoami", "systeminfo", "/etc/shadow",
    "reg add", "reg.exe add",
    "nc.exe", "mimikatz", "rubeus", "procdump",
    "certutil", "-decode",
]

SUSPICIOUS_PARENT = [
    "mshta.exe", "winword.exe", "excel.exe", "powerpnt.exe",
    "wscript.exe", "cscript.exe", "regsvr32.exe",
]

SENSITIVE_REG = [
    "\\currentversion\\run", "\\currentversion\\runonce",
    "\\currentversion\\policies", "\\winlogon",
]

C2_PORTS = {"443", "8080", "8443", "4444", "1234", "9999"}

# Names for the columns produced by _event_to_features, in order.
FEATURE_NAMES = [
    "cmd_length", "cmd_entropy", "suspicious_tokens", "encoded_payload",
    "suspicious_parent", "powershell", "reg_write_sensitive", "reg_query_sensitive",
    "c2_port", "rdp_internal", "auth_failure", "shadow_access", "source_type",
    "process_rarity", "user_process_rarity", "credential_tools", "transfer_tools",
    "hour_sin", "hour_cos",
]


# -----------------------------------------------------------------------
# Feature extraction
# -----------------------------------------------------------------------
def _entropy(s: str) -> float:
    """Shannon entropy of a string. High entropy = encoded/encrypted."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _event_to_features(event, process_counts=None, user_proc_counts=None) -> list[float]:
    """Extract structured numeric features from an Event."""
    cmd = (event.process or "").lower()
    user = (event.user or "").lower()
    host = (event.host or "").lower()
    source = (event.source_type or "").lower()

    parsed = {}
    if event.parsed:
        try:
            parsed = json.loads(event.parsed)
        except (json.JSONDecodeError, TypeError):
            pass

    parsed_lower = {k.lower(): str(v).lower() for k, v in parsed.items() if v}
    full_cmd = parsed_lower.get("command_line", cmd)
    parent = parsed_lower.get("parent_image", parsed_lower.get("parent_command_line", ""))
    target_obj = parsed_lower.get("target_object", "")
    dest_ip = parsed_lower.get("destination_ip", parsed_lower.get("dest_ip", ""))
    dest_port = parsed_lower.get("destination_port", parsed_lower.get("dest_port", ""))
    image = parsed_lower.get("image", "")
    ecar_action = parsed_lower.get("ecar_action", "")

    features = []

    # 1. Command line length (normalized log scale)
    features.append(math.log1p(len(full_cmd)))

    # 2. Command line entropy
    features.append(_entropy(full_cmd))

    # 3. Count of suspicious command indicators
    sus_count = sum(1 for s in SUSPICIOUS_CMD if s in full_cmd)
    features.append(float(sus_count))

    # 4. Has encoded/base64 content (binary: long + high entropy)
    has_encoded = 1.0 if (len(full_cmd) > 100 and _entropy(full_cmd) > 4.5) else 0.0
    features.append(has_encoded)

    # 5. Suspicious parent process
    has_sus_parent = 1.0 if any(p in parent for p in SUSPICIOUS_PARENT) else 0.0
    features.append(has_sus_parent)

    # 6. PowerShell involved
    features.append(1.0 if "powershell" in full_cmd or "powershell" in image else 0.0)

    # 7. Registry write to sensitive key
    reg_sensitive = 1.0 if any(k in target_obj for k in SENSITIVE_REG) else 0.0
    is_write = 1.0 if ("reg add" in full_cmd or ecar_action == "write") else 0.0
    features.append(reg_sensitive * is_write)

    # 8. Registry query of sensitive key (different signal)
    is_query = 1.0 if ("reg query" in full_cmd or ecar_action == "read") else 0.0
    features.append(reg_sensitive * is_query)

    # 9. Network to suspicious port
    features.append(1.0 if dest_port in C2_PORTS else 0.0)

    # 10. Network to private IP (internal lateral movement)
    is_private = 1.0 if (dest_ip.startswith("10.") or dest_ip.startswith("192.168.") or dest_ip.startswith("172.")) else 0.0
    is_rdp = 1.0 if dest_port == "3389" else 0.0
    features.append(is_private * is_rdp)

    # 11. Auth failure (auth.log specific)
    features.append(1.0 if "failed password" in cmd else 0.0)

    # 12. Shadow file access
    features.append(1.0 if "/etc/shadow" in cmd else 0.0)

    # 13. Source type encoding (ecar=0, sysmon=1, authlog=2)
    type_map = {"ecar": 0.0, "sysmon": 0.33, "authlog": 0.66}
    features.append(type_map.get(source, 0.5))

    # 14. Process rarity (if corpus stats available)
    if process_counts and image:
        proc_key = image.split("\\")[-1] if "\\" in image else image
        count = process_counts.get(proc_key, 0)
        total = sum(process_counts.values()) or 1
        features.append(-math.log1p(count / total))  # higher = rarer
    else:
        features.append(0.0)

    # 15. User-process combination rarity
    if user_proc_counts and user and image:
        proc_key = image.split("\\")[-1] if "\\" in image else image
        combo = f"{user}|{proc_key}"
        count = user_proc_counts.get(combo, 0)
        total = sum(user_proc_counts.values()) or 1
        features.append(-math.log1p(count / total))
    else:
        features.append(0.0)

    # 16. Credential tool indicators
    cred_tools = ["lsass", "mimikatz", "procdump", "comsvcs", "shadow", "passwd"]
    features.append(float(sum(1 for t in cred_tools if t in full_cmd)))

    # 17. Download/transfer indicators
    transfer = ["downloadstring", "downloadfile", "invoke-webrequest", "certutil",
                "bitsadmin", "wget", "curl"]
    features.append(float(sum(1 for t in transfer if t in full_cmd)))

    # 18. Time of day (hour as cyclic feature, attacks often happen during business hours)
    if event.timestamp:
        hour = event.timestamp.hour
        features.append(math.sin(2 * math.pi * hour / 24))
        features.append(math.cos(2 * math.pi * hour / 24))
    else:
        features.append(0.0)
        features.append(0.0)

    return features


def _build_corpus_stats(events):
    """Build process and user-process frequency counters."""
    proc_counts = Counter()
    user_proc_counts = Counter()

    for ev in events:
        parsed = {}
        if ev.parsed:
            try:
                parsed = json.loads(ev.parsed)
            except (json.JSONDecodeError, TypeError):
                pass

        image = str(parsed.get("image", ev.process or "")).lower()
        proc_key = image.split("\\")[-1] if "\\" in image else image
        user = (ev.user or "").lower()

        if proc_key:
            proc_counts[proc_key] += 1
        if user and proc_key:
            user_proc_counts[f"{user}|{proc_key}"] += 1

    return proc_counts, user_proc_counts


# -----------------------------------------------------------------------
# Training
# -----------------------------------------------------------------------
def train_model(events: list) -> IsolationForest:
    """Train IsolationForest on structured features."""
    global _model, _scaler, _score_stats

    print("  Building corpus statistics...")
    proc_counts, user_proc_counts = _build_corpus_stats(events)

    print("  Extracting features...")
    X_raw = np.array([
        _event_to_features(ev, proc_counts, user_proc_counts)
        for ev in events
    ], dtype=np.float64)

    _scaler = StandardScaler()
    X = _scaler.fit_transform(X_raw)

    print(f"  Feature matrix: {X.shape[0]:,} events x {X.shape[1]} features")

    _model = IsolationForest(
        n_estimators=200,
        contamination=0.01,  # expect ~1% anomalies
        max_features=0.8,
        random_state=42,
        n_jobs=-1,
    )
    _model.fit(X)

    # Compute score distribution for percentile normalization
    print("  Computing score distribution...")
    raw_scores = _model.decision_function(X)
    _score_stats = {
        "min": float(np.min(raw_scores)),
        "max": float(np.max(raw_scores)),
        "p01": float(np.percentile(raw_scores, 1)),
        "p05": float(np.percentile(raw_scores, 5)),
        "p10": float(np.percentile(raw_scores, 10)),
        "p50": float(np.percentile(raw_scores, 50)),
        "p90": float(np.percentile(raw_scores, 90)),
        "p95": float(np.percentile(raw_scores, 95)),
        "p99": float(np.percentile(raw_scores, 99)),
        "mean": float(np.mean(raw_scores)),
        "std": float(np.std(raw_scores)),
        "proc_counts": dict(proc_counts.most_common(10000)),
        "user_proc_counts": dict(user_proc_counts.most_common(10000)),
    }

    # Persist
    with open(_MODEL_PATH, "wb") as f:
        pickle.dump(_model, f)
    with open(_SCALER_PATH, "wb") as f:
        pickle.dump(_scaler, f)
    with open(_STATS_PATH, "wb") as f:
        pickle.dump(_score_stats, f)

    # Report distribution
    scores_01 = np.array([_raw_to_score(s) for s in raw_scores])
    for t in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
        count = int(np.sum(scores_01 >= t))
        print(f"    Threshold {t:.1f}: {count:,} events ({count/len(events)*100:.2f}%)")

    return _model


def load_model() -> bool:
    """Load a previously trained model from disk."""
    global _model, _scaler, _score_stats
    if _MODEL_PATH.exists() and _SCALER_PATH.exists() and _STATS_PATH.exists():
        with open(_MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        with open(_SCALER_PATH, "rb") as f:
            _scaler = pickle.load(f)
        with open(_STATS_PATH, "rb") as f:
            _score_stats = pickle.load(f)
        return True
    return False


# -----------------------------------------------------------------------
# Scoring
# -----------------------------------------------------------------------
def _raw_to_score(raw: float) -> float:
    """Convert raw decision_function to 0-1 using percentile mapping.

    Uses the stored score distribution to normalize. Lower raw scores
    (more anomalous in sklearn) map to higher ARIS scores.
    """
    if _score_stats is None:
        return 0.0

    mean = _score_stats["mean"]
    std = _score_stats["std"]

    if std < 1e-10:
        return 0.5

    # Z-score based: how many stds below mean (more negative = more anomalous)
    z = (raw - mean) / std

    # Sigmoid transform: z=-2 -> ~0.88 (very anomalous), z=0 -> 0.5, z=2 -> ~0.12
    score = 1.0 / (1.0 + math.exp(z))

    return max(0.0, min(1.0, round(score, 4)))


def score_event(event) -> Optional[float]:
    """Score a single event. Returns anomaly score in [0, 1] or None."""
    if _model is None or _scaler is None:
        if not load_model():
            return None

    proc_counts = _score_stats.get("proc_counts", {}) if _score_stats else {}
    user_proc_counts = _score_stats.get("user_proc_counts", {}) if _score_stats else {}

    features = _event_to_features(event, proc_counts, user_proc_counts)
    X = _scaler.transform([features])
    raw = _model.decision_function(X)[0]

    return _raw_to_score(raw)


def model_info() -> dict:
    """Describe the currently loaded model for the dashboard."""
    if _model is None:
        load_model()
    if _model is None:
        return {"loaded": False, "threshold": settings.ml_anomaly_threshold}

    from datetime import datetime

    stats = _score_stats or {}
    return {
        "loaded": True,
        "algorithm": type(_model).__name__,
        "n_estimators": _model.n_estimators,
        "contamination": _model.contamination,
        "max_features": _model.max_features,
        "n_features": int(getattr(_scaler, "n_features_in_", len(FEATURE_NAMES))),
        "feature_names": FEATURE_NAMES,
        "trained_at": datetime.fromtimestamp(_MODEL_PATH.stat().st_mtime).isoformat(),
        "known_processes": len(stats.get("proc_counts", {})),
        "raw_score_stats": {
            k: stats[k] for k in ("min", "p01", "p05", "p10", "p50", "p90", "p95", "p99", "max", "mean", "std")
            if k in stats
        },
        "threshold": settings.ml_anomaly_threshold,
    }


def is_anomaly(score: Optional[float], threshold: Optional[float] = None) -> bool:
    """Check if a score exceeds the anomaly threshold."""
    if score is None:
        return False
    t = threshold if threshold is not None else settings.ml_anomaly_threshold
    return score >= t
