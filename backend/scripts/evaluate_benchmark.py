"""Reproducible detection benchmark for ARIS.

Runs every detector configuration on the *same* events with the *same*
ground-truth labels and writes one JSON results file that the dashboard's
Evaluation tab renders (GET /api/evaluation).

Corpus: the synthetic eCAR / Sysmon / auth.log dataset written by
scripts.generate_dataset (dataset/manifest.json). This is NOT the DARPA
OpTC release; eCAR here means "OpTC-format" records produced by our own
generator.

Protocol
  - Temporal split: train = 2024-01-01..2024-12-31, test = 2025-01-01 onward.
    Corpus statistics, the scaler, every detector and every tuned threshold
    are fitted on train only; all reported metrics are on test.
  - Evaluation unit: one parsed event (one log record). FPR = FP / (FP + TN),
    i.e. the denominator is every benign parsed event in the test split.
  - The shipped code paths are used unchanged: parsers, run_rules(),
    _event_to_features(), _build_corpus_stats(), _raw_to_score().

Ground-truth labelling (event level, see label_event below)
  ground_truth.json has one record per injected attack line, keyed by
  (host, format, timestamp t). A parsed event is malicious when it is on the
  same host and format and t <= ts <= t + 120 s, and it is not a benign-template
  record (benign eCAR/Sysmon records carry random milliseconds while injected
  ones are whole-second; benign auth.log lines come from six fixed templates).
  The generator also injects C2 beacon flows (to 192.168.1.10:443) that it
  never writes to ground_truth.json; these are labelled T1071.001 by their
  destination and reported separately. Matched counts are checked against
  ground_truth.json per (host, format, t) group and against the manifest total.

Usage (from backend/):
  python -m scripts.evaluate_benchmark --data-dir dataset --work-dir /tmp/aris_eval
  python -m scripts.evaluate_benchmark --data-dir dataset --work-dir /tmp/aris_eval --limit-days 20
"""

from __future__ import annotations

import argparse
import gzip
import json
import math
import pickle
import re
import time
import zlib
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from app.ml import anomaly
from app.ml.anomaly import FEATURE_NAMES, _build_corpus_stats, _event_to_features, _raw_to_score
from app.parsers.authlog import parse_authlog_file
from app.parsers.optc import parse_optc_gzip
from app.parsers.sysmon import parse_sysmon_file
from app.sigma_engine.engine import describe_rule, load_rules, run_rules

SOURCES = [("ecar", "json.gz"), ("sysmon", "jsonl.gz"), ("authlog", "log.gz")]
SPLIT_DATE = date(2025, 1, 1)
EPOCH = date(2024, 1, 1)
LABEL_WINDOW = timedelta(seconds=120)
C2_IP, C2_PORT = "192.168.1.10", "443"
BEACON = "T1071.001"
BENIGN_AUTH = re.compile(
    r"Accepted publickey|pam_unix\((?:sshd|cron):session\)|systemd-logind|Connection closed"
)
SAMPLE_RATE = 0.10  # share of train events kept for fitting the detectors
CHUNK = 5000
OUT_PATH = Path(__file__).resolve().parent.parent / "app" / "evaluation" / "benchmark.json"

COLUMNS = {
    "tech": np.int8, "inst": np.int32, "src": np.int8, "day": np.int16, "mask": np.uint16,
    "if_raw": np.float64, "hbos": np.float32, "pca": np.float32, "ecod": np.float32, "rf": np.float32,
}


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------
class TotalDict(dict):
    """dict whose values() sums to a precomputed total.

    _event_to_features() computes sum(counts.values()) on every call. Keeping
    only the keys a Windows event can look up (and the true total) gives the
    identical feature value without shipping millions of auth.log keys to
    every worker or summing them per event.
    """

    def __init__(self, data, total):
        super().__init__(data)
        self.total = total

    def values(self):
        return (self.total,)


def chunked(it, n=CHUNK):
    buf = []
    for x in it:
        buf.append(x)
        if len(buf) == n:
            yield buf
            buf = []
    if buf:
        yield buf


def iter_events(path, src, day):
    if src == "ecar":
        yield from parse_optc_gzip(path)
        return
    with gzip.open(path, "rt", encoding="utf-8") as f:
        content = f.read()
    if src == "sysmon":
        yield from parse_sysmon_file(content)
    else:
        # auth.log has no year; take it from the file name instead of the
        # parser's hard-coded default of 2024.
        yield from parse_authlog_file(content, year=day.year)


def list_files(data_dir, limit_days=None):
    files = []
    for src, ext in SOURCES:
        # Only YYYY-MM-DD files belong to the manifest; day1..3 are an older run.
        for p in sorted((Path(data_dir) / src).glob(f"20[0-9][0-9]-*.{ext}")):
            day = datetime.strptime(p.name.split(".")[0], "%Y-%m-%d").date()
            files.append((str(p), src, day))
    if limit_days:
        train_days = sorted({d for _, _, d in files if d < SPLIT_DATE})[:limit_days]
        test_days = sorted({d for _, _, d in files if d >= SPLIT_DATE})[:limit_days]
        keep = set(train_days) | set(test_days)
        files = [f for f in files if f[2] in keep]
    return files


def load_ground_truth(data_dir):
    gt = json.loads((Path(data_dir) / "ground_truth.json").read_text())
    techniques = sorted({e["technique"] for e in gt["events"]}) + [BEACON]
    instances = {}
    index = defaultdict(list)
    expected = Counter()
    for e in gt["events"]:
        t = datetime.fromisoformat(e["timestamp"])
        inst = instances.setdefault((e["campaign"], e["host"], e["date"][:10]), len(instances))
        rec = (t, techniques.index(e["technique"]), inst)
        key = (e["host"], e["format"], t.date())
        if rec not in index[key]:
            index[key].append(rec)
        expected[(e["host"], e["format"], e["timestamp"])] += 1
    return {
        "techniques": techniques,
        "instances": [{"campaign": c, "host": h, "date": d} for (c, h, d), _ in
                      sorted(instances.items(), key=lambda kv: kv[1])],
        "index": dict(index),
        "expected": expected,
        "campaigns": gt["campaigns"],
    }


# -----------------------------------------------------------------------
# Worker state and tasks
# -----------------------------------------------------------------------
W = {}


def _init_worker(state_path):
    with open(state_path, "rb") as f:
        W.update(pickle.load(f))
    W["rule_bits"] = {r["id"]: i for i, r in enumerate(load_rules())}
    for m in ("iforest", "rf"):
        if W.get(m) is not None:
            W[m].n_jobs = 1


def label_event(ev, src):
    """Return (technique index, instance id, matched gt timestamp) or (-1, -1, None)."""
    ts = ev.timestamp
    recs = W["gt_index"].get((ev.host, src, ts.date()))
    if not recs:
        return -1, -1, None
    if src == "authlog":
        if BENIGN_AUTH.search(ev.raw or ""):
            return -1, -1, None
    else:
        if ts.microsecond:
            return -1, -1, None
        p = json.loads(ev.parsed)
        if p.get("destination_ip") == C2_IP and str(p.get("destination_port")) == C2_PORT:
            prior = [r for r in recs if r[0] <= ts] or recs
            return W["beacon_idx"], max(prior)[2], None
    for t, tech, inst in recs:
        if t <= ts <= t + LABEL_WINDOW:
            return tech, inst, t
    return -1, -1, None


def task_stats(args):
    path, src, day = args
    pc, upc = Counter(), Counter()
    for chunk in chunked(iter_events(path, src, day)):
        a, b = _build_corpus_stats(chunk)
        pc.update(a)
        upc.update(b)
    return src, pc, upc


def task_sample(args):
    path, src, day = args
    rng = np.random.default_rng(zlib.crc32(path.encode()))
    pc, upc = W["full_pc"], W["full_upc"]
    n, mean, m2 = 0, np.zeros(len(FEATURE_NAMES)), np.zeros(len(FEATURE_NAMES))
    sample, pos, pos_tech = [], [], []
    for chunk in chunked(iter_events(path, src, day)):
        X = np.array([_event_to_features(ev, pc, upc) for ev in chunk], dtype=np.float64)
        tech = np.array([label_event(ev, src)[0] for ev in chunk])
        # Chan et al. parallel mean/variance merge (matches StandardScaler.fit)
        k = len(X)
        cmean = X.mean(0)
        cm2 = ((X - cmean) ** 2).sum(0)
        delta = cmean - mean
        tot = n + k
        mean = mean + delta * k / tot
        m2 = m2 + cm2 + delta ** 2 * n * k / tot
        n = tot
        keep = rng.random(k) < SAMPLE_RATE
        sample.append(X[keep & (tech < 0)])
        pos.append(X[tech >= 0])
        pos_tech.append(tech[tech >= 0])
    return n, mean, m2, np.vstack(sample), np.vstack(pos), np.concatenate(pos_tech)


def task_score(args):
    path, src, day = args
    pc, upc = W["trunc_pc"], W["trunc_upc"]
    src_idx = [s for s, _ in SOURCES].index(src)
    day_idx = (day - EPOCH).days
    cols = defaultdict(list)
    matched = Counter()
    timing = Counter()
    for chunk in chunked(iter_events(path, src, day)):
        t0 = time.perf_counter()
        mask = np.zeros(len(chunk), dtype=np.uint16)
        for i, ev in enumerate(chunk):
            for d in run_rules(ev):
                mask[i] |= 1 << W["rule_bits"][d.rule_id]
        t1 = time.perf_counter()
        X = np.array([_event_to_features(ev, pc, upc) for ev in chunk], dtype=np.float64)
        t2 = time.perf_counter()
        Xs = W["scaler"].transform(X)
        if_raw = W["iforest"].decision_function(Xs)
        t3 = time.perf_counter()
        labels = [label_event(ev, src) for ev in chunk]
        for ev, (_, _, t) in zip(chunk, labels):
            if t is not None:
                matched[(ev.host, src, t.isoformat())] += 1
        cols["tech"].append(np.array([l[0] for l in labels], dtype=np.int8))
        cols["inst"].append(np.array([l[1] for l in labels], dtype=np.int32))
        cols["mask"].append(mask)
        cols["if_raw"].append(if_raw)
        cols["hbos"].append(W["hbos"].score(Xs).astype(np.float32))
        cols["pca"].append(pca_error(W["pca"], Xs).astype(np.float32))
        cols["ecod"].append(W["ecod"].score(Xs).astype(np.float32))
        cols["rf"].append(W["rf"].predict_proba(Xs)[:, 1].astype(np.float32))
        timing["sigma"] += t1 - t0
        timing["features"] += t2 - t1
        timing["iforest"] += t3 - t2
        timing["events"] += len(chunk)
    out = {k: np.concatenate(v) for k, v in cols.items()}
    n = len(out.get("tech", []))
    out["src"] = np.full(n, src_idx, dtype=np.int8)
    out["day"] = np.full(n, day_idx, dtype=np.int16)
    return out, dict(matched), timing


def task_parse_timing(args):
    path, src, day = args
    t0 = time.perf_counter()
    n = sum(1 for _ in iter_events(path, src, day))
    return n, time.perf_counter() - t0


# -----------------------------------------------------------------------
# Baseline detectors (fitted on the same scaled 19-feature train sample)
# -----------------------------------------------------------------------
class HBOS:
    """Histogram-based outlier score (Goldstein & Dengel, 2012)."""

    def __init__(self, bins=50):
        self.bins = bins

    def fit(self, X):
        self.edges, self.neglog, self.oob = [], [], []
        for j in range(X.shape[1]):
            e = np.histogram_bin_edges(X[:, j], self.bins)
            h, _ = np.histogram(X[:, j], e)
            dens = (h + 1) / (h.max() + 1)
            self.edges.append(e)
            self.neglog.append(-np.log(dens))
            self.oob.append(-np.log(1 / (h.max() + 1)))
        return self

    def score(self, X):
        s = np.zeros(len(X))
        for j, e in enumerate(self.edges):
            x = X[:, j]
            idx = np.clip(np.searchsorted(e, x, side="right") - 1, 0, self.bins - 1)
            v = self.neglog[j][idx]
            v[(x < e[0]) | (x > e[-1])] = self.oob[j]
            s += v
        return s


class ECOD:
    """Empirical-CDF outlier detection (Li et al., TKDE 2022)."""

    def fit(self, X, max_rows=200_000, seed=42):
        if len(X) > max_rows:
            X = X[np.random.default_rng(seed).choice(len(X), max_rows, replace=False)]
        self.sorted = np.sort(X, axis=0)
        self.n = len(X)
        mu, sd = X.mean(0), X.std(0)
        sd[sd == 0] = 1
        self.skew = (((X - mu) / sd) ** 3).mean(0)
        return self

    def score(self, X):
        floor = 1 / (self.n + 1)
        ol, orr, oa = np.zeros(len(X)), np.zeros(len(X)), np.zeros(len(X))
        for j in range(X.shape[1]):
            col = self.sorted[:, j]
            left = np.maximum(np.searchsorted(col, X[:, j], side="right") / self.n, floor)
            right = np.maximum((self.n - np.searchsorted(col, X[:, j], side="left")) / self.n, floor)
            ol -= np.log(left)
            orr -= np.log(right)
            oa -= np.log(left if self.skew[j] < 0 else right)
        return np.maximum(np.maximum(ol, orr), oa)


def pca_error(pca, X):
    return ((X - pca.inverse_transform(pca.transform(X))) ** 2).sum(1)


# -----------------------------------------------------------------------
# Metrics
# -----------------------------------------------------------------------
def confusion(flag, y):
    tp = int(np.count_nonzero(flag & y))
    fp = int(np.count_nonzero(flag & ~y))
    fn = int(np.count_nonzero(~flag & y))
    tn = int(len(y) - tp - fp - fn)
    return tp, fp, fn, tn


def metrics(flag, y, days, inst=None):
    tp, fp, fn, tn = confusion(flag, y)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) or 1.0
    out = {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": p, "recall": r, "f1": f1,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "mcc": (tp * tn - fp * fn) / denom,
        "alerts_per_day": (tp + fp) / days, "fp_per_day": fp / days,
    }
    if inst is not None:
        ids = inst[y]
        all_ids = np.unique(ids)
        hit = np.unique(ids[flag[y]])
        out["incidents_total"] = int(len(all_ids))
        out["incidents_detected"] = int(len(hit))
        out["incident_recall"] = len(hit) / len(all_ids) if len(all_ids) else 0.0
    return out


def best_f1_threshold(score, y):
    """Threshold maximising F1 (flag = score >= thr), via one sort."""
    order = np.argsort(-score, kind="stable")
    s, yy = score[order], y[order]
    tp = np.cumsum(yy)
    fp = np.cumsum(~yy)
    last = np.r_[np.nonzero(np.diff(s))[0], len(s) - 1]
    tp, fp, thr = tp[last], fp[last], s[last]
    f1 = 2 * tp / (tp + fp + yy.sum())
    i = int(np.argmax(f1))
    return float(thr[i]), float(f1[i])


def curves(score, y, n_points=120):
    """ROC/PR AUCs plus downsampled curves for the dashboard."""
    order = np.argsort(-score, kind="stable")
    s, yy = score[order], y[order]
    tp = np.cumsum(yy).astype(np.float64)
    fp = np.cumsum(~yy).astype(np.float64)
    last = np.r_[np.nonzero(np.diff(s))[0], len(s) - 1]
    tp, fp = tp[last], fp[last]
    P, N = tp[-1], fp[-1]
    tpr, fpr, prec = tp / P, fp / N, tp / (tp + fp)
    roc_auc = float(np.trapezoid(np.r_[0, tpr], np.r_[0, fpr]))
    ap = float(np.sum(np.diff(np.r_[0, tpr]) * prec))
    roc_idx = np.unique(np.searchsorted(fpr, np.r_[0, np.logspace(-7, 0, n_points)]).clip(0, len(fpr) - 1))
    pr_idx = np.unique(np.searchsorted(tpr, np.linspace(0, 1, n_points)).clip(0, len(tpr) - 1))
    return {
        "roc_auc": roc_auc, "average_precision": ap,
        "roc": [[float(fpr[i]), float(tpr[i])] for i in roc_idx],
        "pr": [[float(tpr[i]), float(prec[i])] for i in pr_idx],
    }


# -----------------------------------------------------------------------
# Pipeline
# -----------------------------------------------------------------------
def run_pool(fn, tasks, state_path, workers, label):
    t0 = time.time()
    out = []
    with Pool(workers, initializer=_init_worker, initargs=(state_path,)) as pool:
        for i, r in enumerate(pool.imap(fn, tasks, chunksize=1), 1):
            out.append(r)
            if i % 50 == 0 or i == len(tasks):
                print(f"\r  {label}: {i}/{len(tasks)} files ({time.time() - t0:.0f}s)", end="", flush=True)
    print()
    return out


def dump_state(work, **kw):
    path = work / "worker_state.pkl"
    with open(path, "wb") as f:
        pickle.dump(kw, f)
    return str(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data-dir", default="dataset")
    ap.add_argument("--work-dir", required=True, help="scratch space for per-event columns (~1.4 GB)")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--limit-days", type=int, default=None, help="first N train and N test days (smoke test)")
    ap.add_argument("--out", default=str(OUT_PATH))
    args = ap.parse_args()

    work = Path(args.work_dir)
    work.mkdir(parents=True, exist_ok=True)
    t_start = time.time()

    gt = load_ground_truth(args.data_dir)
    manifest = json.loads((Path(args.data_dir) / "manifest.json").read_text())
    rules = load_rules()
    base_state = {"gt_index": gt["index"], "beacon_idx": gt["techniques"].index(BEACON)}

    files = list_files(args.data_dir, args.limit_days)
    train_files = [f for f in files if f[2] < SPLIT_DATE]
    print(f"{len(files)} files ({len(train_files)} train)")

    # ---- Pass 1: corpus statistics on train (as train_model does) ----
    state = dump_state(work, **base_state)
    res = run_pool(task_stats, train_files, state, args.workers, "corpus stats")
    full_pc, full_upc, win_keys, win_combos = Counter(), Counter(), set(), set()
    for src, pc, upc in res:
        full_pc.update(pc)
        full_upc.update(upc)
        if src != "authlog":
            win_keys.update(pc)
            win_combos.update(upc)
    del res
    trunc_pc = dict(full_pc.most_common(10000))   # what score_stats.pkl stores
    trunc_upc = dict(full_upc.most_common(10000))
    pc_total, upc_total = sum(full_pc.values()), sum(full_upc.values())
    print(f"  {len(full_pc):,} process keys, {len(full_upc):,} user|process keys")

    # ---- Pass 2: train features -> scaler moments + fitting sample ----
    state = dump_state(
        work, **base_state,
        full_pc=TotalDict({k: full_pc[k] for k in win_keys}, pc_total),
        full_upc=TotalDict({k: full_upc[k] for k in win_combos}, upc_total),
    )
    res = run_pool(task_sample, train_files, state, args.workers, "train features")
    n, mean, m2 = 0, np.zeros(len(FEATURE_NAMES)), np.zeros(len(FEATURE_NAMES))
    for k, cmean, cm2, *_ in res:
        delta = cmean - mean
        tot = n + k
        mean = mean + delta * k / tot
        m2 = m2 + cm2 + delta ** 2 * n * k / tot
        n = tot
    sample = np.vstack([r[3] for r in res])
    pos = np.vstack([r[4] for r in res])
    del res

    scaler = StandardScaler()
    scaler.n_features_in_ = len(FEATURE_NAMES)
    scaler.n_samples_seen_ = n
    scaler.mean_ = mean
    scaler.var_ = m2 / n
    scaler.scale_ = np.where(scaler.var_ > 0, np.sqrt(scaler.var_), 1.0)
    Xs = scaler.transform(sample)
    Ps = scaler.transform(pos)
    print(f"  train events {n:,}; fitting sample {len(Xs):,} benign + {len(Ps):,} malicious")

    t0 = time.time()
    # Same hyper-parameters as anomaly.train_model(). Unsupervised detectors see
    # the sample *with* the train positives mixed in, as they would in deployment.
    unsup_X = np.vstack([Xs, Ps])
    iforest = IsolationForest(n_estimators=200, contamination=0.01, max_features=0.8,
                              random_state=42, n_jobs=-1).fit(unsup_X)
    hbos = HBOS().fit(unsup_X)
    ecod = ECOD().fit(unsup_X)
    pca = PCA(n_components=0.95, svd_solver="full", random_state=42).fit(unsup_X)
    rng = np.random.default_rng(42)
    neg = Xs[rng.choice(len(Xs), min(len(Xs), 400_000), replace=False)]
    rf = RandomForestClassifier(n_estimators=100, min_samples_leaf=2, class_weight="balanced_subsample",
                                n_jobs=-1, random_state=42)
    rf.fit(np.vstack([neg, Ps]), np.r_[np.zeros(len(neg)), np.ones(len(Ps))])
    print(f"  detectors fitted in {time.time() - t0:.0f}s (PCA keeps {pca.n_components_} comps)")

    # ---- Pass 3: score every file ----
    for c in COLUMNS:
        (work / f"{c}.bin").unlink(missing_ok=True)
    handles = {c: open(work / f"{c}.bin", "ab") for c in COLUMNS}
    state = dump_state(
        work, **base_state, scaler=scaler, iforest=iforest, hbos=hbos, ecod=ecod, pca=pca, rf=rf,
        trunc_pc=TotalDict({k: v for k, v in trunc_pc.items() if k in win_keys}, sum(trunc_pc.values())),
        trunc_upc=TotalDict({k: v for k, v in trunc_upc.items() if k in win_combos}, sum(trunc_upc.values())),
    )
    matched, timing = Counter(), Counter()
    t0 = time.time()
    with Pool(args.workers, initializer=_init_worker, initargs=(state,)) as pool:
        for i, (cols, m, tm) in enumerate(pool.imap(task_score, files, chunksize=1), 1):
            for c, dt in COLUMNS.items():
                handles[c].write(cols[c].astype(dt).tobytes())
            matched.update(m)
            timing.update(tm)
            if i % 50 == 0 or i == len(files):
                print(f"\r  scoring: {i}/{len(files)} files ({time.time() - t0:.0f}s)", end="", flush=True)
    print()
    for h in handles.values():
        h.close()
    parse_t = run_pool(task_parse_timing, files[:: max(1, len(files) // 40)], state, args.workers, "parse timing")

    col = {c: np.memmap(work / f"{c}.bin", dtype=dt, mode="r") for c, dt in COLUMNS.items()}
    total = len(col["tech"])
    train_mask = col["day"] < (SPLIT_DATE - EPOCH).days

    # ---- ARIS score with the shipped transform ----
    raw_train = col["if_raw"][train_mask].astype(np.float64)
    anomaly._score_stats = {"mean": float(raw_train.mean()), "std": float(raw_train.std())}
    aris = np.fromiter(map(_raw_to_score, col["if_raw"].astype(np.float64)), dtype=np.float32, count=total)
    del raw_train

    verification = verify_score_event(files, scaler, iforest, trunc_pc, trunc_upc,
                                      anomaly._score_stats, col, aris)

    results = analyse(col, aris, train_mask, gt, rules, manifest, matched, {(s, d) for _, s, d in files})
    results["score_transform"] = score_transform_report(aris, train_mask, anomaly._score_stats, verification)
    results["throughput"] = throughput_report(timing, parse_t, verification)
    results["meta"].update({
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "runtime_s": round(time.time() - t_start),
        "events_total": int(total),
        "limit_days": args.limit_days,
        "fit_sample": {"benign": int(len(Xs)), "malicious": int(len(Ps)), "rate": SAMPLE_RATE},
        "pca_components": int(pca.n_components_),
        "process_keys": len(full_pc),
    })
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(results, indent=1))
    print(f"\nWrote {args.out} in {time.time() - t_start:.0f}s")
    print_summary(results)


def verify_score_event(files, scaler, iforest, trunc_pc, trunc_upc, stats, col, aris):
    """Score the first events of one test file with the shipped score_event()
    and compare against the batched harness values at the same positions."""
    anomaly._model, anomaly._scaler = iforest, scaler
    anomaly._score_stats = {**stats, "proc_counts": trunc_pc, "user_proc_counts": trunc_upc}
    iforest.n_jobs = 1
    # Columns are written in file order, so a file's events are contiguous.
    target = next(f for f in files if f[2] >= SPLIT_DATE and f[1] == "ecar")
    start = int(np.argmax((col["day"] == (target[2] - EPOCH).days) & (col["src"] == 0)))
    events = []
    for ev in iter_events(*target):
        events.append(ev)
        if len(events) == 2000:
            break
    t0 = time.perf_counter()
    shipped = np.array([anomaly.score_event(ev) for ev in events], dtype=np.float64)
    per_event_s = (time.perf_counter() - t0) / len(events)
    batched = aris[start:start + len(events)].astype(np.float64)
    return {
        "events_compared": len(events),
        "max_abs_diff": float(np.max(np.abs(shipped - batched))),
        "score_event_ms_per_event": per_event_s * 1000,
    }


def score_transform_report(aris, train_mask, stats, verification):
    tr = aris[train_mask]
    return {
        "formula": "s(x) = 1 / (1 + exp((f(x) - mu) / sigma)) = sigmoid(-(f(x) - mu) / sigma), rounded to 4 dp",
        "mu": stats["mean"], "sigma": stats["std"],
        "train_share_ge": {str(t): float(np.mean(tr >= t)) for t in (0.5, 0.6, 0.7, 0.75, 0.8, 0.9)},
        "notes": [
            "f(x) is IsolationForest.decision_function: lower = more anomalous, so the minus sign is required.",
            "contamination only shifts decision_function by a constant offset, which cancels in (f - mu) / sigma; "
            "it has no effect on s(x).",
            "The share of events above 0.5 is set by the skew of f, not fixed at 5% (module docstring was wrong).",
        ],
        "verification": verification,
    }


def throughput_report(timing, parse_t, verification):
    n = timing["events"]
    pn = sum(r[0] for r in parse_t)
    ps = sum(r[1] for r in parse_t)
    parse_us = ps / pn * 1e6 if pn else 0
    per = {
        "parse_us": parse_us,
        "sigma_us": timing["sigma"] / n * 1e6,
        "features_us": timing["features"] / n * 1e6,
        "iforest_batched_us": timing["iforest"] / n * 1e6,
        "iforest_per_event_us": verification["score_event_ms_per_event"] * 1000,
    }
    sigma_only = per["parse_us"] + per["sigma_us"]
    hybrid_b = sigma_only + per["features_us"] + per["iforest_batched_us"]
    hybrid_e = sigma_only + per["iforest_per_event_us"]
    per.update({
        "single_core_eps": {
            "sigma_only": 1e6 / sigma_only,
            "hybrid_batched_scoring": 1e6 / hybrid_b,
            "hybrid_per_event_scoring (ingest path)": 1e6 / hybrid_e,
        },
        "note": "Single-core events/second derived from per-component CPU time; excludes DB writes.",
    })
    return per


def analyse(col, aris, train_mask, gt, rules, manifest, matched, evaluated):
    techniques = gt["techniques"]
    beacon_idx = techniques.index(BEACON)
    days_all = col["day"]
    test = ~train_mask
    test_days = len(np.unique(days_all[test]))
    train_days = len(np.unique(days_all[train_mask]))
    rule_meta = [describe_rule(r) for r in rules]
    sources = [s for s, _ in SOURCES]

    # Labels. Primary = ground_truth.json records; the generator's unlabelled
    # C2 beacons are excluded from the primary metrics (neither positive nor
    # negative) and counted as positives in the secondary table.
    tech = col["tech"]
    is_beacon = tech == beacon_idx
    tr = train_mask & ~is_beacon
    te = test & ~is_beacon
    y_tr, y_te = tech[tr] >= 0, tech[te] >= 0
    inst_te = col["inst"][te]
    sig_all = col["mask"] != 0

    # ---- Threshold tuning on train only ----
    aris_tr = aris[tr]
    sig_tr = sig_all[tr]
    thr_if, _ = best_f1_threshold(aris_tr, y_tr)
    thr_hyb, _ = best_f1_threshold(np.where(sig_tr, 2.0, aris_tr), y_tr)

    scores = {"hbos": col["hbos"], "pca": col["pca"], "ecod": col["ecod"], "rf": col["rf"]}
    thr = {"if": thr_if, "hyb": thr_hyb}
    for k, s in scores.items():
        s_tr = s[tr]
        thr[k], _ = best_f1_threshold(s_tr, y_tr)
        thr[k + "_hyb"], _ = best_f1_threshold(np.where(sig_tr, s_tr.max() + 1, s_tr), y_tr)
    del aris_tr

    # Flags are computed on the whole test split (beacons included) so the
    # secondary table can reuse them; `keep` selects the primary rows.
    te_all = test
    keep = ~is_beacon[te_all]
    aris_all = aris[te_all]
    sig_all_te = sig_all[te_all]
    aris_te = aris_all[keep]
    sig_te = sig_all_te[keep]
    src_te = col["src"][te]
    S_all = {k: v[te_all] for k, v in scores.items()}
    S = {k: v[keep] for k, v in S_all.items()}
    y_beacon = tech[te_all] >= 0
    inst_beacon = col["inst"][te_all]

    flags, flags_all = {}, {}
    configs = []

    def add(key, name, family, flag_all, desc, threshold=None):
        flags_all[key] = flag_all
        flags[key] = flag = flag_all[keep]
        configs.append({"key": key, "name": name, "family": family, "description": desc,
                        "threshold": threshold, **metrics(flag, y_te, test_days, inst_te)})

    # Rebind the per-row inputs of the configuration list to the full test split.
    aris_te_k, sig_te_k, S_k = aris_te, sig_te, S
    aris_te, sig_te, S = aris_all, sig_all_te, S_all

    if_t = aris_te >= thr_if
    add("sigma", "Sigma-only", "aris", sig_te, "10 ARIS Sigma rules, any rule fires")
    add("if_050", "IsolationForest (θ=0.50, code default)", "aris", aris_te >= 0.5,
        "ARIS score ≥ 0.50 (ARIS_ML_ANOMALY_THRESHOLD default)", 0.5)
    add("if_075", "IsolationForest (θ=0.75, report)", "aris", aris_te >= 0.75, "ARIS score ≥ 0.75", 0.75)
    add("if_tuned", "IsolationForest (θ tuned)", "aris", if_t, "θ maximising IF-only F1 on 2024", thr_if)
    add("hybrid_050", "Hybrid OR (θ=0.50)", "aris", sig_te | (aris_te >= 0.5), "Sigma ∪ IF@0.50", 0.5)
    add("hybrid_075", "Hybrid OR (θ=0.75)", "aris", sig_te | (aris_te >= 0.75), "Sigma ∪ IF@0.75", 0.75)
    add("hybrid", "ARIS Hybrid OR (θ tuned)", "aris", sig_te | (aris_te >= thr_hyb),
        "Sigma ∪ IF, θ maximising hybrid F1 on 2024", thr_hyb)
    add("hybrid_and", "Hybrid AND (θ tuned)", "aris", sig_te & if_t, "Sigma ∩ IF@θ tuned", thr_if)
    names = {"hbos": "HBOS", "pca": "PCA reconstruction", "ecod": "ECOD", "rf": "Random Forest (supervised)"}
    for k, s in S.items():
        fam = "supervised" if k == "rf" else "unsupervised"
        add(k, names[k], fam, s >= thr[k], f"{names[k]} on the same 19 features, θ tuned on 2024", thr[k])
        add(k + "_hybrid", f"Sigma ∪ {names[k]}", fam, sig_te | (s >= thr[k + "_hyb"]),
            f"Sigma ∪ {names[k]}, θ tuned for hybrid F1 on 2024", thr[k + "_hyb"])
    aris_te, sig_te, S = aris_te_k, sig_te_k, S_k
    if_t = aris_te >= thr_if
    # Random flagging at the ARIS hybrid's alert volume (analytic expectation)
    q = flags["hybrid_075"].mean()
    P_te, N_te = int(y_te.sum()), int((~y_te).sum())
    tp, fp = q * P_te, q * N_te
    configs.append({
        "key": "random", "name": "Random (same alert volume as Hybrid θ=0.75)", "family": "reference",
        "description": "Expected value, flag rate q = Hybrid OR (θ=0.75) flag rate", "threshold": None,
        "tp": tp, "fp": fp, "fn": P_te - tp, "tn": N_te - fp, "precision": P_te / (P_te + N_te),
        "recall": q, "f1": 2 * (P_te / (P_te + N_te)) * q / ((P_te / (P_te + N_te)) + q),
        "fpr": q, "mcc": 0.0, "alerts_per_day": (tp + fp) / test_days, "fp_per_day": fp / test_days,
    })

    # Secondary: same flags, C2 beacons counted as malicious
    with_beacons = {k: metrics(f, y_beacon, test_days, inst_beacon) for k, f in flags_all.items()}

    # ---- Curves ----
    curve_set = {
        "if": curves(aris_te, y_te),
        "hybrid": curves(np.where(sig_te, 2.0, aris_te), y_te),
        **{k: curves(s, y_te) for k, s in S.items()},
    }
    sig_m = metrics(sig_te, y_te, test_days)
    curve_set["sigma_point"] = {"fpr": sig_m["fpr"], "tpr": sig_m["recall"], "precision": sig_m["precision"]}

    # ---- Threshold sweep on the ARIS score (test) ----
    sweep = []
    for t in np.round(np.arange(0.30, 1.0, 0.01), 2):
        f_if = aris_te >= t
        a = metrics(f_if, y_te, test_days)
        b = metrics(sig_te | f_if, y_te, test_days)
        sweep.append({"theta": float(t),
                      "if": {k: a[k] for k in ("precision", "recall", "f1", "fpr", "tp", "fp")},
                      "hybrid": {k: b[k] for k in ("precision", "recall", "f1", "fpr", "tp", "fp")}})

    # ---- Per technique (test, beacons included as their own row) ----
    tech_all = tech[te_all]
    mask_all = col["mask"][te_all]
    per_tech = []
    for ti, name in enumerate(techniques):
        m = tech_all == ti
        if not m.any():
            continue
        fired = Counter()
        for bits in mask_all[m]:
            for b in range(len(rule_meta)):
                if bits >> b & 1:
                    fired[rule_meta[b]["rule_id"]] += 1
        per_tech.append({
            "technique": name, "events": int(m.sum()),
            **{k: int(flags_all[k][m].sum()) for k in
               ("sigma", "if_050", "if_075", "if_tuned", "hybrid_075", "hbos", "pca", "ecod", "rf")},
            "rules_fired": dict(fired),
            "in_ground_truth_json": name != BEACON,
        })

    # ---- Leave-one-rule-out: does the ML layer cover a missing rule? ----
    loro_thetas = {"0.50": 0.5, "0.75": 0.75, "tuned": thr_if}
    if_at = {k: aris_te >= t for k, t in loro_thetas.items()}
    tech_te = tech[te]
    mask_te = col["mask"][te]
    loro = []
    for b, rm in enumerate(rule_meta):
        tidx = techniques.index(rm["technique"]) if rm["technique"] in techniques else None
        sig_r = (mask_te & ~np.uint16(1 << b)) != 0
        m = (tech_te == tidx) if tidx is not None else np.zeros(len(sig_r), bool)
        row = {
            "rule_id": rm["rule_id"], "technique": rm["technique"], "events": int(m.sum()),
            "sigma_full": int(sig_te[m].sum()), "sigma_without_rule": int(sig_r[m].sum()),
            "overall_sigma_without_rule": metrics(sig_r, y_te, test_days),
            "hybrid_without_rule": {},
        }
        for k, f in if_at.items():
            h = sig_r | f
            row["hybrid_without_rule"][k] = {"caught": int(h[m].sum()), **metrics(h, y_te, test_days)}
        loro.append(row)

    # ---- Per source (test) ----
    per_source = {}
    for si, s in enumerate(sources):
        m = src_te == si
        if m.any():
            per_source[s] = {k: metrics(flags[k][m], y_te[m], test_days)
                             for k in ("sigma", "if_tuned", "hybrid", "if_075", "hybrid_075")}
            per_source[s]["events"] = int(m.sum())
            per_source[s]["malicious"] = int(y_te[m].sum())

    # ---- Sigma rule hits on test, split by label ----
    rule_hits = []
    for b, rm in enumerate(rule_meta):
        f = (mask_te >> b & 1).astype(bool)
        rule_hits.append({**rm, "tp": int((f & y_te).sum()), "fp": int((f & ~y_te).sum())})

    # ---- Train-split metrics (transparency, same thresholds) ----
    aris_tr = aris[tr]
    train_metrics = {
        "sigma": metrics(sig_tr, y_tr, train_days),
        "if_tuned": metrics(aris_tr >= thr_if, y_tr, train_days),
        "hybrid": metrics(sig_tr | (aris_tr >= thr_hyb), y_tr, train_days),
    }

    # ---- Label verification (only groups on evaluated days) ----
    expected = {k: n for k, n in gt["expected"].items()
                if (k[1], datetime.fromisoformat(k[2]).date()) in evaluated}
    exp_tot = sum(expected.values())
    mismatches = [{"host": h, "format": f, "t": t, "expected": n, "matched": matched.get((h, f, t), 0)}
                  for (h, f, t), n in expected.items() if matched.get((h, f, t), 0) != n]
    extra = sum(v for k, v in matched.items() if k not in expected)
    beacons = int((tech == beacon_idx).sum())
    label_check = {
        "ground_truth_records": exp_tot,
        "matched_events": int(sum(matched.values())),
        "groups": len(expected),
        "group_mismatches": len(mismatches),
        "mismatch_examples": mismatches[:10],
        "unexpected_matches": extra,
        "beacon_events": beacons,
        "provenance_total": int((tech >= 0).sum()),
        "manifest_total_malicious": manifest["total_malicious"],
        "manifest_total_events": manifest["total_events"],
        "parsed_events": int(len(tech)),
    }

    # ---- Instances (incidents) ----
    inst_test = np.unique(col["inst"][te][y_te])
    return {
        "meta": {
            "dataset": "Synthetic ARIS corpus (scripts/generate_dataset.py, seed "
                       f"{manifest['seed']}); eCAR records are OpTC-format, not DARPA OpTC",
            "range": manifest["range"],
            "split": {"train": f"{EPOCH} .. {SPLIT_DATE - timedelta(days=1)}", "test": f"{SPLIT_DATE} .. end",
                      "train_days": train_days, "test_days": test_days},
            "unit": "parsed event (one log record)",
            "fpr_definition": "FPR = FP / (FP + TN); denominator = all benign parsed events in the test split",
            "positives_test": P_te, "negatives_test": N_te,
            "positives_train": int(y_tr.sum()), "negatives_train": int((~y_tr).sum()),
            "prevalence_test": P_te / (P_te + N_te),
            "incidents_test": int(len(inst_test)),
            "thresholds": thr,
            "label_procedure": [
                "ground_truth.json lists one record per injected attack line: host, format, timestamp t, technique.",
                "A parsed event is malicious if it has the same host and format and t <= ts <= t + 120 s.",
                "eCAR/Sysmon: benign records carry random milliseconds, injected ones are whole-second; "
                "only whole-second events can match.",
                "auth.log: lines from the six benign generator templates never match.",
                "C2 beacon flows to 192.168.1.10:443 are injected by the generator but absent from "
                "ground_truth.json; they are labelled T1071.001, excluded from the primary metrics "
                "(neither positive nor negative) and counted as positives in the secondary table.",
                "Matched counts are checked against ground_truth.json per (host, format, t) group.",
                "Incident = (campaign, host, date); detected if any of its events is flagged.",
            ],
        },
        "label_check": label_check,
        "configs": configs,
        "configs_with_beacons": with_beacons,
        "train_metrics": train_metrics,
        "curves": curve_set,
        "sweep": sweep,
        "per_technique": per_tech,
        "leave_one_rule_out": loro,
        "per_source": per_source,
        "rule_hits": rule_hits,
        "report_audit": report_audit(),
        "external_references": EXTERNAL_REFERENCES,
        "source_matrix": SOURCE_MATRIX,
    }


def report_audit():
    """Check the arithmetic of report Table 6.1 (values as printed)."""
    rows = {"sigma": (0.82, 0.61), "ml": (0.34, 0.78), "hybrid": (0.58, 0.89)}
    # Per unit of positives P: TP = R, FP = R (1 - p) / p
    fp = {k: r * (1 - p) / p for k, (p, r) in rows.items()}
    hyb_r = rows["hybrid"][1]
    max_p = hyb_r / (hyb_r + max(fp["sigma"], fp["ml"]))
    return {
        "table_6_1": {k: {"precision": p, "recall": r, "tp_per_P": r, "fp_per_P": fp[k]} for k, (p, r) in rows.items()},
        "union_constraint": "Hybrid = Sigma ∪ ML, so FP_hybrid ≥ max(FP_sigma, FP_ml) and TP_hybrid ≤ TP_sigma + TP_ml.",
        "hybrid_precision_upper_bound": max_p,
        "consistent": rows["hybrid"][0] <= max_p + 1e-9,
        "explanation": (
            f"ML-only at P=0.34, R=0.78 implies FP = {fp['ml']:.3f}·P. The union keeps every ML false positive, "
            f"so at R=0.89 the hybrid precision is at most 0.89 / (0.89 + {fp['ml']:.3f}) = {max_p:.3f}. "
            "The reported 0.58 implies FP = 0.644·P, fewer false positives than ML-only alone, which a union cannot have."
        ),
        "figure_6_2": "IF 'FPR 0.48 at recall 0.40' contradicts IF-only at recall 0.78 with FP = 1.51·P: "
                      "on one ROC curve FPR cannot fall while recall rises.",
    }


EXTERNAL_REFERENCES = [
    {"system": "DeepLog (Du et al., CCS 2017)", "dataset": "HDFS (Hadoop logs)",
     "unit": "log session (block_id)", "precision": 0.95, "recall": 0.96, "f1": 0.96,
     "note": "LSTM over log-key sequences; needs parsed log templates and sessions."},
    {"system": "LogBERT (Guo et al., IJCNN 2021)", "dataset": "HDFS",
     "unit": "log sequence", "precision": 0.8702, "recall": 0.7810, "f1": 0.8232,
     "note": "Self-supervised Transformer over log-key sequences."},
    {"system": "LogBERT (Guo et al., IJCNN 2021)", "dataset": "BGL",
     "unit": "log sequence (window)", "precision": 0.8940, "recall": 0.9232, "f1": 0.9083, "note": ""},
    {"system": "LogBERT (Guo et al., IJCNN 2021)", "dataset": "Thunderbird",
     "unit": "log sequence (window)", "precision": 0.9675, "recall": 0.9652, "f1": 0.9664, "note": ""},
]

SOURCE_MATRIX = [
    {
        "source": "Sysmon JSONL",
        "parser": "app/parsers/sysmon.py",
        "event_types": "Any EventID with Image / CommandLine / ParentImage / TargetObject / "
                       "DestinationIp / DestinationPort / TargetFilename. Exercised: EID 1 (process create), "
                       "EID 3 (network connect), EID 13 (registry set).",
        "rules": "aris_r_0001 whoami (T1033), 0002 Run key (T1547.001), 0003 encoded PowerShell (T1059.001), "
                 "0006 systeminfo (T1082), 0007 RDP 3389 (T1021.001), 0008 LSASS dump (T1003.001), "
                 "0009 download cradle (T1105, command-line selections only), 0010 mshta / Base64 (T1027)",
        "limitations": "0009 tool-drop selection matches field file_path, but the parser emits target_filename, "
                       "so it never fires. Flat JSON only (no Windows XML / EVTX). EventID is not used by any "
                       "rule, so 0002 also fires on registry reads that carry a Run-key TargetObject.",
    },
    {
        "source": "Linux auth.log",
        "parser": "app/parsers/authlog.py",
        "event_types": "Any syslog line matching 'Mon dd HH:MM:SS host daemon[pid]: msg' "
                       "(sshd, sudo, cron, systemd-logind…); actions classified as auth_failure, auth_success, "
                       "session_open/close, privilege_escalation.",
        "rules": "aris_r_0004 SSH failed password (T1110.001), aris_r_0005 /etc/shadow access (T1003.008)",
        "limitations": "Syslog has no year; the parser hard-codes 2024 (wrong for 2025/2026 files and at "
                       "year rollover). 0004 fires per failed line, with no count or time-window aggregation "
                       "(engine has no aggregations), so one typo is an alert. Many of the 19 IF features "
                       "are Windows-only and always 0 here.",
    },
    {
        "source": "eCAR (OpTC-format)",
        "parser": "app/parsers/optc.py",
        "event_types": "PROCESS CREATE/OPEN, REGISTRY WRITE/READ/DELETE, FLOW OPEN/START, SHELL EXECUTE, "
                       "FILE CREATE/DELETE/MODIFY, MODULE LOAD, USER_SESSION LOGIN/LOGOUT (other pairs dropped).",
        "rules": "aris_r_0001, 0002 (key → target_object), 0003, 0006, 0007 (dest_port), 0008, "
                 "0009 (command line only), 0010 (parent_image_path)",
        "limitations": "Only validated on generator output, not on the DARPA OpTC release. actorID is not "
                       "resolved to its process, so FLOW/REGISTRY/FILE events carry no command line or parent. "
                       "0009 tool-drop never fires (file_path vs target_filename). No rules for FILE or MODULE "
                       "events.",
    },
]


def print_summary(r):
    lc = r["label_check"]
    print(f"\nLabels: {lc['matched_events']}/{lc['ground_truth_records']} GT records matched, "
          f"{lc['group_mismatches']} group mismatches, {lc['beacon_events']} beacons, "
          f"provenance total {lc['provenance_total']} (manifest {lc['manifest_total_malicious']})")
    m = r["meta"]
    print(f"Test: {m['positives_test']:,} malicious / {m['negatives_test']:,} benign events, "
          f"{m['split']['test_days']} days")
    print(f"\n{'Configuration':45s} {'TP':>6s} {'FP':>9s} {'FN':>6s} {'P':>6s} {'R':>6s} {'F1':>6s} {'FPR':>9s}")
    for c in r["configs"]:
        print(f"{c['name'][:45]:45s} {c['tp']:6.0f} {c['fp']:9.0f} {c['fn']:6.0f} "
              f"{c['precision']:6.3f} {c['recall']:6.3f} {c['f1']:6.3f} {c['fpr']:9.2e}")


if __name__ == "__main__":
    main()
