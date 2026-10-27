# ARIS evaluation: corrected Chapter 6 material

All numbers come from `backend/scripts/evaluate_benchmark.py` (results in
`backend/app/evaluation/benchmark.json`; also shown in the dashboard's
Evaluation tab). Rerun with:

```bash
cd backend
python -m scripts.evaluate_benchmark --data-dir dataset --work-dir <scratch dir>
```

## Contributions (rephrased)

1. **One rule set across three log sources.** Field-mapping parsers project
   Sysmon JSONL, Linux auth.log and eCAR (OpTC-format) records into one schema,
   so ten Sigma rules (10 ATT&CK techniques, 6 tactics) run unchanged on all
   three. The rules are evaluated by a ~200-line Sigma-subset engine
   (contains / startswith / endswith / re / all; and / or / not; no aggregation).
2. **An inline anomaly scorer and an honest measurement of it.** An
   IsolationForest over 19 engineered features, with a sigmoid z-score
   transform documented and verified against the code. At every threshold the
   standalone scorer has event-level precision below 0.1 %.
3. **A reproducible, event-level benchmark.** A temporal train/test split over
   42.9 M events, with ground-truth labels checked record by record. Confusion
   matrices and an explicit FPR denominator are reported. Sigma-only,
   IsolationForest and hybrid configurations are compared on identical data
   against four in-house baselines (HBOS, PCA, ECOD, supervised Random
   Forest). A leave-one-rule-out experiment measures what the ML layer
   contributes when a rule is missing.
4. **ATT&CK-grounded incident narratives** from an LLM, with an offline
   template fallback. These are not evaluated quantitatively in this work.

## 6.1 Evaluation protocol

| Item | Value |
|---|---|
| Corpus | Synthetic, `scripts/generate_dataset.py`, seed 2024, 2024-01-01 to 2026-03-31, 42,947,331 events, 47 campaigns. eCAR records are OpTC-*format*; this is **not** the DARPA OpTC release. |
| Split | Train 2024-01-01 to 2024-12-31 (366 days, 19.1 M events). Test 2025-01-01 to 2026-03-31 (455 days, 23.8 M events). Corpus statistics, scaler, all detectors and all tuned thresholds are fitted on train only. |
| Evaluation unit | One parsed event (one log record) |
| Test positives / negatives | 1,345 malicious / 23,799,322 benign (prevalence 0.0057 %) |
| **FPR** | FPR = FP / (FP + TN). The denominator is **all 23,799,322 benign parsed events in the test split**. |
| Incident unit | (campaign, host, day): 107 incidents in test. An incident counts as detected if any of its events is flagged. |

### Ground-truth labelling procedure

1. `ground_truth.json` lists one record per injected attack line: host,
   format, timestamp *t* and technique.
2. A parsed event is malicious if it has the same host and format as a record
   and *t* ≤ ts ≤ *t* + 120 s. The window covers T1105 file drops
   (*t* + 5–20 s) and SSH brute-force bursts (up to *t* + 96 s).
3. Benign eCAR and Sysmon records carry random milliseconds, while injected
   records are whole-second, so only whole-second events can match. Lines from
   the six benign auth.log templates never match.
4. **Verification:** 2,450 of 2,450 records were matched, with 0 mismatches
   across 1,478 (host, format, *t*) groups and 0 unexpected matches.
5. The generator also injects **1,626 C2 beacon flows** (to 192.168.1.10:443)
   that it never writes to `ground_truth.json`. Adding them gives
   2,450 + 1,626 = 4,076, which equals `manifest.json`'s `total_malicious`.
   Beacons are excluded from the primary metrics (neither positive nor
   negative) and counted as positives in a secondary table.

The earlier time-window labelling in `app/parsers/optc_labels.py` (2019 OpTC
windows, all events on the host for 4–7 h) is not used. It labels nothing in
this corpus.

## 6.2 How the hybrid trades precision for recall

The hybrid is a union, Hybrid = Sigma ∪ {score ≥ θ}. It follows that:

- TP_H = TP_S + TP_ML − TP_both, so recall can only rise.
- FP_H = FP_S + FP_ML − FP_both ≥ max(FP_S, FP_ML), so every ML false
  positive is inherited.

Hybrid precision is therefore capped by the ML layer's false-positive count.

**Report Table 6.1 cannot be correct as printed.** ML-only with P = 0.34 and
R = 0.78 implies FP = 1.514·P, where P is the number of positives. A union at
R = 0.89 therefore has precision at most 0.89 / (0.89 + 1.514) = **0.370**. The
printed 0.58 implies FP = 0.644·P, which is fewer false positives than ML-only
alone. Figure 6.2 has the same problem: "IF FPR 0.48 at recall 0.40" cannot
sit on the same ROC curve as recall 0.78 with FP = 1.51·P.

## 6.3 Results (test split, primary labels)

| Configuration | θ | TP | FP | FN | TN | Precision | Recall | F1 | FPR | FP/day |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Sigma-only | – | 1,294 | 0 | 51 | 23,799,322 | 1.000 | 0.962 | 0.981 | 0 | 0 |
| IsolationForest | 0.50 (code default) | 1,302 | 9,024,065 | 43 | 14,775,257 | 0.0001 | 0.968 | 0.0003 | 0.379 | 19,833 |
| IsolationForest | 0.75 (report) | 580 | 3,930,679 | 765 | 19,868,643 | 0.0001 | 0.431 | 0.0003 | 0.165 | 8,639 |
| IsolationForest | 0.974 (tuned on 2024) | 0 | 11,460 | 1,345 | 23,787,862 | 0 | 0 | 0 | 4.8e-4 | 25 |
| Hybrid OR | 0.50 | 1,345 | 9,024,065 | 0 | 14,775,257 | 0.0001 | 1.000 | 0.0003 | 0.379 | 19,833 |
| **Hybrid OR** | **0.75** | **1,315** | **3,930,679** | **30** | **19,868,643** | **0.0003** | **0.978** | **0.0007** | **0.165** | **8,639** |
| Hybrid OR, θ tuned for hybrid F1 | ∞ (IF off) | 1,294 | 0 | 51 | 23,799,322 | 1.000 | 0.962 | 0.981 | 0 | 0 |
| HBOS | tuned | 45 | 143 | 1,300 | – | 0.239 | 0.033 | 0.059 | 6.0e-6 | 0.3 |
| PCA reconstruction | tuned | 198 | 0 | 1,147 | – | 1.000 | 0.147 | 0.257 | 0 | 0 |
| ECOD | tuned | 276 | 468 | 1,069 | – | 0.371 | 0.205 | 0.264 | 2.0e-5 | 1.0 |
| Random Forest (supervised reference) | tuned | 564 | 0 | 781 | – | 1.000 | 0.419 | 0.591 | 0 | 0 |
| Sigma ∪ {HBOS, PCA, ECOD, RF} | tuned for hybrid F1 | 1,294 | 0 | 51 | – | 1.000 | 0.962 | 0.981 | 0 | 0 |

For the baseline rows, TN = 23,799,322 − FP.

Threshold-free comparison on the test split:

| Detector | ROC-AUC | Average precision |
|---|---:|---:|
| IsolationForest | 0.819 | 0.0002 |
| ECOD | 0.846 | 0.165 |
| PCA | 0.548 | 0.147 |
| HBOS | 0.497 | 0.035 |
| RF (supervised) | 0.991 | 0.429 |
| Hybrid (Sigma ∪ IF) | 0.993 | 0.962 |

**Reading the results**

- **Sigma's 51 false negatives are all T1105 tool-drop events** (`nc.exe`
  written to Temp). Rule `aris_r_0009` matches the field `file_path`, but both
  parsers emit `target_filename`, so that selection never fires. This is a
  field-mapping bug, not a coverage limit.
- **Hybrid at θ = 0.75** recovers 21 of those 51 events, at the cost of
  3,930,679 false positives (8,639 per day).
- **Tuning θ on 2024 selects "IF off".** No threshold improves on Sigma-only
  for F1. Every unsupervised detector, and even the supervised RF, adds
  nothing to Sigma at its tuned threshold.
- **The IsolationForest ranks attacks above average** (ROC-AUC 0.82) but has
  near-zero precision, because the base rate is 1 in 17,700.
- **Labelling leakage limits what this corpus can show.** Sigma reaches
  P = 1.0 because the generator's attack templates and the rules were written
  together, so these results describe the synthetic corpus, not real
  telemetry.

**Secondary labels (C2 beacons counted as malicious, 2,183 positives):**

| Configuration | TP | FN | Recall |
|---|---:|---:|---:|
| Sigma | 1,294 | 889 | 0.593 |
| Hybrid θ = 0.75 | 2,153 | 30 | 0.986 |
| IF θ = 0.75 alone | 1,418 | 765 | 0.650 |

There is no beacon rule. IF at θ = 0.75 flags all 838 test beacons, together
with 16.5 % of benign events.

### Leave-one-rule-out (coverage-gap experiment)

Each row removes one rule, then counts that technique's test events caught by
the remaining rules alone, and by the remaining rules ∪ IF.

| Rule removed | Technique | Events | Other rules | ∪ IF 0.50 | ∪ IF 0.75 | ∪ IF 0.974 |
|---|---|---:|---:|---:|---:|---:|
| 0001 | T1033 | 102 | 0 | 102 | 17 | 0 |
| 0002 | T1547.001 | 110 | 0 | 110 | 110 | 0 |
| 0003 | T1059.001 | 128 | 41 | 128 | 128 | 41 |
| 0004 | T1110.001 | 540 | 0 | 540 | 35 | 0 |
| 0005 | T1003.008 | 34 | 0 | 34 | 34 | 0 |
| 0006 | T1082 | 102 | 0 | 102 | 8 | 0 |
| 0007 | T1021.001 | 51 | 0 | 8 | 0 | 0 |
| 0008 | T1003.001 | 51 | 0 | 51 | 51 | 0 |
| 0009 | T1105 | 153 | 0 | 153 | 123 | 0 |
| 0010 | T1027 | 74 | 74 | 74 | 74 | 74 |

Overall precision is about 0.03 % at θ = 0.75 and about 0.015 % at θ = 0.50.
This is the defensible hybrid argument: when a rule is missing, the
IsolationForest fully recovers 4 of the 9 techniques that lose all coverage
(T1547.001, T1059.001, T1003.008, T1003.001), plus 123 of 153 T1105 events,
at θ = 0.75. T1027 stays covered by rule 0003 anyway. The cost is
about 8,600 false alerts per day, so the ML layer is usable only as a
*ranking* over Sigma-silent events, not as an alert source.

## 6.4 Comparison with baselines (replaces report §6.4 and Table 6.2)

Every baseline in §6.3 is run on the same events, labels, features, split and
evaluation unit. The previous Table 6.2 mixed "Traditional SIEM", DeepLog and
LogBERT figures that were *not* run on this data. Those rows are removed. The
claimed coverage figures ("x / 14 OpTC techniques", "T1003 uncovered") are
also not reproducible: rule `aris_r_0008` covers T1003.001, and this corpus
labels 10 techniques.

**Technique coverage on test** (techniques with at least one event caught,
out of 10):

| Configuration | Coverage |
|---|---:|
| Sigma | 10 |
| IF θ = 0.75 | 9 (misses T1021.001) |
| Hybrid θ = 0.75 | 10 |
| ECOD | 6 |
| PCA | 3 |
| HBOS | 2 |

**External references (context only, not baselines).** These systems model
log-key sequences on different datasets and evaluation units, so their numbers
cannot be compared with event-level results here. Verify each figure against
the original paper before citing.

| System | Dataset | Unit | P | R | F1 |
|---|---|---|---:|---:|---:|
| DeepLog (Du et al., CCS 2017) | HDFS | session | 0.95 | 0.96 | 0.96 |
| LogBERT (Guo et al., IJCNN 2021) | HDFS | sequence | 0.87 | 0.78 | 0.82 |
| LogBERT | BGL | window | 0.89 | 0.92 | 0.91 |
| LogBERT | Thunderbird | window | 0.97 | 0.97 | 0.97 |

### Throughput (replaces Figure 6.4 numbers)

Measured single-core, excluding DB writes:

| Component | Cost |
|---|---:|
| Parse | 18 µs/event |
| Sigma | 68 µs/event |
| Features | 18 µs/event |
| IF, batched | 9 µs/event |
| `score_event()` per event (the ingest path) | 6.2 ms/event |

Single-core totals:

| Pipeline | Events/s |
|---|---:|
| Sigma-only | 11.6 k |
| Hybrid, batched scoring | 8.8 k |
| Hybrid, current ingest path | **160** |

The report's 3,800 / 2,400 / 700 / 400 events/s were not measured on this code.

## IsolationForest score transform (corrects §4.3.2 and §5.4)

The code computes `s(x) = 1 / (1 + exp((f(x) − μ) / σ))`. Here f is
`decision_function` (lower means more anomalous), and μ and σ are its 2024
training mean and std (μ = 0.1512, σ = 0.0550). The report's
`sigmoid((f − μ)/σ)` has the sign inverted. The batched harness matches the
shipped `score_event()` to within 3 × 10⁻⁸.

Other facts about the transform:

- `contamination` only shifts f by a constant, which cancels in (f − μ), so it
  does not affect the score.
- The share of 2024 events at or above each threshold is set by the skew of f:

  | θ | Share flagged |
  |---|---:|
  | 0.5 | 37.9 % |
  | 0.75 | 16.5 % |
  | 0.9 | 4.8 % |

  The module docstring's "≈5 % above 0.5" was wrong and has been corrected.

Other report-vs-code mismatches to fix in the text:

| Item | Report says | Code does |
|---|---|---|
| Features | 20 | 19 (see `FEATURE_NAMES`) |
| `contamination` | `auto` | `0.01` |
| Default θ | 0.75 | 0.5 |
| Scoring | batch | per event |
| Rules | 11 | 10 |
| Dataset | DARPA OpTC | synthetic eCAR-format corpus; the "605k OpTC subset" equals the DB's auth.log row count (605,275) |

## Sources, rules and limitations

| Source | Supported event types | Applicable rules | Known limitations |
|---|---|---|---|
| Sysmon JSONL (`parsers/sysmon.py`) | Flat JSON with Image, CommandLine, ParentImage, TargetObject, DestinationIp/Port, TargetFilename. Exercised: EID 1, 3, 13. | 0001 T1033, 0002 T1547.001, 0003 T1059.001, 0006 T1082, 0007 T1021.001, 0008 T1003.001, 0009 T1105 (command-line selections only), 0010 T1027 | 0009 tool-drop selection never fires (`file_path` vs `target_filename`). No EVTX/XML. EventID is not checked, so 0002 also fires on reads of Run keys. |
| Linux auth.log (`parsers/authlog.py`) | Any `Mon dd HH:MM:SS host daemon[pid]: msg` line (sshd, sudo, cron, systemd-logind), classified as auth failure/success, session open/close or privilege escalation | 0004 T1110.001, 0005 T1003.008 | No year in syslog, and the parser hard-codes 2024. 0004 fires per line with no count or window aggregation. Most IF features are Windows-only and always 0 here. |
| eCAR, OpTC-format (`parsers/optc.py`) | PROCESS CREATE/OPEN, REGISTRY WRITE/READ/DELETE, FLOW OPEN/START, SHELL EXECUTE, FILE CREATE/DELETE/MODIFY, MODULE LOAD, USER_SESSION LOGIN/LOGOUT | 0001, 0002, 0003, 0006, 0007, 0008, 0009 (command line only), 0010 | Validated only on generator output, not on the DARPA OpTC release. actorID is not resolved, so FLOW/REGISTRY/FILE events carry no command line or parent. 0009 tool-drop never fires. No FILE or MODULE rules. |
