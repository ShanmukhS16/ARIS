"use client";
import { useState } from "react";
import { fetchEvaluation } from "../../lib/api";
import { fmtNum } from "../../lib/format";
import { LineChart } from "../charts";
import { EmptyState, Panel, Skeleton, useLoader } from "../ui";

// Fixed entity colours (validated dark categorical order on the panel surface).
const COLORS = {
  hybrid: "#3987e5", sigma: "#d95926", hbos: "#199e70", pca: "#c98500",
  ecod: "#d55181", if: "#9085e9", rf: "#e66767",
};

const pct = (v, d = 1) => (v === null || v === undefined ? "-" : `${(v * 100).toFixed(d)}%`);
const prec = (v) => (v > 0 && v < 0.001 ? `${(v * 100).toFixed(3)}%` : pct(v));
const rate = (v) => (v === 0 ? "0" : v < 0.001 ? v.toExponential(1) : v.toFixed(3));
const int = (v) => Math.round(v).toLocaleString();

const TABS = [
  ["results", "Results"],
  ["baselines", "Baselines"],
  ["threshold", "Threshold"],
  ["coverage", "Coverage"],
  ["method", "Method"],
];

export default function EvaluationView({ refreshKey }) {
  const { data, error } = useLoader(fetchEvaluation, [refreshKey]);
  const [tab, setTab] = useState("results");

  if (error && !data) {
    return (
      <div className="view">
        <EmptyState
          title="No benchmark results"
          message={<>Run <code>python -m scripts.evaluate_benchmark --work-dir &lt;tmp&gt;</code> in <code>backend/</code>.</>}
        />
      </div>
    );
  }
  if (!data) return <div className="view"><Skeleton height={400} /></div>;

  const m = data.meta;
  return (
    <div className="view">
      <div className="eval-head">
        <p className="eval-note">
          Synthetic dataset (OpTC-format, not DARPA OpTC) · trained on 2024, tested on {m.split.test_days} days of 2025–26 ·{" "}
          {fmtNum(m.positives_test)} attack and {fmtNum(m.negatives_test)} benign events · one row = one log event
        </p>
        <div className="seg">
          {TABS.map(([id, label]) => (
            <button key={id} className={tab === id ? "on" : ""} onClick={() => setTab(id)}>{label}</button>
          ))}
        </div>
      </div>

      {tab === "results" && <Results data={data} />}
      {tab === "baselines" && <Baselines data={data} />}
      {tab === "threshold" && <Threshold data={data} />}
      {tab === "coverage" && <Coverage data={data} />}
      {tab === "method" && <Method data={data} />}
    </div>
  );
}

// ---- Results ----

const CORE = ["sigma", "if_050", "if_075", "hybrid_050", "hybrid_075"];
const SHORT = {
  sigma: "Sigma", if_050: "IsolationForest θ 0.50", if_075: "IsolationForest θ 0.75",
  hybrid_050: "Hybrid θ 0.50", hybrid_075: "Hybrid θ 0.75",
};

function Results({ data }) {
  const [beacons, setBeacons] = useState(false);
  const rows = CORE.map((k) => {
    const c = data.configs.find((x) => x.key === k);
    return beacons ? { ...c, ...data.configs_with_beacons[k] } : c;
  });

  return (
    <div className="grid-12">
      <Panel className="span-12" title="Detection results" subtitle="FPR = false positives ÷ all benign test events">
        <div className="table-wrapper">
          <table className="detection-table eval-table">
            <thead>
              <tr>
                <th /><th className="num">TP</th><th className="num">FP</th><th className="num">FN</th>
                <th className="num">Precision</th><th className="num">Recall</th><th className="num">F1</th>
                <th className="num">FPR</th><th className="num">False alarms / day</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.key}>
                  <td>{SHORT[c.key]}</td>
                  <td className="num cell-mono">{int(c.tp)}</td>
                  <td className="num cell-mono">{int(c.fp)}</td>
                  <td className="num cell-mono">{int(c.fn)}</td>
                  <td className="num cell-mono">{prec(c.precision)}</td>
                  <td className="num cell-mono">{pct(c.recall)}</td>
                  <td className="num cell-mono">{c.f1.toFixed(3)}</td>
                  <td className="num cell-mono">{rate(c.fpr)}</td>
                  <td className="num cell-mono">{int(c.fp_per_day)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <label className="eval-check">
          <input type="checkbox" checked={beacons} onChange={(e) => setBeacons(e.target.checked)} />
          Count the {fmtNum(data.label_check.beacon_events)} C2 beacon events as attacks (the generator injects them but leaves them out of ground_truth.json)
        </label>
      </Panel>

      {["sigma", "if_075", "hybrid_075"].map((k) => (
        <Panel key={k} className="span-4" title={SHORT[k]}>
          <Confusion c={rows.find((r) => r.key === k)} />
        </Panel>
      ))}
    </div>
  );
}

function Confusion({ c }) {
  return (
    <>
      <div className="cm-grid">
        <div />
        <div className="cm-head">flagged</div>
        <div className="cm-head">not flagged</div>
        <div className="cm-head cm-row">attack</div>
        <div className="cm-cell"><span className="cm-n">{int(c.tp)}</span><span className="cm-k">TP</span></div>
        <div className="cm-cell"><span className="cm-n">{int(c.fn)}</span><span className="cm-k">FN</span></div>
        <div className="cm-head cm-row">benign</div>
        <div className="cm-cell"><span className="cm-n">{fmtNum(c.fp)}</span><span className="cm-k">FP</span></div>
        <div className="cm-cell"><span className="cm-n">{fmtNum(c.tn)}</span><span className="cm-k">TN</span></div>
      </div>
      <div className="cm-sub">precision {prec(c.precision)} · recall {pct(c.recall)}</div>
    </>
  );
}

// ---- Baselines ----

const DETECTORS = [
  { key: "if", cfg: "if_tuned", hyb: "hybrid", label: "IsolationForest (ours)" },
  { key: "hbos", cfg: "hbos", hyb: "hbos_hybrid", label: "HBOS" },
  { key: "pca", cfg: "pca", hyb: "pca_hybrid", label: "PCA reconstruction" },
  { key: "ecod", cfg: "ecod", hyb: "ecod_hybrid", label: "ECOD" },
  { key: "rf", cfg: "rf", hyb: "rf_hybrid", label: "Random Forest (supervised)", dash: true },
];

function Baselines({ data }) {
  const [mode, setMode] = useState("pr");
  const by = Object.fromEntries(data.configs.map((c) => [c.key, c]));
  const cv = data.curves;
  const sigma = by.sigma;

  const series = [
    { key: "hybrid", label: "Sigma + IsolationForest", color: COLORS.hybrid },
    ...DETECTORS.map((d) => ({ key: d.key, label: d.label, color: COLORS[d.key], dash: d.dash })),
  ].map((s) => ({
    ...s,
    points: mode === "pr" ? cv[s.key].pr : cv[s.key].roc.map(([f, t]) => [Math.max(f, 1e-7), t]),
  }));
  const sp = cv.sigma_point;

  return (
    <div className="grid-12">
      <Panel className="span-12" title="Same data, same features, same labels" subtitle="Each detector alone, and combined with Sigma. Thresholds were tuned on 2024 only.">
        <div className="table-wrapper">
          <table className="detection-table eval-table">
            <thead>
              <tr>
                <th rowSpan={2}>Detector</th>
                <th colSpan={3} className="num eval-group">Alone</th>
                <th colSpan={3} className="num eval-group">With Sigma</th>
                <th rowSpan={2} className="num">ROC-AUC</th>
                <th rowSpan={2} className="num">Avg precision</th>
              </tr>
              <tr>
                <th className="num">Precision</th><th className="num">Recall</th><th className="num">F1</th>
                <th className="num">Precision</th><th className="num">Recall</th><th className="num">F1</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Sigma rules only</td>
                <td className="num cell-mono">{prec(sigma.precision)}</td>
                <td className="num cell-mono">{pct(sigma.recall)}</td>
                <td className="num cell-mono">{sigma.f1.toFixed(3)}</td>
                <td className="num muted" colSpan={3}>-</td>
                <td className="num muted">-</td><td className="num muted">-</td>
              </tr>
              {DETECTORS.map((d) => (
                <tr key={d.key}>
                  <td>{d.label}</td>
                  <td className="num cell-mono">{prec(by[d.cfg].precision)}</td>
                  <td className="num cell-mono">{pct(by[d.cfg].recall)}</td>
                  <td className="num cell-mono">{by[d.cfg].f1.toFixed(3)}</td>
                  <td className="num cell-mono">{prec(by[d.hyb].precision)}</td>
                  <td className="num cell-mono">{pct(by[d.hyb].recall)}</td>
                  <td className="num cell-mono">{by[d.hyb].f1.toFixed(3)}</td>
                  <td className="num cell-mono">{cv[d.key].roc_auc.toFixed(3)}</td>
                  <td className="num cell-mono">{cv[d.key].average_precision.toFixed(4)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="eval-note eval-foot">
          At its tuned threshold no detector adds anything to Sigma: the best combined setting is Sigma on its own.
        </p>
      </Panel>

      <Panel
        className="span-12" title={mode === "pr" ? "Precision vs recall" : "True vs false positive rate"}
        subtitle="Sigma has no score, so it is a single point"
        actions={
          <div className="seg">
            <button className={mode === "pr" ? "on" : ""} onClick={() => setMode("pr")}>PR</button>
            <button className={mode === "roc" ? "on" : ""} onClick={() => setMode("roc")}>ROC</button>
          </div>
        }
      >
        <LineChart
          series={series}
          xDomain={mode === "pr" ? [0, 1] : [1e-7, 1]}
          xLog={mode === "roc"}
          xTitle={mode === "pr" ? "recall" : "false-positive rate (log)"}
          xFormat={mode === "pr" ? (v) => `${(v * 100).toFixed(0)}%` : (v) => v.toExponential(0)}
          height={300}
          dots={[{
            x: mode === "pr" ? sp.tpr : Math.max(sp.fpr, 1e-7),
            y: mode === "pr" ? sp.precision : sp.tpr,
            label: "Sigma", color: COLORS.sigma,
          }]}
        />
        <LegendLines items={series} />
      </Panel>
    </div>
  );
}

// ---- Threshold ----

function Threshold({ data }) {
  const s = data.sweep;
  const series = [
    { key: "hr", label: "Hybrid recall", color: COLORS.hybrid, points: s.map((x) => [x.theta, x.hybrid.recall]) },
    { key: "hp", label: "Hybrid precision", color: COLORS.hybrid, dash: true, points: s.map((x) => [x.theta, x.hybrid.precision]) },
    { key: "ir", label: "IsolationForest recall", color: COLORS.if, points: s.map((x) => [x.theta, x.if.recall]) },
  ];
  return (
    <div className="grid-12">
      <Panel className="span-8" title="Moving the anomaly threshold" subtitle="Hybrid = Sigma OR (score ≥ θ)">
        <LineChart
          xDomain={[0.3, 0.99]} xTitle="θ" height={280} series={series}
          markers={[{ x: 0.5, label: "code default" }, { x: 0.75, label: "report" }]}
        />
        <LegendLines items={series} />
      </Panel>
      <Panel className="span-4" title="Hybrid at a few thresholds">
        <table className="mini-table">
          <thead><tr><td>θ</td><td className="num">TP</td><td className="num">FP</td><td className="num">Precision</td><td className="num">Recall</td></tr></thead>
          <tbody>
            {s.filter((x) => [0.5, 0.75, 0.9, 0.95].includes(x.theta)).map((x) => (
              <tr key={x.theta}>
                <td>{x.theta.toFixed(2)}</td>
                <td className="num">{x.hybrid.tp}</td>
                <td className="num">{fmtNum(x.hybrid.fp)}</td>
                <td className="num">{prec(x.hybrid.precision)}</td>
                <td className="num">{pct(x.hybrid.recall)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="eval-note eval-foot">
          The hybrid keeps every false alarm from both layers, so lowering θ buys recall with millions of false positives.
        </p>
      </Panel>
    </div>
  );
}

// ---- Coverage ----

const TECH_COLS = [["sigma", "Sigma"], ["if_075", "IF θ 0.75"], ["hybrid_075", "Hybrid θ 0.75"], ["rf", "RF"]];

function Coverage({ data }) {
  return (
    <div className="grid-12">
      <Panel className="span-6" title="Caught per technique" subtitle="Test events caught / total">
        <table className="detection-table eval-table">
          <thead>
            <tr><th>Technique</th>{TECH_COLS.map(([k, l]) => <th key={k} className="num">{l}</th>)}</tr>
          </thead>
          <tbody>
            {data.per_technique.map((r) => (
              <tr key={r.technique}>
                <td className="cell-mono">{r.technique}{!r.in_ground_truth_json && <span className="muted"> (beacon)</span>}</td>
                {TECH_COLS.map(([k]) => (
                  <td key={k} className={`num cell-mono ${r[k] === 0 ? "muted" : ""}`}>{r[k]}/{r.events}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <Panel className="span-6" title="If a rule were missing" subtitle="Remove one rule; events of its technique still caught">
        <table className="detection-table eval-table">
          <thead>
            <tr>
              <th>Rule</th><th className="num">Events</th><th className="num">Other rules</th>
              <th className="num">+ IF θ 0.50</th><th className="num">+ IF θ 0.75</th>
            </tr>
          </thead>
          <tbody>
            {data.leave_one_rule_out.filter((r) => r.events > 0).map((r) => (
              <tr key={r.rule_id}>
                <td className="cell-mono">{r.rule_id.replace("aris_r_", "")} <span className="muted">{r.technique}</span></td>
                <td className="num cell-mono">{r.events}</td>
                <td className="num cell-mono">{r.sigma_without_rule}</td>
                <td className="num cell-mono">{r.hybrid_without_rule["0.50"].caught}</td>
                <td className="num cell-mono">{r.hybrid_without_rule["0.75"].caught}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="eval-note eval-foot">
          The IsolationForest often fills the gap, but at about 0.03% precision.
        </p>
      </Panel>
    </div>
  );
}

// ---- Method ----

function Method({ data }) {
  const m = data.meta;
  const lc = data.label_check;
  const st = data.score_transform;
  const tp = data.throughput;
  const audit = data.report_audit;
  return (
    <div className="grid-12">
      <Panel className="span-6" title="How events are labelled">
        <ol className="eval-note eval-list">
          {m.label_procedure.map((s) => <li key={s}>{s}</li>)}
        </ol>
        <p className="eval-note eval-foot">
          {fmtNum(lc.matched_events)} of {fmtNum(lc.ground_truth_records)} ground-truth records matched, {lc.group_mismatches} mismatches.
          Labelled + beacon events = {fmtNum(lc.provenance_total)}, manifest says {fmtNum(lc.manifest_total_malicious)}.
        </p>
      </Panel>

      <Panel className="span-6" title="Anomaly score">
        <p className="cell-mono eval-formula">s = 1 / (1 + exp((f − μ) / σ))</p>
        <p className="eval-note">
          f is the IsolationForest decision_function (lower = more anomalous), μ = {st.mu.toFixed(4)}, σ = {st.sigma.toFixed(4)} from 2024.
          Matches the shipped score_event() to {st.verification.max_abs_diff.toExponential(0)}.
          Share of events above θ: 0.50 → {pct(st.train_share_ge["0.5"])}, 0.75 → {pct(st.train_share_ge["0.75"])}, 0.90 → {pct(st.train_share_ge["0.9"])}.
        </p>
        <p className="eval-note eval-foot">
          Report Table 6.1 check: with ML-only at P 0.34 / R 0.78, a union at R 0.89 can reach at most{" "}
          {audit.hybrid_precision_upper_bound.toFixed(2)} precision, not 0.58.
        </p>
        <p className="eval-note eval-foot">
          Speed (one core): Sigma {fmtNum(Math.round(tp.single_core_eps.sigma_only))}/s, hybrid batched{" "}
          {fmtNum(Math.round(tp.single_core_eps.hybrid_batched_scoring))}/s, current ingest path{" "}
          {fmtNum(Math.round(tp.single_core_eps["hybrid_per_event_scoring (ingest path)"]))}/s.
        </p>
      </Panel>

      <Panel className="span-12" title="Log sources">
        <div className="table-wrapper">
          <table className="detection-table eval-wrap">
            <thead><tr><th>Source</th><th>Supported event types</th><th>Applicable rules</th><th>Known limitations</th></tr></thead>
            <tbody>
              {data.source_matrix.map((s) => (
                <tr key={s.source}>
                  <td>{s.source}</td><td>{s.event_types}</td><td>{s.rules}</td><td>{s.limitations}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel className="span-12" title="Published results from other work" subtitle="Different datasets and units; for context, not comparable with the numbers above">
        <table className="detection-table eval-table">
          <thead><tr><th>System</th><th>Dataset</th><th className="num">Precision</th><th className="num">Recall</th><th className="num">F1</th></tr></thead>
          <tbody>
            {data.external_references.map((r) => (
              <tr key={r.system + r.dataset}>
                <td>{r.system}</td><td>{r.dataset}</td>
                <td className="num cell-mono">{r.precision.toFixed(2)}</td>
                <td className="num cell-mono">{r.recall.toFixed(2)}</td>
                <td className="num cell-mono">{r.f1.toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}

function LegendLines({ items }) {
  return (
    <div className="chart-legend eval-legend">
      {items.map((it) => (
        <span key={it.key || it.label} className="legend-item">
          <span className={`legend-line ${it.dash ? "dashed" : ""}`} style={{ background: it.color, color: it.color }} />
          {it.label}
        </span>
      ))}
    </div>
  );
}
