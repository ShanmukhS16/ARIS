"use client";
import { useState } from "react";
import { fetchModel, trainModel } from "../../lib/api";
import { LEVEL_COLORS, fmtNum, fmtTs } from "../../lib/format";
import { Legend, StackedChart } from "../charts";
import { ErrorBanner, KpiTile, Panel, Skeleton, StatusDot, useLoader } from "../ui";

const SERIES = [
  { key: "none", label: "Clean", color: "#06b6d4" },
  { key: "ml", label: "ML only", color: LEVEL_COLORS.ml },
  { key: "sigma", label: "Sigma only", color: LEVEL_COLORS.sigma },
  { key: "both", label: "Sigma + ML", color: LEVEL_COLORS.both },
];

export default function ModelView({ scope, refreshKey, onRefresh, notify }) {
  const { data, error } = useLoader(() => fetchModel(scope), [scope.hours, scope.ingestionId, refreshKey]);
  const [training, setTraining] = useState(false);

  async function handleRetrain() {
    const ok = window.confirm(
      "Retrain IsolationForest on every event currently in the database?\n\n" +
      "This overwrites model.pkl, scaler.pkl and score_stats.pkl. If the database only " +
      "holds sample files, the model trained on the full dataset will be replaced."
    );
    if (!ok) return;
    setTraining(true);
    try {
      const res = await trainModel();
      notify(`Model retrained on ${fmtNum(res.events_trained)} events`, "success");
      onRefresh();
    } catch (err) {
      notify(`Training failed: ${err.message}`, "error");
    } finally {
      setTraining(false);
    }
  }

  if (!data) {
    return <div className="view"><ErrorBanner message={error} /><Skeleton height={400} /></div>;
  }

  const pct = data.scored_events ? (data.above_threshold / data.scored_events) * 100 : 0;
  const stats = data.raw_score_stats || {};

  return (
    <div className="view">
      <div className="kpi-grid kpi-grid-4">
        <KpiTile
          label="Model status"
          value={<span className="kpi-status"><StatusDot status={data.loaded ? "ok" : "down"} />{data.loaded ? "Serving" : "Not trained"}</span>}
          sub={data.loaded ? `${data.algorithm} · trained ${fmtTs(data.trained_at)}` : "Run training to create a model"}
        />
        <KpiTile label="Anomaly threshold" value={data.threshold.toFixed(2)} color="var(--purple)" sub="ARIS_ML_ANOMALY_THRESHOLD" />
        <KpiTile label="Events scored" value={data.scored_events} color="var(--accent)" sub="in selected range" />
        <KpiTile label="Above threshold" value={data.above_threshold} color="var(--danger)" sub={`${pct.toFixed(1)}% of scored events`} />
      </div>

      <div className="grid-12">
        <Panel
          className="span-8" title="Anomaly score distribution"
          subtitle="Events per score bucket, coloured by final detection layer"
          actions={<Legend series={SERIES} />}
        >
          <StackedChart
            data={data.histogram}
            series={SERIES}
            type="bar"
            height={260}
            xLabel={(d) => d.lo.toFixed(2)}
            tooltipTitle={(d) => `score ${d.lo.toFixed(2)} – ${d.hi.toFixed(2)}`}
            marker={{ at: data.threshold, label: `threshold ${data.threshold}` }}
          />
        </Panel>

        <Panel
          className="span-4" title="Model card"
          actions={
            <button className="btn btn-secondary btn-sm" onClick={handleRetrain} disabled={training}>
              {training ? "Training…" : "Retrain"}
            </button>
          }
        >
          <dl className="spec-list">
            <dt>Algorithm</dt><dd>{data.algorithm || "-"}</dd>
            <dt>Estimators</dt><dd>{data.n_estimators ?? "-"}</dd>
            <dt>Contamination</dt><dd>{data.contamination ?? "-"}</dd>
            <dt>Max features</dt><dd>{data.max_features ?? "-"}</dd>
            <dt>Input features</dt><dd>{data.n_features ?? "-"}</dd>
            <dt>Known processes</dt><dd>{fmtNum(data.known_processes)}</dd>
            <dt>Scaler</dt><dd>StandardScaler</dd>
            <dt>Score mapping</dt><dd>sigmoid(−z) of decision_function</dd>
            <dt>Artifacts</dt><dd><code>model.pkl · scaler.pkl · score_stats.pkl</code></dd>
          </dl>
        </Panel>

        <Panel className="span-8" title="Feature vector" subtitle="Engineered behavioural features fed to the forest, in column order">
          <div className="feature-chips">
            {(data.feature_names || []).map((f, i) => (
              <span key={f} className="feature-chip"><span className="feature-idx">{i}</span>{f}</span>
            ))}
          </div>
        </Panel>

        <Panel className="span-4" title="Raw decision_function stats" subtitle="From the training corpus">
          <table className="mini-table">
            <tbody>
              {Object.entries(stats).map(([k, v]) => (
                <tr key={k}><td>{k}</td><td className="cell-mono num">{v.toFixed(4)}</td></tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
    </div>
  );
}
