"use client";
import { Fragment, useState } from "react";
import { fetchRules } from "../../lib/api";
import { fmtNum, fmtTs } from "../../lib/format";
import { ErrorBanner, KpiTile, Panel, Skeleton, StatusDot, useLoader } from "../ui";

export default function RulesView({ scope, refreshKey }) {
  const { data, error } = useLoader(() => fetchRules(scope), [scope.hours, scope.ingestionId, refreshKey]);
  const [open, setOpen] = useState(null);

  if (!data) {
    return <div className="view"><ErrorBanner message={error} /><Skeleton height={400} /></div>;
  }

  const fired = data.filter((r) => r.hits > 0).length;
  const techniques = new Set(data.map((r) => r.technique).filter(Boolean)).size;
  const totalHits = data.reduce((s, r) => s + r.hits, 0);

  return (
    <div className="view">
      <div className="kpi-grid kpi-grid-4">
        <KpiTile label="Rules loaded" value={data.length} color="var(--accent)" sub="from sigma_engine/rules/*.yml" />
        <KpiTile label="Rules fired" value={`${fired} / ${data.length}`} color="var(--warning)" sub="in selected range" />
        <KpiTile label="Total hits" value={totalHits} color="var(--danger)" />
        <KpiTile label="ATT&CK techniques" value={techniques} color="var(--purple)" sub="covered by detection-as-code" />
      </div>

      <Panel title="Sigma rule catalogue" subtitle="Click a rule to view its YAML definition">
        <ErrorBanner message={error} />
        <div className="table-wrapper">
          <table className="detection-table rules-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Rule ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Technique</th>
                <th>Tactic</th>
                <th className="num">Hits</th>
                <th>Last fired</th>
              </tr>
            </thead>
            <tbody>
              {data.map((r) => (
                <Fragment key={r.rule_id}>
                  <tr className="clickable" onClick={() => setOpen(open === r.rule_id ? null : r.rule_id)}>
                    <td>
                      <span className="rule-status">
                        <StatusDot status={r.hits > 0 ? "live" : "ok"} />
                        {r.status}
                      </span>
                    </td>
                    <td className="cell-mono">{r.rule_id}</td>
                    <td>{r.title}</td>
                    <td><span className={`badge badge-${r.severity}`}>{r.severity}</span></td>
                    <td><span className="technique-badge">{r.technique || "-"}</span></td>
                    <td>{r.tactic || "-"}</td>
                    <td className="cell-mono num">{fmtNum(r.hits)}</td>
                    <td className="cell-mono">{r.last_fired ? fmtTs(r.last_fired) : "never"}</td>
                  </tr>
                  {open === r.rule_id && (
                    <tr className="rule-detail-row">
                      <td colSpan={8}>
                        <p className="rule-desc">{r.description}</p>
                        <pre className="code-block">{r.yaml}</pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
