"use client";
import { fetchIngestions } from "../../lib/api";
import { fmtNum, fmtTs } from "../../lib/format";
import FileUpload from "../FileUpload";
import { ErrorBanner, Panel, Skeleton, StatusDot, useLoader } from "../ui";

export default function IngestionView({ refreshKey, scope, onIngested, onInspect }) {
  const { data, error } = useLoader(() => fetchIngestions(), [refreshKey]);

  return (
    <div className="view">
      <Panel title="New ingestion" subtitle="Upload a log file. The pipeline runs parse → Sigma → ML scoring → store.">
        <div className="pipeline">
          {["Parse", "Sigma rules", "ML scoring", "Store"].map((s, i) => (
            <div key={s} className="pipeline-stage">
              <span className="pipeline-num">{i + 1}</span>{s}
            </div>
          ))}
        </div>
        <FileUpload onIngested={onIngested} />
      </Panel>

      <Panel title="Ingestion jobs" subtitle="Every upload or bulk-ingest run, newest first">
        <ErrorBanner message={error} />
        {!data ? (
          <Skeleton height={200} />
        ) : data.length === 0 ? (
          <div className="empty-inline">No jobs yet.</div>
        ) : (
          <div className="table-wrapper">
            <table className="detection-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Job ID</th>
                  <th>Source</th>
                  <th className="num">Events</th>
                  <th className="num">Flagged</th>
                  <th className="num">Hosts</th>
                  <th>Data span</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.map((j) => (
                  <tr key={j.ingestion_id} className={scope.ingestionId === j.ingestion_id ? "row-selected" : ""}>
                    <td><span className="job-status"><StatusDot status="ok" />Completed</span></td>
                    <td className="cell-mono">{j.ingestion_id}</td>
                    <td><span className="source-tag">{j.source_type}</span></td>
                    <td className="cell-mono num">{fmtNum(j.events)}</td>
                    <td className="cell-mono num">
                      {fmtNum(j.detected)}
                      <span className="muted"> ({j.events ? ((j.detected / j.events) * 100).toFixed(0) : 0}%)</span>
                    </td>
                    <td className="cell-mono num">{fmtNum(j.hosts)}</td>
                    <td className="cell-mono">{fmtTs(j.first_event)} → {fmtTs(j.last_event)}</td>
                    <td>
                      <button className="btn btn-secondary btn-sm" onClick={() => onInspect(j.ingestion_id)}>
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
