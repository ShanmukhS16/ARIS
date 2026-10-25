"use client";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

export default function DetectionTable({ events }) {
  if (!events || events.length === 0) {
    return <div className="empty-state">No events loaded.</div>;
  }

  // Sort: detections first, then by timestamp
  const sorted = [...events].sort((a, b) => {
    const aHas = a.detection_level !== "none" ? 0 : 1;
    const bHas = b.detection_level !== "none" ? 0 : 1;
    if (aHas !== bHas) return aHas - bHas;
    return new Date(a.timestamp) - new Date(b.timestamp);
  });

  return (
    <div className="table-wrapper">
      <table className="detection-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Host</th>
            <th>User</th>
            <th>Process</th>
            <th>Detection</th>
            <th>ML Score</th>
            <th>Rules</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((ev, i) => (
            <tr key={i} className={`row-${ev.detection_level}`}>
              <td className="cell-mono">{new Date(ev.timestamp).toLocaleTimeString()}</td>
              <td>{ev.host}</td>
              <td>{ev.user || "-"}</td>
              <td className="cell-process" title={ev.process}>
                <code>{(ev.process || "-").slice(0, 80)}</code>
              </td>
              <td>
                <span className={`badge badge-${ev.detection_level}`}>
                  {ev.detection_level}
                </span>
              </td>
              <td className="cell-mono">
                {ev.anomaly_score != null ? ev.anomaly_score.toFixed(3) : "-"}
              </td>
              <td>
                {ev.detections?.map((d, j) => (
                  <span key={j} className={`rule-tag severity-${d.severity}`} title={d.rule_title}>
                    {d.mitre_attack_id || d.rule_id}
                  </span>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
