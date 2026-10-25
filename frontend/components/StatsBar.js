"use client";

export default function StatsBar({ stats }) {
  if (!stats) return null;

  const cards = [
    { label: "Total Events", value: stats.total_events, color: "#64748b" },
    { label: "Sigma Hits", value: stats.by_detection_level?.sigma || 0, color: "#f97316" },
    { label: "ML Anomalies", value: stats.by_detection_level?.ml || 0, color: "#8b5cf6" },
    { label: "Both", value: stats.by_detection_level?.both || 0, color: "#ef4444" },
    { label: "Hosts", value: stats.unique_hosts, color: "#06b6d4" },
    { label: "Detections", value: stats.total_detections, color: "#f59e0b" },
  ];

  return (
    <div className="stats-bar">
      {cards.map((c) => (
        <div key={c.label} className="stat-card">
          <div className="stat-value" style={{ color: c.color }}>{c.value}</div>
          <div className="stat-label">{c.label}</div>
        </div>
      ))}
    </div>
  );
}
