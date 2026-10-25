"use client";
import { useState } from "react";

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  none: "#64748b",
};

const LEVEL_COLORS = {
  both: "#ef4444",
  sigma: "#f97316",
  ml: "#8b5cf6",
  none: "#334155",
};

export default function Timeline({ events }) {
  const [selected, setSelected] = useState(null);

  if (!events || events.length === 0) {
    return <div className="empty-state">No events to display. Upload a log file to get started.</div>;
  }

  const width = 900;
  const height = 200;
  const padding = { top: 30, right: 40, bottom: 40, left: 40 };
  const plotW = width - padding.left - padding.right;
  const plotH = height - padding.top - padding.bottom;

  // Map events to x positions
  const hosts = [...new Set(events.map((e) => e.host))];
  const hostY = {};
  hosts.forEach((h, i) => {
    hostY[h] = padding.top + (plotH / (hosts.length + 1)) * (i + 1);
  });

  const timestamps = events.map((e) => new Date(e.timestamp).getTime());
  const minT = Math.min(...timestamps);
  const maxT = Math.max(...timestamps);
  const range = maxT - minT || 1;

  function xPos(ts) {
    return padding.left + ((new Date(ts).getTime() - minT) / range) * plotW;
  }

  return (
    <div className="timeline-container">
      <svg viewBox={`0 0 ${width} ${height}`} className="timeline-svg">
        {/* Host lane lines */}
        {hosts.map((host) => (
          <g key={host}>
            <line
              x1={padding.left} y1={hostY[host]}
              x2={width - padding.right} y2={hostY[host]}
              stroke="var(--border)" strokeWidth="1" strokeDasharray="4,4"
            />
            <text
              x={padding.left - 8} y={hostY[host] + 4}
              textAnchor="end" fill="var(--text-muted)" fontSize="11"
              fontFamily="var(--font-mono)"
            >
              {host}
            </text>
          </g>
        ))}

        {/* Event markers */}
        {events.map((ev, i) => {
          const cx = xPos(ev.timestamp);
          const cy = hostY[ev.host] || padding.top + plotH / 2;
          const color = LEVEL_COLORS[ev.detection_level] || LEVEL_COLORS.none;
          const r = ev.detection_level === "none" ? 4 : 6;

          return (
            <g key={i} onClick={() => setSelected(selected === i ? null : i)} style={{ cursor: "pointer" }}>
              {ev.detection_level !== "none" && (
                <circle cx={cx} cy={cy} r={r + 3} fill={color} opacity="0.2" />
              )}
              <circle cx={cx} cy={cy} r={r} fill={color} stroke="var(--bg)" strokeWidth="1.5" />
              {selected === i && (
                <circle cx={cx} cy={cy} r={r + 5} fill="none" stroke={color} strokeWidth="1.5" />
              )}
            </g>
          );
        })}

        {/* Time axis */}
        <line
          x1={padding.left} y1={height - padding.bottom + 10}
          x2={width - padding.right} y2={height - padding.bottom + 10}
          stroke="var(--border)" strokeWidth="1"
        />
        <text
          x={padding.left} y={height - 8}
          fill="var(--text-muted)" fontSize="10" fontFamily="var(--font-mono)"
        >
          {new Date(minT).toLocaleTimeString()}
        </text>
        <text
          x={width - padding.right} y={height - 8}
          textAnchor="end" fill="var(--text-muted)" fontSize="10" fontFamily="var(--font-mono)"
        >
          {new Date(maxT).toLocaleTimeString()}
        </text>
      </svg>

      {/* Legend */}
      <div className="timeline-legend">
        {Object.entries(LEVEL_COLORS).map(([level, color]) => (
          <span key={level} className="legend-item">
            <span className="legend-dot" style={{ background: color }} />
            {level === "both" ? "Sigma + ML" : level === "none" ? "Clean" : level.toUpperCase()}
          </span>
        ))}
      </div>

      {/* Selected event detail */}
      {selected !== null && events[selected] && (
        <div className="event-detail">
          <div className="detail-header">
            <span className={`badge badge-${events[selected].detection_level}`}>
              {events[selected].detection_level}
            </span>
            <span className="detail-time">{events[selected].timestamp}</span>
          </div>
          <div className="detail-body">
            <div><strong>Host:</strong> {events[selected].host}</div>
            <div><strong>User:</strong> {events[selected].user || "N/A"}</div>
            <div><strong>Process:</strong> <code>{events[selected].process || "N/A"}</code></div>
            {events[selected].anomaly_score != null && (
              <div><strong>ML Score:</strong> {events[selected].anomaly_score.toFixed(4)}</div>
            )}
            {events[selected].detections?.length > 0 && (
              <div>
                <strong>Detections:</strong>
                {events[selected].detections.map((d, j) => (
                  <span key={j} className={`badge badge-${d.severity}`} style={{ marginLeft: 4 }}>
                    {d.rule_id} ({d.mitre_attack_id})
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
