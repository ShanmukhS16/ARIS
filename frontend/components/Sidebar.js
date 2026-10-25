"use client";
import { Icon, StatusDot } from "./ui";

export const NAV = [
  { group: "Monitor", items: [
    { id: "overview", label: "Overview", icon: "grid" },
    { id: "logs", label: "Live Logs", icon: "terminal" },
    { id: "timeline", label: "Timeline", icon: "clock" },
  ]},
  { group: "Detect", items: [
    { id: "detections", label: "Detections", icon: "alert" },
    { id: "rules", label: "Sigma Rules", icon: "rules" },
    { id: "model", label: "ML Model", icon: "cpu" },
  ]},
  { group: "Respond", items: [
    { id: "incident", label: "Incident Report", icon: "report" },
  ]},
  { group: "Data", items: [
    { id: "ingestion", label: "Ingestion", icon: "database" },
  ]},
];

export function findPage(id) {
  for (const g of NAV) {
    const item = g.items.find((it) => it.id === id);
    if (item) return { ...item, group: g.group };
  }
  return null;
}

export default function Sidebar({ page, onNavigate, health }) {
  const status = health ? (health.status === "ok" ? "ok" : "warn") : "down";
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <span className="brand-icon"><Icon name="shield" size={22} /></span>
        <div>
          <div className="brand-name">ARIS</div>
          <div className="brand-sub">Detection Ops Console</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {NAV.map((g) => (
          <div key={g.group} className="nav-group">
            <div className="nav-group-label">{g.group}</div>
            {g.items.map((it) => (
              <button
                key={it.id}
                className={`nav-item ${page === it.id ? "nav-active" : ""}`}
                onClick={() => onNavigate(it.id)}
              >
                <Icon name={it.icon} />
                <span>{it.label}</span>
              </button>
            ))}
          </div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-service">
          <StatusDot status={status} />
          <span>API {status === "ok" ? "online" : "unreachable"}</span>
        </div>
        <div className="sidebar-service">
          <StatusDot status={health?.model_loaded ? "ok" : "down"} />
          <span>Model {health?.model_loaded ? "loaded" : "missing"}</span>
        </div>
        <div className="sidebar-service">
          <StatusDot status={health?.llm_enabled ? "ok" : "warn"} />
          <span>LLM {health?.llm_enabled ? "enabled" : "offline mode"}</span>
        </div>
        <div className="sidebar-version">v{health?.version || "?"}</div>
      </div>
    </aside>
  );
}
