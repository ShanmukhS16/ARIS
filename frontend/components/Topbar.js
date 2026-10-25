"use client";
import { Icon, StatusDot } from "./ui";
import { fmtAgo } from "../lib/format";

export const RANGES = [
  { label: "All data", value: "" },
  { label: "Last 1h", value: 1 },
  { label: "Last 6h", value: 6 },
  { label: "Last 24h", value: 24 },
  { label: "Last 7d", value: 168 },
  { label: "Last 30d", value: 720 },
];

export const REFRESH = [
  { label: "Off", value: 0 },
  { label: "5s", value: 5000 },
  { label: "30s", value: 30000 },
  { label: "1m", value: 60000 },
];

export default function Topbar({
  pageInfo, hours, onHours, refreshMs, onRefreshMs, onRefresh,
  lastUpdated, now, health, ingestionId, onClearIngestion,
}) {
  const healthy = health?.status === "ok";
  return (
    <header className="topbar">
      <div className="breadcrumb">
        <span className="crumb-muted">ARIS</span>
        <Icon name="chevron" size={12} />
        <span className="crumb-muted">{pageInfo?.group}</span>
        <Icon name="chevron" size={12} />
        <span className="crumb-current">{pageInfo?.label}</span>
        {ingestionId && (
          <span className="scope-chip" title="All panels are scoped to this ingestion job">
            ingestion: <code>{ingestionId}</code>
            <button onClick={onClearIngestion} aria-label="Clear ingestion scope"><Icon name="x" size={12} /></button>
          </span>
        )}
      </div>

      <div className="topbar-controls">
        <label className="control" title="Relative to the newest event in scope">
          <Icon name="clock" size={14} />
          <select value={hours ?? ""} onChange={(e) => onHours(e.target.value ? Number(e.target.value) : null)}>
            {RANGES.map((r) => <option key={r.label} value={r.value}>{r.label}</option>)}
          </select>
        </label>

        <label className="control" title="Auto-refresh interval">
          <span className="control-label">Auto</span>
          <select value={refreshMs} onChange={(e) => onRefreshMs(Number(e.target.value))}>
            {REFRESH.map((r) => <option key={r.label} value={r.value}>{r.label}</option>)}
          </select>
        </label>

        <button className="icon-btn" onClick={onRefresh} title="Refresh now">
          <Icon name="refresh" size={14} />
        </button>

        <span className="updated">{lastUpdated ? `Updated ${fmtAgo(lastUpdated, now)}` : ""}</span>

        <span className={`health-pill ${healthy ? "health-ok" : "health-down"}`}>
          <StatusDot status={healthy ? "ok" : "down"} />
          {healthy ? "Healthy" : "Backend down"}
        </span>
      </div>
    </header>
  );
}
