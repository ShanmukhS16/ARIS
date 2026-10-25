"use client";
import { useEffect, useState } from "react";
import { Sparkline } from "./charts";
import { fmtNum } from "../lib/format";

// Load data whenever deps change; keeps the previous data while refreshing.
export function useLoader(loader, deps) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  useEffect(() => {
    let alive = true;
    setState((s) => ({ ...s, loading: true }));
    loader()
      .then((data) => alive && setState({ data, error: null, loading: false }))
      .catch((err) => alive && setState((s) => ({ ...s, error: err.message, loading: false })));
    return () => {
      alive = false;
    };
  }, deps); // eslint-disable-line react-hooks/exhaustive-deps
  return state;
}

export function Panel({ title, subtitle, actions, children, className = "", bodyClass = "" }) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="panel-header">
          <div>
            <h2 className="panel-title">{title}</h2>
            {subtitle && <div className="panel-subtitle">{subtitle}</div>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      <div className={`panel-body ${bodyClass}`}>{children}</div>
    </section>
  );
}

export function KpiTile({ label, value, sub, color = "var(--text)", spark, sparkColor, trend, trendGoodWhenDown = false }) {
  let trendEl = null;
  if (trend !== null && trend !== undefined && isFinite(trend)) {
    const up = trend >= 0;
    const good = trendGoodWhenDown ? !up : up;
    trendEl = (
      <span className={`kpi-trend ${good ? "trend-good" : "trend-bad"}`}>
        {up ? "▲" : "▼"} {Math.abs(trend).toFixed(0)}%
      </span>
    );
  }
  return (
    <div className="kpi">
      <div className="kpi-label">{label}</div>
      <div className="kpi-row">
        <span className="kpi-value" style={{ color }}>{typeof value === "number" ? fmtNum(value) : value}</span>
        {trendEl}
      </div>
      {sub && <div className="kpi-sub">{sub}</div>}
      {spark && (
        <div className="kpi-spark">
          <Sparkline values={spark} color={sparkColor || color} />
        </div>
      )}
    </div>
  );
}

export function EmptyState({ title, message, action }) {
  return (
    <div className="empty-state">
      <Icon name="inbox" size={36} />
      <h3>{title}</h3>
      {message && <p>{message}</p>}
      {action}
    </div>
  );
}

export function ErrorBanner({ message }) {
  if (!message) return null;
  return <div className="alert alert-error">Request failed: {message}</div>;
}

export function Skeleton({ height = 120 }) {
  return <div className="skeleton" style={{ height }} />;
}

export function StatusDot({ status }) {
  return <span className={`status-dot status-${status}`} />;
}

const ICONS = {
  grid: <><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /></>,
  terminal: <><polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" /></>,
  clock: <><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></>,
  alert: <><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></>,
  rules: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /></>,
  cpu: <><rect x="4" y="4" width="16" height="16" rx="2" /><rect x="9" y="9" width="6" height="6" /><line x1="9" y1="1" x2="9" y2="4" /><line x1="15" y1="1" x2="15" y2="4" /><line x1="9" y1="20" x2="9" y2="23" /><line x1="15" y1="20" x2="15" y2="23" /><line x1="20" y1="9" x2="23" y2="9" /><line x1="20" y1="14" x2="23" y2="14" /><line x1="1" y1="9" x2="4" y2="9" /><line x1="1" y1="14" x2="4" y2="14" /></>,
  report: <><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" /><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" /></>,
  database: <><ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" /><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" /></>,
  refresh: <><polyline points="23 4 23 10 17 10" /><polyline points="1 20 1 14 7 14" /><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" /></>,
  shield: <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />,
  inbox: <><polyline points="22 12 16 12 14 15 10 15 8 12 2 12" /><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" /></>,
  x: <><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></>,
  chevron: <polyline points="9 18 15 12 9 6" />,
};

export function Icon({ name, size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      {ICONS[name]}
    </svg>
  );
}
