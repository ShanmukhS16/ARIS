"use client";
import { fetchOverview } from "../../lib/api";
import {
  LEVEL_COLORS, SEVERITY_COLORS, fmtDuration, fmtNum, fmtTs, pctChange, timeTickFormatter,
} from "../../lib/format";
import { BarList, Donut, Legend, StackedChart } from "../charts";
import AttackMatrix from "../AttackMatrix";
import { EmptyState, ErrorBanner, KpiTile, Panel, Skeleton, useLoader } from "../ui";

const VOLUME_SERIES = [
  { key: "both", label: "Sigma + ML", color: LEVEL_COLORS.both },
  { key: "sigma", label: "Sigma only", color: LEVEL_COLORS.sigma },
  { key: "ml", label: "ML only", color: LEVEL_COLORS.ml },
  { key: "none", label: "Clean", color: "#06b6d4" },
];
const DETECTION_SERIES = VOLUME_SERIES.slice(0, 3);

export default function OverviewView({ scope, refreshKey, onNavigate }) {
  const { data, error } = useLoader(() => fetchOverview(scope), [scope.hours, scope.ingestionId, refreshKey]);

  if (!data) {
    return (
      <div className="view">
        <ErrorBanner message={error} />
        <div className="kpi-grid">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} height={110} />)}</div>
        <Skeleton height={280} />
      </div>
    );
  }

  if (data.empty) {
    return (
      <div className="view">
        <EmptyState
          title="No telemetry yet"
          message="Ingest a Sysmon, auth.log or OpTC eCAR file to start populating the console."
          action={<button className="btn btn-primary" onClick={() => onNavigate("ingestion")}>Go to Ingestion</button>}
        />
      </div>
    );
  }

  const { kpis, previous, timeseries, window } = data;
  const sum = (d, keys) => keys.reduce((s, k) => s + (d[k] || 0), 0);
  const sparkTotal = timeseries.map((d) => sum(d, ["none", "sigma", "ml", "both"]));
  const sparkDetected = timeseries.map((d) => sum(d, ["sigma", "ml", "both"]));
  const sparkSigma = timeseries.map((d) => sum(d, ["sigma", "both"]));
  const sparkMl = timeseries.map((d) => sum(d, ["ml", "both"]));
  const detectRate = kpis.total_events ? (kpis.detected_events / kpis.total_events) * 100 : 0;

  const span = timeseries.length * window.bucket_seconds;
  const tick = timeTickFormatter(span);
  const xLabel = (d) => tick(d.t);
  const tooltipTitle = (d) => `${fmtTs(d.t)} (+${fmtDuration(window.bucket_seconds)})`;

  const severityItems = ["critical", "high", "medium", "low"].map((s) => ({
    label: s[0].toUpperCase() + s.slice(1),
    value: data.severity[s] || 0,
    color: SEVERITY_COLORS[s],
  }));

  return (
    <div className="view">
      <div className="kpi-grid">
        <KpiTile
          label="Events ingested" value={kpis.total_events} color="var(--accent)"
          spark={sparkTotal} trend={previous && pctChange(kpis.total_events, previous.total_events)}
          sub={`${fmtTs(window.start)} → ${fmtTs(window.end)}`}
        />
        <KpiTile
          label="Flagged events" value={kpis.detected_events} color="var(--warning)"
          spark={sparkDetected} trendGoodWhenDown
          trend={previous && pctChange(kpis.detected_events, previous.detected_events)}
          sub={`${detectRate.toFixed(1)}% of all events`}
        />
        <KpiTile label="Sigma rule hits" value={kpis.sigma_events} color={LEVEL_COLORS.sigma} spark={sparkSigma}
          sub={`${kpis.both_events} confirmed by ML`} />
        <KpiTile label="ML anomalies" value={kpis.ml_events} color={LEVEL_COLORS.ml} spark={sparkMl}
          sub={`${kpis.ml_events - kpis.both_events} missed by Sigma`} />
        <KpiTile label="Critical alerts" value={kpis.critical} color="var(--danger)"
          sub={`${fmtNum(kpis.detections)} alerts total`} />
        <KpiTile label="Hosts affected" value={`${fmtNum(kpis.hosts_detected)} / ${fmtNum(kpis.hosts)}`}
          sub="hosts with at least one flag" />
      </div>

      <div className="grid-12">
        <Panel
          className="span-8" title="Event volume"
          subtitle={`Events per ${fmtDuration(window.bucket_seconds)} by detection layer`}
          actions={<Legend series={VOLUME_SERIES} />}
        >
          <StackedChart data={timeseries} series={VOLUME_SERIES} type="area" height={240}
            xLabel={xLabel} tooltipTitle={tooltipTitle} />
        </Panel>

        <Panel className="span-4" title="Alert severity" subtitle="Sigma detections by rule level">
          <Donut items={severityItems} centerLabel="alerts" />
        </Panel>

        <Panel
          className="span-8" title="Detections over time"
          subtitle="Flagged events only"
          actions={<Legend series={DETECTION_SERIES} />}
        >
          <StackedChart data={timeseries} series={DETECTION_SERIES} type="bar" height={220}
            xLabel={xLabel} tooltipTitle={tooltipTitle} />
        </Panel>

        <Panel
          className="span-4 panel-scroll" title="Recent alerts"
          actions={<button className="link-btn" onClick={() => onNavigate("detections")}>View all →</button>}
        >
          {data.recent_alerts.length === 0 && <div className="empty-inline">No alerts in range.</div>}
          <ul className="alert-feed">
            {data.recent_alerts.map((a) => (
              <li key={a.id} className={`feed-item feed-${a.severity}`}>
                <div className="feed-top">
                  <span className={`badge badge-${a.severity}`}>{a.severity}</span>
                  <span className="feed-time">{fmtTs(a.timestamp)}</span>
                </div>
                <div className="feed-title">{a.rule_title}</div>
                <div className="feed-meta">
                  <code>{a.host}</code>
                  {a.user && <span>· {a.user}</span>}
                  {a.technique && <span className="technique-badge">{a.technique}</span>}
                </div>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel className="span-12" title="MITRE ATT&CK coverage"
          subtitle="Techniques covered by Sigma rules, shaded by detections in range">
          <AttackMatrix cells={data.attack_matrix} />
        </Panel>

        <Panel className="span-6" title="Top noisy hosts" subtitle="Flagged events per host">
          <BarList
            emptyText="No flagged hosts in range."
            items={data.top_hosts.map((h) => ({
              key: h.host,
              label: h.host,
              value: h.count,
              sub: h.max_score != null ? `max ML ${h.max_score.toFixed(2)}` : null,
              color: h.max_score >= 0.8 ? "rgba(239,68,68,0.35)" : "rgba(249,115,22,0.3)",
            }))}
          />
        </Panel>

        <Panel className="span-6" title="Top firing rules"
          actions={<button className="link-btn" onClick={() => onNavigate("rules")}>All rules →</button>}>
          <BarList
            emptyText="No rule hits in range."
            items={data.top_rules.filter((r) => r.count > 0).slice(0, 8).map((r) => ({
              key: r.rule_id,
              label: r.title,
              title: `${r.rule_id} · ${r.technique}`,
              value: r.count,
              sub: r.technique,
              color: `${SEVERITY_COLORS[r.severity] || "#64748b"}55`,
            }))}
          />
        </Panel>
      </div>
    </div>
  );
}
