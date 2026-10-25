"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import Sidebar, { findPage } from "../components/Sidebar";
import Topbar from "../components/Topbar";
import OverviewView from "../components/views/OverviewView";
import LiveLogsView from "../components/views/LiveLogsView";
import { DetectionsView, IncidentView, TimelineView } from "../components/views/EventViews";
import RulesView from "../components/views/RulesView";
import ModelView from "../components/views/ModelView";
import IngestionView from "../components/views/IngestionView";
import { healthCheck } from "../lib/api";
import { fmtNum } from "../lib/format";

const DEFAULT_PAGE = "overview";

export default function Console() {
  const [page, setPage] = useState(DEFAULT_PAGE);
  const [hours, setHours] = useState(null);
  const [ingestionId, setIngestionId] = useState(null);
  const [refreshMs, setRefreshMs] = useState(0);
  const [refreshKey, setRefreshKey] = useState(0);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [now, setNow] = useState(Date.now());
  const [health, setHealth] = useState(null);
  const [toasts, setToasts] = useState([]);

  // Keep the current page in the URL hash so refresh/back work
  useEffect(() => {
    const sync = () => {
      const id = window.location.hash.slice(1);
      setPage(findPage(id) ? id : DEFAULT_PAGE);
    };
    sync();
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, []);

  const navigate = useCallback((id) => {
    window.location.hash = id;
    setPage(id);
  }, []);

  const refresh = useCallback(() => setRefreshKey((k) => k + 1), []);

  useEffect(() => {
    if (!refreshMs) return;
    const t = setInterval(refresh, refreshMs);
    return () => clearInterval(t);
  }, [refreshMs, refresh]);

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    setLastUpdated(Date.now());
    healthCheck().then(setHealth).catch(() => setHealth(null));
  }, [refreshKey, hours, ingestionId]);

  const notify = useCallback((message, kind = "info") => {
    const id = Math.random().toString(36).slice(2);
    setToasts((ts) => [...ts, { id, message, kind }]);
    setTimeout(() => setToasts((ts) => ts.filter((t) => t.id !== id)), 4500);
  }, []);

  function handleIngested(result) {
    notify(
      `Job ${result.ingestion_id} completed: ${fmtNum(result.events_parsed)} events, ` +
      `${result.sigma_detections} Sigma hits, ${result.ml_anomalies} ML anomalies`,
      "success"
    );
    refresh();
  }

  function handleInspect(id) {
    setIngestionId(id);
    navigate("overview");
  }

  const scope = useMemo(() => ({ hours, ingestionId }), [hours, ingestionId]);
  const viewProps = { scope, refreshKey, onNavigate: navigate, onRefresh: refresh, notify };

  return (
    <div className="app-shell">
      <Sidebar page={page} onNavigate={navigate} health={health} />

      <div className="app-main">
        <Topbar
          pageInfo={findPage(page)}
          hours={hours}
          onHours={setHours}
          refreshMs={refreshMs}
          onRefreshMs={setRefreshMs}
          onRefresh={refresh}
          lastUpdated={lastUpdated}
          now={now}
          health={health}
          ingestionId={ingestionId}
          onClearIngestion={() => setIngestionId(null)}
        />

        <main className="app-content">
          {page === "overview" && <OverviewView {...viewProps} />}
          {page === "logs" && <LiveLogsView {...viewProps} />}
          {page === "timeline" && <TimelineView {...viewProps} />}
          {page === "detections" && <DetectionsView {...viewProps} />}
          {page === "rules" && <RulesView {...viewProps} />}
          {page === "model" && <ModelView {...viewProps} />}
          {page === "incident" && <IncidentView {...viewProps} />}
          {page === "ingestion" && (
            <IngestionView {...viewProps} onIngested={handleIngested} onInspect={handleInspect} />
          )}
        </main>
      </div>

      <div className="toast-stack">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.kind}`}>{t.message}</div>
        ))}
      </div>
    </div>
  );
}
