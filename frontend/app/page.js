"use client";
import { useState, useEffect, useCallback } from "react";
import FileUpload from "../components/FileUpload";
import Timeline from "../components/Timeline";
import DetectionTable from "../components/DetectionTable";
import NarrativePanel from "../components/NarrativePanel";
import StatsBar from "../components/StatsBar";
import { fetchEvents, fetchStats, trainModel } from "../lib/api";

const TABS = [
  { id: "timeline", label: "Timeline" },
  { id: "events", label: "Events" },
  { id: "narrative", label: "Narrative" },
];

export default function Dashboard() {
  const [tab, setTab] = useState("timeline");
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [ingestionId, setIngestionId] = useState(null);
  const [filter, setFilter] = useState("all");
  const [training, setTraining] = useState(false);

  const loadData = useCallback(async (iid, filterOverride) => {
    const activeFilter = filterOverride ?? filter;
    try {
      const [evts, st] = await Promise.all([
        fetchEvents({ ingestion_id: iid, detection_level: activeFilter !== "all" ? activeFilter : undefined }),
        fetchStats(iid),
      ]);
      setEvents(evts);
      setStats(st);
    } catch (err) {
      console.error("Failed to load data:", err);
    }
  }, [filter]);

  useEffect(() => {
    // Try loading existing data on mount
    loadData(null);
  }, [loadData]);

  function handleIngested(result) {
    setIngestionId(result.ingestion_id);
    loadData(result.ingestion_id);
  }

  async function handleTrain() {
    setTraining(true);
    try {
      await trainModel();
      // Reload to get updated ML scores
      await loadData(ingestionId);
    } catch (err) {
      console.error("Training failed:", err);
    } finally {
      setTraining(false);
    }
  }

  function handleFilterChange(newFilter) {
    setFilter(newFilter);
    loadData(ingestionId, newFilter);
  }

  return (
    <main className="dashboard">
      <header className="dashboard-header">
        <div className="header-left">
          <h1 className="logo">
            <span className="logo-icon">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </span>
            ARIS
          </h1>
          <span className="subtitle">Automated Registry and Incident Sifting</span>
        </div>
        <div className="header-right">
          <button
            onClick={handleTrain}
            disabled={training || !events.length}
            className="btn btn-secondary"
          >
            {training ? "Training..." : "Train ML"}
          </button>
        </div>
      </header>

      <FileUpload onIngested={handleIngested} />

      {stats && <StatsBar stats={stats} />}

      {events.length > 0 && (
        <>
          {/* Tab bar */}
          <div className="tab-bar">
            {TABS.map((t) => (
              <button
                key={t.id}
                className={`tab ${tab === t.id ? "tab-active" : ""}`}
                onClick={() => setTab(t.id)}
              >
                {t.label}
              </button>
            ))}

            {/* Detection filter */}
            <div className="filter-group">
              {["all", "any", "sigma", "ml", "both"].map((f) => (
                <button
                  key={f}
                  className={`filter-btn ${filter === f ? "filter-active" : ""}`}
                  onClick={() => handleFilterChange(f)}
                >
                  {f === "any" ? "Detected" : f.charAt(0).toUpperCase() + f.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {/* Tab content */}
          <div className="tab-content">
            {tab === "timeline" && <Timeline events={events} />}
            {tab === "events" && <DetectionTable events={events} />}
            {tab === "narrative" && <NarrativePanel ingestionId={ingestionId} />}
          </div>
        </>
      )}
    </main>
  );
}
