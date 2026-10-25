"use client";
import { useState } from "react";
import { searchEvents } from "../../lib/api";
import DetectionTable from "../DetectionTable";
import NarrativePanel from "../NarrativePanel";
import Timeline from "../Timeline";
import { ErrorBanner, Panel, Skeleton, useLoader } from "../ui";

const FILTERS = ["any", "sigma", "ml", "both", "all"];

export function TimelineView({ scope, refreshKey }) {
  const { data, error } = useLoader(
    () => searchEvents({
      ingestion_id: scope.ingestionId, hours: scope.hours,
      detection_level: "any", order: "desc", limit: 300,
    }).then((rows) => rows.reverse()),
    [scope.hours, scope.ingestionId, refreshKey]
  );
  return (
    <div className="view">
      <Panel title="Incident timeline" subtitle="Latest 300 flagged events, one lane per host. Click a marker for details.">
        <ErrorBanner message={error} />
        {data ? <Timeline events={data} /> : <Skeleton height={240} />}
      </Panel>
    </div>
  );
}

export function DetectionsView({ scope, refreshKey }) {
  const [filter, setFilter] = useState("any");
  const [input, setInput] = useState("");
  const [query, setQuery] = useState("");
  const { data, error, loading } = useLoader(
    () => searchEvents({
      ingestion_id: scope.ingestionId, hours: scope.hours,
      detection_level: filter !== "all" ? filter : undefined,
      q: query, order: "desc", limit: 500,
    }),
    [filter, query, scope.hours, scope.ingestionId, refreshKey]
  );

  return (
    <div className="view">
      <Panel
        title="Detections"
        subtitle={data ? `${data.length}${data.length === 500 ? "+" : ""} events${loading ? " · refreshing…" : ""}` : "Loading…"}
        actions={
          <div className="filter-group">
            {FILTERS.map((f) => (
              <button key={f} className={`filter-btn ${filter === f ? "filter-active" : ""}`} onClick={() => setFilter(f)}>
                {f === "any" ? "All flagged" : f === "all" ? "Everything" : f.toUpperCase()}
              </button>
            ))}
          </div>
        }
      >
        <form className="inline-search" onSubmit={(e) => { e.preventDefault(); setQuery(input); }}>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Filter by host, user or command line…"
          />
          <button className="btn btn-secondary btn-sm" type="submit">Search</button>
        </form>
        <ErrorBanner message={error} />
        {data ? <DetectionTable events={data} /> : <Skeleton height={300} />}
      </Panel>
    </div>
  );
}

export function IncidentView({ scope }) {
  return (
    <div className="view">
      <Panel
        title="Incident report"
        subtitle={
          scope.ingestionId
            ? `Postmortem for ingestion ${scope.ingestionId}`
            : "Postmortem for the most recent ingestion. Pick a job on the Ingestion page to change scope."
        }
      >
        <NarrativePanel ingestionId={scope.ingestionId} />
      </Panel>
    </div>
  );
}
