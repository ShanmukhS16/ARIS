"use client";
import { useEffect, useRef, useState } from "react";
import { searchEvents } from "../../lib/api";
import { fmtTs } from "../../lib/format";
import { ErrorBanner, Panel, StatusDot } from "../ui";

const LEVELS = ["all", "any", "sigma", "ml", "both"];
const POLL_MS = 3000;

// "host:srv-01 level:sigma powershell" -> { host, detection_level, q }
function parseQuery(text) {
  const params = {};
  const free = [];
  for (const tok of text.trim().split(/\s+/)) {
    if (!tok) continue;
    const m = tok.match(/^(host|level|user):(.+)$/i);
    if (!m) free.push(tok);
    else if (m[1].toLowerCase() === "host") params.host = m[2];
    else if (m[1].toLowerCase() === "level") params.detection_level = m[2];
    else free.push(m[2]);
  }
  if (free.length) params.q = free.join(" ");
  return params;
}

function prettyParsed(parsed) {
  try {
    return JSON.stringify(JSON.parse(parsed), null, 2);
  } catch {
    return parsed || "{}";
  }
}

export default function LiveLogsView({ scope, refreshKey }) {
  const [input, setInput] = useState("");
  const [query, setQuery] = useState("");
  const [level, setLevel] = useState("all");
  const [follow, setFollow] = useState(true);
  const [rows, setRows] = useState([]);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(null);
  const scroller = useRef(null);

  useEffect(() => {
    let alive = true;
    async function load() {
      try {
        const parsed = parseQuery(query);
        const data = await searchEvents({
          ingestion_id: scope.ingestionId,
          hours: scope.hours,
          ...parsed,
          detection_level: parsed.detection_level || (level !== "all" ? level : undefined),
          order: "desc",
          limit: 300,
          include_parsed: true,
        });
        if (alive) {
          setRows(data.reverse());
          setError(null);
        }
      } catch (err) {
        if (alive) setError(err.message);
      }
    }
    load();
    const timer = follow ? setInterval(load, POLL_MS) : null;
    return () => {
      alive = false;
      if (timer) clearInterval(timer);
    };
  }, [query, level, follow, scope.hours, scope.ingestionId, refreshKey]);

  // Tail behaviour: stick to the bottom while following
  useEffect(() => {
    if (follow && scroller.current) scroller.current.scrollTop = scroller.current.scrollHeight;
  }, [rows, follow]);

  return (
    <div className="view">
      <Panel
        title="Live log stream"
        subtitle="Newest 300 events matching the query, polled every 3s while streaming"
        actions={
          <div className="log-status">
            <StatusDot status={follow ? "live" : "warn"} />
            <span>{follow ? "Streaming" : "Paused"}</span>
            <button className="btn btn-secondary btn-sm" onClick={() => setFollow((f) => !f)}>
              {follow ? "Pause" : "Resume"}
            </button>
          </div>
        }
      >
        <form
          className="log-toolbar"
          onSubmit={(e) => {
            e.preventDefault();
            setQuery(input);
          }}
        >
          <span className="log-prompt">$</span>
          <input
            className="log-search"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Search…  e.g.  host:SysClient0201 level:sigma powershell"
            spellCheck={false}
          />
          <button className="btn btn-primary btn-sm" type="submit">Run</button>
          <div className="filter-group">
            {LEVELS.map((l) => (
              <button
                type="button"
                key={l}
                className={`filter-btn ${level === l ? "filter-active" : ""}`}
                onClick={() => setLevel(l)}
              >
                {l === "any" ? "Flagged" : l === "all" ? "All" : l.toUpperCase()}
              </button>
            ))}
          </div>
        </form>

        <ErrorBanner message={error} />

        <div className="log-terminal" ref={scroller}>
          {rows.length === 0 && <div className="log-empty">-- no matching events --</div>}
          {rows.map((ev) => (
            <div key={ev.id}>
              <div
                className={`log-line log-${ev.detection_level}`}
                onClick={() => {
                  // Pause the stream while inspecting so the line doesn't scroll away
                  if (expanded !== ev.id) setFollow(false);
                  setExpanded(expanded === ev.id ? null : ev.id);
                }}
              >
                <span className="log-ts">{fmtTs(ev.timestamp)}</span>
                <span className={`log-level lvl-${ev.detection_level}`}>
                  {ev.detection_level === "none" ? "INFO" : ev.detection_level.toUpperCase()}
                </span>
                <span className="log-host">{ev.host}</span>
                <span className="log-src">{ev.source_type}</span>
                <span className="log-user">{ev.user || "-"}</span>
                <span className="log-msg">{ev.process || "-"}</span>
                {ev.detections.map((d) => (
                  <span key={d.rule_id} className={`rule-tag severity-${d.severity}`}>{d.mitre_attack_id || d.rule_id}</span>
                ))}
                {ev.anomaly_score != null && (
                  <span className={`log-score ${ev.anomaly_score >= 0.5 ? "score-hot" : ""}`}>
                    ml={ev.anomaly_score.toFixed(2)}
                  </span>
                )}
              </div>
              {expanded === ev.id && (
                <pre className="log-json">
                  {prettyParsed(ev.parsed)}
                  {ev.detections.length > 0 && `\n\n// detections\n${JSON.stringify(ev.detections, null, 2)}`}
                </pre>
              )}
            </div>
          ))}
        </div>
        <div className="log-footer">
          <span>{rows.length} lines</span>
          <span>Click a line to expand the parsed event JSON</span>
        </div>
      </Panel>
    </div>
  );
}
