"use client";
import { useState } from "react";
import { generateNarrative } from "../lib/api";

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

export default function NarrativePanel({ ingestionId }) {
  const [narrative, setNarrative] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleGenerate() {
    setLoading(true);
    setError(null);
    try {
      const data = await generateNarrative(ingestionId);
      setNarrative(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="narrative-panel">
      <div className="narrative-header">
        <button
          onClick={handleGenerate}
          disabled={loading}
          className="btn btn-primary"
        >
          {loading ? "Generating..." : "Generate Narrative"}
        </button>
        {narrative?._source && (
          <span className="source-badge">
            Source: {narrative._source}
            {narrative._model && ` (${narrative._model})`}
          </span>
        )}
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {narrative && (
        <div className="narrative-content">
          {/* Severity + Summary */}
          <div className="narrative-summary">
            <span
              className="severity-indicator"
              style={{ background: SEVERITY_COLORS[narrative.severity] || "#64748b" }}
            >
              {(narrative.severity || "unknown").toUpperCase()}
            </span>
            <p>{narrative.summary}</p>
          </div>

          {/* Kill Chain */}
          {narrative.kill_chain?.length > 0 && (
            <div className="kill-chain">
              <h3>Kill Chain</h3>
              <div className="chain-steps">
                {narrative.kill_chain.map((step, i) => (
                  <div key={i} className="chain-step">
                    <div className="step-marker">
                      <span className="step-num">{step.step}</span>
                      {i < narrative.kill_chain.length - 1 && <div className="step-line" />}
                    </div>
                    <div className="step-content">
                      <div className="step-header">
                        <span className="technique-badge">
                          {step.technique_id}
                        </span>
                        <span className="technique-name">{step.technique_name}</span>
                      </div>
                      <p className="step-desc">{step.description}</p>
                      {step.evidence && (
                        <code className="step-evidence">{step.evidence}</code>
                      )}
                      {step.timestamp && step.timestamp !== "unknown" && (
                        <span className="step-time">{step.timestamp}</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Visibility Gaps + Recommendations side by side */}
          <div className="narrative-cards">
            {narrative.visibility_gaps?.length > 0 && (
              <div className="card card-gaps">
                <h3>Visibility Gaps</h3>
                <ul>
                  {narrative.visibility_gaps.map((gap, i) => (
                    <li key={i}>{gap}</li>
                  ))}
                </ul>
              </div>
            )}
            {narrative.recommendations?.length > 0 && (
              <div className="card card-recs">
                <h3>Recommendations</h3>
                <ol>
                  {narrative.recommendations.map((rec, i) => (
                    <li key={i}>{rec}</li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
