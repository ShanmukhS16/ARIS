"use client";
import { useState, useRef } from "react";
import { ingestFile } from "../lib/api";

export default function FileUpload({ onIngested }) {
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef(null);

  async function handleFile(file) {
    if (!file) return;
    setUploading(true);
    setError(null);
    setResult(null);
    try {
      const data = await ingestFile(file);
      setResult(data);
      if (onIngested) onIngested(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setUploading(false);
    }
  }

  function handleDrop(e) {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    handleFile(file);
  }

  return (
    <div className="upload-section">
      <div
        className={`drop-zone ${dragOver ? "drag-over" : ""}`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".jsonl,.json,.log,.gz"
          style={{ display: "none" }}
          onChange={(e) => handleFile(e.target.files[0])}
        />
        <div className="drop-icon">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
            <polyline points="17,8 12,3 7,8" />
            <line x1="12" y1="3" x2="12" y2="15" />
          </svg>
        </div>
        <p className="drop-text">
          {uploading ? "Processing..." : "Drop a log file here or click to browse"}
        </p>
        <p className="drop-hint">Supports Sysmon JSONL, auth.log, OpTC eCAR</p>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {result && (
        <div className="alert alert-success">
          Ingested <strong>{result.events_parsed}</strong> events
          ({result.source}) with{" "}
          <strong>{result.sigma_detections}</strong> Sigma detections and{" "}
          <strong>{result.ml_anomalies}</strong> ML anomalies.
          <span className="ingestion-id">ID: {result.ingestion_id}</span>
        </div>
      )}
    </div>
  );
}
