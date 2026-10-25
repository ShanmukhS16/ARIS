const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function healthCheck() {
  const res = await fetch(`${API_BASE}/api/health`);
  return res.json();
}

export async function ingestFile(file) {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_BASE}/api/ingest`, {
    method: "POST",
    body: form,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Upload failed" }));
    throw new Error(err.detail || "Upload failed");
  }
  return res.json();
}

export async function fetchEvents(params = {}) {
  const qs = new URLSearchParams();
  if (params.ingestion_id) qs.set("ingestion_id", params.ingestion_id);
  if (params.host) qs.set("host", params.host);
  if (params.detection_level) qs.set("detection_level", params.detection_level);
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.offset) qs.set("offset", String(params.offset));
  const res = await fetch(`${API_BASE}/api/events?${qs}`);
  return res.json();
}

export async function fetchDetections(params = {}) {
  const qs = new URLSearchParams();
  if (params.ingestion_id) qs.set("ingestion_id", params.ingestion_id);
  if (params.severity) qs.set("severity", params.severity);
  const res = await fetch(`${API_BASE}/api/detections?${qs}`);
  return res.json();
}

export async function fetchStats(ingestionId) {
  const qs = ingestionId ? `?ingestion_id=${ingestionId}` : "";
  const res = await fetch(`${API_BASE}/api/stats${qs}`);
  return res.json();
}

export async function generateNarrative(ingestionId) {
  const qs = ingestionId ? `?ingestion_id=${ingestionId}` : "";
  const res = await fetch(`${API_BASE}/api/narrative${qs}`, { method: "POST" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Narrative generation failed" }));
    throw new Error(err.detail || "Narrative generation failed");
  }
  return res.json();
}

export async function trainModel() {
  const res = await fetch(`${API_BASE}/api/train`, { method: "POST" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Training failed" }));
    throw new Error(err.detail || "Training failed");
  }
  return res.json();
}
