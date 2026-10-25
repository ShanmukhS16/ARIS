export const LEVEL_COLORS = {
  both: "#ef4444",
  sigma: "#f97316",
  ml: "#8b5cf6",
  none: "#475569",
};

export const LEVEL_LABELS = {
  both: "Sigma + ML",
  sigma: "Sigma only",
  ml: "ML only",
  none: "Clean",
};

export const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

export function fmtNum(n) {
  if (n === null || n === undefined) return "-";
  const a = Math.abs(n);
  const trim = (x) => x.toFixed(1).replace(/\.0$/, "");
  if (a >= 1e9) return `${trim(n / 1e9)}B`;
  if (a >= 1e6) return `${trim(n / 1e6)}M`;
  if (a >= 1e4) return `${trim(n / 1e3)}k`;
  return n.toLocaleString();
}

// Log-style timestamp straight from the ISO string, no timezone shifting.
export function fmtTs(iso) {
  return iso ? iso.replace("T", " ").slice(0, 19) : "-";
}

export function fmtAgo(ms, now = Date.now()) {
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

export function fmtDuration(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

export function pctChange(cur, prev) {
  if (!prev) return null;
  return ((cur - prev) / prev) * 100;
}

// Pick a tick label format based on how much time the chart spans.
export function timeTickFormatter(spanSeconds) {
  return (iso) => {
    const d = new Date(iso);
    if (spanSeconds <= 2 * 86400) {
      return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });
    }
    if (spanSeconds <= 120 * 86400) {
      return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
    }
    return d.toLocaleDateString(undefined, { month: "short", year: "numeric" });
  };
}
