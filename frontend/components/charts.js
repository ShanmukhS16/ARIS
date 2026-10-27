"use client";
import { useEffect, useRef, useState } from "react";
import { fmtNum } from "../lib/format";

// Track an element's rendered width so charts draw at real pixel size.
export function useWidth() {
  const ref = useRef(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([entry]) => setWidth(Math.floor(entry.contentRect.width)));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, width];
}

function niceMax(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const m = v / p;
  return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p;
}

// ---- Sparkline (used in KPI tiles) ----

export function Sparkline({ values, color = "var(--accent)", height = 32 }) {
  if (!values || values.length < 2) return <div style={{ height }} />;
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => [(i / (values.length - 1)) * 100, height - 2 - (v / max) * (height - 4)]);
  const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x},${y}`).join(" ");
  return (
    <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" width="100%" height={height}>
      <path d={`${line} L100,${height} L0,${height} Z`} fill={color} opacity="0.12" />
      <path d={line} fill="none" stroke={color} strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

// ---- Stacked area / bar chart with hover tooltip ----

export function StackedChart({
  data,
  series,
  type = "area",
  height = 220,
  xLabel = (d, i) => i,
  tooltipTitle = (d, i) => xLabel(d, i),
  marker = null, // { at: 0..1 fraction of x axis, label }
}) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState(null);

  const pad = { top: 12, right: 12, bottom: 24, left: 44 };
  const w = Math.max(width - pad.left - pad.right, 10);
  const h = height - pad.top - pad.bottom;
  const n = data.length;
  const step = w / Math.max(n, 1);

  // Cumulative stacks: stacks[s][i] = [lower, upper]
  const stacks = [];
  const base = new Array(n).fill(0);
  for (const s of series) {
    stacks.push(data.map((d, i) => {
      const lo = base[i];
      base[i] += d[s.key] || 0;
      return [lo, base[i]];
    }));
  }
  const max = niceMax(Math.max(1, ...base));
  const x = (i) => pad.left + step * i + step / 2;
  const y = (v) => pad.top + h - (v / max) * h;

  const tickEvery = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(w / 90))));

  function onMove(e) {
    const rect = e.currentTarget.getBoundingClientRect();
    const i = Math.floor((e.clientX - rect.left - pad.left) / step);
    setHover(i >= 0 && i < n ? i : null);
  }

  return (
    <div ref={ref} className="chart" style={{ height }}>
      {width > 0 && (
        <svg width={width} height={height} onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
          {[0, 0.25, 0.5, 0.75, 1].map((f) => (
            <g key={f}>
              <line x1={pad.left} x2={pad.left + w} y1={y(max * f)} y2={y(max * f)} className="chart-grid" />
              <text x={pad.left - 6} y={y(max * f) + 3} textAnchor="end" className="chart-axis">
                {fmtNum(max * f)}
              </text>
            </g>
          ))}

          {type === "area" &&
            series.map((s, si) => {
              const top = stacks[si].map(([, hi], i) => `${i ? "L" : "M"}${x(i)},${y(hi)}`).join(" ");
              const bottom = stacks[si]
                .map(([lo], i) => [i, lo])
                .reverse()
                .map(([i, lo]) => `L${x(i)},${y(lo)}`)
                .join(" ");
              return (
                <g key={s.key}>
                  <path d={`${top} ${bottom} Z`} fill={s.color} opacity="0.25" />
                  <path d={top} fill="none" stroke={s.color} strokeWidth="1.5" />
                </g>
              );
            })}

          {type === "bar" &&
            series.map((s, si) =>
              stacks[si].map(([lo, hi], i) =>
                hi > lo ? (
                  <rect
                    key={`${s.key}-${i}`}
                    x={x(i) - step * 0.35}
                    width={Math.max(step * 0.7, 1)}
                    y={y(hi)}
                    height={Math.max(y(lo) - y(hi), 1)}
                    fill={s.color}
                    opacity={hover === null || hover === i ? 0.9 : 0.45}
                  />
                ) : null
              )
            )}

          {data.map((d, i) =>
            i % tickEvery === 0 ? (
              <text key={i} x={x(i)} y={height - 6} textAnchor="middle" className="chart-axis">
                {xLabel(d, i)}
              </text>
            ) : null
          )}

          {marker && (
            <g>
              <line
                x1={pad.left + w * marker.at} x2={pad.left + w * marker.at}
                y1={pad.top} y2={pad.top + h}
                className="chart-marker"
              />
              <text x={pad.left + w * marker.at + 4} y={pad.top + 10} className="chart-marker-label">
                {marker.label}
              </text>
            </g>
          )}

          {hover !== null && type === "area" && (
            <line x1={x(hover)} x2={x(hover)} y1={pad.top} y2={pad.top + h} className="chart-crosshair" />
          )}
        </svg>
      )}

      {hover !== null && data[hover] && (
        <div
          className="chart-tooltip"
          style={{ left: Math.min(x(hover) + 12, Math.max(width - 180, 0)), top: pad.top }}
        >
          <div className="chart-tooltip-title">{tooltipTitle(data[hover], hover)}</div>
          {series.map((s) => (
            <div key={s.key} className="chart-tooltip-row">
              <span className="legend-dot" style={{ background: s.color }} />
              <span>{s.label}</span>
              <span className="chart-tooltip-val">{fmtNum(data[hover][s.key] || 0)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function Legend({ series }) {
  return (
    <div className="chart-legend">
      {series.map((s) => (
        <span key={s.key} className="legend-item">
          <span className="legend-dot" style={{ background: s.color }} />
          {s.label}
        </span>
      ))}
    </div>
  );
}

// ---- Donut ----

export function Donut({ items, size = 150, thickness = 18, centerLabel = "total" }) {
  const total = items.reduce((s, it) => s + it.value, 0);
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div className="donut">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--bg-hover)" strokeWidth={thickness} />
        {total > 0 &&
          items.map((it) => {
            const len = (it.value / total) * c;
            const el = (
              <circle
                key={it.label}
                cx={size / 2} cy={size / 2} r={r}
                fill="none"
                stroke={it.color}
                strokeWidth={thickness}
                strokeDasharray={`${len} ${c - len}`}
                strokeDashoffset={-offset}
                transform={`rotate(-90 ${size / 2} ${size / 2})`}
              >
                <title>{`${it.label}: ${it.value}`}</title>
              </circle>
            );
            offset += len;
            return el;
          })}
        <text x="50%" y="48%" textAnchor="middle" className="donut-value">{fmtNum(total)}</text>
        <text x="50%" y="62%" textAnchor="middle" className="donut-label">{centerLabel}</text>
      </svg>
      <div className="donut-legend">
        {items.map((it) => (
          <div key={it.label} className="donut-legend-row">
            <span className="legend-dot" style={{ background: it.color }} />
            <span className="donut-legend-label">{it.label}</span>
            <span className="donut-legend-val">{fmtNum(it.value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---- Horizontal bar list ----

export function BarList({ items, emptyText = "No data" }) {
  if (!items.length) return <div className="empty-inline">{emptyText}</div>;
  const max = Math.max(1, ...items.map((it) => it.value));
  return (
    <div className="bar-list">
      {items.map((it) => (
        <div key={it.key || it.label} className="bar-row" title={it.title}>
          <div className="bar-fill" style={{ width: `${(it.value / max) * 100}%`, background: it.color }} />
          <span className="bar-label">{it.label}</span>
          {it.sub && <span className="bar-sub">{it.sub}</span>}
          <span className="bar-value">{fmtNum(it.value)}</span>
        </div>
      ))}
    </div>
  );
}

// ---- Multi-series line chart over a numeric x axis ----
// series: [{ key, label, color, points: [[x, y], ...], dash }]; y is a 0..1 rate.

function nearestY(points, xv) {
  let lo = 0, hi = points.length - 1;
  while (hi - lo > 1) {
    const mid = (lo + hi) >> 1;
    if (points[mid][0] < xv) lo = mid; else hi = mid;
  }
  if (!points.length) return null;
  return Math.abs(points[lo][0] - xv) <= Math.abs(points[hi][0] - xv) ? points[lo] : points[hi];
}

export function LineChart({
  series,
  xDomain,
  xLog = false,
  height = 240,
  xFormat = (v) => v.toFixed(2),
  yFormat = (v) => `${(v * 100).toFixed(0)}%`,
  xTitle,
  yTitle,
  markers = [], // [{ x, label }]
  dots = [],    // [{ x, y, label, color }]
}) {
  const [ref, width] = useWidth();
  const [hoverX, setHoverX] = useState(null);

  const pad = { top: 12, right: 16, bottom: 34, left: 44 };
  const w = Math.max(width - pad.left - pad.right, 10);
  const h = height - pad.top - pad.bottom;
  const [x0, x1] = xDomain;
  const tx = (v) => (xLog ? Math.log10(Math.max(v, x0)) : v);
  const fx = (v) => pad.left + ((tx(v) - tx(x0)) / (tx(x1) - tx(x0))) * w;
  const fy = (v) => pad.top + h - v * h;
  const invX = (px) => {
    const t = tx(x0) + ((px - pad.left) / w) * (tx(x1) - tx(x0));
    return xLog ? Math.pow(10, t) : t;
  };

  const xTicks = xLog
    ? Array.from({ length: Math.round(Math.log10(x1 / x0)) + 1 }, (_, i) => x0 * Math.pow(10, i))
    : [0, 0.25, 0.5, 0.75, 1].map((f) => x0 + f * (x1 - x0));

  function onMove(e) {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = e.clientX - rect.left;
    setHoverX(px >= pad.left && px <= pad.left + w ? invX(px) : null);
  }

  return (
    <div ref={ref} className="chart" style={{ height }}>
      {width > 0 && (
        <svg width={width} height={height} onMouseMove={onMove} onMouseLeave={() => setHoverX(null)}>
          {[0, 0.25, 0.5, 0.75, 1].map((f) => (
            <g key={f}>
              <line x1={pad.left} x2={pad.left + w} y1={fy(f)} y2={fy(f)} className="chart-grid" />
              <text x={pad.left - 6} y={fy(f) + 3} textAnchor="end" className="chart-axis">{yFormat(f)}</text>
            </g>
          ))}
          {xTicks.map((v) => (
            <text key={v} x={fx(v)} y={pad.top + h + 14} textAnchor="middle" className="chart-axis">{xFormat(v)}</text>
          ))}
          {xTitle && (
            <text x={pad.left + w / 2} y={height - 4} textAnchor="middle" className="chart-axis">{xTitle}</text>
          )}
          {yTitle && (
            <text transform={`translate(10 ${pad.top + h / 2}) rotate(-90)`} textAnchor="middle" className="chart-axis">{yTitle}</text>
          )}
          {markers.map((m) => (
            <g key={m.label}>
              <line x1={fx(m.x)} x2={fx(m.x)} y1={pad.top} y2={pad.top + h} className="chart-crosshair" />
              <text x={fx(m.x) + 4} y={pad.top + 10} className="chart-axis">{m.label}</text>
            </g>
          ))}
          {series.map((s) => (
            <path
              key={s.key}
              d={s.points.map(([x, y], i) => `${i ? "L" : "M"}${fx(x)},${fy(y)}`).join(" ")}
              fill="none" stroke={s.color} strokeWidth="2" strokeDasharray={s.dash ? "5 4" : undefined}
              strokeLinejoin="round"
            />
          ))}
          {dots.map((d) => (
            <g key={d.label}>
              <circle cx={fx(d.x)} cy={fy(d.y)} r="5" fill={d.color} stroke="var(--bg-card)" strokeWidth="2" />
              <text x={fx(d.x) + 8} y={fy(d.y) - 6} className="chart-axis">{d.label}</text>
            </g>
          ))}
          {hoverX !== null && (
            <line x1={fx(hoverX)} x2={fx(hoverX)} y1={pad.top} y2={pad.top + h} className="chart-crosshair" />
          )}
        </svg>
      )}
      {hoverX !== null && (
        <div className="chart-tooltip" style={{ left: Math.min(fx(hoverX) + 12, Math.max(width - 200, 0)), top: pad.top }}>
          <div className="chart-tooltip-title">{xTitle || "x"} {xFormat(hoverX)}</div>
          {series.map((s) => {
            const p = nearestY(s.points, hoverX);
            return p ? (
              <div key={s.key} className="chart-tooltip-row">
                <span className="legend-line" style={{ background: s.color }} />
                <span>{s.label}</span>
                <span className="chart-tooltip-val">{yFormat(p[1])}</span>
              </div>
            ) : null;
          })}
        </div>
      )}
    </div>
  );
}
