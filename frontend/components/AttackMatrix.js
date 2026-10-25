"use client";

const TACTIC_ORDER = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command And Control",
  "Exfiltration", "Impact",
];

// MITRE ATT&CK coverage grid: one column per tactic, one cell per technique
// covered by a Sigma rule, shaded by how often it fired.
export default function AttackMatrix({ cells }) {
  if (!cells?.length) return <div className="empty-inline">No ATT&CK techniques mapped.</div>;

  const byTactic = {};
  for (const c of cells) (byTactic[c.tactic || "Other"] ||= []).push(c);
  const tactics = Object.keys(byTactic).sort((a, b) => {
    const ia = TACTIC_ORDER.indexOf(a), ib = TACTIC_ORDER.indexOf(b);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });
  const max = Math.max(1, ...cells.map((c) => c.count));

  return (
    <div className="attack-matrix" style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(150px, 1fr))` }}>
      {tactics.map((t) => (
        <div key={t} className="attack-col">
          <div className="attack-tactic">
            {t}
            <span className="attack-tactic-count">{byTactic[t].length}</span>
          </div>
          {byTactic[t]
            .sort((a, b) => b.count - a.count)
            .map((c) => {
              const ratio = c.count / max;
              return (
                <div
                  key={c.technique}
                  className={`attack-cell ${c.count ? "attack-hit" : "attack-idle"}`}
                  style={c.count ? { background: `rgba(239, 68, 68, ${0.15 + ratio * 0.55})` } : undefined}
                  title={`${c.technique} ${c.name}\n${c.count} detections`}
                >
                  <div className="attack-id">
                    {c.technique}
                    <span className="attack-count">{c.count}</span>
                  </div>
                  <div className="attack-name">{c.name}</div>
                </div>
              );
            })}
        </div>
      ))}
    </div>
  );
}
