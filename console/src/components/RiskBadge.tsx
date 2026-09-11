function riskColor(score: number | null): string {
  if (score == null) return "var(--color-text-dim)";
  if (score >= 0.8) return "var(--color-risk-critical)";
  if (score >= 0.6) return "var(--color-risk-high)";
  if (score >= 0.35) return "var(--color-risk-med)";
  return "var(--color-risk-low)";
}

export function RiskBadge({ score }: { score: number | null }) {
  const color = riskColor(score);
  return (
    <span
      className="mono inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-semibold"
      style={{ borderColor: color, color }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {score != null ? score.toFixed(2) : "—"}
    </span>
  );
}

export function RiskBar({ terms }: { terms: Record<string, number> }) {
  const entries = Object.entries(terms);
  return (
    <div className="space-y-1.5">
      {entries.map(([name, value]) => (
        <div key={name} className="flex items-center gap-2">
          <span className="w-24 shrink-0 text-xs text-[var(--color-text-dim)]">{name}</span>
          <div className="h-2 flex-1 overflow-hidden rounded-full bg-[var(--color-surface-2)]">
            <div
              className="h-full rounded-full"
              style={{ width: `${Math.min(100, value * 100)}%`, background: riskColor(value) }}
            />
          </div>
          <span className="mono w-10 shrink-0 text-right text-xs text-[var(--color-text-dim)]">
            {value.toFixed(2)}
          </span>
        </div>
      ))}
    </div>
  );
}

export function StateBadge({ state }: { state: string }) {
  const colors: Record<string, string> = {
    MONITORED: "var(--color-accent)",
    ENROLLING: "var(--color-risk-med)",
    DRIFTING: "var(--color-risk-med)",
    QUARANTINED: "var(--color-risk-critical)",
    REFUSED: "var(--color-risk-critical)",
  };
  const color = colors[state] ?? "var(--color-text-dim)";
  return (
    <span className="mono inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-semibold" style={{ borderColor: color, color }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {state}
    </span>
  );
}
