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

export function AttributionChart({ contributions }: { contributions: { name: string; value: number; contribution: number }[] }) {
  const maxAbs = Math.max(...contributions.map((c) => Math.abs(c.contribution)), 0.001);
  return (
    <div className="space-y-2" role="img" aria-label="SHAP feature attribution chart">
      {contributions.map((c) => {
        const positive = c.contribution >= 0;
        const widthPct = (Math.abs(c.contribution) / maxAbs) * 100;
        return (
          <div key={c.name} className="flex items-center gap-2 text-xs">
            <span className="mono w-40 shrink-0 truncate text-[var(--color-text-dim)]" title={c.name}>
              {c.name}
            </span>
            <div className="flex h-4 flex-1 items-center">
              <div className="relative h-full flex-1 overflow-hidden rounded bg-[var(--color-surface-2)]">
                <div
                  className="h-full rounded"
                  style={{
                    width: `${widthPct}%`,
                    background: positive ? "var(--color-risk-high)" : "var(--color-accent)",
                    marginLeft: positive ? "0" : "auto",
                  }}
                />
              </div>
            </div>
            <span className="mono w-16 shrink-0 text-right" style={{ color: positive ? "var(--color-risk-high)" : "var(--color-accent)" }}>
              {positive ? "+" : ""}{c.contribution.toFixed(3)}
            </span>
          </div>
        );
      })}
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
