import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { StateBadge } from "../components/RiskBadge";
import { Cpu, Wifi, WifiOff } from "lucide-react";

export function Fleet() {
  const { data: devices, isLoading, error } = useQuery({
    queryKey: ["devices"],
    queryFn: api.devices,
    refetchInterval: 8000,
  });

  return (
    <div className="mx-auto max-w-7xl px-4 py-6">
      <div className="mb-5 flex items-baseline justify-between">
        <div>
          <h1 className="text-xl font-semibold">Fleet</h1>
          <p className="text-sm text-[var(--color-text-dim)]">
            Every enrolled device, its state, and whether it's currently drifting.
          </p>
        </div>
        {devices && (
          <span className="mono text-sm text-[var(--color-text-dim)]">{devices.length} devices</span>
        )}
      </div>

      {isLoading && <SkeletonGrid />}
      {error && <ErrorCard message={(error as Error).message} />}

      {devices && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {devices.map((d) => (
            <div
              key={d.device_id}
              className="group rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4 transition-colors hover:border-[var(--color-accent-dim)]"
            >
              <div className="mb-3 flex items-start justify-between">
                <div className="flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-[var(--color-text-dim)]" />
                  <span className="mono text-sm font-semibold">{d.device_id}</span>
                </div>
                {d.is_drifting ? (
                  <WifiOff className="h-4 w-4 text-[var(--color-risk-med)]" />
                ) : (
                  <Wifi className="h-4 w-4 text-[var(--color-accent)]" />
                )}
              </div>
              <div className="mb-3 text-xs text-[var(--color-text-dim)]">{d.device_type}</div>
              <div className="flex items-center justify-between">
                <StateBadge state={d.state} />
                <span className="mono text-xs text-[var(--color-text-dim)]">
                  crit {d.criticality.toFixed(2)}
                </span>
              </div>
              {d.is_drifting && (
                <div className="mt-3 rounded-md border border-[var(--color-risk-med)]/40 bg-[var(--color-risk-med)]/10 px-2 py-1 text-[11px] text-[var(--color-risk-med)]">
                  Drift detected — escalation suppressed for this device
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SkeletonGrid() {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
      {Array.from({ length: 8 }).map((_, i) => (
        <div key={i} className="h-28 animate-pulse rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]" />
      ))}
    </div>
  );
}

export function ErrorCard({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-[var(--color-risk-high)]/40 bg-[var(--color-risk-high)]/10 p-4 text-sm text-[var(--color-risk-high)]">
      <div className="font-semibold">Could not reach the API.</div>
      <div className="mono mt-1 text-xs opacity-80">{message}</div>
      <div className="mt-2 text-xs text-[var(--color-text-dim)]">
        Run the backend with <code className="mono">uvicorn argus.api.main:app</code> and seed demo data from the Control screen.
      </div>
    </div>
  );
}
