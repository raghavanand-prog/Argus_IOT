import { NavLink, useLocation } from "react-router-dom";
import { Radar, ShieldAlert, FileSearch, SlidersHorizontal, FlaskConical, Radio } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";

const secondaryLinks = [
  { to: "/incidents", label: "Incidents", icon: ShieldAlert },
  { to: "/fleet", label: "Demo Fleet (Synthetic)", icon: Radar },
  { to: "/control", label: "Control", icon: SlidersHorizontal },
];

export function Nav() {
  const location = useLocation();
  const { data: status } = useQuery({
    queryKey: ["control-status"],
    queryFn: api.controlStatus,
    refetchInterval: 5000,
  });
  const { data: liveStatus } = useQuery({
    queryKey: ["live-status"],
    queryFn: api.liveStatus,
    refetchInterval: 10000,
  });

  const inLiveMode = location.pathname === "/live";

  return (
    <header className="sticky top-0 z-20 border-b border-[var(--color-border)] bg-[var(--color-surface)]/95 backdrop-blur">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-3 gap-y-2 px-4 pt-3 sm:gap-x-6">
        <div className="flex items-center gap-2">
          <FileSearch className="h-5 w-5 text-[var(--color-accent)]" aria-hidden="true" />
          <span className="text-lg font-semibold tracking-tight">ARGUS</span>
          <span className="hidden text-xs text-[var(--color-text-dim)] sm:inline">
            closed-loop IoT intrusion response
          </span>
        </div>
        <div className="ml-auto flex items-center gap-2 sm:gap-3" role="status" aria-live="polite">
          {status && (
            <span
              className={`mono whitespace-nowrap rounded-full border px-2 py-1 text-[10px] font-semibold sm:px-2.5 sm:text-xs ${
                status.enforce
                  ? "border-[var(--color-risk-high)] text-[var(--color-risk-high)]"
                  : "border-[var(--color-accent-dim)] text-[var(--color-accent)]"
              }`}
            >
              {status.enforce ? "ENFORCEMENT LIVE" : "DRY-RUN"}
            </span>
          )}
          {status?.kill_switch_engaged && (
            <span className="mono whitespace-nowrap rounded-full border border-[var(--color-risk-critical)] px-2 py-1 text-[10px] font-semibold text-[var(--color-risk-critical)] sm:px-2.5 sm:text-xs">
              KILL SWITCH ENGAGED
            </span>
          )}
        </div>
      </div>

      {/* Mode selector: BENCHMARK (labelled/CICIoT2023 evaluation) vs LIVE NETWORK
          (real sensor-reported devices/traffic). Deliberately the most visually
          prominent thing in the header -- these two tracks must never be
          confused with each other. */}
      <div className="mx-auto max-w-7xl px-4 pt-3">
        <nav aria-label="Data mode" className="grid grid-cols-2 gap-2">
          <NavLink
            to="/"
            aria-label="Benchmark Evaluation mode: real labelled CICIoT2023 dataset evaluation"
            className={`flex items-center justify-center gap-2 rounded-lg border-2 px-3 py-2.5 text-sm font-bold uppercase tracking-wide transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--color-accent)] ${
              !inLiveMode
                ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                : "border-[var(--color-border)] text-[var(--color-text-dim)] hover:border-[var(--color-accent-dim)] hover:text-[var(--color-text)]"
            }`}
          >
            <FlaskConical className="h-4 w-4" aria-hidden="true" />
            Benchmark Evaluation
          </NavLink>
          <NavLink
            to="/live"
            aria-label="Live Network mode: real devices and traffic from your connected local sensor"
            className={`flex items-center justify-center gap-2 rounded-lg border-2 px-3 py-2.5 text-sm font-bold uppercase tracking-wide transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--color-accent)] ${
              inLiveMode
                ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                : "border-[var(--color-border)] text-[var(--color-text-dim)] hover:border-[var(--color-accent-dim)] hover:text-[var(--color-text)]"
            }`}
          >
            <Radio className="h-4 w-4" aria-hidden="true" />
            Live Network
            <span
              className={`mono ml-1 h-2 w-2 rounded-full ${
                liveStatus?.any_connected ? "bg-[var(--color-accent)]" : "bg-[var(--color-text-dim)]"
              }`}
              aria-label={liveStatus?.any_connected ? "sensor connected" : "no sensor connected"}
              role="img"
            />
          </NavLink>
        </nav>
        <p className="mt-1.5 text-center text-[11px] text-[var(--color-text-dim)]">
          {inLiveMode
            ? "Live Network: real LAN devices/traffic from your connected local sensor. No labelled ground truth — detections, not scored accuracy."
            : "Benchmark Evaluation: real labelled CICIoT2023 dataset — prediction vs. ground truth, real TP/TN/FP/FN metrics."}
        </p>
      </div>

      <div className="mx-auto max-w-7xl px-4 pb-3 pt-2">
        <nav aria-label="Secondary" className="flex items-center gap-1">
          {secondaryLinks.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              aria-label={label}
              className={({ isActive }) =>
                `flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-sm font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--color-accent)] ${
                  isActive
                    ? "bg-[var(--color-surface-2)] text-[var(--color-accent)]"
                    : "text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
                }`
              }
            >
              <Icon className="h-4 w-4" aria-hidden="true" />
              <span className="hidden sm:inline">{label}</span>
            </NavLink>
          ))}
        </nav>
      </div>
    </header>
  );
}
