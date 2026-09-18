import { NavLink } from "react-router-dom";
import { Radar, ShieldAlert, FileSearch, SlidersHorizontal, FlaskConical } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";

const links = [
  { to: "/", label: "Fleet", icon: Radar },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert },
  { to: "/ids-evaluation", label: "IDS Evaluation", icon: FlaskConical },
  { to: "/control", label: "Control", icon: SlidersHorizontal },
];

export function Nav() {
  const { data: status } = useQuery({
    queryKey: ["control-status"],
    queryFn: api.controlStatus,
    refetchInterval: 5000,
  });

  return (
    <header className="sticky top-0 z-20 border-b border-[var(--color-border)] bg-[var(--color-surface)]/95 backdrop-blur">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-3 gap-y-2 px-4 py-3 sm:gap-x-6">
        <div className="flex items-center gap-2">
          <FileSearch className="h-5 w-5 text-[var(--color-accent)]" aria-hidden="true" />
          <span className="text-lg font-semibold tracking-tight">ARGUS</span>
          <span className="hidden text-xs text-[var(--color-text-dim)] sm:inline">
            closed-loop IoT intrusion response
          </span>
        </div>
        <nav aria-label="Main" className="flex items-center gap-1 sm:ml-4">
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
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
    </header>
  );
}
