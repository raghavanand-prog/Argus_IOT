import { NavLink } from "react-router-dom";
import { Radar, ShieldAlert, FileSearch, SlidersHorizontal } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";

const links = [
  { to: "/", label: "Fleet", icon: Radar },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert },
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
      <div className="mx-auto flex max-w-7xl items-center gap-6 px-4 py-3">
        <div className="flex items-center gap-2">
          <FileSearch className="h-5 w-5 text-[var(--color-accent)]" aria-hidden="true" />
          <span className="text-lg font-semibold tracking-tight">ARGUS</span>
          <span className="hidden text-xs text-[var(--color-text-dim)] sm:inline">
            closed-loop IoT intrusion response
          </span>
        </div>
        <nav aria-label="Main" className="ml-4 flex items-center gap-1">
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                `flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--color-accent)] ${
                  isActive
                    ? "bg-[var(--color-surface-2)] text-[var(--color-accent)]"
                    : "text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
                }`
              }
            >
              <Icon className="h-4 w-4" aria-hidden="true" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-3" role="status" aria-live="polite">
          {status && (
            <span
              className={`mono rounded-full border px-2.5 py-1 text-xs font-semibold ${
                status.enforce
                  ? "border-[var(--color-risk-high)] text-[var(--color-risk-high)]"
                  : "border-[var(--color-accent-dim)] text-[var(--color-accent)]"
              }`}
            >
              {status.enforce ? "ENFORCEMENT LIVE" : "DRY-RUN"}
            </span>
          )}
          {status?.kill_switch_engaged && (
            <span className="mono rounded-full border border-[var(--color-risk-critical)] px-2.5 py-1 text-xs font-semibold text-[var(--color-risk-critical)]">
              KILL SWITCH ENGAGED
            </span>
          )}
        </div>
      </div>
    </header>
  );
}
