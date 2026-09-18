import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useAdminToken } from "../lib/token";
import { AlertOctagon, Database, KeyRound, Power } from "lucide-react";
import { ErrorCard } from "./Fleet";

export function Control() {
  const { token, setToken } = useAdminToken();
  const [tokenInput, setTokenInput] = useState(token);
  const qc = useQueryClient();

  const { data: status } = useQuery({ queryKey: ["control-status"], queryFn: api.controlStatus, refetchInterval: 4000 });
  const { data: actions, error: actionsError } = useQuery({ queryKey: ["actions"], queryFn: api.actions, refetchInterval: 8000 });

  const seedMutation = useMutation({
    mutationFn: () => api.seedDemo(token),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["devices"] });
      qc.invalidateQueries({ queryKey: ["incidents"] });
      qc.invalidateQueries({ queryKey: ["actions"] });
    },
  });

  const killSwitchMutation = useMutation({
    mutationFn: (engage: boolean) => api.toggleKillSwitch(engage, token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["control-status"] }),
  });

  return (
    <div className="mx-auto max-w-4xl px-4 py-6">
      <div className="mb-5">
        <h1 className="text-xl font-semibold">Control</h1>
        <p className="text-sm text-[var(--color-text-dim)]">
          Enforcement mode, the kill switch, and active enforcement actions with time remaining.
        </p>
      </div>

      <section className="mb-6 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold">
          <KeyRound className="h-4 w-4" aria-hidden="true" /> Admin token
        </h2>
        <p className="mb-3 text-xs text-[var(--color-text-dim)]">
          Required for the kill switch and replay actions. Matches <code className="mono">ARGUS_ADMIN_TOKEN</code> in
          the backend's <code className="mono">.env</code>. Stored only in this browser's localStorage.
        </p>
        <div className="flex gap-2">
          <input
            type="password"
            value={tokenInput}
            onChange={(e) => setTokenInput(e.target.value)}
            placeholder="paste ARGUS_ADMIN_TOKEN"
            className="mono min-w-0 flex-1 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2 text-sm outline-none focus:border-[var(--color-accent-dim)]"
          />
          <button
            onClick={() => setToken(tokenInput)}
            className="rounded-md bg-[var(--color-surface-2)] px-4 py-2 text-sm font-medium hover:bg-[var(--color-border)]"
          >
            Save
          </button>
        </div>
      </section>

      <section className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold">
            <Power className="h-4 w-4" aria-hidden="true" /> Enforcement mode
          </h2>
          <p className="mono text-2xl font-bold" style={{ color: status?.enforce ? "var(--color-risk-high)" : "var(--color-accent)" }}>
            {status?.enforce ? "LIVE" : "DRY-RUN"}
          </p>
          <p className="mt-2 text-xs text-[var(--color-text-dim)]">
            Set by <code className="mono">ARGUS_ENFORCE</code> on the backend. Never toggled from the UI on purpose
            (docs/03: "do not remove these [safety defaults] to make a demo easier").
          </p>
        </div>

        <div className="rounded-xl border border-[var(--color-risk-critical)]/40 bg-[var(--color-surface)] p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-[var(--color-risk-critical)]">
            <AlertOctagon className="h-4 w-4" aria-hidden="true" /> Kill switch
          </h2>
          <p className="mono mb-3 text-sm">
            {status?.kill_switch_engaged ? "ENGAGED — all enforcement vetoed" : "disengaged"}
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => killSwitchMutation.mutate(true)}
              disabled={!token || killSwitchMutation.isPending}
              className="flex-1 rounded-md bg-[var(--color-risk-critical)] px-3 py-2 text-sm font-semibold text-black disabled:opacity-40"
            >
              Engage
            </button>
            <button
              onClick={() => killSwitchMutation.mutate(false)}
              disabled={!token || killSwitchMutation.isPending}
              className="flex-1 rounded-md border border-[var(--color-border)] px-3 py-2 text-sm font-semibold disabled:opacity-40"
            >
              Disengage
            </button>
          </div>
          {!token && <p className="mt-2 text-[11px] text-[var(--color-text-dim)]">Save an admin token above first.</p>}
        </div>
      </section>

      <section className="mb-6 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold">
          <Database className="h-4 w-4" aria-hidden="true" /> Demo data (synthetic testbed)
        </h2>
        <p className="mb-3 text-xs text-[var(--color-text-dim)]">
          Runs the full simulated loop (enrollment → attack scenarios → detect → correlate → risk → evidence →
          respond → verify) and persists it — this is what populates the Demo Fleet page and the synthetic-scenario
          rows on Incidents. Synthetic devices only, unrelated to the CICIoT2023 evaluation — see IDS Evaluation for
          the real dataset-derived results.
        </p>
        <button
          onClick={() => seedMutation.mutate()}
          disabled={!token || seedMutation.isPending}
          className="rounded-md bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-black disabled:opacity-40"
        >
          {seedMutation.isPending ? "Running pipeline…" : "Run demo pipeline"}
        </button>
        {seedMutation.data && (
          <p className="mono mt-2 text-xs text-[var(--color-accent)]">
            seeded {seedMutation.data.incidents} incidents, {seedMutation.data.bundles} evidence bundles,{" "}
            {seedMutation.data.actions} actions.
          </p>
        )}
      </section>

      <section className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
        <h2 className="mb-3 text-sm font-semibold">Active / recent actions</h2>
        {actionsError && <ErrorCard message={(actionsError as Error).message} />}
        {actions && actions.length === 0 && (
          <p className="text-xs text-[var(--color-text-dim)]">No actions yet — run the demo pipeline above.</p>
        )}
        {actions && actions.length > 0 && (
          <div className="space-y-2">
            {actions.map((a) => (
              <div key={a.action_id} className="mono flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md bg-[var(--color-surface-2)] px-3 py-2 text-xs">
                <span>{a.device_id}</span>
                <span className="text-[var(--color-text-dim)]">tier {a.tier}</span>
                <span>{a.action}</span>
                <span className={a.dry_run ? "text-[var(--color-accent)]" : "text-[var(--color-risk-high)]"}>
                  {a.dry_run ? "dry-run" : "LIVE"}
                </span>
                <span className="ml-auto text-[var(--color-text-dim)]">TTL {a.ttl_seconds}s</span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
