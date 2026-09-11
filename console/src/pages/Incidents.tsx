import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { api, type Incident } from "../lib/api";
import { RiskBadge, RiskBar } from "../components/RiskBadge";
import { ErrorCard } from "./Fleet";
import { X, PlayCircle, CheckCircle2, XCircle, Link2, ShieldCheck } from "lucide-react";
import { useAdminToken } from "../lib/token";

export function Incidents() {
  const { data: incidents, isLoading, error } = useQuery({
    queryKey: ["incidents"],
    queryFn: api.incidents,
    refetchInterval: 8000,
  });
  const [selected, setSelected] = useState<Incident | null>(null);

  return (
    <div className="mx-auto max-w-7xl px-4 py-6">
      <div className="mb-5">
        <h1 className="text-xl font-semibold">Incidents</h1>
        <p className="text-sm text-[var(--color-text-dim)]">
          Correlated detections, risk breakdown, decision trace, and enforcement outcome.
        </p>
      </div>

      {isLoading && <div className="text-sm text-[var(--color-text-dim)]">Loading…</div>}
      {error && <ErrorCard message={(error as Error).message} />}

      {incidents && (
        <div className="overflow-hidden rounded-xl border border-[var(--color-border)]">
          <table className="w-full text-sm">
            <thead className="bg-[var(--color-surface-2)] text-left text-xs uppercase tracking-wide text-[var(--color-text-dim)]">
              <tr>
                <th className="px-4 py-2.5 font-medium">Device</th>
                <th className="px-4 py-2.5 font-medium">Scenario</th>
                <th className="px-4 py-2.5 font-medium">Sources</th>
                <th className="px-4 py-2.5 font-medium">Risk</th>
                <th className="px-4 py-2.5 font-medium">Action</th>
                <th className="px-4 py-2.5 font-medium">Verification</th>
                <th className="px-4 py-2.5 font-medium">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((inc) => (
                <tr
                  key={inc.incident_id}
                  onClick={() => setSelected(inc)}
                  className="cursor-pointer border-t border-[var(--color-border)] bg-[var(--color-surface)] transition-colors hover:bg-[var(--color-surface-2)]"
                >
                  <td className="mono px-4 py-2.5">{inc.device_id}</td>
                  <td className="px-4 py-2.5 text-[var(--color-text-dim)]">{inc.scenario}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-1">
                      {inc.detection_sources.map((s) => (
                        <span key={s} className="mono rounded bg-[var(--color-surface-2)] px-1.5 py-0.5 text-[10px] text-[var(--color-text-dim)]">
                          {s}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-2.5"><RiskBadge score={inc.risk_score} /></td>
                  <td className="px-4 py-2.5">
                    <ActionPill action={inc.action} dryRun={inc.dry_run} />
                  </td>
                  <td className="px-4 py-2.5">
                    <VerificationPill outcome={inc.verification_outcome} />
                  </td>
                  <td className="mono px-4 py-2.5 text-xs text-[var(--color-text-dim)]">
                    {new Date(inc.last_seen).toLocaleTimeString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && <IncidentDrawer incident={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function ActionPill({ action, dryRun }: { action: string | null; dryRun: boolean | null }) {
  if (!action) return <span className="text-xs text-[var(--color-text-dim)]">—</span>;
  return (
    <span className="mono inline-flex items-center gap-1 rounded-md border border-[var(--color-border)] px-2 py-0.5 text-xs">
      {action}
      {dryRun && <span className="text-[var(--color-accent)]">(dry-run)</span>}
    </span>
  );
}

function VerificationPill({ outcome }: { outcome: string | null }) {
  if (!outcome) return <span className="text-xs text-[var(--color-text-dim)]">pending</span>;
  const map: Record<string, { color: string; icon: typeof CheckCircle2 }> = {
    contained: { color: "var(--color-risk-low)", icon: CheckCircle2 },
    partially_contained: { color: "var(--color-risk-med)", icon: PlayCircle },
    not_contained: { color: "var(--color-risk-high)", icon: XCircle },
    collateral_damage: { color: "var(--color-risk-critical)", icon: XCircle },
    inconclusive: { color: "var(--color-text-dim)", icon: PlayCircle },
  };
  const { color, icon: Icon } = map[outcome] ?? map.inconclusive;
  return (
    <span className="inline-flex items-center gap-1 text-xs" style={{ color }}>
      <Icon className="h-3.5 w-3.5" />
      {outcome.replace(/_/g, " ")}
    </span>
  );
}

function IncidentDrawer({ incident, onClose }: { incident: Incident; onClose: () => void }) {
  const { token } = useAdminToken();
  const { data: bundle } = useQuery({
    queryKey: ["evidence", incident.bundle_id],
    queryFn: () => api.evidence(incident.bundle_id!),
    enabled: !!incident.bundle_id,
  });
  const replayMutation = useMutation({
    mutationFn: () => api.replay(incident.bundle_id!, token),
  });

  return (
    <div className="fixed inset-0 z-30 flex justify-end bg-black/50" onClick={onClose}>
      <div
        className="h-full w-full max-w-xl overflow-y-auto border-l border-[var(--color-border)] bg-[var(--color-surface)] p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between">
          <div>
            <h2 className="mono text-lg font-semibold">{incident.device_id}</h2>
            <p className="text-xs text-[var(--color-text-dim)]">{incident.scenario} · {incident.chain_position}</p>
          </div>
          <button onClick={onClose} className="rounded-md p-1 text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)]">
            <X className="h-5 w-5" />
          </button>
        </div>

        {incident.risk_terms && (
          <section className="mb-5">
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
              Risk breakdown
            </h3>
            <RiskBar terms={incident.risk_terms} />
          </section>
        )}

        {bundle && (
          <>
            <section className="mb-5">
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
                Decision trace
              </h3>
              <ol className="space-y-1">
                {bundle.trace.map((step, i) => (
                  <li key={i} className="mono flex gap-2 text-xs text-[var(--color-text-dim)]">
                    <span className="text-[var(--color-accent)]">{i + 1}.</span>
                    {step}
                  </li>
                ))}
              </ol>
              {bundle.decision.gates_failed.length > 0 && (
                <div className="mt-2 rounded-md border border-[var(--color-risk-high)]/40 bg-[var(--color-risk-high)]/10 p-2 text-xs text-[var(--color-risk-high)]">
                  Gates failed: {bundle.decision.gates_failed.join(", ")}
                </div>
              )}
            </section>

            <section className="mb-5">
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
                Explanation
              </h3>
              <div className="space-y-1.5">
                {((bundle.detection.explanations as string[]) ?? []).slice(0, 4).map((e, i) => (
                  <p key={i} className="rounded-md bg-[var(--color-surface-2)] p-2 text-xs text-[var(--color-text-dim)]">
                    {e}
                  </p>
                ))}
              </div>
            </section>

            <section className="mb-5">
              <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
                <Link2 className="h-3.5 w-3.5" /> Evidence bundle
              </h3>
              <div className="mono space-y-1 rounded-md bg-[var(--color-surface-2)] p-3 text-[11px] text-[var(--color-text-dim)]">
                <div>bundle_id: {bundle.bundle_id}</div>
                <div>merkle_root: {bundle.merkle_root.slice(0, 24)}…</div>
                <div>prev_hash: {bundle.prev_bundle_hash === "genesis" ? "genesis" : bundle.prev_bundle_hash.slice(0, 24) + "…"}</div>
              </div>
            </section>

            <button
              onClick={() => replayMutation.mutate()}
              disabled={replayMutation.isPending}
              className="flex w-full items-center justify-center gap-2 rounded-md bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-black transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              <ShieldCheck className="h-4 w-4" />
              {replayMutation.isPending ? "Replaying…" : "Replay decision"}
            </button>

            {replayMutation.data && (
              <div
                className={`mono mt-3 rounded-md border p-3 text-xs ${
                  replayMutation.data.reproduced
                    ? "border-[var(--color-accent-dim)] text-[var(--color-accent)]"
                    : "border-[var(--color-risk-high)]/40 text-[var(--color-risk-high)]"
                }`}
              >
                {replayMutation.data.reproduced ? "✓ Reproduced identically" : "✗ Mismatch"} — original:{" "}
                {replayMutation.data.original_action} (tier {replayMutation.data.original_tier}), replayed:{" "}
                {replayMutation.data.replayed_action} (tier {replayMutation.data.replayed_tier})
              </div>
            )}
            {replayMutation.isError && (
              <div className="mt-3 rounded-md border border-[var(--color-risk-high)]/40 p-3 text-xs text-[var(--color-risk-high)]">
                {(replayMutation.error as Error).message}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
