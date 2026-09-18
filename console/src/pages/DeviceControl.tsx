import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type LiveDevice } from "../lib/api";
import { useAdminToken } from "../lib/token";
import { ErrorCard } from "./Fleet";
import {
  Power, PowerOff, Volume2, VolumeX, RefreshCw, KeyRound, ShieldAlert, Info, Clock,
} from "lucide-react";

const ACTION_LABELS: Record<string, { label: string; icon: typeof Power; disruptive: boolean }> = {
  get_status: { label: "Refresh status", icon: RefreshCw, disruptive: false },
  power_on: { label: "Power on", icon: Power, disruptive: true },
  power_off: { label: "Power off", icon: PowerOff, disruptive: true },
  mute_on: { label: "Mute", icon: VolumeX, disruptive: true },
  mute_off: { label: "Unmute", icon: Volume2, disruptive: true },
};

export function DeviceControl() {
  const { token } = useAdminToken();
  const qc = useQueryClient();
  const [confirming, setConfirming] = useState<{ device: LiveDevice; action: string } | null>(null);
  const [justQueued, setJustQueued] = useState<Record<string, string>>({});

  const { data: devices, isLoading: devicesLoading, error: devicesError } = useQuery({
    queryKey: ["live-devices"],
    queryFn: api.liveDevices,
    refetchInterval: 5000,
  });
  const { data: audit, error: auditError } = useQuery({
    queryKey: ["control-audit"],
    queryFn: api.controlAudit,
    refetchInterval: 5000,
  });

  const queueMutation = useMutation({
    mutationFn: ({ device, action }: { device: LiveDevice; action: string }) =>
      api.queueControlCommand(device.sensor_id, device.identifier, action, token),
    onSuccess: (_result, { device, action }) => {
      setJustQueued((prev) => ({ ...prev, [device.identifier]: action }));
      qc.invalidateQueries({ queryKey: ["control-audit"] });
    },
  });

  const controllable = (devices ?? []).filter((d) => d.control_protocol);

  function runAction(device: LiveDevice, action: string) {
    const meta = ACTION_LABELS[action];
    if (meta?.disruptive) {
      setConfirming({ device, action });
      return;
    }
    queueMutation.mutate({ device, action });
  }

  return (
    <div className="mx-auto max-w-5xl px-4 py-6">
      <div className="mb-5">
        <h1 className="text-xl font-semibold">Device Control</h1>
        <p className="text-sm text-[var(--color-text-dim)]">
          Authorized devices with a real, detected, documented control protocol. ARGUS never assumes a
          discovered device is controllable — only devices your local sensor has actually probed, found a
          supported protocol for, and you've explicitly authorized appear with controls below.
        </p>
      </div>

      <div className="mb-6 flex items-start gap-2 rounded-xl border border-[var(--color-accent-dim)] bg-[var(--color-accent)]/10 p-4 text-sm text-[var(--color-accent)]">
        <Info className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
        <div>
          <p className="font-semibold">How actions actually happen (this matters)</p>
          <p className="mt-1 text-[var(--color-text-dim)]">
            Vercel cannot reach your LAN directly (docs/18/19). Clicking a button below <em>queues a request</em> —
            it does not execute anything itself. Your local sensor, running with{" "}
            <code className="mono">--enable-control</code>, picks it up on its next poll (every ~30s), re-checks
            authorization against <em>its own local file</em> — never trusting this cloud page's word — and only
            then actually sends the command. A stolen admin token alone can never make a device do anything; it
            still has to be authorized on the machine running the sensor.
          </p>
        </div>
      </div>

      <div className="mb-6 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 text-xs">
        <h2 className="mb-2 flex items-center gap-2 text-sm font-semibold">
          <KeyRound className="h-4 w-4" aria-hidden="true" /> Authorizing a device (done locally, not here)
        </h2>
        <p className="mb-2 text-[var(--color-text-dim)]">
          This console never authorizes a device — that decision is made on the machine running your sensor,
          which is the only one with real access to it:
        </p>
        <pre className="mono overflow-x-auto rounded-md bg-[var(--color-surface-2)] p-2">
          python -m sensor.control_cli discover-capability &lt;device IP&gt;{"\n"}
          python -m sensor.control_cli authorize &lt;device IP&gt;
        </pre>
      </div>

      {devicesLoading && <div className="text-sm text-[var(--color-text-dim)]">Loading…</div>}
      {devicesError && <ErrorCard message={(devicesError as Error).message} />}

      {devices && controllable.length === 0 && (
        <div className="mb-6 rounded-xl border border-dashed border-[var(--color-border)] p-8 text-center text-sm text-[var(--color-text-dim)]">
          No devices with a detected, supported control protocol yet. Probe a device with{" "}
          <code className="mono">sensor.control_cli discover-capability</code> from the machine running your
          sensor.
        </div>
      )}

      {controllable.length > 0 && (
        <div className="mb-8 space-y-3">
          {controllable.map((d) => (
            <div key={d.identifier} className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="mono text-sm font-semibold">{d.hostname ?? d.identifier}</div>
                  <div className="mono text-xs text-[var(--color-text-dim)]">
                    {d.ip} · {d.control_protocol} · {d.vendor ?? "Unknown vendor"}
                  </div>
                </div>
                {d.authorized ? (
                  <span className="mono rounded-full border border-[var(--color-accent-dim)] px-2.5 py-1 text-[10px] font-semibold text-[var(--color-accent)]">
                    AUTHORIZED FOR CONTROL
                  </span>
                ) : (
                  <span className="mono flex items-center gap-1 rounded-full border border-[var(--color-risk-med)]/40 px-2.5 py-1 text-[10px] font-semibold text-[var(--color-risk-med)]">
                    <ShieldAlert className="h-3 w-3" /> DISCOVERED, NOT AUTHORIZED
                  </span>
                )}
              </div>

              {d.authorized ? (
                <div className="flex flex-wrap gap-2">
                  {d.control_capabilities.map((cap) => {
                    const actionsForCap: string[] =
                      cap === "power" ? ["power_on", "power_off"]
                      : cap === "mute" ? ["mute_on", "mute_off"]
                      : cap === "status" ? ["get_status"]
                      : [];
                    return actionsForCap.map((action) => {
                      const meta = ACTION_LABELS[action];
                      if (!meta) return null;
                      const Icon = meta.icon;
                      return (
                        <button
                          key={action}
                          onClick={() => runAction(d, action)}
                          disabled={!token || queueMutation.isPending}
                          className="flex items-center gap-1.5 rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium hover:border-[var(--color-accent-dim)] disabled:opacity-40"
                        >
                          <Icon className="h-3.5 w-3.5" /> {meta.label}
                        </button>
                      );
                    });
                  })}
                </div>
              ) : (
                <p className="text-xs text-[var(--color-text-dim)]">
                  Not authorized on the machine running the sensor — run{" "}
                  <code className="mono">sensor.control_cli authorize {d.ip}</code> there first.
                </p>
              )}
              {!token && (
                <p className="mt-2 text-[11px] text-[var(--color-text-dim)]">Save an admin token on the Control page first.</p>
              )}
              {justQueued[d.identifier] && (
                <p className="mono mt-2 flex items-center gap-1 text-[11px] text-[var(--color-accent)]">
                  <Clock className="h-3 w-3" /> Queued {justQueued[d.identifier]} — waiting for the sensor's next poll to fulfil it.
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      <section className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
        <h2 className="mb-3 text-sm font-semibold">Control audit log</h2>
        {auditError && <ErrorCard message={(auditError as Error).message} />}
        {audit && audit.length === 0 && (
          <p className="text-xs text-[var(--color-text-dim)]">No control actions recorded yet.</p>
        )}
        {audit && audit.length > 0 && (
          <div className="space-y-1.5">
            {audit.map((e, i) => (
              <div key={i} className="mono flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md bg-[var(--color-surface-2)] px-3 py-2 text-[11px]">
                <span className="text-[var(--color-text-dim)]">{new Date(e.ts).toLocaleString()}</span>
                <span>{e.device_identifier}</span>
                <span className="text-[var(--color-text-dim)]">{e.device_ip}</span>
                <span>{e.action}</span>
                <span className="text-[var(--color-text-dim)]">{e.protocol}</span>
                <span
                  className={
                    e.result === "SUCCESS" ? "text-[var(--color-accent)]"
                    : e.result === "DENIED" ? "text-[var(--color-risk-med)]"
                    : "text-[var(--color-risk-high)]"
                  }
                >
                  {e.result}
                </span>
                <span className="ml-auto text-[var(--color-text-dim)]">{e.authorization_state}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      {confirming && (
        <div className="fixed inset-0 z-30 flex items-center justify-center bg-black/50" onClick={() => setConfirming(null)}>
          <div
            role="dialog"
            aria-modal="true"
            className="w-full max-w-sm rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5"
            onClick={(e) => e.stopPropagation()}
          >
            <p className="mb-3 text-sm">
              You are about to send <span className="font-semibold">{ACTION_LABELS[confirming.action]?.label}</span> to:
            </p>
            <div className="mono mb-4 space-y-0.5 rounded-md bg-[var(--color-surface-2)] p-3 text-xs">
              <div>{confirming.device.hostname ?? confirming.device.identifier}</div>
              <div className="text-[var(--color-text-dim)]">{confirming.device.ip}</div>
            </div>
            <p className="mb-4 text-xs text-[var(--color-text-dim)]">
              This device is authorized for control. The sensor will re-verify locally before acting.
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setConfirming(null)}
                className="flex-1 rounded-md border border-[var(--color-border)] px-3 py-2 text-sm font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  queueMutation.mutate({ device: confirming.device, action: confirming.action });
                  setConfirming(null);
                }}
                className="flex-1 rounded-md bg-[var(--color-risk-high)] px-3 py-2 text-sm font-semibold text-black"
              >
                Confirm {ACTION_LABELS[confirming.action]?.label}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
