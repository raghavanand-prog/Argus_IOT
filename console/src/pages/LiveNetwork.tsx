import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorCard } from "./Fleet";
import { Radio, RadioTower, WifiOff, ShieldCheck, ShieldQuestion, Terminal } from "lucide-react";

export function LiveNetwork() {
  const { data: status, isLoading: statusLoading, error: statusError } = useQuery({
    queryKey: ["live-status"],
    queryFn: api.liveStatus,
    refetchInterval: 5000,
  });
  const { data: devices, isLoading: devicesLoading, error: devicesError } = useQuery({
    queryKey: ["live-devices"],
    queryFn: api.liveDevices,
    refetchInterval: 5000,
  });

  const anyConnected = !!status?.any_connected;

  return (
    <div className="mx-auto max-w-7xl px-4 py-6">
      <div className="mb-5 flex items-baseline justify-between">
        <div>
          <h1 className="text-xl font-semibold">Live Network</h1>
          <p className="text-sm text-[var(--color-text-dim)]">
            Real devices discovered by a local ARGUS sensor on your actual LAN — passive ARP/neighbour-table
            observation only, nothing fabricated. No sensor connected means no data, not a fallback demo.
          </p>
        </div>
        {devices && (
          <span className="mono text-sm text-[var(--color-text-dim)]">{devices.length} device(s)</span>
        )}
      </div>

      {(statusLoading || devicesLoading) && (
        <div className="text-sm text-[var(--color-text-dim)]">Loading…</div>
      )}
      {(statusError || devicesError) && (
        <ErrorCard message={((statusError ?? devicesError) as Error).message} />
      )}

      {status && (
        <div className="mb-5 space-y-3">
          {anyConnected ? (
            <div className="flex items-start gap-2 rounded-xl border border-[var(--color-accent-dim)] bg-[var(--color-accent)]/10 p-4 text-sm text-[var(--color-accent)]">
              <RadioTower className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
              <div>
                <p className="font-semibold">Local sensor connected.</p>
                <p className="mt-1 text-[var(--color-text-dim)]">
                  Real device discovery and detection data below came from a sensor running on your own network
                  (<code className="mono">python -m sensor.agent</code>) that has POSTed to this ARGUS API within
                  the last 90 seconds.
                </p>
              </div>
            </div>
          ) : (
            <div className="flex items-start gap-2 rounded-xl border border-[var(--color-risk-med)]/40 bg-[var(--color-risk-med)]/10 p-4 text-sm text-[var(--color-risk-med)]">
              <WifiOff className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
              <div>
                <p className="font-semibold">No live network sensor connected.</p>
                <p className="mt-1 text-[var(--color-text-dim)]">
                  ARGUS cannot see your LAN directly from this deployment — a local sensor has to run on your own
                  Mac, Linux box, or Raspberry Pi and report to this API. Nothing below is fabricated to fill the
                  gap; this page shows real data or nothing.
                </p>
                <div className="mono mt-3 flex items-center gap-2 rounded-md bg-[var(--color-surface-2)] p-2 text-xs text-[var(--color-text)]">
                  <Terminal className="h-3.5 w-3.5 flex-shrink-0" aria-hidden="true" />
                  python -m sensor.agent --api-url &lt;this API's URL&gt; --token &lt;ARGUS_ADMIN_TOKEN&gt;
                </div>
              </div>
            </div>
          )}

          {status.sensors.length > 0 && (
            <div className="overflow-x-auto rounded-xl border border-[var(--color-border)]">
              <table className="w-full min-w-[600px] text-sm">
                <thead className="bg-[var(--color-surface-2)] text-left text-xs uppercase tracking-wide text-[var(--color-text-dim)]">
                  <tr>
                    <th className="px-4 py-2.5 font-medium">Sensor</th>
                    <th className="px-4 py-2.5 font-medium">Host</th>
                    <th className="px-4 py-2.5 font-medium">Status</th>
                    <th className="px-4 py-2.5 font-medium">Monitoring</th>
                    <th className="px-4 py-2.5 font-medium">Devices discovered</th>
                    <th className="px-4 py-2.5 font-medium">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {status.sensors.map((s) => (
                    <tr key={s.sensor_id} className="border-t border-[var(--color-border)] bg-[var(--color-surface)]">
                      <td className="mono px-4 py-2.5">{s.sensor_id}</td>
                      <td className="mono px-4 py-2.5 text-[var(--color-text-dim)]">{s.hostname}</td>
                      <td className="px-4 py-2.5">
                        {s.connected ? (
                          <span className="inline-flex items-center gap-1 text-xs text-[var(--color-accent)]">
                            <Radio className="h-3.5 w-3.5" /> connected
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs text-[var(--color-text-dim)]">
                            <WifiOff className="h-3.5 w-3.5" /> stale / disconnected
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2.5">
                        {s.monitoring_active ? (
                          <span className="text-xs text-[var(--color-accent)]">capture enabled</span>
                        ) : (
                          <span className="text-xs text-[var(--color-text-dim)]">discovery only</span>
                        )}
                      </td>
                      <td className="mono px-4 py-2.5">{s.devices_discovered}</td>
                      <td className="mono px-4 py-2.5 text-xs text-[var(--color-text-dim)]">
                        {new Date(s.last_seen).toLocaleTimeString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {status.note && (
            <p className="text-xs text-[var(--color-text-dim)]">{status.note}</p>
          )}
        </div>
      )}

      {devices && devices.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-[var(--color-border)]">
          <table className="w-full min-w-[900px] text-sm">
            <thead className="bg-[var(--color-surface-2)] text-left text-xs uppercase tracking-wide text-[var(--color-text-dim)]">
              <tr>
                <th className="px-4 py-2.5 font-medium">Device</th>
                <th className="px-4 py-2.5 font-medium">IP</th>
                <th className="px-4 py-2.5 font-medium">MAC / vendor</th>
                <th className="px-4 py-2.5 font-medium">Type</th>
                <th className="px-4 py-2.5 font-medium">Interface</th>
                <th className="px-4 py-2.5 font-medium">First seen</th>
                <th className="px-4 py-2.5 font-medium">Last seen</th>
                <th className="px-4 py-2.5 font-medium">Flows</th>
                <th className="px-4 py-2.5 font-medium">Detection</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.identifier} className="border-t border-[var(--color-border)] bg-[var(--color-surface)]">
                  <td className="mono px-4 py-2.5 text-xs">{d.identifier}</td>
                  <td className="mono px-4 py-2.5">{d.ip}</td>
                  <td className="px-4 py-2.5 text-xs">
                    {d.mac ? (
                      <span className="mono">{d.mac}</span>
                    ) : (
                      <span className="text-[var(--color-text-dim)]">unresolved</span>
                    )}
                    {d.vendor && <span className="ml-1.5 text-[var(--color-text-dim)]">({d.vendor})</span>}
                  </td>
                  <td className="px-4 py-2.5 text-xs">
                    {d.device_type === "unknown" ? (
                      <span className="text-[var(--color-text-dim)]">Unknown device</span>
                    ) : (
                      d.device_type
                    )}
                  </td>
                  <td className="mono px-4 py-2.5 text-xs text-[var(--color-text-dim)]">{d.interface ?? "—"}</td>
                  <td className="mono px-4 py-2.5 text-xs text-[var(--color-text-dim)]">
                    {new Date(d.first_seen).toLocaleTimeString()}
                  </td>
                  <td className="mono px-4 py-2.5 text-xs text-[var(--color-text-dim)]">
                    {new Date(d.last_seen).toLocaleTimeString()}
                  </td>
                  <td className="mono px-4 py-2.5">{d.flow_count}</td>
                  <td className="px-4 py-2.5">
                    {d.monitored ? (
                      <span className="inline-flex items-center gap-1 text-xs text-[var(--color-accent)]">
                        <ShieldCheck className="h-3.5 w-3.5" /> baseline fitted
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-xs text-[var(--color-text-dim)]">
                        <ShieldQuestion className="h-3.5 w-3.5" /> learning baseline
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {status && !anyConnected && devices && devices.length === 0 && (
        <div className="rounded-xl border border-dashed border-[var(--color-border)] p-8 text-center text-sm text-[var(--color-text-dim)]">
          No live network sensor connected. Nothing to show — this is expected, not an error.
        </div>
      )}
    </div>
  );
}
