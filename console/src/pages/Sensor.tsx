import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorCard } from "./Fleet";
import { Radio, RadioTower, WifiOff, Terminal } from "lucide-react";

export function Sensor() {
  const { data: status, isLoading, error } = useQuery({
    queryKey: ["live-status"],
    queryFn: api.liveStatus,
    refetchInterval: 5000,
  });

  const anyConnected = !!status?.any_connected;

  return (
    <div className="mx-auto max-w-4xl px-4 py-6">
      <div className="mb-5">
        <h1 className="text-xl font-semibold">Local Sensor Connection</h1>
        <p className="text-sm text-[var(--color-text-dim)]">
          Vercel cannot directly access your private LAN — a small local agent runs on your own Mac, Linux box,
          or Raspberry Pi and reports here over HTTPS. This page shows whether one is actually connected right now.
        </p>
      </div>

      {isLoading && <div className="text-sm text-[var(--color-text-dim)]">Loading…</div>}
      {error && <ErrorCard message={(error as Error).message} />}

      {status && (
        <div className="space-y-4">
          {anyConnected ? (
            <div className="flex items-start gap-2 rounded-xl border border-[var(--color-accent-dim)] bg-[var(--color-accent)]/10 p-4 text-sm text-[var(--color-accent)]">
              <RadioTower className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
              <div>
                <p className="font-semibold">Local sensor connected.</p>
                <p className="mt-1 text-[var(--color-text-dim)]">
                  A sensor has POSTed to this ARGUS API within the last 90 seconds.
                </p>
              </div>
            </div>
          ) : (
            <div className="flex items-start gap-2 rounded-xl border border-[var(--color-risk-med)]/40 bg-[var(--color-risk-med)]/10 p-4 text-sm text-[var(--color-risk-med)]">
              <WifiOff className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
              <div>
                <p className="font-semibold">No live network sensor connected.</p>
                <p className="mt-1 text-[var(--color-text-dim)]">
                  Run the sensor on a machine actually connected to your LAN.
                </p>
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
          {status.note && <p className="text-xs text-[var(--color-text-dim)]">{status.note}</p>}
        </div>
      )}

      <section className="mt-6 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold">
          <Terminal className="h-4 w-4" aria-hidden="true" /> Run the sensor
        </h2>
        <div className="space-y-2 text-xs">
          <p className="text-[var(--color-text-dim)]">Discovery only (safe default, no extra dependencies):</p>
          <pre className="mono overflow-x-auto rounded-md bg-[var(--color-surface-2)] p-2">
            python -m sensor.agent --api-url https://argus-iot-live.vercel.app/api --token $ARGUS_ADMIN_TOKEN
          </pre>
          <p className="mt-3 text-[var(--color-text-dim)]">
            Real packet capture + detection (needs <code className="mono">pip install -e ".[live-testbed]"</code>):
          </p>
          <pre className="mono overflow-x-auto rounded-md bg-[var(--color-surface-2)] p-2">
            python -m sensor.agent --api-url https://argus-iot-live.vercel.app/api --token $ARGUS_ADMIN_TOKEN \
            --enable-capture --interfaces en0 --target-host &lt;a device IP you own&gt;
          </pre>
          <p className="mt-3 text-[var(--color-text-dim)]">
            Device control (see the <span className="font-semibold">Device Control</span> page):
          </p>
          <pre className="mono overflow-x-auto rounded-md bg-[var(--color-surface-2)] p-2">
            python -m sensor.agent --api-url https://argus-iot-live.vercel.app/api --token $ARGUS_ADMIN_TOKEN --enable-control
          </pre>
        </div>
      </section>
    </div>
  );
}
