import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { ShieldCheck, ShieldQuestion, Terminal, WifiOff, SlidersHorizontal } from "lucide-react";

export function Fleet() {
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
  const isLoading = statusLoading || devicesLoading;
  const error = statusError ?? devicesError;

  return (
    <div className="mx-auto max-w-7xl px-4 py-6">
      <div className="mb-5 flex items-baseline justify-between">
        <div>
          <h1 className="text-xl font-semibold">Fleet — Live Network</h1>
          <p className="text-sm text-[var(--color-text-dim)]">
            Real devices discovered by a local ARGUS sensor on your actual LAN. Nothing here is fabricated,
            seeded, or simulated — every row came from a real sensor observation, or the page shows nothing.
          </p>
        </div>
        {devices && <span className="mono text-sm text-[var(--color-text-dim)]">{devices.length} device(s)</span>}
      </div>

      {isLoading && <SkeletonGrid />}
      {error && <ErrorCard message={(error as Error).message} />}

      {status && !anyConnected && (
        <div className="mb-5 flex items-start gap-2 rounded-xl border border-[var(--color-risk-med)]/40 bg-[var(--color-risk-med)]/10 p-4 text-sm text-[var(--color-risk-med)]">
          <WifiOff className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
          <div>
            <p className="font-semibold">No live network sensor connected.</p>
            <p className="mt-1 text-[var(--color-text-dim)]">
              ARGUS cannot see your LAN directly from this deployment — a local sensor has to run on your own
              Mac, Linux box, or Raspberry Pi and report to this API. Nothing below is fabricated to fill the
              gap; this page shows real data or nothing. See{" "}
              <Link to="/sensor" className="font-semibold text-[var(--color-accent)] underline">Sensor</Link> for
              connection details and setup.
            </p>
            <div className="mono mt-3 flex items-center gap-2 rounded-md bg-[var(--color-surface-2)] p-2 text-xs text-[var(--color-text)]">
              <Terminal className="h-3.5 w-3.5 flex-shrink-0" aria-hidden="true" />
              python -m sensor.agent --api-url &lt;this API's URL&gt; --token &lt;ARGUS_ADMIN_TOKEN&gt;
            </div>
          </div>
        </div>
      )}

      {status && anyConnected && devices && devices.length === 0 && (
        <div className="rounded-xl border border-dashed border-[var(--color-border)] p-8 text-center text-sm text-[var(--color-text-dim)]">
          A sensor is connected, but no devices discovered yet. No devices discovered — nothing fabricated to fill the gap.
        </div>
      )}

      {devices && devices.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-[var(--color-border)]">
          <table className="w-full min-w-[1100px] text-sm">
            <thead className="bg-[var(--color-surface-2)] text-left text-xs uppercase tracking-wide text-[var(--color-text-dim)]">
              <tr>
                <th className="px-4 py-2.5 font-medium">Device</th>
                <th className="px-4 py-2.5 font-medium">IP</th>
                <th className="px-4 py-2.5 font-medium">MAC / vendor</th>
                <th className="px-4 py-2.5 font-medium">Hostname</th>
                <th className="px-4 py-2.5 font-medium">Type</th>
                <th className="px-4 py-2.5 font-medium">Source</th>
                <th className="px-4 py-2.5 font-medium">First / last seen</th>
                <th className="px-4 py-2.5 font-medium">Flows</th>
                <th className="px-4 py-2.5 font-medium">IDS status</th>
                <th className="px-4 py-2.5 font-medium">Control</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.identifier} className="border-t border-[var(--color-border)] bg-[var(--color-surface)]">
                  <td className="mono px-4 py-2.5 text-xs">{d.identifier}</td>
                  <td className="mono px-4 py-2.5">{d.ip}</td>
                  <td className="px-4 py-2.5 text-xs">
                    {d.mac ? <span className="mono">{d.mac}</span> : <span className="text-[var(--color-text-dim)]">Not available</span>}
                    {d.vendor && <span className="ml-1.5 text-[var(--color-text-dim)]">({d.vendor})</span>}
                  </td>
                  <td className="px-4 py-2.5 text-xs">
                    {d.hostname ?? <span className="text-[var(--color-text-dim)]">Not available</span>}
                  </td>
                  <td className="px-4 py-2.5 text-xs">
                    {d.device_type === "unknown" ? (
                      <span className="text-[var(--color-text-dim)]">Unknown device</span>
                    ) : (
                      d.device_type
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-[10px] text-[var(--color-text-dim)]">
                    {d.discovery_sources.join(", ")}
                  </td>
                  <td className="mono px-4 py-2.5 text-xs text-[var(--color-text-dim)]">
                    {new Date(d.first_seen).toLocaleTimeString()} / {new Date(d.last_seen).toLocaleTimeString()}
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
                  <td className="px-4 py-2.5 text-xs">
                    {d.control_protocol ? (
                      <Link to="/device-control" className="inline-flex items-center gap-1 text-[var(--color-accent)] underline">
                        <SlidersHorizontal className="h-3.5 w-3.5" />
                        {d.authorized ? "authorized" : "supported, not authorized"}
                      </Link>
                    ) : (
                      <span className="text-[var(--color-text-dim)]">Not available</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
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
        Run the backend with <code className="mono">uvicorn argus.api.main:app</code> and connect a local sensor
        from the Sensor page.
      </div>
    </div>
  );
}
