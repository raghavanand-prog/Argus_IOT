import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type CicioTEvalSummary, type CicioTRecord, type CicioTConfusionMatrix, type CicioTMetrics } from "../lib/api";
import { useAdminToken } from "../lib/token";
import { ErrorCard } from "./Fleet";
import {
  FlaskConical, X, CheckCircle2, XCircle, AlertTriangle, ShieldQuestion,
  Database, RefreshCw, ListChecks,
} from "lucide-react";

const PAGE_SIZE = 25;

export function IdsEvaluation() {
  const { token } = useAdminToken();
  const qc = useQueryClient();
  const [selected, setSelected] = useState<CicioTRecord | null>(null);
  const [filter, setFilter] = useState<"all" | "TP" | "TN" | "FP" | "FN">("all");
  const [page, setPage] = useState(0);

  const { data: summary, isLoading, error } = useQuery({
    queryKey: ["cicioT2023-eval-summary"],
    queryFn: api.cicioTEvalSummary,
    retry: false,
  });
  const { data: records, error: recordsError } = useQuery({
    queryKey: ["cicioT2023-eval-records"],
    queryFn: api.cicioTEvalRecords,
    enabled: !!summary,
    retry: false,
  });

  const runMutation = useMutation({
    mutationFn: () => api.runCicioTEval(token),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cicioT2023-eval-summary"] });
      qc.invalidateQueries({ queryKey: ["cicioT2023-eval-records"] });
      qc.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  const filtered = useMemo(() => {
    if (!records) return [];
    return filter === "all" ? records : records.filter((r) => r.outcome === filter);
  }, [records, filter]);
  const pageRows = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));

  return (
    <div className="mx-auto max-w-7xl px-4 py-6">
      <div className="mb-5">
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <FlaskConical className="h-5 w-5 text-[var(--color-accent)]" aria-hidden="true" />
          Benchmark Evaluation
        </h1>
        <p className="text-sm text-[var(--color-text-dim)]">
          Real detections from ARGUS's actual detection pipeline against the labelled CICIoT2023 benchmark
          dataset — real prediction vs. ground truth, real TP/TN/FP/FN metrics. Not simulated telemetry, not a
          hardcoded result, and not live network traffic (see Live Network mode for that — real LAN data has no
          labelled ground truth to score against).
        </p>
      </div>

      {isLoading && <div className="text-sm text-[var(--color-text-dim)]">Loading…</div>}

      {error && (
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
          <p className="mb-3 text-sm text-[var(--color-text-dim)]">
            No CICIoT2023 evaluation has been run in this backend yet.
          </p>
          {token ? (
            <button
              onClick={() => runMutation.mutate()}
              disabled={runMutation.isPending}
              className="rounded-md bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-black disabled:opacity-40"
            >
              {runMutation.isPending ? "Running real evaluation…" : "Run CICIoT2023 evaluation"}
            </button>
          ) : (
            <ErrorCard message={(error as Error).message} />
          )}
        </div>
      )}

      {summary && (
        <>
          <DatasetPanel summary={summary} onRerun={() => runMutation.mutate()} rerunPending={runMutation.isPending} token={token} />
          <MetricsPanel summary={summary} />

          <section className="mb-6 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <h2 className="flex items-center gap-2 text-sm font-semibold">
                <ListChecks className="h-4 w-4" aria-hidden="true" /> Individual detections
              </h2>
              <div className="flex gap-1 text-xs">
                {(["all", "TP", "TN", "FP", "FN"] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => { setFilter(f); setPage(0); }}
                    className={`rounded-md px-2.5 py-1 font-medium ${
                      filter === f
                        ? "bg-[var(--color-accent)] text-black"
                        : "bg-[var(--color-surface-2)] text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
                    }`}
                  >
                    {f === "all" ? "All" : f}
                  </button>
                ))}
              </div>
            </div>
            <p className="mb-3 text-xs text-[var(--color-text-dim)]">
              Each row is one real CICIoT2023 record, run individually through the actual IDS pipeline. Click a row
              for the full trace — input features → preprocessing → prediction → ground truth → incident/evidence
              (the "Live Evaluation / Replay" view).
            </p>
            {recordsError && <ErrorCard message={(recordsError as Error).message} />}
            {records && (
              <>
                <div className="overflow-x-auto rounded-lg border border-[var(--color-border)]">
                  <table className="w-full min-w-[720px] text-sm">
                    <thead className="bg-[var(--color-surface-2)] text-left text-xs uppercase tracking-wide text-[var(--color-text-dim)]">
                      <tr>
                        <th className="px-3 py-2 font-medium">Record</th>
                        <th className="px-3 py-2 font-medium">Ground truth</th>
                        <th className="px-3 py-2 font-medium">IDS prediction</th>
                        <th className="px-3 py-2 font-medium">Score</th>
                        <th className="px-3 py-2 font-medium">Result</th>
                        <th className="px-3 py-2 font-medium">Incident</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pageRows.map((r) => (
                        <tr
                          key={r.record_id}
                          onClick={() => setSelected(r)}
                          role="button"
                          tabIndex={0}
                          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setSelected(r); } }}
                          className="cursor-pointer border-t border-[var(--color-border)] hover:bg-[var(--color-surface-2)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--color-accent)]"
                        >
                          <td className="mono px-3 py-2 text-xs">{r.record_id}</td>
                          <td className="px-3 py-2">
                            <LabelPill label={r.ground_truth} />
                          </td>
                          <td className="px-3 py-2">
                            <LabelPill label={r.prediction} />
                          </td>
                          <td className="mono px-3 py-2 text-xs">{r.score.toFixed(3)}</td>
                          <td className="px-3 py-2">
                            <OutcomePill outcome={r.outcome} />
                          </td>
                          <td className="mono px-3 py-2 text-xs text-[var(--color-text-dim)]">
                            {r.incident_id ? r.incident_id.slice(0, 8) + "…" : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="mt-3 flex items-center justify-between text-xs text-[var(--color-text-dim)]">
                  <span>{filtered.length} records{filter !== "all" ? ` (${filter})` : ""}</span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setPage((p) => Math.max(0, p - 1))}
                      disabled={page === 0}
                      className="rounded-md bg-[var(--color-surface-2)] px-2 py-1 disabled:opacity-30"
                    >
                      Prev
                    </button>
                    <span>Page {page + 1} / {pageCount}</span>
                    <button
                      onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                      disabled={page >= pageCount - 1}
                      className="rounded-md bg-[var(--color-surface-2)] px-2 py-1 disabled:opacity-30"
                    >
                      Next
                    </button>
                  </div>
                </div>
              </>
            )}
          </section>
        </>
      )}

      {selected && <RecordDrawer record={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function DatasetPanel({
  summary, onRerun, rerunPending, token,
}: {
  summary: CicioTEvalSummary;
  onRerun: () => void;
  rerunPending: boolean;
  token: string;
}) {
  const m = summary.manifest;
  return (
    <section className="mb-6 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <Database className="h-4 w-4" aria-hidden="true" /> Dataset &amp; reproducibility manifest
          </h2>
          <p className="mt-1 max-w-2xl text-xs text-[var(--color-text-dim)]">
            {m.dataset_name ?? "CICIoT2023 (binary, feature-selected FL export)"} — a publicly available IoT
            cybersecurity benchmark dataset, not live or production network traffic. Results below are{" "}
            {summary.mode === "production-snapshot" ? "a real, precomputed run" : "a real, live-executed run"} of
            ARGUS's actual detection code against it.
          </p>
          <p className="mt-2 max-w-2xl text-xs font-semibold text-[var(--color-risk-med)]">
            Device identity is not available in this benchmark export.
          </p>
        </div>
        {summary.mode === "production-snapshot" ? (
          <span className="mono whitespace-nowrap rounded-full border border-[var(--color-accent-dim)] px-2.5 py-1 text-[10px] font-semibold text-[var(--color-accent)]">
            PRECOMPUTED — Vercel cannot run scikit-learn per request
          </span>
        ) : (
          <button
            onClick={onRerun}
            disabled={!token || rerunPending}
            className="flex items-center gap-1.5 rounded-md bg-[var(--color-surface-2)] px-3 py-1.5 text-xs font-medium hover:bg-[var(--color-border)] disabled:opacity-40"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${rerunPending ? "animate-spin" : ""}`} aria-hidden="true" />
            {rerunPending ? "Running…" : "Re-run live"}
          </button>
        )}
      </div>
      <div className="mono grid grid-cols-2 gap-2 text-xs text-[var(--color-text-dim)] sm:grid-cols-4">
        <Field label="Seed" value={String(m.seed)} />
        <Field label="Detection threshold" value={`p(attack) ≥ ${m.detection_threshold}`} />
        <Field label="Train (benign-only)" value={String(m.n_train_benign)} />
        <Field label="Calib (bal.)" value={`${m.n_calib_benign}+${m.n_calib_attack}`} />
        <Field label="Test (held-out)" value={`${m.n_test_benign}+${m.n_test_attack}`} />
        <Field label="Features" value={String(m.feature_keys.length)} />
        <Field label="Dataset file" value={m.dataset_filename} />
        <Field label="File SHA-256" value={m.dataset_sha256.slice(0, 12) + "…"} />
      </div>
      {m.label_map_assumption && (
        <p className="mt-3 flex items-start gap-1.5 rounded-md border border-[var(--color-risk-med)]/30 bg-[var(--color-risk-med)]/10 p-2 text-[11px] text-[var(--color-risk-med)]">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" aria-hidden="true" />
          {m.label_map_assumption}
        </p>
      )}
      {m.limitations && m.limitations.length > 0 && (
        <details className="mt-3 text-xs text-[var(--color-text-dim)]">
          <summary className="cursor-pointer font-medium">Known limitations ({m.limitations.length})</summary>
          <ul className="mt-2 list-disc space-y-1 pl-4">
            {m.limitations.map((l, i) => <li key={i}>{l}</li>)}
          </ul>
        </details>
      )}
    </section>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md bg-[var(--color-surface-2)] px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide opacity-70">{label}</div>
      <div className="truncate text-[var(--color-text)]">{value}</div>
    </div>
  );
}

function MetricsPanel({ summary }: { summary: { confusion_matrix: CicioTConfusionMatrix; metrics: CicioTMetrics; n_incidents_generated: number } }) {
  const cm = summary.confusion_matrix;
  const m = summary.metrics;
  return (
    <section className="mb-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
        <h2 className="mb-3 text-sm font-semibold">Confusion matrix</h2>
        <div className="mono grid grid-cols-2 gap-2 text-center text-sm">
          <div className="rounded-md border border-[var(--color-accent-dim)] bg-[var(--color-accent)]/10 p-3">
            <div className="text-2xl font-bold text-[var(--color-accent)]">{cm.tp}</div>
            <div className="text-[11px] text-[var(--color-text-dim)]">True Positive</div>
          </div>
          <div className="rounded-md border border-[var(--color-risk-high)]/40 bg-[var(--color-risk-high)]/10 p-3">
            <div className="text-2xl font-bold text-[var(--color-risk-high)]">{cm.fp}</div>
            <div className="text-[11px] text-[var(--color-text-dim)]">False Positive</div>
          </div>
          <div className="rounded-md border border-[var(--color-risk-high)]/40 bg-[var(--color-risk-high)]/10 p-3">
            <div className="text-2xl font-bold text-[var(--color-risk-high)]">{cm.fn}</div>
            <div className="text-[11px] text-[var(--color-text-dim)]">False Negative</div>
          </div>
          <div className="rounded-md border border-[var(--color-accent-dim)] bg-[var(--color-accent)]/10 p-3">
            <div className="text-2xl font-bold text-[var(--color-accent)]">{cm.tn}</div>
            <div className="text-[11px] text-[var(--color-text-dim)]">True Negative</div>
          </div>
        </div>
        <p className="mt-3 text-[11px] text-[var(--color-text-dim)]">
          {summary.n_incidents_generated} real incidents were generated by the IDS's own predictions (TP + FP) —
          never inserted because the dataset label said "attack."
        </p>
      </div>
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
        <h2 className="mb-3 text-sm font-semibold">Metrics (computed from the confusion matrix above)</h2>
        <div className="grid grid-cols-3 gap-2 text-center">
          <MetricTile label="Accuracy" value={m.accuracy} />
          <MetricTile label="Precision" value={m.precision} />
          <MetricTile label="Recall" value={m.recall} />
          <MetricTile label="F1" value={m.f1} />
          <MetricTile label="FPR" value={m.false_positive_rate} bad />
          <MetricTile label="FNR" value={m.false_negative_rate} bad />
        </div>
      </div>
    </section>
  );
}

function MetricTile({ label, value, bad }: { label: string; value: number; bad?: boolean }) {
  return (
    <div className="rounded-md bg-[var(--color-surface-2)] p-3">
      <div className="mono text-lg font-bold" style={{ color: bad ? "var(--color-risk-med)" : "var(--color-accent)" }}>
        {(value * 100).toFixed(1)}%
      </div>
      <div className="text-[10px] uppercase tracking-wide text-[var(--color-text-dim)]">{label}</div>
    </div>
  );
}

function LabelPill({ label }: { label: "benign" | "attack" }) {
  return (
    <span
      className="mono inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium"
      style={{
        color: label === "attack" ? "var(--color-risk-high)" : "var(--color-accent)",
        backgroundColor: label === "attack" ? "color-mix(in srgb, var(--color-risk-high) 12%, transparent)" : "color-mix(in srgb, var(--color-accent) 12%, transparent)",
      }}
    >
      {label}
    </span>
  );
}

function OutcomePill({ outcome }: { outcome: "TP" | "TN" | "FP" | "FN" }) {
  const map = {
    TP: { color: "var(--color-accent)", icon: CheckCircle2, label: "TP — correctly detected" },
    TN: { color: "var(--color-accent)", icon: CheckCircle2, label: "TN — correctly quiet" },
    FP: { color: "var(--color-risk-high)", icon: XCircle, label: "FP — false alarm" },
    FN: { color: "var(--color-risk-critical)", icon: ShieldQuestion, label: "FN — missed attack" },
  }[outcome];
  const Icon = map.icon;
  return (
    <span className="inline-flex items-center gap-1 text-xs font-semibold" style={{ color: map.color }} title={map.label}>
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      {outcome}
    </span>
  );
}

function RecordDrawer({ record, onClose }: { record: CicioTRecord; onClose: () => void }) {
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const titleId = `record-drawer-title-${record.record_id}`;
  const { data: incident } = useQuery({
    queryKey: ["incidents"],
    queryFn: api.incidents,
    enabled: !!record.incident_id,
  });
  const matchedIncident = incident?.find((i) => i.incident_id === record.incident_id);

  useEffect(() => {
    closeButtonRef.current?.focus();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-30 flex justify-end bg-black/50" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="h-full w-full max-w-xl overflow-y-auto border-l border-[var(--color-border)] bg-[var(--color-surface)] p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between">
          <div>
            <h2 id={titleId} className="mono text-lg font-semibold">{record.record_id}</h2>
            <p className="text-xs text-[var(--color-text-dim)]">{record.flow_identifier} — a real CICIoT2023 row, not a physical device</p>
          </div>
          <button
            ref={closeButtonRef}
            onClick={onClose}
            aria-label="Close record detail"
            className="rounded-md p-1 text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)]"
          >
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        <ol className="mb-5 space-y-2 text-xs">
          <Step n={1} label="Input features (real dataset columns)">
            <div className="mono grid grid-cols-2 gap-1 rounded-md bg-[var(--color-surface-2)] p-2">
              {Object.entries(record.features).map(([k, v]) => (
                <div key={k} className="flex justify-between gap-2">
                  <span className="text-[var(--color-text-dim)]">{k}</span>
                  <span>{typeof v === "number" ? v.toFixed(3) : String(v)}</span>
                </div>
              ))}
            </div>
          </Step>
          <Step n={2} label="Preprocessing">
            Column rename + type coercion into ARGUS's FeatureVector (this export ships pre-computed features;
            no raw flow fields exist to re-extract).
          </Step>
          <Step n={3} label="IDS prediction (CalibratedDetector: IsolationForest + isotonic calibration)">
            <span className="mono">p(attack) = {record.score.toFixed(4)}</span> → <LabelPill label={record.prediction} />
            <div className="mt-1 text-[var(--color-text-dim)]">conformal set: {record.conformal_set.join(", ")}</div>
          </Step>
          <Step n={4} label="Ground truth (dataset's sub_label — never used to influence the prediction above)">
            <LabelPill label={record.ground_truth} />
          </Step>
          <Step n={5} label="Classification">
            <OutcomePill outcome={record.outcome} />
          </Step>
          <Step n={6} label="Incident generated?">
            {record.incident_id ? (
              <span className="mono text-[var(--color-accent)]">{record.incident_id}</span>
            ) : (
              <span className="text-[var(--color-text-dim)]">No — IDS predicted benign, no incident created</span>
            )}
          </Step>
        </ol>

        {matchedIncident && (
          <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3 text-xs">
            <div className="mb-1 font-semibold">Corresponding real incident (Incidents page)</div>
            <div className="mono text-[var(--color-text-dim)]">
              risk {matchedIncident.risk_score?.toFixed(2)} · sources {matchedIncident.detection_sources.join(", ")}
            </div>
            {matchedIncident.bundle_id && (
              <div className="mono mt-1 text-[var(--color-text-dim)]">evidence bundle {matchedIncident.bundle_id.slice(0, 16)}…</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function Step({ n, label, children }: { n: number; label: string; children: ReactNode }) {
  return (
    <li className="rounded-md border border-[var(--color-border)] p-2.5">
      <div className="mb-1.5 flex items-center gap-2 font-semibold text-[var(--color-text-dim)]">
        <span className="mono flex h-5 w-5 items-center justify-center rounded-full bg-[var(--color-accent)]/15 text-[10px] text-[var(--color-accent)]">
          {n}
        </span>
        {label}
      </div>
      <div className="pl-7">{children}</div>
    </li>
  );
}
