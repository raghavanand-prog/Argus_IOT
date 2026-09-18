const BASE = "/api";

export interface Device {
  device_id: string;
  device_type: string;
  state: string;
  criticality: number;
  is_drifting: boolean;
  last_seen: string | null;
}

export interface Incident {
  incident_id: string;
  device_id: string;
  scenario: string;
  first_seen: string;
  last_seen: string;
  chain_position: string;
  agreement_score: number;
  detection_sources: string[];
  status: string;
  risk_score: number | null;
  risk_terms: Record<string, number> | null;
  bundle_id: string | null;
  action: string | null;
  dry_run: boolean | null;
  verification_outcome: string | null;
}

export interface ShapContribution {
  name: string;
  value: number;
  contribution: number;
}

export interface EvidenceBundle {
  bundle_id: string;
  incident_id: string;
  created_at: string;
  device: Record<string, unknown>;
  feature_vector: Record<string, unknown>;
  detection: Record<string, unknown>;
  baseline: Record<string, unknown>;
  risk: { score: number; terms: Record<string, number> };
  decision: {
    action: string;
    tier: number;
    dry_run: boolean;
    gates_passed: string[];
    gates_failed: string[];
  };
  trace: string[];
  prev_bundle_hash: string;
  merkle_root: string;
}

export interface ReplayResult {
  bundle_id: string;
  reproduced: boolean;
  original_action: string;
  replayed_action: string;
  original_tier: number;
  replayed_tier: number;
}

export interface ControlStatus {
  enforce: boolean;
  kill_switch_engaged: boolean;
}

export interface ActionRow {
  action_id: string;
  device_id: string;
  tier: number;
  action: string;
  dry_run: boolean;
  applied_at: string | null;
  ttl_seconds: number;
}

export interface CicioTManifest {
  run_id: string;
  dataset_filename: string;
  dataset_sha256: string;
  seed: number;
  feature_keys: string[];
  model_config: Record<string, unknown>;
  detection_threshold: number;
  generated_at: string;
  n_train_benign: number;
  n_calib_benign: number;
  n_calib_attack: number;
  n_test_benign: number;
  n_test_attack: number;
  n_total_rows_in_file: number;
  dataset_name?: string;
  dataset_source?: string;
  label_map_assumption?: string;
  limitations?: string[];
}

export interface CicioTConfusionMatrix {
  tp: number;
  tn: number;
  fp: number;
  fn: number;
}

export interface CicioTMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  false_positive_rate: number;
  false_negative_rate: number;
}

export interface CicioTEvalSummary {
  run_id: string;
  manifest: CicioTManifest;
  confusion_matrix: CicioTConfusionMatrix;
  metrics: CicioTMetrics;
  n_incidents_generated: number;
  n_records: number;
  mode: "local-live" | "production-snapshot";
}

export interface CicioTRecord {
  record_id: string;
  row_index: number;
  ground_truth: "benign" | "attack";
  prediction: "benign" | "attack";
  score: number;
  conformal_set: string[];
  flow_identifier: string;
  features: Record<string, number>;
  incident_id: string | null;
  outcome: "TP" | "TN" | "FP" | "FN";
}

async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, opts);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${body}`);
  }
  return res.json() as Promise<T>;
}

function authHeaders(token: string): HeadersInit {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

export const api = {
  health: () => req<{ status: string; enforce: string; kill_switch: boolean }>("/health"),
  devices: () => req<Device[]>("/devices"),
  incidents: () => req<Incident[]>("/incidents"),
  evidence: (bundleId: string) => req<EvidenceBundle>(`/evidence/${bundleId}`),
  replay: (bundleId: string, token: string) =>
    req<ReplayResult>(`/evidence/${bundleId}/replay`, { method: "POST", headers: authHeaders(token) }),
  controlStatus: () => req<ControlStatus>("/control/status"),
  toggleKillSwitch: (engage: boolean, token: string) =>
    req<{ kill_switch_engaged: boolean }>(`/control/kill-switch?engage=${engage}`, {
      method: "POST",
      headers: authHeaders(token),
    }),
  seedDemo: (token: string) =>
    req<{ seeded: boolean; incidents: number; bundles: number; actions: number }>("/control/seed-demo", {
      method: "POST",
      headers: authHeaders(token),
    }),
  actions: () => req<ActionRow[]>("/actions"),
  cicioTEvalSummary: () => req<CicioTEvalSummary>("/cicioT2023/eval"),
  cicioTEvalRecords: () => req<CicioTRecord[]>("/cicioT2023/eval/records"),
  cicioTEvalRecord: (recordId: string) => req<CicioTRecord>(`/cicioT2023/eval/records/${recordId}`),
  runCicioTEval: (token: string) =>
    req<{ run_id: string; manifest: CicioTManifest; confusion_matrix: CicioTConfusionMatrix; metrics: CicioTMetrics }>(
      "/control/run-cicioT2023-eval",
      { method: "POST", headers: authHeaders(token) },
    ),
};
