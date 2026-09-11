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
};
