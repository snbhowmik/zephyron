/** Response shapes of the QAVACH API (`ARCH.md §12`). The FastAPI routes return
 *  plain dicts, so these are hand-written and kept in step with `tests/api`. */

export interface Meta {
  demo: boolean;
  collectors: string[];
  auth: string;
  demo_note?: string;
}

export interface ScanListItem {
  id: string;
  target_ref: string;
  status: string;
  started: string;
  finished: string | null;
  z_scenario: string;
  assets: number | null;
}

export interface StageInfo {
  status: string;
  seconds?: number;
  detail?: string;
  error?: string;
}

export interface ScanDetail {
  id: string;
  target_ref: string;
  status: string;
  started: string;
  finished: string | null;
  z_scenario: string;
  as_of: string;
  policy_snapshot_id: string;
  stages: Record<string, StageInfo>;
  summary: {
    assets?: number;
    claims?: number;
    by_finding_class?: Record<string, number>;
    collectors?: Record<string, string>;
    degraded_collectors?: string[];
    unresolved_names?: string[];
    unassigned?: number;
    bridges?: number;
    infeasible?: number;
    adjudications?: {
      applied: number;
      reopened: unknown[];
      orphaned: unknown[];
      superseded: number;
    };
  };
  collectors: {
    collector: string;
    tool_version: string;
    partial: boolean;
    exit_code: number | null;
    errors: { message: string; fatal: boolean }[];
  }[];
}

export interface AssetScore {
  system_id: string | null;
  band: string;
  outcome: string | null;
  mosca_gap: number | null;
  ev: number | null;
}

export interface AssetListItem {
  id: string;
  identity_key: string;
  family: string;
  parameter_set: string | null;
  curve: string | null;
  function: string | null;
  finding_class: string;
  migration_authority: string;
  disputed: boolean;
  occurrences: number;
  suppressed: boolean;
  capability_only: boolean;
  scores: AssetScore[];
}

export type Facets = Record<string, Record<string, number>>;

export interface AssetPage {
  items: AssetListItem[];
  total: number;
  page: number;
  page_size: number;
  facets: Facets;
}

export interface Occurrence {
  collector: string;
  tool_version: string;
  locus: Record<string, unknown> & { locus_type: string };
  confidence: string;
  detection_method: string;
  raw_ref: string;
}

export interface ExplanationDoc {
  name: string;
  formula: string;
  inputs: Record<string, unknown>;
  policy: { path: string; value: unknown; basis: string }[];
  steps: string[];
  heuristic: boolean;
}

export interface RegisterEntry {
  bom_ref: string;
  system_id: string | null;
  finding_class: string;
  migration_authority: string;
  authority_basis: string;
  band: string;
  outcome: string | null;
  reason: string;
  disputed: boolean;
  capability_only: boolean;
  mosca: {
    x_conf_years: number;
    x_integ_years: number;
    y_years: number;
    y_is_heuristic: boolean;
    z_years: number;
    gap_years: number | null;
    mitigation: string | null;
    note: string;
  } | null;
  expected_value: {
    ev: number;
    criticality: number;
    sensitivity: number;
    exposure: number;
    gap_factor: number;
  } | null;
  z_effective: { date: string; bound_by: string; binding: boolean; scenario: string } | null;
  recommendation: Record<string, unknown> | null;
  roadmap: Record<string, unknown> | null;
  explanations: ExplanationDoc[];
}

export interface AssetDetail {
  id: string;
  scan_run_id: string;
  identity_key: string;
  asset_type: string;
  function: string | null;
  family: string;
  parameter_set: string | null;
  curve: string | null;
  mode: string | null;
  padding: string | null;
  oid: string | null;
  finding_class: string;
  migration_authority: string;
  authority_basis: string;
  concluded_tier: string;
  disputed: boolean;
  disputes: {
    attribute: string;
    claims: { value: string | null; source_collector: string; confidence: number }[];
    adjudicated_value: string | null;
  }[];
  occurrences: Occurrence[];
  risk: RegisterEntry[];
  systems: { system_id: string; basis: string[] }[];
  recommendation: {
    kind: string;
    target: string | null;
    reason?: string;
    primary?: {
      name: string;
      status_text: string;
      source_url: string;
      verified_on: string | null;
    } | null;
    watch?: string[];
    hybrid?: string[];
    notes?: string[];
    classical_fix?: string | null;
  } | null;
}

export interface RiskRegister {
  policy: { snapshot_id: string; z_scenario: string };
  as_of: string;
  heuristics_notice: string;
  summary: {
    total: number;
    by_finding_class: Record<string, number>;
    by_band: Record<string, number>;
    coverage_failures: number;
    coverage_failures_capability_only: number;
    coverage_failure_note: string;
    unassigned: number;
  };
  entries: RegisterEntry[];
  roadmap: RoadmapDoc | null;
}

export interface RoadmapDoc {
  waves: { index: number; kind: string; units: string[]; schedule_risk: string | null }[];
  bridges: { members: string[]; variant: string; phases: string[]; gate: string }[];
  vendor_dependencies: unknown[];
  named_blockers: unknown[];
  infeasible: {
    unit_id: string;
    deadline_quarter: string;
    earliest_finish_quarter: string;
    deadline_source: string;
    blocking_chain: string[];
    contended_resource: string | null;
  }[];
  excluded_trust_anchors: number;
  triage: string[];
  notes: string[];
}

export interface RoadmapResponse {
  roadmap: RoadmapDoc | null;
  units: {
    id: string;
    system_id: string;
    function: string;
    wave: number | null;
    target_quarter: string | null;
    feasible: boolean;
    schedule_risk: string | null;
  }[];
  edges: { from: string; to: string; kind: string }[];
}

export interface SimulateResult {
  scan_id: string;
  baseline_policy_snapshot_id: string;
  candidate_policy_snapshot_id: string;
  z_scenario: { baseline: string; candidate: string };
  overrides: Record<string, unknown>;
  scored: number;
  changed: number;
  bands: { baseline: Record<string, number>; candidate: Record<string, number> };
  transitions: Record<string, number>;
  top_movers: {
    asset_id: string;
    family: string;
    system_id: string | null;
    band: { from: string; to: string };
    gap_years: { from: number; to: number };
  }[];
  scoring_ms: number;
  heuristics_notice: string;
}

export interface PolicyDoc {
  snapshot_id: string;
  nodes: { path: string; fields: Record<string, unknown>; basis: string }[];
}

export interface ProgressEvent {
  stage: string;
  status: string;
  collector: string | null;
  detail: string | null;
}
