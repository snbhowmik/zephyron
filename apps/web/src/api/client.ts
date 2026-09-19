import type {
  AssetDetail,
  AssetPage,
  Meta,
  PolicyDoc,
  RiskRegister,
  RoadmapResponse,
  ScanDetail,
  ScanListItem,
  SimulateResult,
} from "./types";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* keep statusText */
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
});

export interface AssetQuery {
  finding_class?: string;
  migration_authority?: string;
  band?: string;
  outcome?: string;
  system_id?: string;
  disputed?: boolean;
  family?: string;
  q?: string;
  page?: number;
  page_size?: number;
}

export function queryString(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export const api = {
  meta: () => request<Meta>("/api/v1/meta"),
  scans: () => request<ScanListItem[]>("/api/v1/scans"),
  scan: (id: string) => request<ScanDetail>(`/api/v1/scans/${id}`),
  assets: (id: string, query: AssetQuery) =>
    request<AssetPage>(`/api/v1/scans/${id}/assets${queryString({ ...query })}`),
  asset: (id: string) => request<AssetDetail>(`/api/v1/assets/${id}`),
  roadmap: (id: string) => request<RoadmapResponse>(`/api/v1/scans/${id}/roadmap`),
  register: (id: string) => request<RiskRegister>(`/api/v1/scans/${id}/export/risk-register`),
  policy: () => request<PolicyDoc>("/api/v1/policy"),
  simulate: (body: { scan_id: string; overrides: Record<string, unknown>; z_scenario?: string }) =>
    request<SimulateResult>("/api/v1/policy/simulate", json(body)),
  startScan: (body: { target_type: string; target_ref: string; z_scenario?: string }) =>
    request<{ scan_id: string; status: string }>("/api/v1/scans", json(body)),
  importSystems: (content: string, contentType: string) =>
    request<{
      imported: number;
      ok: boolean;
      issues: { row: number; field: string | null; message: string; severity: string }[];
    }>("/api/v1/systems/import", {
      method: "POST",
      headers: { "content-type": contentType },
      body: content,
    }),
  suppress: (assetId: string, body: { reason: string; author: string; days: number }) =>
    request<{ suppression_id: string }>(`/api/v1/assets/${assetId}/suppress`, json(body)),
  adjudicate: (
    assetId: string,
    body: { attribute: string; value: string; by: string; reason: string },
  ) => request<{ adjudication_id: string }>(`/api/v1/assets/${assetId}/adjudicate`, json(body)),
  exportUrl: (id: string, kind: "cbom" | "risk-register", spec = "1.7") =>
    kind === "cbom"
      ? `/api/v1/scans/${id}/export/cbom?spec=${spec}`
      : `/api/v1/scans/${id}/export/risk-register`,
};

export function progressSocket(scanId: string): WebSocket {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return new WebSocket(`${proto}://${window.location.host}/api/v1/scans/${scanId}/progress`);
}
