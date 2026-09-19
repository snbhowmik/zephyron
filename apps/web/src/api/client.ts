import type {
  AgentDetail,
  AgentSummary,
  AssetDetail,
  AssetPage,
  IssuedToken,
  Meta,
  PolicyDoc,
  RiskRegister,
  RoadmapResponse,
  ScanDetail,
  ScanDiff,
  ScanListItem,
  SimulateResult,
  TokenRow,
} from "./types";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

const TOKEN_KEY = "qavach.api-token";

/** The bearer token lives in sessionStorage only: gone when the tab closes, never
 *  in a URL or a log (SECURITY.md §6). */
export function getToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: the token simply is not remembered */
  }
}

function withAuth(init?: RequestInit): RequestInit {
  const token = getToken();
  if (!token) return init ?? {};
  const headers = new Headers(init?.headers);
  headers.set("authorization", `Bearer ${token}`);
  return { ...init, headers };
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, withAuth(init));
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
  agents: () => request<AgentSummary[]>("/api/v1/agents"),
  agent: (id: string) => request<AgentDetail>(`/api/v1/agents/${id}`),
  agentTokens: () => request<TokenRow[]>("/api/v1/agents/tokens"),
  issueToken: (body: { host: string; ttl_minutes: number }) =>
    request<IssuedToken>("/api/v1/agents/tokens", json(body)),
  dispatchAgent: (id: string, body: { paths: string[]; collectors: string[] }) =>
    request<{ run_id: string }>(`/api/v1/agents/${id}/dispatch`, json(body)),
  revokeAgent: (id: string) =>
    request<{ revoked: boolean }>(`/api/v1/agents/${id}/revoke`, { method: "POST" }),
  diff: (before: string, after: string) =>
    request<ScanDiff>(`/api/v1/scans/${before}/diff/${after}`),
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
};

export function progressSocket(scanId: string): WebSocket {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const token = getToken();
  // A browser WebSocket cannot set headers; the token rides as a subprotocol,
  // never in the URL (access logs).
  return new WebSocket(
    `${proto}://${window.location.host}/api/v1/scans/${scanId}/progress`,
    token ? [`qavach.bearer.${token}`] : undefined,
  );
}

/** Exports are fetched (so the Authorization header goes with them) and saved
 *  from a Blob - a plain link could not authenticate. */
export async function downloadExport(
  id: string,
  kind: "cbom" | "risk-register" | "sarif",
  spec = "1.7",
): Promise<void> {
  const path =
    kind === "cbom"
      ? `/api/v1/scans/${id}/export/cbom?spec=${spec}`
      : `/api/v1/scans/${id}/export/${kind}`;
  const response = await fetch(path, withAuth());
  if (!response.ok) throw new ApiError(response.status, response.statusText);
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = kind === "cbom" ? `${id}.cbom-${spec}.cdx.json` : `${id}.${kind}.json`;
  link.click();
  URL.revokeObjectURL(url);
}
