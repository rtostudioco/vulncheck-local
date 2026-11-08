/**
 * VulnCheck Local — typed client API helpers.
 * All requests are client-side, relative-path only, no-store.
 * Download endpoints use an anchor click so Content-Disposition is honored.
 */

import type {
  MetaDTO,
  ReportHistoryDTO,
  SessionDetail,
  SessionSummary,
  SettingsDTO,
} from "@/lib/vulncheck/core/types";

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function toApiError(res: Response): Promise<ApiError> {
  let message = `Request failed with status ${res.status}`;
  try {
    const body = (await res.json()) as { error?: unknown };
    if (body && typeof body.error === "string" && body.error.length > 0) {
      message = body.error;
    }
  } catch {
    // response body was not JSON — keep the generic message
  }
  return new ApiError(res.status, message);
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { cache: "no-store", ...init });
  } catch {
    throw new ApiError(0, "Network error — could not reach the local API");
  }
  if (!res.ok) {
    throw await toApiError(res);
  }
  return (await res.json()) as T;
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

export function fetchMeta(): Promise<MetaDTO> {
  return requestJson<MetaDTO>("/api/meta");
}

// ---------------------------------------------------------------------------
// Audit sessions
// ---------------------------------------------------------------------------

export function startAudit(): Promise<{ sessionId: string }> {
  return requestJson<{ sessionId: string }>("/api/audit/run", { method: "POST" });
}

export function fetchSessions(): Promise<{ sessions: SessionSummary[] }> {
  return requestJson<{ sessions: SessionSummary[] }>("/api/audit/sessions");
}

export function fetchSessionDetail(id: string): Promise<SessionDetail> {
  return requestJson<SessionDetail>(
    `/api/audit/sessions/${encodeURIComponent(id)}`
  );
}

export function deleteSession(id: string): Promise<{ ok: boolean }> {
  return requestJson<{ ok: boolean }>(
    `/api/audit/sessions/${encodeURIComponent(id)}`,
    { method: "DELETE" }
  );
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

export function fetchReportHistory(): Promise<{ reports: ReportHistoryDTO[] }> {
  return requestJson<{ reports: ReportHistoryDTO[] }>("/api/reports/history");
}

/**
 * Triggers a browser download for binary/attachment endpoints.
 * Uses an anchor click (NOT fetch) so the Content-Disposition header
 * and suggested filename are honored by the browser.
 */
export function downloadAttachment(
  path: string,
  params: Record<string, string>
): void {
  const qs = new URLSearchParams(params).toString();
  const url = qs ? `${path}?${qs}` : path;
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}

export function downloadPdfReport(sessionId: string): void {
  downloadAttachment("/api/reports/pdf", { sessionId });
}

export function downloadExport(
  sessionId: string,
  format: "json" | "csv"
): void {
  downloadAttachment("/api/reports/export", { sessionId, format });
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

export function fetchSettings(): Promise<SettingsDTO> {
  return requestJson<SettingsDTO>("/api/settings");
}

export function saveSettings(patch: {
  aiConsentEnabled?: boolean;
  retentionDays?: number;
}): Promise<SettingsDTO> {
  return requestJson<SettingsDTO>("/api/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
}

// ---------------------------------------------------------------------------
// AI explanations
// ---------------------------------------------------------------------------

export function explainFinding(
  sessionId: string,
  findingId: string
): Promise<{ explanation: string }> {
  return requestJson<{ explanation: string }>("/api/ai/explain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sessionId, findingId }),
  });
}
