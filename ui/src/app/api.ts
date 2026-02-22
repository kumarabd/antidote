const BASE = "";

export async function fetchJson<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

async function fetchJsonOptional<T>(path: string): Promise<T | null> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) return null;
  return res.json();
}

export const api = {
  uiState: (params?: { recent_limit?: number }) => {
    const q = params?.recent_limit ? `?recent_limit=${params.recent_limit}` : "";
    return fetchJson<import("./types").UIStateResponse>(`/ui/state${q}`);
  },
  uiSession: (id: string, params?: { events_limit?: number }) => {
    const q = params?.events_limit
      ? `?events_limit=${params.events_limit}`
      : "";
    return fetchJson<import("./types").UISessionResponse>(
      `/ui/sessions/${encodeURIComponent(id)}${q}`
    );
  },
  debugZeroConfigStatus: () =>
    fetchJsonOptional<unknown>("/debug/zero_config_status"),
  debugHealth: () => fetchJson<unknown>("/debug/health"),
  debugConfidence: () => fetchJson<unknown>("/debug/confidence"),
  exportDiagnostics: async (params?: { include_logs?: boolean; include_config?: boolean }) => {
    const q = new URLSearchParams();
    if (params?.include_logs !== undefined) q.set("include_logs", String(params.include_logs));
    if (params?.include_config !== undefined) q.set("include_config", String(params.include_config));
    const res = await fetch(`/support/diagnostics/export?${q}`, { method: "POST" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blob = await res.blob();
    const cd = res.headers.get("Content-Disposition");
    const match = cd?.match(/filename="?([^";\n]+)"?/);
    const filename = match?.[1] || `antidote-diagnostics-${Date.now()}.zip`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  },
};
