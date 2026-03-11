import { useEffect, useState, useCallback } from "react";
import { api } from "./api";

export function usePoll<T>(
  fetcher: () => Promise<T>,
  intervalMs: number,
  deps: unknown[] = []
) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      setError(null);
      const result = await fetcher();
      setData(result);
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setLoading(false);
    }
  }, deps);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, intervalMs);
    return () => clearInterval(id);
  }, [refresh, intervalMs]);

  return { data, error, loading, refresh };
}

export function useUIState() {
  return usePoll(() => api.uiState(), 2000);
}

export function useUISession(id: string | undefined, eventsLimit = 50) {
  return usePoll(
    () =>
      id && id.trim()
        ? api.uiSession(id, { events_limit: eventsLimit })
        : Promise.reject(new Error("No session id")),
    2000,
    [id, eventsLimit]
  );
}

export function useUIRootDetail(id: number | undefined, eventsLimit = 50) {
  return usePoll(
    () =>
      id != null
        ? api.uiRootDetail(id, { events_limit: eventsLimit })
        : Promise.reject(new Error("No root id")),
    2000,
    [id, eventsLimit]
  );
}

export function useUIAppDetail(app: string | undefined, eventsLimit = 50) {
  return usePoll(
    () =>
      app && app.trim()
        ? api.uiAppDetail(app, { events_limit: eventsLimit })
        : Promise.reject(new Error("No app name")),
    2000,
    [app, eventsLimit]
  );
}

export function useDiagnostics() {
  const [zeroConfig, setZeroConfig] = useState<unknown | null>(null);
  const [health, setHealth] = useState<unknown | null>(null);
  const [confidence, setConfidence] = useState<unknown | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchAll = useCallback(async () => {
    setError(null);
    try {
      const [zc, h, c] = await Promise.all([
        api.debugZeroConfigStatus(),
        api.debugHealth(),
        api.debugConfidence(),
      ]);
      setZeroConfig(zc);
      setHealth(h);
      setConfidence(c);
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const id = setInterval(fetchAll, 3000);
    return () => clearInterval(id);
  }, [fetchAll]);

  return { zeroConfig, health, confidence, error, loading, refresh: fetchAll };
}
