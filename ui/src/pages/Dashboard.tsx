import { useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { useUIState } from "../app/hooks";
import { formatDate, formatRelative } from "../app/format";
import StatusPill from "../components/StatusPill";
import Card from "../components/Card";
import Table from "../components/Table";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";
import { api } from "../app/api";
import type { TrustStatus } from "../app/types";

const TRUST_FILTER_OPTIONS: { value: TrustStatus | "all"; label: string }[] = [
  { value: "all", label: "All" },
  { value: "Trusted", label: "Trusted" },
  { value: "NeedsReview", label: "Needs Review" },
  { value: "Risky", label: "Risky" },
];

export default function Dashboard() {
  const { data, error, loading, refresh } = useUIState();
  const [exporting, setExporting] = useState(false);
  const [exportToast, setExportToast] = useState(false);
  const [trustFilter, setTrustFilter] = useState<TrustStatus | "all">("all");
  const [appFilter, setAppFilter] = useState<string>("all");

  const handleExportDiagnostics = async () => {
    setExporting(true);
    try {
      await api.exportDiagnostics();
      setExportToast(true);
      setTimeout(() => setExportToast(false), 3000);
    } catch (e) {
      console.error("Export failed:", e);
    } finally {
      setExporting(false);
    }
  };

  const active_sessions = data?.active_sessions ?? [];
  const recent_sessions = data?.recent_sessions ?? [];
  const global = data?.global;

  const apps = useMemo(() => {
    const set = new Set<string>();
    for (const s of [...active_sessions, ...recent_sessions]) {
      if (s?.app) set.add(s.app);
    }
    return Array.from(set).sort();
  }, [active_sessions, recent_sessions]);

  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorState error={error} onRetry={refresh} />;
  if (!global) {
    return <ErrorState error={new Error("Invalid API response: missing global state")} onRetry={refresh} />;
  }

  const reasons = global.reasons ?? [];
  const warnings = global.warnings ?? [];

  const matchesTrust = (trust: string | undefined) =>
    trustFilter === "all" || (trust != null && trust === trustFilter);
  const matchesApp = (app: string | undefined) =>
    appFilter === "all" || (app != null && app === appFilter);
  const matchesFilters = (s: { trust?: string; app?: string }) =>
    matchesTrust(s.trust) && matchesApp(s.app);

  const filteredActive = active_sessions.filter((s) => s && matchesFilters(s));
  const filteredRecent = recent_sessions.filter((s) => s && matchesFilters(s));

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem", flexWrap: "wrap", gap: "0.5rem" }}>
        <h2 style={{ fontSize: "1.5rem", margin: 0 }}>Dashboard</h2>
        <button
          onClick={handleExportDiagnostics}
          disabled={exporting}
          style={{
            padding: "0.5rem 1rem",
            background: "var(--accent)",
            color: "white",
            border: "none",
            borderRadius: 4,
            cursor: exporting ? "not-allowed" : "pointer",
            fontSize: "0.9rem",
          }}
        >
          {exporting ? "Exporting…" : "Export Diagnostics"}
        </button>
        {exportToast && (
          <span style={{ color: "var(--success)", fontSize: "0.9rem" }}>Diagnostics exported</span>
        )}
      </div>

      <Card title="Trust Summary">
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "1rem",
            flexWrap: "wrap",
          }}
        >
          <span>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginRight: "0.25rem" }}>System</span>
            <StatusPill status={global.trust} />
          </span>
          <span>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginRight: "0.25rem" }}>Confidence</span>
            <StatusPill status={global.confidence} />
          </span>
          <span>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginRight: "0.25rem" }}>Health</span>
            <StatusPill status={global.health} />
          </span>
        </div>
        <p style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "0.5rem", marginBottom: 0 }}>
          System = telemetry reliability (watchers, proxy). Sessions below show per-session risk.
        </p>
        {reasons.length > 0 && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", marginTop: "0.75rem" }}>
            {reasons.map((r, i) => (
              <span
                key={i}
                style={{
                  padding: "0.2rem 0.5rem",
                  background: "var(--surface-hover)",
                  borderRadius: 4,
                  fontSize: "0.8rem",
                }}
              >
                {r}
              </span>
            ))}
          </div>
        )}
        <div style={{ marginTop: "1rem", paddingTop: "1rem", borderTop: "1px solid var(--border)" }}>
          <p style={{ fontSize: "0.9rem", color: "var(--text-muted)", margin: 0 }}>
            Local-only. No file contents or prompts captured.
          </p>
          <Link to="/privacy" style={{ fontSize: "0.85rem", color: "var(--accent)", marginTop: "0.25rem", display: "inline-block" }}>
            What we collect
          </Link>
        </div>
      </Card>

      {warnings.length > 0 && (
        <Card title="Warnings">
          <ul style={{ paddingLeft: "1.25rem", margin: 0 }}>
            {warnings.map((w, i) => (
              <li
                key={i}
                style={{
                  color: w.severity === "high" ? "var(--danger)" : "var(--warning)",
                  marginBottom: "0.25rem",
                }}
              >
                [{w.severity}] {w.message || w.code}
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card title="Sessions">
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: "0.75rem 1.5rem",
            marginBottom: "1rem",
            alignItems: "center",
          }}
        >
          <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>Filter:</span>
          <label style={{ display: "flex", alignItems: "center", gap: "0.35rem", fontSize: "0.9rem" }}>
            Trust
            <select
              value={trustFilter}
              onChange={(e) => setTrustFilter(e.target.value as TrustStatus | "all")}
              style={{
                padding: "0.35rem 0.6rem",
                borderRadius: 4,
                border: "1px solid var(--border)",
                background: "var(--surface)",
                color: "var(--text)",
                fontSize: "0.9rem",
              }}
            >
              {TRUST_FILTER_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: "0.35rem", fontSize: "0.9rem" }}>
            App
            <select
              value={appFilter}
              onChange={(e) => setAppFilter(e.target.value)}
              style={{
                padding: "0.35rem 0.6rem",
                borderRadius: 4,
                border: "1px solid var(--border)",
                background: "var(--surface)",
                color: "var(--text)",
                fontSize: "0.9rem",
              }}
            >
              <option value="all">All</option>
              {apps.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </label>
          {(trustFilter !== "all" || appFilter !== "all") && (
            <button
              type="button"
              onClick={() => {
                setTrustFilter("all");
                setAppFilter("all");
              }}
              style={{
                padding: "0.25rem 0.5rem",
                fontSize: "0.8rem",
                background: "var(--surface-hover)",
                border: "none",
                borderRadius: 4,
                cursor: "pointer",
                color: "var(--text)",
              }}
            >
              Clear filters
            </button>
          )}
        </div>

        <h3 style={{ fontSize: "1rem", marginBottom: "0.5rem" }}>Active Sessions</h3>
        {filteredActive.length === 0 ? (
          <p style={{ color: "var(--text-muted)" }}>
            {active_sessions.length === 0 ? "No active sessions" : "No sessions match the selected filters"}
          </p>
        ) : (
          <Table
            headers={[
              "App",
              "Started",
              "Last Active",
              "Trust",
              "Risk",
              "Drift",
              "Events",
              "",
            ]}
          >
            {filteredActive.map((s) => (
              <tr
                key={s.id}
                style={{ borderBottom: "1px solid var(--border)" }}
              >
                <td style={{ padding: "0.5rem 0.75rem" }}>{s.app}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  {formatDate(s.started_at)}
                </td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  {formatRelative(s.last_active_ts)}
                </td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  <StatusPill status={s.trust} />
                </td>
                <td style={{ padding: "0.5rem 0.75rem" }}>{s.risk_score}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>{s.drift_score}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>{s.event_count}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  <Link to={`/sessions/${s.id}`}>Open</Link>
                </td>
              </tr>
            ))}
          </Table>
        )}

        <h3 style={{ fontSize: "1rem", marginTop: "1.5rem", marginBottom: "0.5rem" }}>Recent Sessions</h3>
        {filteredRecent.length === 0 ? (
          <p style={{ color: "var(--text-muted)" }}>
            {recent_sessions.length === 0 ? "No recent sessions" : "No sessions match the selected filters"}
          </p>
        ) : (
          <Table
            headers={[
              "App",
              "Time",
              "Trust",
              "Risk",
              "Drift",
              "Events",
              "",
            ]}
          >
            {filteredRecent.map((s) => (
              <tr
                key={s.id}
                style={{ borderBottom: "1px solid var(--border)" }}
              >
                <td style={{ padding: "0.5rem 0.75rem" }}>{s.app}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  {formatDate(s.started_at)}
                  {s.ended_at && ` → ${formatDate(s.ended_at)}`}
                </td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  <StatusPill status={s.trust} />
                </td>
                <td style={{ padding: "0.5rem 0.75rem" }}>{s.risk_score}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>{s.drift_score}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>{s.event_count}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  <Link to={`/sessions/${s.id}`}>Open</Link>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
