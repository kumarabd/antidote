import { useState } from "react";
import { Link } from "react-router-dom";
import { useUIState } from "../app/hooks";
import StatusPill from "../components/StatusPill";
import Card from "../components/Card";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";
import { api } from "../app/api";

export default function Dashboard() {
  const { data, error, loading, refresh } = useUIState();
  const [exporting, setExporting] = useState(false);
  const [exportToast, setExportToast] = useState(false);

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

  const global = data?.global;

  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorState error={error} onRetry={refresh} />;
  if (!global) {
    return <ErrorState error={new Error("Invalid API response: missing global state")} onRetry={refresh} />;
  }

  const reasons = global.reasons ?? [];
  const warnings = global.warnings ?? [];

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
          System = telemetry reliability (watchers, proxy).
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
    </div>
  );
}
