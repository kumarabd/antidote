import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useUIRootDetail } from "../app/hooks";
import { formatDate, formatBytes } from "../app/format";
import StatusPill from "../components/StatusPill";
import Card from "../components/Card";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";
import type { TrustStatus } from "../app/types";

export default function RootDetail() {
  const { id } = useParams<{ id: string }>();
  const rootId = id ? parseInt(id, 10) : undefined;
  const [eventsExpanded, setEventsExpanded] = useState(false);
  const { data, error, loading, refresh } = useUIRootDetail(rootId);

  if (loading && !data) return <Loading />;
  if (error && !data)
    return <ErrorState error={error} onRetry={refresh} />;
  if (!data || rootId == null || isNaN(rootId))
    return <p style={{ color: "var(--text-muted)" }}>Root not found</p>;

  const { path, trust, top_findings, touched_files, domains, recent_events } = data;

  return (
    <div>
      <p style={{ marginBottom: "1rem" }}>
        <Link to="/" style={{ color: "var(--accent)" }}>← Dashboard</Link>
      </p>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "1rem",
          marginBottom: "1.5rem",
          flexWrap: "wrap",
        }}
      >
        <h2 style={{ fontSize: "1.25rem", fontFamily: "monospace", wordBreak: "break-all" }}>
          {path}
        </h2>
        <StatusPill status={trust as TrustStatus} />
      </div>

      {top_findings.length > 0 && (
        <Card title="Top Findings">
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
            {top_findings.map((f, i) => (
              <span
                key={i}
                style={{
                  padding: "0.25rem 0.5rem",
                  borderRadius: 4,
                  background: "var(--surface-hover)",
                  fontSize: "0.8rem",
                  borderLeft: `3px solid ${
                    f.severity === "high"
                      ? "var(--danger)"
                      : f.severity === "medium"
                      ? "var(--warning)"
                      : "var(--text-muted)"
                  }`,
                }}
              >
                {f.label} ({f.count})
              </span>
            ))}
          </div>
        </Card>
      )}

      <Card title="Touched Files (top 20)">
        {touched_files.length === 0 ? (
          <p style={{ color: "var(--text-muted)" }}>None</p>
        ) : (
          <ul style={{ listStyle: "none", fontSize: "0.85rem", margin: 0, padding: 0 }}>
            {touched_files.map((f, i) => (
              <li
                key={i}
                style={{
                  padding: "0.25rem 0",
                  borderBottom: "1px solid var(--border)",
                  fontFamily: "monospace",
                }}
              >
                <span
                  style={{
                    color:
                      f.op === "delete"
                        ? "var(--danger)"
                        : f.op === "write"
                        ? "var(--warning)"
                        : "var(--text-muted)",
                    marginRight: "0.5rem",
                  }}
                >
                  [{f.op}]
                </span>
                {f.path} <span style={{ color: "var(--text-muted)" }}>(×{f.count})</span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Domains (top 20)">
        {domains.length === 0 ? (
          <p style={{ color: "var(--text-muted)" }}>None</p>
        ) : (
          <ul style={{ listStyle: "none", fontSize: "0.85rem", margin: 0, padding: 0 }}>
            {domains.map((d, i) => (
              <li
                key={i}
                style={{
                  padding: "0.25rem 0",
                  borderBottom: "1px solid var(--border)",
                }}
              >
                {d.domain} — {d.count} req, {formatBytes(d.egress_bytes)}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card
        title={
          <span>
            Raw Events
            <button
              onClick={() => setEventsExpanded(!eventsExpanded)}
              style={{
                marginLeft: "0.5rem",
                fontSize: "0.8rem",
                padding: "0.2rem 0.5rem",
                background: "var(--surface-hover)",
                color: "var(--text)",
              }}
            >
              {eventsExpanded ? "Collapse" : "Show raw timeline"}
            </button>
          </span>
        }
      >
        {eventsExpanded ? (
          <ul style={{ listStyle: "none", fontSize: "0.8rem", margin: 0, padding: 0 }}>
            {recent_events.map((e, i) => (
              <li
                key={i}
                style={{
                  padding: "0.5rem 0",
                  borderBottom: "1px solid var(--border)",
                  fontFamily: "monospace",
                  fontSize: "0.8rem",
                }}
              >
                <div style={{ display: "flex", flexWrap: "wrap", gap: "0.25rem 1rem", alignItems: "baseline" }}>
                  <span style={{ color: "var(--text-muted)", flexShrink: 0 }}>{formatDate(e.ts)}</span>
                  <span
                    style={{
                      padding: "0.1rem 0.35rem",
                      borderRadius: 3,
                      background: e.kind === "fs" ? "rgba(255,193,7,0.2)" : e.kind === "net" ? "rgba(33,150,243,0.2)" : e.kind === "cmd" ? "rgba(76,175,80,0.2)" : "var(--surface-hover)",
                      fontSize: "0.7rem",
                    }}
                  >
                    {e.event_type}
                  </span>
                  <span>{e.summary}</span>
                  {e.details?.path && (
                    <span style={{ color: "var(--accent)", wordBreak: "break-all" }} title={e.details.path}>
                      {e.details.rel_path ?? e.details.path}
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p style={{ color: "var(--text-muted)" }}>
            {recent_events.length} events (expand to view)
          </p>
        )}
      </Card>
    </div>
  );
}
