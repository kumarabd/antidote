import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useUISession } from "../app/hooks";
import { formatDate, formatBytes, formatDuration } from "../app/format";
import StatusPill from "../components/StatusPill";
import Card from "../components/Card";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";

export default function SessionDetail() {
  const { id } = useParams<{ id: string }>();
  const [eventsExpanded, setEventsExpanded] = useState(false);
  const { data, error, loading, refresh } = useUISession(id);

  if (loading && !data) return <Loading />;
  if (error && !data)
    return (
      <ErrorState
        error={error}
        onRetry={refresh}
      />
    );
  if (!data || !id)
    return (
      <p style={{ color: "var(--text-muted)" }}>Session not found</p>
    );

  const { session, top_findings, touched_files, domains, recent_events, diagnostics } = data;
  const dur = session.duration_seconds ?? 0;

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
        <h2 style={{ fontSize: "1.5rem" }}>
          {session.app} — {formatDate(session.started_at)}
        </h2>
        <StatusPill status={session.trust} />
        {dur > 0 && (
          <span style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>
            Duration: {formatDuration(dur)}
          </span>
        )}
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(140px, 1fr))",
          gap: "1rem",
          marginBottom: "1.5rem",
        }}
      >
        <Card>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Risk</div>
          <div style={{ fontSize: "1.25rem", fontWeight: 600 }}>{session.risk_score}</div>
        </Card>
        <Card>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Drift</div>
          <div style={{ fontSize: "1.25rem", fontWeight: 600 }}>{session.drift_score}</div>
        </Card>
        <Card>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Events</div>
          <div style={{ fontSize: "1.25rem", fontWeight: 600 }}>{session.event_count}</div>
        </Card>
        <Card>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Egress</div>
          <div style={{ fontSize: "1.25rem", fontWeight: 600 }}>
            {formatBytes(
              domains.reduce((s, d) => s + d.egress_bytes, 0)
            )}
          </div>
        </Card>
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
          <ul style={{ listStyle: "none", fontSize: "0.85rem" }}>
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
          <ul style={{ listStyle: "none", fontSize: "0.85rem" }}>
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
              {eventsExpanded ? "Collapse" : "Expand"}
            </button>
          </span>
        }
      >
        {eventsExpanded ? (
          <ul style={{ listStyle: "none", fontSize: "0.8rem" }}>
            {recent_events.map((e, i) => (
              <li
                key={i}
                style={{
                  padding: "0.35rem 0",
                  borderBottom: "1px solid var(--border)",
                  fontFamily: "monospace",
                }}
              >
                {formatDate(e.ts)} [{e.kind}] {e.summary}
                {e.attribution_reason && (
                  <span style={{ color: "var(--text-muted)" }}>
                    {" "}
                    attr={e.attribution_reason}
                    {e.confidence && ` conf=${e.confidence}`}
                  </span>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <p style={{ color: "var(--text-muted)" }}>
            {recent_events.length} events (expand to view)
          </p>
        )}
      </Card>

      <Card title="Diagnostics">
        <div style={{ fontSize: "0.9rem" }}>
          Telemetry: {diagnostics.telemetry_confidence} · Attribution:{" "}
          {(diagnostics.attribution_quality * 100).toFixed(0)}% · Root coverage:{" "}
          {(diagnostics.root_coverage * 100).toFixed(0)}%
        </div>
      </Card>
    </div>
  );
}
