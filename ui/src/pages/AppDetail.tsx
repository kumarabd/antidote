import { Link, useParams } from "react-router-dom";
import { useUIAppDetail } from "../app/hooks";
import { formatDate, formatRelative } from "../app/format";
import StatusPill from "../components/StatusPill";
import type { TrustStatus } from "../app/types";
import Card from "../components/Card";
import Table from "../components/Table";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";

export default function AppDetail() {
  const { app } = useParams<{ app: string }>();
  const { data, error, loading, refresh } = useUIAppDetail(app);

  if (loading && !data) return <Loading />;
  if (error && !data)
    return <ErrorState error={error} onRetry={refresh} />;
  if (!data || !app)
    return <p style={{ color: "var(--text-muted)" }}>App not found</p>;

  const { active_sessions, recent_sessions, roots_with_trust } = data;

  const sessions = [...active_sessions, ...recent_sessions];

  return (
    <div>
      <p style={{ marginBottom: "1rem" }}>
        <Link to="/" style={{ color: "var(--accent)" }}>← Dashboard</Link>
      </p>

      <h2 style={{ fontSize: "1.5rem", marginBottom: "1.5rem" }}>{app}</h2>

      <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap", marginBottom: "1.5rem" }}>
        <Card>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Active sessions</div>
          <div style={{ fontSize: "1.25rem", fontWeight: 600 }}>{active_sessions.length}</div>
        </Card>
        <Card>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Recent sessions</div>
          <div style={{ fontSize: "1.25rem", fontWeight: 600 }}>{recent_sessions.length}</div>
        </Card>
        <Card>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Roots</div>
          <div style={{ fontSize: "1.25rem", fontWeight: 600 }}>{roots_with_trust.length}</div>
        </Card>
      </div>

      {roots_with_trust.length > 0 && (
        <Card title="Roots (trust from events — Open for details)">
          <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: "0.75rem" }}>
            Roots observed by this app. Open a root to see events, touched files, and domains.
          </p>
          <ul style={{ listStyle: "none", fontSize: "0.85rem", fontFamily: "monospace", margin: 0, padding: 0 }}>
            {roots_with_trust.map((r) => (
              <li
                key={r.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.75rem",
                  padding: "0.5rem 0",
                  borderBottom: "1px solid var(--border)",
                  wordBreak: "break-all",
                }}
              >
                <StatusPill status={r.trust as TrustStatus} />
                <span style={{ flex: 1 }}>{r.path}</span>
                <Link to={`/roots/${r.id}`} style={{ color: "var(--accent)", fontSize: "0.9rem", flexShrink: 0 }}>
                  Open
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card title="Sessions">
        <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: "0.75rem" }}>
          Active and recent sessions for this app. Open roots above to see event details.
        </p>
        {sessions.length === 0 ? (
          <p style={{ color: "var(--text-muted)" }}>No sessions for this app</p>
        ) : (
          <Table
            headers={[
              "Started",
              "Last Active",
              "Risk",
              "Drift",
              "Events",
            ]}
          >
            {sessions.map((s) => (
              <tr key={s.id} style={{ borderBottom: "1px solid var(--border)" }}>
                <td style={{ padding: "0.5rem 0.75rem" }}>{formatDate(s.started_at)}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  {s.last_active_ts ? formatRelative(s.last_active_ts) : "—"}
                </td>
                <td style={{ padding: "0.5rem 0.75rem" }}>{s.risk_score}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>{s.drift_score}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>{s.event_count}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
