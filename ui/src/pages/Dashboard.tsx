import { Link } from "react-router-dom";
import { useUIState } from "../app/hooks";
import { formatDate, formatRelative } from "../app/format";
import StatusPill from "../components/StatusPill";
import Card from "../components/Card";
import Table from "../components/Table";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";

export default function Dashboard() {
  const { data, error, loading, refresh } = useUIState();

  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorState error={error} onRetry={refresh} />;

  const state = data!;
  const { global, active_sessions, recent_sessions } = state;

  return (
    <div>
      <h2 style={{ marginBottom: "1rem", fontSize: "1.5rem" }}>Dashboard</h2>

      <Card title="Trust Status">
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "1rem",
            flexWrap: "wrap",
          }}
        >
          <StatusPill status={global.trust} />
          <span style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>
            Health: {global.health} · Confidence: {global.confidence}
          </span>
        </div>
        {global.reasons.length > 0 && (
          <p
            style={{
              marginTop: "0.75rem",
              fontSize: "0.85rem",
              color: "var(--text-muted)",
            }}
          >
            {global.reasons.join("; ")}
          </p>
        )}
        {global.warnings.length > 0 && (
          <ul
            style={{
              marginTop: "0.5rem",
              fontSize: "0.85rem",
              color: "var(--warning)",
              paddingLeft: "1.25rem",
            }}
          >
            {global.warnings.map((w, i) => (
              <li key={i}>
                [{w.severity}] {w.message || w.code}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Active Sessions">
        {active_sessions.length === 0 ? (
          <p style={{ color: "var(--text-muted)" }}>No active sessions</p>
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
            {active_sessions.map((s) => (
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
      </Card>

      <Card title="Recent Sessions">
        {recent_sessions.length === 0 ? (
          <p style={{ color: "var(--text-muted)" }}>No recent sessions</p>
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
            {recent_sessions.map((s) => (
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
