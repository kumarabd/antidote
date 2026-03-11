import type { TrustStatus, ConfidenceLevel, HealthStatus } from "../app/types";

type Status = TrustStatus | ConfidenceLevel | HealthStatus;

const styles: Record<string, React.CSSProperties> = {
  Trusted: { background: "var(--success)", color: "#fff" },
  NeedsReview: { background: "var(--warning)", color: "#000" },
  Risky: { background: "var(--danger)", color: "#fff" },
  High: { background: "var(--success)", color: "#fff" },
  Medium: { background: "var(--warning)", color: "#000" },
  Low: { background: "var(--danger)", color: "#fff" },
  Healthy: { background: "var(--success)", color: "#fff" },
  Degraded: { background: "var(--warning)", color: "#000" },
  Unhealthy: { background: "var(--danger)", color: "#fff" },
};

const FALLBACK_STYLE = { background: "var(--surface-hover)", color: "var(--text)" };

export default function StatusPill({ status }: { status: Status }) {
  const s = status != null ? String(status) : "";
  const style = s && styles[s] ? styles[s] : FALLBACK_STYLE;
  return (
    <span
      style={{
        display: "inline-block",
        padding: "0.2rem 0.6rem",
        borderRadius: 12,
        fontSize: "0.75rem",
        fontWeight: 600,
        ...style,
      }}
    >
      {s || "—"}
    </span>
  );
}
