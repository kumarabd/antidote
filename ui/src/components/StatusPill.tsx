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

export default function StatusPill({ status }: { status: Status }) {
  return (
    <span
      style={{
        display: "inline-block",
        padding: "0.2rem 0.6rem",
        borderRadius: 12,
        fontSize: "0.75rem",
        fontWeight: 600,
        ...styles[status],
      }}
    >
      {status}
    </span>
  );
}
