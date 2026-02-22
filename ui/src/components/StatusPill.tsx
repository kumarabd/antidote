import type { TrustStatus } from "../app/types";

const styles: Record<string, React.CSSProperties> = {
  Trusted: { background: "var(--success)", color: "#fff" },
  NeedsReview: { background: "var(--warning)", color: "#000" },
  Risky: { background: "var(--danger)", color: "#fff" },
};

export default function StatusPill({ status }: { status: TrustStatus }) {
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
