import { ReactNode } from "react";

export default function Card({
  title,
  children,
}: {
  title?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: 8,
        overflow: "hidden",
        marginBottom: "1rem",
      }}
    >
      {title && (
        <div
          style={{
            padding: "0.75rem 1rem",
            borderBottom: "1px solid var(--border)",
            fontSize: "0.9rem",
            fontWeight: 600,
          }}
        >
          {title}
        </div>
      )}
      <div style={{ padding: "1rem" }}>{children}</div>
    </div>
  );
}
