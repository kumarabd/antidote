import { ReactNode } from "react";

export default function Table({
  headers,
  children,
}: {
  headers: string[];
  children: ReactNode;
}) {
  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.875rem" }}>
      <thead>
        <tr>
          {headers.map((h) => (
            <th
              key={h}
              style={{
                padding: "0.5rem 0.75rem",
                textAlign: "left",
                fontWeight: 600,
                color: "var(--text-muted)",
                borderBottom: "1px solid var(--border)",
              }}
            >
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>{children}</tbody>
    </table>
  );
}
