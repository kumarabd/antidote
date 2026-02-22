import { ReactNode } from "react";
import { Link } from "react-router-dom";

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <header
        style={{
          background: "var(--surface)",
          borderBottom: "1px solid var(--border)",
          padding: "1rem 1.5rem",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <Link to="/" style={{ color: "var(--text)", textDecoration: "none" }}>
          <h1 style={{ fontSize: "1.25rem", fontWeight: 600 }}>Antidote</h1>
        </Link>
        <nav style={{ display: "flex", gap: "1.5rem" }}>
          <Link to="/" style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>
            Dashboard
          </Link>
          <Link
            to="/diagnostics"
            style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}
          >
            Diagnostics
          </Link>
        </nav>
      </header>
      <main style={{ flex: 1, padding: "1.5rem", maxWidth: 1200, margin: "0 auto", width: "100%" }}>
        {children}
      </main>
    </div>
  );
}
