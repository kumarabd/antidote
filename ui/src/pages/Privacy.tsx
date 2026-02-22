import { Link } from "react-router-dom";
import Card from "../components/Card";

export default function Privacy() {
  return (
    <div>
      <h2 style={{ marginBottom: "1rem", fontSize: "1.5rem" }}>What we collect</h2>
      <p style={{ color: "var(--text-muted)", marginBottom: "1.5rem" }}>
        Antidote is local-only. No file contents, prompts, or sensitive data are captured or sent
        anywhere.
      </p>

      <Card title="We collect">
        <ul style={{ paddingLeft: "1.25rem", lineHeight: 1.8 }}>
          <li>File paths + read/write/delete metadata</li>
          <li>Domains contacted + byte counts</li>
          <li>Command names (not full output)</li>
          <li>Timestamps + session boundaries</li>
        </ul>
      </Card>

      <Card title="We do NOT collect">
        <ul style={{ paddingLeft: "1.25rem", lineHeight: 1.8 }}>
          <li>File contents</li>
          <li>Prompt text</li>
          <li>Clipboard content</li>
          <li>Keystrokes</li>
          <li>Passwords (we redact in diagnostics export)</li>
        </ul>
      </Card>

      <p style={{ marginTop: "1.5rem" }}>
        <Link to="/" style={{ color: "var(--accent)" }}>← Back to Dashboard</Link>
      </p>
    </div>
  );
}
