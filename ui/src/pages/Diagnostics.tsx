import { useState, useCallback } from "react";
import { useDiagnostics } from "../app/hooks";
import Card from "../components/Card";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [text]);
  return (
    <button
      onClick={copy}
      style={{
        padding: "0.3rem 0.6rem",
        fontSize: "0.8rem",
        background: "var(--surface-hover)",
        color: "var(--text)",
        border: "1px solid var(--border)",
      }}
    >
      {copied ? "Copied" : "Copy JSON"}
    </button>
  );
}

function JsonBlock({
  title,
  data,
}: {
  title: string;
  data: unknown;
}) {
  const str =
    data == null
      ? "null"
      : typeof data === "object"
      ? JSON.stringify(data, null, 2)
      : String(data);

  return (
    <Card title={title}>
      <div
        style={{
          display: "flex",
          justifyContent: "flex-end",
          marginBottom: "0.5rem",
        }}
      >
        <CopyButton text={str} />
      </div>
      <pre
        style={{
          background: "var(--bg)",
          padding: "1rem",
          borderRadius: 4,
          overflow: "auto",
          fontSize: "0.8rem",
          maxHeight: 400,
        }}
      >
        {str}
      </pre>
    </Card>
  );
}

export default function Diagnostics() {
  const {
    zeroConfig,
    health,
    confidence,
    error,
    loading,
    refresh,
  } = useDiagnostics();

  if (loading && !zeroConfig && !health && !confidence)
    return <Loading />;
  if (error && !zeroConfig && !health && !confidence)
    return <ErrorState error={error} onRetry={refresh} />;

  return (
    <div>
      <h2 style={{ marginBottom: "1rem", fontSize: "1.5rem" }}>Diagnostics</h2>

      {zeroConfig != null && (
        <JsonBlock title="Zero Config Status" data={zeroConfig} />
      )}
      {health != null && <JsonBlock title="Health" data={health} />}
      {confidence != null && <JsonBlock title="Confidence" data={confidence} />}

      {zeroConfig == null && health == null && confidence == null && (
        <p style={{ color: "var(--text-muted)" }}>
          No diagnostic data available. Ensure the daemon is running and debug
          endpoints are enabled.
        </p>
      )}
    </div>
  );
}
