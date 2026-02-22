export default function ErrorState({
  error,
  onRetry,
}: {
  error: Error;
  onRetry?: () => void;
}) {
  return (
    <div
      style={{
        padding: "2rem",
        background: "rgba(248, 81, 73, 0.1)",
        border: "1px solid var(--danger)",
        borderRadius: 8,
        textAlign: "center",
      }}
    >
      <p style={{ color: "var(--danger)", marginBottom: "1rem" }}>{error.message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          style={{
            padding: "0.5rem 1rem",
            background: "var(--surface)",
            color: "var(--text)",
            border: "1px solid var(--border)",
          }}
        >
          Retry
        </button>
      )}
    </div>
  );
}
