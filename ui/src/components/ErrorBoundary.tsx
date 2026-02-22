import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("ErrorBoundary caught:", error, info.componentStack);
  }

  render() {
    if (this.state.hasError && this.state.error) {
      if (this.props.fallback) return this.props.fallback;
      return (
        <div
          style={{
            padding: "2rem",
            maxWidth: 600,
            fontFamily: "system-ui, sans-serif",
            color: "#f85149",
            background: "rgba(248,81,73,0.1)",
            borderRadius: 8,
            border: "1px solid var(--danger, #f85149)",
          }}
        >
          <h3 style={{ marginBottom: "0.5rem" }}>Something went wrong</h3>
          <pre
            style={{
              fontSize: "0.85rem",
              overflow: "auto",
              whiteSpace: "pre-wrap",
              marginTop: "1rem",
            }}
          >
            {this.state.error.message}
          </pre>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{
              marginTop: "1rem",
              padding: "0.5rem 1rem",
              background: "var(--accent, #58a6ff)",
              color: "white",
              border: "none",
              borderRadius: 4,
              cursor: "pointer",
            }}
          >
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
