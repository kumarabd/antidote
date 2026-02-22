export type TrustStatus = "Trusted" | "NeedsReview" | "Risky";
export type ConfidenceLevel = "High" | "Medium" | "Low";
export type HealthStatus = "Healthy" | "Degraded" | "Unhealthy";

export interface Warning {
  code: string;
  severity: string;
  message?: string;
}

export interface SessionSummaryRow {
  id: string;
  app: string;
  started_at: string;
  last_active_ts?: string;
  ended_at?: string;
  trust: TrustStatus;
  risk_score: number;
  drift_score: number;
  event_count: number;
}

export interface GlobalState {
  trust: TrustStatus;
  confidence: ConfidenceLevel;
  health: HealthStatus;
  reasons: string[];
  warnings: Warning[];
}

export interface UIStateResponse {
  version: string;
  now: string;
  global: GlobalState;
  active_sessions: SessionSummaryRow[];
  recent_sessions: SessionSummaryRow[];
}

export interface TopFinding {
  label: string;
  severity: "low" | "medium" | "high";
  count: number;
  examples: string[];
}

export interface TouchedFile {
  path: string;
  op: "read" | "write" | "delete";
  count: number;
}

export interface DomainContact {
  domain: string;
  count: number;
  egress_bytes: number;
}

export interface RecentEvent {
  ts: string;
  kind: "fs" | "net" | "cmd" | "flag";
  summary: string;
  attribution_reason?: string;
  confidence?: string;
}

export interface SessionDiagnostics {
  telemetry_confidence: ConfidenceLevel;
  attribution_quality: number;
  root_coverage: number;
}

export interface UISessionResponse {
  session: SessionSummaryRow & {
    duration_seconds?: number;
    summary_json?: Record<string, unknown>;
  };
  top_findings: TopFinding[];
  touched_files: TouchedFile[];
  domains: DomainContact[];
  recent_events: RecentEvent[];
  diagnostics: SessionDiagnostics;
}
