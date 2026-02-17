# Antidote Architecture

This document explains the structure of the Antidote codebase: what each package does and how data flows through the system.

## Overview

Antidote is a **macOS-only** Rust application that monitors AI-related activity (Cursor, Claude, VS Code, etc.) using:

- **Process polling** and (optionally) **macOS audit** for process and file/network events
- **File system watcher** for writes/creates/deletes/renames under watched roots
- **HTTP proxy** for network telemetry (domain + bytes; no HTTPS decryption)
- **Rule engine** for deterministic risk scoring and flags
- **Behavioral baseline** (Phase 5) for anomaly detection and drift
- **Enforcement** (Phase 6) for optional blocking and emergency freeze

All processing is **local**; no AI/LLM calls; no cloud.

---

## Workspace layout

```
antidote/
├── Cargo.toml                 # Workspace manifest
├── rules/
│   └── rules.yaml             # Rules config (known_domains, globs, thresholds)
├── crates/
│   ├── core/                  # Shared types and constants
│   ├── collectors/            # Event sources (process, FS, proxy, audit)
│   ├── session/               # Session lifecycle and attribution
│   ├── ruleengine/           # Rule evaluation and risk scoring
│   ├── behavior/             # Baselines, anomaly, drift, risk memory
│   ├── storage/              # SQLite persistence and migrations
│   ├── api/                   # HTTP API and UI
│   └── daemon/                # Main binary and pipeline
├── docs/                      # Documentation
└── scripts/                   # Test and setup scripts
```

---

## Crates (packages)

### antidote-core

**Purpose:** Shared types and configuration used across the rest of the system.

**What it contains:**

- **Event types:** `Event`, `EventType` (Heartbeat, ProcStart, FileWrite, NetHttp, CmdExec, etc.)
- **Session:** `SessionSummary` (counts, risk, labels, evidence, drift_index, enforcement fields)
- **Risk:** `RiskSummary`, `RiskBucket`, `Severity`, `Label`
- **Evidence:** `Evidence` (sensitive_paths, unknown_domains, dangerous_commands)
- **Flags:** `Flag` (rule_id, severity, weight, label, message)
- **Config:** `EnforcementConfig`, `SafeModeConfig` (Phase 6)
- **Payload helpers:** `payloads::NetPayload`, `ProcPayload`, etc.

**Why it exists:** So that daemon, api, storage, ruleengine, behavior, and collectors all use the same definitions for events, sessions, and flags without circular dependencies. Core has no I/O; it is the “contract” of the system.

---

### antidote-collectors

**Purpose:** Produce **events** that the rest of the system consumes.

**What it contains:**

- **ProcessPoller:** Periodically scans running processes (e.g. Cursor, Code, Claude), emits `ProcStart` / `ProcExit`.
- **FsWatcherManager:** Uses `notify` to watch configured roots; emits `FileWrite`, `FileCreate`, `FileDelete`, `FileRename` (debounced).
- **ProxyServer:** Listens for HTTP/CONNECT traffic; extracts domain; can block when enforcement/safe mode is on; emits `NetHttp` (and optionally sends `Flag`s for blocks).
- **AuditCollector** (macOS): Reads from `/dev/auditpipe` via `praudit`; emits `CmdExec`, `FileRead`, `FileWrite`, `NetConnect` with pid/ppid; maintains a process tree for attribution.

**Why it exists:** Decouples “how we see the world” (process list, FS, proxy, audit) from “what we do with it” (sessions, rules, storage). Collectors only send events on a channel; they do not know about sessions or rules.

---

### antidote-session

**Purpose:** Session **lifecycle** and **attribution**: which events belong to which session.

**What it contains:**

- **SessionState:** Summary, last_event_ts, candidate_roots, observed_roots.
- **SessionManager:** Maps root_pid → session_id; creates/ends sessions; idle timeout; **foreground session** (focus) for attribution; `get_or_assign_session`, `get_sessions_for_path`, `get_active_sessions`, `force_end_sessions` (Phase 6).

**Why it exists:** The pipeline and API need a single place that decides “this event belongs to session X.” Session manager owns that mapping and the concept of “active” vs “ended” and “foreground.”

---

### antidote-ruleengine

**Purpose:** Turn **events** and **session state** into **flags** and **risk score**.

**What it contains:**

- **RuleEngine:** Loads `rules.yaml` (known_domains, sensitive/benign globs, thresholds). `evaluate_event(event, session_state)` returns new flags and updates session state (counts, evidence, labels).
- **SessionState** (ruleengine): Counts, evidence, label set, rule-hit tracking, timestamps for windows.
- **Rules:** R1–R15+ (sensitive file write, shell persistence, dangerous command, unknown domain, egress, bulk delete/write, secrets hunting, exfil, etc.). Uses globset for path matching and `is_known_domain` / `is_dangerous_command`.

**Why it exists:** All “is this suspicious?” logic lives in one place with a clear contract: event + state → new flags + updated state. Storage and daemon do not interpret rules; they only persist flags and summaries.

---

### antidote-behavior

**Purpose:** **Behavioral baseline**, **anomaly detection**, **risk memory**, and **drift** (Phase 5).

**What it contains:**

- **AppBaseline:** Per-app EMA of files_written, bytes_out, unknown_domains, cmds, etc., plus variances.
- **update_baseline_ema:** Called when a session ends; updates baseline from current counts.
- **detect_anomalies:** Z-score vs baseline; emits ANOMALOUS_* flags (e.g. file activity, egress, domain, command) when over threshold.
- **Risk history / check_escalation:** Tracks (app, rule_id) counts; emits ESCALATING_PATTERN when same high-severity rule triggers ≥3 times in 7 days.
- **compute_drift_index, build_baseline_comparison_summary:** Drift 0–100 and human-readable comparison text.

**Why it exists:** Phase 5 adds “normal vs not” and “repeated bad pattern” on top of rule-only scoring. Behavior is pure logic; storage holds baselines and risk_history; daemon wires “on session end” and “on flag persist.”

---

### antidote-storage

**Purpose:** **Persistence** for sessions, events, flags, roots, baselines, and risk history.

**What it contains:**

- **Storage:** SQLite via sqlx. Methods: `upsert_session_summary`, `insert_event`, `insert_flags`, `list_sessions`, `get_session`, `list_events`, `list_flags`, `get_enabled_roots`, `add_watched_root`, etc.
- **Migrations:** 0001_init through 0007_enforcement (sessions, events, flags, roots, observed_roots, audit fields, behavioral tables, enforcement columns).
- **AppBaselineRow, risk_history:** Tables and accessors for Phase 5/6.
- **Labels and SessionSummary fields:** All phases (including drift_index, forced_terminated, enforcement_actions_count).

**Why it exists:** Single place for all DB schema and access. Daemon and API both use `Storage`; no direct SQL elsewhere.

---

### antidote-api

**Purpose:** **HTTP API** and **static UI** for humans and scripts.

**What it contains:**

- **Router (axum):** Routes for health, sessions, roots, proxy/status, debug (emit, focus, db, prune), capabilities, baselines, insights, enforcement (GET/POST), emergency freeze/unfreeze, and UI (/, /ui/insights, /ui/security).
- **ApiState:** Holds storage, session_manager, proxy config, enforcement/safe_mode/frozen state, freeze_tx.
- **Static pages:** index.html (dashboard), insights.html, security.html (Phase 5/6).

**Why it exists:** So the daemon can serve a local dashboard and a stable API for automation without embedding all UI logic in the daemon crate. API is the only HTTP surface.

---

### antidote-daemon

**Purpose:** **Orchestration**: run collectors, pipeline, API, idle task, retention, and (Phase 6) freeze and proxy-flag consumer.

**What it contains:**

- **main:** Load config, init storage, load baselines into memory, load rule engine, create session manager, event channel. Spawn: API server, process poller, tick, **pipeline worker**, **idle task** (session end → baseline update, anomaly, escalation, drift), retention prune, **proxy-flag consumer**, **freeze task**, and (if enabled) proxy server. On shutdown: signal tasks, drop channels, join handles.
- **PipelineWorker:** Receives events; resolves session_id (path, pid, focus); updates session; runs rule engine; persists events and flags; records risk history for high/crit; (Phase 6) dangerous-command blocking and safe-mode path checks. Uses storage, rule_engine, session_manager, enforcement, safe_mode.
- **run_emergency_freeze:** Kill active session root processes, mark sessions forced_terminated, persist and emit EMERGENCY_FREEZE flags.

**Why it exists:** The daemon is the only binary. It wires “who produces events,” “who consumes them,” “when to update baselines,” and “when to block or freeze.” Pipeline is the central “event → session → rules → storage” flow.

---

## Data flow (high level)

1. **Events in:** ProcessPoller, FsWatcher, Proxy, (optional) AuditCollector send `Event` into a single channel.
2. **Pipeline:** Reads events in batches; for each event:
   - Resolves **session_id** (session manager: path, pid, focus).
   - Updates session last_event_ts (session manager).
   - Gets/creates **SessionState** (ruleengine); runs **RuleEngine.evaluate_event** → new flags and updated state.
   - Persists event (storage) and flags (storage); records risk_history for high/crit.
   - (Phase 6) If CmdExec + dangerous and enforcement: kill process, persist BLOCKED_COMMAND. If safe mode and write outside allowed_roots: persist SAFE_MODE_VIOLATION.
   - Updates **session summary** (storage) from session state + session manager.
3. **Idle task (periodic):** For each session that just ended (idle timeout):
   - Updates **app baseline** (EMA), writes to storage and in-memory cache.
   - Runs **anomaly detection**; **escalation** from risk_history; persists new flags and risk_history.
   - Computes **drift index** and **baseline comparison**; writes summary to storage.
4. **Proxy:** If enforcement/safe mode on, can deny request and send a **Flag** (e.g. BLOCKED_DOMAIN) into a channel; daemon task persists those flags.
5. **Freeze:** API POST freeze sets frozen and notifies daemon; daemon task kills sessions and marks them forced_terminated.
6. **API/UI:** Read sessions, events, flags, baselines, insights, enforcement from storage and in-memory state; serve HTML and JSON.

---

## Dependency graph (conceptual)

```
daemon
  ├── api (router, handlers)
  ├── pipeline (uses storage, ruleengine, session, behavior, enforcement)
  ├── collectors (process, fs, proxy, audit)
  ├── storage
  ├── ruleengine
  ├── session
  └── behavior

api
  ├── core
  ├── storage
  └── session

storage, ruleengine, session, behavior, collectors
  └── core
```

Core has no dependencies on other antidote crates. Storage, ruleengine, session, and behavior depend only on core (and std/tokio/serde/etc.). API and daemon tie them together.

---

## Configuration and defaults

- **Database:** `sqlite:./var/monitor.db` (daemon creates `var` if needed).
- **API listen:** `127.0.0.1:17845`.
- **Proxy listen:** `127.0.0.1:17846`.
- **Rules:** `./rules/rules.yaml`.
- **Watched processes:** Cursor, Code, Claude (configurable in daemon Config).
- **Idle timeout:** 7 minutes.
- **Retention:** 7 days (events, flags, risk_history pruned).
- **Enforcement / safe mode:** Off by default; toggled via API or config.

For more on how to run and configure the system, see [User Guide](USER_GUIDE.md). For testing, see [Testing](TESTING.md).
