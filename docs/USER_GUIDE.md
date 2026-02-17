# Antidote User Guide

This guide explains how to install and use Antidote on your Mac.

## What Antidote Does

Antidote is a **local-only** monitor for AI-related apps (Cursor, Claude, VS Code, etc.). It:

- **Tracks activity** – Process starts/stops, file changes under watched folders, and network traffic through its proxy (metadata only; no file contents, no decrypted HTTPS).
- **Scores risk** – Uses rules (sensitive file writes, dangerous commands, unknown domains, high egress, etc.) to assign a risk score and labels to each session.
- **Learns behavior** – Builds a per-app baseline and can flag anomalies and repeated high-risk patterns (Phase 5).
- **Optional enforcement** – Can block unknown domains or dangerous commands and supports an emergency “freeze” of AI activity (Phase 6; experimental).

Everything stays on your machine; no cloud or AI calls.

---

## Requirements

- **macOS** (Intel or Apple Silicon)
- **Rust** (stable): install from [rustup.rs](https://rustup.rs) and run `rustup default stable`
- For **audit-based telemetry** (Phase 4): root/sudo to read from the audit pipe (optional)

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-org/antidote.git
cd antidote
```

(Replace with your actual repo URL.)

### 2. Build the daemon

```bash
cargo build -p antidote-daemon --release
```

The binary will be at `target/release/antidote-daemon`.

### 3. (Optional) Install somewhere on your PATH

```bash
cp target/release/antidote-daemon /usr/local/bin/
# or any directory on your PATH
```

---

## Running Antidote

### Start the daemon

From the project root (so it can find `./rules/rules.yaml` and create `./var/monitor.db`):

```bash
cargo run -p antidote-daemon
```

Or, if you installed the binary:

```bash
antidote-daemon
```

You should see logs like:

- Storage initialized  
- Rules engine loaded  
- Session manager initialized  
- FS watcher initialized  
- Starting API server on 127.0.0.1:17845  
- Proxy server listening on 127.0.0.1:17846 (if proxy enabled)

Press **Ctrl+C** to stop.

### Run with debug logging

```bash
RUST_LOG=antidote=debug cargo run -p antidote-daemon
```

---

## First Steps

### 1. Check that it’s running

```bash
curl http://127.0.0.1:17845/health
# Expected: {"ok":true}
```

### 2. Open the dashboard

In your browser, open:

**http://127.0.0.1:17845/ui/**

You’ll see:

- **Sessions** – Table of sessions (app, risk, score, labels). Click a row for details.
- **Session detail** – Counts (files written/deleted, bytes out, unknown domains), drift badge and baseline comparison (when available), flags, and recent events.

### 3. Add a watched folder

So that file activity is attributed to sessions, add at least one “watched root”:

```bash
curl -X POST http://127.0.0.1:17845/roots \
  -H "Content-Type: application/json" \
  -d '{"path": "/Users/you/your-project"}'
```

Replace with a real path. The daemon will watch that directory for file writes/creates/deletes/renames.

### 4. Use the proxy (optional)

To capture **network** telemetry (domains and bytes):

1. Confirm proxy is listening: `curl http://127.0.0.1:17845/proxy/status`
2. Set your system (or browser) HTTP/HTTPS proxy to `127.0.0.1:17846`.

Then traffic from apps using that proxy will appear in session counts and can trigger rules (e.g. unknown domain, high egress). The proxy does **not** decrypt HTTPS or log content.

---

## Main features

### Sessions and risk

- **Sessions** are created when watched processes (e.g. Cursor) start and end after an idle timeout (default 7 minutes).
- Each session has a **risk score** (0–100) and **labels** (e.g. SENSITIVE_ACCESS, UNKNOWN_ENDPOINT) from the rule engine.
- **Session summary** includes counts, evidence (sensitive paths, unknown domains), and (when computed) **drift index** and **baseline comparison** text.

### Focus (foreground session)

For better attribution of network (and some FS) events, you can set the “focus” session (e.g. the app you’re actively using):

- In the UI: open a session and click **Set Focus**.
- Via API: `POST /debug/focus` with `{"session_id": "..."}`.

### Insights (Phase 5)

- **http://127.0.0.1:17845/ui/insights** – Risk trend (last 7 days), top repeated risk patterns, sessions with drift, per-app baselines.
- **GET /baselines** – Raw baseline data per app.
- **GET /insights** – JSON used by the insights page.

### Security and enforcement (Phase 6, experimental)

- **http://127.0.0.1:17845/ui/security** – Toggles for enforcement (block unknown domains, block dangerous commands, etc.), **Freeze AI Activity** button, and safe mode.
- **Enforcement** is off by default. When enabled, the proxy can block unknown domains; the pipeline can block dangerous commands (with audit) and safe mode can restrict domains and file writes.
- **Emergency freeze** stops new proxy connections and terminates active AI sessions. Use with caution; see the in-app warning on the Security page.

---

## Configuration

Defaults are in the daemon code; key values:

| Item              | Default                    |
|-------------------|----------------------------|
| Database          | `./var/monitor.db`         |
| API address       | `127.0.0.1:17845`         |
| Proxy address     | `127.0.0.1:17846`         |
| Rules file        | `./rules/rules.yaml`       |
| Watched processes | Cursor, Code, Claude      |
| Idle timeout      | 7 minutes                 |
| Retention         | 7 days                    |

To change behavior you currently need to edit the daemon config struct or pass a config file if the daemon adds support for it. Rules (known domains, sensitive paths, thresholds) are in **rules/rules.yaml**.

---

## API quick reference

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /sessions` | List sessions (query: limit, offset, since, until) |
| `GET /sessions/:id/summary` | Session summary (includes drift if set) |
| `GET /sessions/:id/events` | Events for a session |
| `GET /sessions/:id/flags` | Flags for a session |
| `GET /roots` | List watched roots |
| `POST /roots` | Add root `{"path":"..."}` |
| `GET /capabilities` | Audit/proxy/FS status |
| `GET /baselines` | App baselines (Phase 5) |
| `GET /insights` | Risk trend, repeated risk, drift, baselines |
| `GET /enforcement` | Enforcement and safe mode state |
| `POST /enforcement` | Update enforcement (e.g. `{"enabled":true}`) |
| `POST /emergency/freeze` | Freeze AI activity |
| `POST /emergency/unfreeze` | Unfreeze |
| `GET /debug/focus` | Current focus session |
| `POST /debug/focus` | Set focus `{"session_id":"..."}` |
| `POST /debug/emit` | Emit a test event (debug) |

---

## Database

The SQLite database is created at **./var/monitor.db** (or as configured). You can inspect it with:

```bash
sqlite3 ./var/monitor.db
.tables
SELECT * FROM sessions LIMIT 5;
```

---

## Audit mode (Phase 4, optional)

For process-level events (execve, file open, network connect) you can run with **macOS audit**:

1. See **scripts/audit_setup.md** for enabling and configuring audit.
2. Run the daemon with **sudo**: `sudo cargo run -p antidote-daemon`
3. Check: `curl http://127.0.0.1:17845/capabilities` – `audit_collector_active` should be true.

Only use audit in a trusted/dev environment; it requires root.

---

## Troubleshooting

- **“Daemon not reachable”** – Ensure the daemon is running and nothing else is using port 17845.
- **No sessions** – Start Cursor (or another watched app) or use `POST /debug/emit` to generate events for a test session.
- **No file events** – Add a watched root that contains the files you’re changing; ensure the path is correct and the daemon has read access.
- **No network events** – Configure the app (or system) to use the proxy at 127.0.0.1:17846.
- **Enforcement not blocking** – Ensure `POST /enforcement` was used to set `enabled` and the relevant options (e.g. `block_unknown_domains`); see Phase 6 docs.

For more on testing, see [Testing](TESTING.md). For architecture and packages, see [Architecture](ARCHITECTURE.md).
