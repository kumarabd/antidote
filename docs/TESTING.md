# Testing Antidote

This document describes how to test and verify all Antidote features. Use the test script for automated checks and the manual steps for targeted verification.

## Prerequisites

- **macOS** (required for full feature set; some tests skip on other platforms)
- **Rust** toolchain: `rustup default stable`
- **curl** and **jq** (for the test script and examples)
- Daemon running: `cargo run -p antidote-daemon` (in another terminal)

Default API base: `http://127.0.0.1:17845`  
Default proxy: `127.0.0.1:17846`

---

## Automated Test Script

The repository includes a test script that exercises core flows.

### Run the full test script

```bash
# From the repo root, with the daemon already running
./test.sh
```

Environment variables (optional):

| Variable    | Default                     | Description                    |
|------------|-----------------------------|--------------------------------|
| `API_BASE` | `http://127.0.0.1:17845`   | API base URL                   |
| `PROXY_ADDR` | `127.0.0.1:17846`        | Proxy host:port for curl -x    |
| `TEST_ROOT` | Project path               | Watched root for FS activity   |
| `VERBOSE`   | `0`                        | Set to `1` to print more output |

Example:

```bash
VERBOSE=1 ./test.sh
```

### What the script does

1. **Health** – `GET /health`, expects `{"ok": true}`.
2. **Capabilities** – `GET /capabilities` (audit/proxy/FS status).
3. **Watched roots** – Add a test root, list roots (and delete if present).
4. **Cursor session** – Waits for a Cursor session (user can open Cursor), sets focus.
5. **FS activity** – Writes/renames/deletes under `TEST_ROOT`, including `.env` and bulk delete pattern.
6. **Session report** – Fetches session summary, flags, and optionally events.
7. **Flag checks** – Best-effort assert for flags like `SENSITIVE_FILE_WRITE`, `BULK_DELETE`, `UNKNOWN_DOMAIN_CONTACT`, `HIGH_EGRESS`.
8. **Proxy** – Sends traffic through the proxy (example.com + optional large download).
9. **Audit note** – Reminds that Phase 4 audit affects event types (e.g. FileRead).

---

## Unit Tests

Run the full test suite:

```bash
cargo test
```

Run tests for a specific crate:

```bash
cargo test -p antidote-core
cargo test -p antidote-behavior
cargo test -p antidote-ruleengine
cargo test -p antidote-session
cargo test -p antidote-storage
cargo test -p antidote-collectors
```

Notable test coverage:

- **antidote-behavior**: EMA baseline update, drift bucket, z-score anomaly, zero variance, min-sessions, escalation, drift index bounds, baseline persistence (in-memory).
- **antidote-ruleengine**: Rule hit caps, dangerous command detection, known-domain matching.
- **antidote-collectors**: Domain allowlist (proxy blocking / safe mode).
- **antidote-core**: Enforcement and safe mode defaults.
- **antidote-session**: Force-end sessions (empty / nonexistent).

---

## Manual Verification by Feature

### 1. Health and API

```bash
curl -s http://127.0.0.1:17845/health | jq .
# Expected: {"ok":true}
```

### 2. Sessions

```bash
# List sessions (recent first)
curl -s "http://127.0.0.1:17845/sessions?limit=10" | jq .

# Get one session
curl -s "http://127.0.0.1:17845/sessions/<SESSION_ID>" | jq .

# Session summary (includes drift_index, baseline_comparison_summary when set)
curl -s "http://127.0.0.1:17845/sessions/<SESSION_ID>/summary" | jq .

# Events and flags
curl -s "http://127.0.0.1:17845/sessions/<SESSION_ID>/events?limit=20" | jq .
curl -s "http://127.0.0.1:17845/sessions/<SESSION_ID>/flags" | jq .
```

### 3. Watched roots

```bash
curl -s http://127.0.0.1:17845/roots | jq .
curl -X POST http://127.0.0.1:17845/roots -H "Content-Type: application/json" -d '{"path":"/tmp/antidote-test"}'
curl -s http://127.0.0.1:17845/roots | jq .
# Delete: curl -X DELETE http://127.0.0.1:17845/roots/<ID>
```

### 4. Debug: emit event and focus

```bash
# Emit a file-write event (sensitive path)
curl -X POST http://127.0.0.1:17845/debug/emit -H "Content-Type: application/json" \
  -d '{"session_id":"test","event_type":"FILE_WRITE","payload":{"path":"/tmp/.env","bytes":100}}'

# Emit NetHttp to unknown domain
curl -X POST http://127.0.0.1:17845/debug/emit -H "Content-Type: application/json" \
  -d '{"session_id":"test","event_type":"NET_HTTP","payload":{"domain":"unknown.example","bytes_out":5000000,"bytes_in":0}}'

# Get/set foreground session
curl -s http://127.0.0.1:17845/debug/focus | jq .
curl -X POST http://127.0.0.1:17845/debug/focus -H "Content-Type: application/json" -d '{"session_id":"<SESSION_ID>"}'
```

### 5. Capabilities (Phase 4)

```bash
curl -s http://127.0.0.1:17845/capabilities | jq .
# Check: audit_collector_active, proxy_active, fs_watcher_active, telemetry_confidence
```

### 6. Phase 5: Baselines and insights

```bash
# App baselines (after some sessions have ended)
curl -s http://127.0.0.1:17845/baselines | jq .

# Insights (risk trend, repeated risk, sessions with drift, baselines)
curl -s http://127.0.0.1:17845/insights | jq .
```

### 7. Phase 6: Enforcement and emergency

```bash
# Get enforcement config and frozen state
curl -s http://127.0.0.1:17845/enforcement | jq .

# Enable enforcement (e.g. block unknown domains)
curl -X POST http://127.0.0.1:17845/enforcement -H "Content-Type: application/json" \
  -d '{"enabled":true,"block_unknown_domains":true}'

# Emergency freeze (stops proxy, terminates active sessions)
curl -X POST http://127.0.0.1:17845/emergency/freeze

# Unfreeze
curl -X POST http://127.0.0.1:17845/emergency/unfreeze
```

### 8. Proxy and DB

```bash
curl -s http://127.0.0.1:17845/proxy/status | jq .
curl -s http://127.0.0.1:17845/debug/db | jq .
curl -X POST http://127.0.0.1:17845/debug/prune
```

---

## UI verification

1. **Dashboard** – Open `http://127.0.0.1:17845/ui/`  
   - Session list, risk badges, labels, observed roots.  
   - Click a session: stats, drift badge, baseline comparison (if set), flags, events.

2. **Insights** – Open `http://127.0.0.1:17845/ui/insights`  
   - Risk trend (7 days), top repeated risk, sessions with drift, per-app baselines.

3. **Security** – Open `http://127.0.0.1:17845/ui/security`  
   - Enforcement toggles, freeze button, safe mode.  
   - Warning that enforcement is experimental.

---

## Feature verification script

A short script checks that all main API surfaces respond correctly (no deep validation of behavior):

```bash
./scripts/verify_features.sh
# Or with custom base: ./scripts/verify_features.sh http://127.0.0.1:17845
```

It verifies: health, sessions, roots, capabilities, baselines, insights, enforcement GET, proxy status, debug/db. Requires `curl` and `jq`; daemon must be running.

## Integration test script (optional)

For a more comprehensive automated run (health → roots → emit → focus → FS → proxy → baselines → enforcement GET), you can extend `test.sh` or add a custom script that:

1. Assumes daemon is running.
2. Calls health, capabilities, roots, debug/emit, focus, then triggers FS/proxy as in `test.sh`.
3. Optionally calls `/baselines`, `/insights`, `/enforcement` and checks JSON structure (e.g. with `jq 'keys'`).

See `./test.sh` for patterns; the same `API_BASE`, `curl_json`, and helper functions can be reused.

---

## CI / release checklist

Before release or in CI, ensure:

- [ ] `cargo test` passes (all crates).
- [ ] `cargo clippy` (no warnings if configured).
- [ ] `./test.sh` passes with daemon running (manual or in CI with daemon in background).
- [ ] At least one session exists and has summary/flags (e.g. after running test script).
- [ ] Enforcement GET returns `enabled: false` and `frozen: false` by default.
