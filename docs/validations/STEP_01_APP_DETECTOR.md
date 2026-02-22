# Step 1: AppDetector — Validation Guide

## Overview

The AppDetector polls for running AI tool processes (Cursor, VSCode, Claude) and emits `Started` and `Exited` lifecycle events. These events drive session creation/teardown and feed the WorkspaceResolver.

## What to Validate

- Cursor, VSCode, and Claude are detected when launched
- `Started` events are emitted when apps are first seen
- `Exited` events are emitted when apps terminate
- Detected instances are exposed via the debug API

## Debug Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /debug/apps` | List detected app instances (app, pid, bundle_id, started_at) |
| `GET /debug/foreground` | Current foreground app (used by FocusManager) |

## Validation Steps

### 1. Verify App Detection (macOS only)

1. Start the daemon: `cargo run -p antidote-daemon`
2. With no AI apps running:
   ```bash
   curl -s http://127.0.0.1:17845/debug/apps | jq .
   ```
   Expected: `{"detected":[], "last_scan_ts":null}` or similar
3. Launch Cursor (or VSCode, Claude)
4. Wait ~2 seconds (default poll interval)
5. Re-check:
   ```bash
   curl -s http://127.0.0.1:17845/debug/apps | jq .
   ```
   Expected: `detected` array contains an entry with `app: "cursor"`, `pid` set
6. Quit the app and wait; `detected` should no longer list it

### 2. Verify Session Creation (Step 5 integration)

- When Cursor starts, a session should appear:
  ```bash
  curl -s "http://127.0.0.1:17845/sessions?limit=5" | jq '.[0]'
  ```
  Expected: `app: "Cursor"`, `root_pid` matches the PID from `/debug/apps`

### 3. Config

| Config key | Default | Description |
|------------|---------|-------------|
| `app_detector.enabled` | `true` | Enable app detection |
| `app_detector.poll_interval_ms` | `2000` | Poll interval in ms |

## Success Criteria

- [ ] `/debug/apps` returns detected instances within poll interval after launch
- [ ] Sessions are created when Cursor/VSCode/Claude start
- [ ] Sessions end when apps exit (or via idle timeout)
