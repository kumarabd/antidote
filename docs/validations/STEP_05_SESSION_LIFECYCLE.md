# Step 5: Session Lifecycle Automation — Validation Guide

## Overview

Session lifecycle is automated: sessions are created on `AppEvent::Started`, ended on `AppEvent::Exited`, and rotated on idle timeout. On finalize, baseline updates, anomaly detection, and escalation run.

## What to Validate

- Sessions created when Cursor/VSCode/Claude start
- Sessions ended when apps exit (or idle timeout)
- Baseline and summary updated on session end
- Session survives daemon restart (persisted by root_pid)

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /sessions` | List sessions (recent first) |
| `GET /sessions/:id` | Session details |
| `GET /sessions/:id/summary` | Session summary (counts, risk, etc.) |
| `GET /sessions/:id/events` | Events for session |
| `GET /baselines` | App baselines (Phase 5) |

## Validation Steps

### 1. Session Creation on App Start

1. Start daemon with no Cursor
2. Launch Cursor
3. List sessions:
   ```bash
   curl -s "http://127.0.0.1:17845/sessions?limit=5" | jq '.[0] | {session_id, app, root_pid, start_ts, end_ts}'
   ```
   Expected: New session with `app: "Cursor"`, `root_pid` set, `end_ts: null`

### 2. Session End on App Exit

1. Quit Cursor
2. Re-fetch sessions
   Expected: Same session now has `end_ts` set

### 3. Idle Timeout Rotation

- Leave Cursor open but idle (no file/network activity)
- Wait `idle_timeout_minutes` (default 20)
- Session should be ended and a new one created on next activity

### 4. Baseline on Finalize

- After a session ends, check baselines:
  ```bash
  curl -s http://127.0.0.1:17845/baselines | jq .
  ```
  Expected: Entry for "Cursor" (or the app) with updated counts

### 5. Daemon Restart Persistence

1. Create session (open Cursor), note `session_id`
2. Stop daemon
3. Restart daemon
4. Open Cursor again (same PID if possible, or new)
5. Verify session is reused or new one created; no duplicate for same root_pid

## Config

| Config key | Default | Description |
|------------|---------|-------------|
| `idle_timeout_minutes` | `20` | Idle before ending session |

## Success Criteria

- [ ] Sessions created on app start
- [ ] Sessions ended on app exit or idle
- [ ] Baselines updated when sessions finalize
- [ ] Session state persists across daemon restart
