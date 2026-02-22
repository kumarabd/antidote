# Step 7: Attribution Stabilization + Heat-Based Session Selection — Validation Guide

## Overview

Step 7 makes attribution stable and resistant to rapid foreground switching, ambiguous paths, and network bursts:

- **Foreground stabilization** — Require same foreground app for `stabilization_ms` before switching
- **Session heat model** — Activity-based scores for tie-breaking
- **Heat-based tie break** — PID → foreground → heat → recency → oldest
- **Recent session window** — Network events use sessions active within window
- **Workspace confidence decay** — Downgrade attribution when resolver confidence is low
- **PID → session cache** — TTL cache for audit-attributed PIDs
- **Attribution explainability** — `attribution_details_json`, debug endpoint

## What to Validate

- Rapid app switching does not flap attribution
- Heat scores increase with activity and decay over time
- Tie-breaking uses heat when roots are ambiguous
- Network events attribute to recent/foreground sessions
- Debug endpoint shows heat, PID cache, stabilization state

## Debug Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /debug/attribution/state` | Heat scores, PID cache, candidate/committed foreground, config |

## Validation Steps

### 1. Foreground Stabilization

1. Open Cursor with a project and edit files
2. Switch to another app briefly (< 1 second)
3. Switch back to Cursor and continue editing
4. Check events: they should remain attributed to the same session
5. Alternatively: Cmd+Tab rapidly; attribution should not flip

### 2. Heat-Based Tie Breaking

1. Open two Cursor windows with different project roots
2. Generate activity in both (edit files, network)
3. Trigger an ambiguous event (e.g. path under both roots, or network with Cursor not foreground)
4. Event should attribute to the session with higher heat or most recent activity

### 3. Attribution Debug State

```bash
curl -s http://127.0.0.1:17845/debug/attribution/state | jq .
```

Expected structure:
```json
{
  "heat_scores": { "session-id": 12, ... },
  "heat_details": { ... },
  "pid_to_session": { 12345: "session-id", ... },
  "candidate_foreground": { "app": "Cursor", "pid": 12345, "since": "..." },
  "last_committed": ["Cursor", 12345],
  "stabilization_ms": 1000,
  "pid_cache_ttl_secs": 600
}
```

### 4. Attribution Details on Events

Fetch events and check `attribution_details_json`:
```bash
curl -s "http://127.0.0.1:17845/sessions/$SID/events?limit=3" | jq '.[].attribution_details_json'
```

Expected: Optional JSON with `reason`, `confidence`, `details.heat_scores` when tie-breaking by heat.

### 5. Config

| Config key | Default | Description |
|------------|---------|-------------|
| `focus.stabilization_ms` | `1000` | Ms to hold foreground before committing |
| `attribution.recent_session_window_seconds` | `300` | Window for "recent" sessions (network) |

### 6. Example Attributed Event

```json
{
  "session_id": "cursor-abc123",
  "event_type": "FILE_WRITE",
  "payload": { "path": "/Users/me/proj/src/main.rs" },
  "attribution_reason": "heat",
  "attribution_confidence": 70,
  "attribution_details_json": {
    "reason": "heat",
    "confidence": "Medium",
    "details": { "heat_scores": { "cursor-abc123": 12, "cursor-xyz456": 7 } }
  }
}
```

## Success Criteria

- [ ] Rapid app switches do not cause attribution flap
- [ ] `/debug/attribution/state` returns heat scores and stabilization info
- [ ] Events include `attribution_reason` and `attribution_confidence`
- [ ] Heat-based tie-breaking works when multiple sessions match
- [ ] Network events attribute to recent/foreground sessions when applicable
