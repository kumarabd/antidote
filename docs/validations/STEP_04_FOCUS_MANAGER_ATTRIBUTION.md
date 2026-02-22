# Step 4: FocusManager + Attribution — Validation Guide

## Overview

FocusManager maps the foreground app to `ForegroundContext` (session_id, workspace_roots, confidence). Events are attributed to sessions using PID, path (root match), or foreground.

## What to Validate

- Foreground app is tracked and resolved to a session
- Events are attributed with `attribution_reason` and `attribution_confidence`
- File events match roots; network events use foreground when applicable

## Debug Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /debug/foreground` | Raw foreground app (name, pid) |
| `GET /debug/focus` | Resolved ForegroundContext (app, pid, roots, session_id, confidence) |
| `GET /debug/attribution/simulate` | Simulate attribution (query: `path`, `domain`) |

## Validation Steps

### 1. Verify Foreground Tracking (macOS)

1. Start daemon and open Cursor
2. Ensure Cursor is the foreground app
3. Check focus:
   ```bash
   curl -s http://127.0.0.1:17845/debug/focus | jq .
   ```
   Expected: `app: "Cursor"`, `session_id` set, `workspace_roots` populated

### 2. Verify Attribution Reasons

- Create a file under a watched root while Cursor is foreground:
  ```bash
  touch /path/to/watched/root/test.rs
  ```
- Fetch recent events:
  ```bash
  curl -s "http://127.0.0.1:17845/sessions?limit=1" | jq '.[0].session_id'
  SID="<session_id>"
  curl -s "http://127.0.0.1:17845/sessions/$SID/events?limit=5" | jq '.[].attribution_reason'
  ```
  Expected: `root_match`, `foreground`, or `pid`

### 3. Simulate Attribution

```bash
# File event
curl -s "http://127.0.0.1:17845/debug/attribution/simulate?path=/path/to/root/file.rs" | jq .

# Network event
curl -s "http://127.0.0.1:17845/debug/attribution/simulate?domain=api.openai.com" | jq .
```

Expected: `session_id`, `reason`, `confidence` in response

### 4. Event Schema

Events include:
- `attribution_reason`: `pid`, `root_match`, `foreground`, etc.
- `attribution_confidence`: 0–100

## Success Criteria

- [ ] `/debug/focus` reflects foreground app and session
- [ ] File events under watched roots get correct `session_id`
- [ ] Attribution simulate returns sensible results for path and domain
