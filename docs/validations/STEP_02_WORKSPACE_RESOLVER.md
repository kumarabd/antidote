# Step 2: WorkspaceResolver — Validation Guide

## Overview

The WorkspaceResolver infers workspace roots for Cursor and VSCode from app storage JSON, window title, or `lsof`. It emits `WorkspaceEvent::Updated` with roots and confidence tiers (Tier1/Tier2/Tier3).

## What to Validate

- Workspace roots are resolved for open Cursor/VSCode windows
- Confidence and source tier are reported
- Roots feed AutoRootManager and attribution

## Debug Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /debug/workspaces` | All resolved workspaces (app, pid, roots, confidence, source) |
| `GET /debug/workspaces/:app` | Workspaces for a specific app (e.g. `cursor`) |

## Validation Steps

### 1. Verify Workspace Resolution (macOS only)

1. Start the daemon and open Cursor with a project (e.g. `~/code/my-project`)
2. Wait ~5 seconds (default poll interval)
3. Fetch workspaces:
   ```bash
   curl -s http://127.0.0.1:17845/debug/workspaces | jq .
   ```
   Expected: Entry for Cursor with `roots` containing the project path
4. Check by app:
   ```bash
   curl -s http://127.0.0.1:17845/debug/workspaces/cursor | jq .
   ```

### 2. Verify Confidence and Source Tiers

- `confidence`: `High`, `Medium`, or `Low`
- `source_tier`: `Tier1` (storage JSON), `Tier2` (window/lsof), `Tier3` (fallback)
- Higher confidence = more reliable roots for attribution

### 3. Config

| Config key | Default | Description |
|------------|---------|-------------|
| `workspace_resolver.enabled` | `true` | Enable workspace resolution |
| `workspace_resolver.poll_interval_ms` | `5000` | Poll interval |
| `workspace_resolver.max_roots_per_app` | `5` | Max roots per app instance |
| `workspace_resolver.lsof_fallback_enabled` | `true` | Use lsof when storage fails |
| `workspace_resolver.lsof_min_interval_ms` | `30000` | Min interval between lsof calls |

## Success Criteria

- [ ] `/debug/workspaces` shows roots for open Cursor/VSCode projects
- [ ] Roots match the actual workspace (folder) being edited
- [ ] Confidence/source_tier reflect expected reliability
