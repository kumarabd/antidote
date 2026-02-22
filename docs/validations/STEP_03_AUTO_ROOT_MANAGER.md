# Step 3: AutoRootManager — Validation Guide

## Overview

The AutoRootManager consumes `WorkspaceEvent`s from the WorkspaceResolver, upserts roots as `source=auto`, reconciles stale roots, enforces caps, and syncs the FS watcher and watched roots cache.

## What to Validate

- Roots from workspace events are added as auto roots
- Stale roots are disabled after inactivity
- Root count is capped
- FS watcher and watched roots cache stay in sync

## Debug Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /roots` | List all roots (including auto roots) |
| `GET /debug/watchers` | Active FS watcher roots |
| `GET /debug/roots` | Internal root state (if exposed) |

## Validation Steps

### 1. Verify Auto Roots Added

1. Start the daemon with Cursor closed
2. Add no manual roots initially
3. Open Cursor with a project (e.g. `~/code/proj`)
4. Wait for WorkspaceResolver to emit roots (~5–10s)
5. List roots:
   ```bash
   curl -s http://127.0.0.1:17845/roots | jq .
   ```
   Expected: Project path present with `source: "auto"` (or similar)

### 2. Verify FS Watcher Sync

```bash
curl -s http://127.0.0.1:17845/debug/watchers | jq .
```

Expected: Watched roots include the auto-discovered project path

### 3. Verify Stale Root Disable

- Close Cursor and stop using the project
- Wait `stale_disable_days` (default 14)
- Root should be disabled (not deleted) when stale

### 4. Config

| Config key | Default | Description |
|------------|---------|-------------|
| `auto_roots.enabled` | `true` | Enable auto-root management |
| `auto_roots.max_auto_roots` | `20` | Max auto roots |
| `auto_roots.stale_disable_days` | `14` | Days before disabling stale roots |
| `auto_roots.apply_debounce_ms` | `2000` | Debounce before applying |
| `auto_roots.min_presence_seconds` | `5` | Min presence before accepting (Step 6 flap protection) |

## Success Criteria

- [ ] Auto roots appear in `/roots` when Cursor opens a project
- [ ] Watched roots cache and FS watcher include auto roots
- [ ] Root policy rejects unsafe paths (e.g. `/`, home dir as root)
