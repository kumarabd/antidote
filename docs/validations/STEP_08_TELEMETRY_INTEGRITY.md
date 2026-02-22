# Step 8: Telemetry Integrity & Trust Layer — Validation Guide

## Overview

Step 8 makes the system self-aware of signal health, attribution quality, and coverage:

- **TelemetryCapabilities** — Which signals are active
- **Global & per-session confidence** — Attribution reliability
- **Component health** — Derived from last_scan_ts, last_run_at
- **Attribution quality** — Rolling stats (high/medium/low/background)
- **Root coverage** — File events attributed vs total
- **Signal gap detection** — Warnings (WORKSPACE_MISSING, etc.)
- **Pipeline integrity** — events_received, stored, dropped, coalesced

## Debug Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /debug/capabilities` | fs_watcher_active, proxy_active, workspace_resolution_active, etc. |
| `GET /debug/confidence` | global, global_reasons, per_session |
| `GET /debug/health` | components (AppDetector, WorkspaceResolver, …), system_healthy |
| `GET /debug/attribution/quality` | total_last_5min, high/medium/low/background, quality_score |
| `GET /debug/root_coverage` | file_events_total, attributed, root_coverage_ratio |
| `GET /debug/warnings` | warnings[] (code, severity, message) |
| `GET /debug/pipeline` | events_received, stored, dropped, coalesced, rate_limited |
| `GET /debug/zero_config_status` | Comprehensive snapshot (confidence, health, attribution_quality, etc.) |

## Validation Steps

### 1. Capabilities

```bash
curl -s http://127.0.0.1:17845/debug/capabilities | jq .
```

Expected: `fs_watcher_active`, `proxy_active`, `workspace_resolution_active`, etc.

### 2. Confidence degradation

1. Run daemon and open Cursor.
2. `curl -s http://127.0.0.1:17845/debug/zero_config_status | jq .global_confidence`
   - Should be High or Medium.
3. Simulate FS watcher failure (e.g. remove all roots).
4. Re-check: `global_confidence` should degrade; `system_health` may be Degraded.
5. Disable proxy in config; restart.
6. `curl -s http://127.0.0.1:17845/debug/capabilities | jq .proxy_active`
   - Should be false.

### 3. Attribution quality

1. Generate file and network events (edit files, use proxy).
2. `curl -s http://127.0.0.1:17845/debug/attribution/quality | jq .`
3. During stable use, `quality_score` should be > 0.8.

### 4. Root coverage

```bash
curl -s http://127.0.0.1:17845/debug/root_coverage | jq .
```

Expected: `root_coverage_ratio` between 0 and 1.

### 5. Pipeline integrity

```bash
curl -s http://127.0.0.1:17845/debug/pipeline | jq .
```

Expected: `events_received`, `events_stored`, `events_dropped`, `coalesced_events`.

### 6. Warnings

```bash
curl -s http://127.0.0.1:17845/debug/warnings | jq .
```

When Cursor runs but no workspace detected: `WORKSPACE_MISSING`.

### 7. Health

```bash
curl -s http://127.0.0.1:17845/debug/health | jq .
```

Expected: `components` with `healthy`, `last_tick`, `system_healthy`.

## Success Criteria

- [ ] `/debug/capabilities` reflects actual component state
- [ ] `/debug/zero_config_status` returns global_confidence, system_health
- [ ] Confidence degrades when FS watcher inactive or proxy disabled
- [ ] Attribution quality score > 0.8 during stable use
- [ ] Root coverage ratio reflects attributed vs total file events
- [ ] Pipeline shows received, stored, dropped, coalesced counts
- [ ] Warnings appear when signal gaps detected
