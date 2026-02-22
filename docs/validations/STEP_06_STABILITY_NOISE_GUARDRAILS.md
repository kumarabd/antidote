# Step 6: Stability + Noise Guardrails — Validation Guide

## Overview

Step 6 adds:
- **Rate limiter** — Drops events when over threshold to prevent DB/CPU overload
- **File event coalescer** — Merges rapid writes into single events with `repeat_count`
- **Root policy** — Sanity checks (reject `/`, overly broad paths)
- **Ignore filters** — Drop noisy paths before processing
- **AutoRootManager flap protection** — `min_presence_seconds` before accepting roots

## What to Validate

- Rate limiting drops events when overloaded
- Rapid file writes are coalesced
- Unsafe roots are rejected
- Noisy paths are ignored
- Auto roots require sustained presence

## Debug Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /debug/zero_config_health` | Drop metrics (rate limit) |
| `GET /debug/watchers` | Active watchers |

## Validation Steps

### 1. Rate Limiter

1. Generate many events quickly (e.g. bulk file writes, or use test script)
2. Check drop metrics:
   ```bash
   curl -s http://127.0.0.1:17845/debug/zero_config_health | jq .
   ```
   Expected: `dropped_events` may be > 0 under load

### 2. File Event Coalescing

1. Create rapid writes to the same file:
   ```bash
   for i in {1..20}; do echo "$i" >> /watched/root/test.txt; done
   ```
2. Check events for the session:
   ```bash
   curl -s "http://127.0.0.1:17845/sessions/$SID/events?limit=5" | jq '.[0].payload'
   ```
   Expected: `repeat_count` in payload; fewer events than writes

### 3. Root Policy

- Try adding root `/` or `~` (if supported):
  ```bash
  curl -s -X POST http://127.0.0.1:17845/roots \
    -H "Content-Type: application/json" \
    -d '{"path": "/"}'
  ```
  Expected: Rejected or normalized per policy

### 4. Ignore Filters

- Paths matching ignore patterns (e.g. `node_modules`, `.git`) should not produce flags
- Check that events under ignored paths have reduced noise

### 5. Config

| Config key | Default | Description |
|------------|---------|-------------|
| `limits.max_events_per_second` | `200` | Rate limit threshold |
| `file_events.coalesce_window_ms` | `800` | Coalesce window for rapid writes |
| `auto_roots.min_presence_seconds` | `5` | Min presence before accepting root |

## Success Criteria

- [ ] Drop metrics available at `/debug/zero_config_health`
- [ ] Rapid writes produce coalesced events with `repeat_count`
- [ ] Unsafe roots are rejected by root policy
- [ ] Auto roots require sustained presence (flap protection)
