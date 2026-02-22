# Antidote Validation Documentation

This directory contains validation guides for each implementation step of Antidote. Use these documents to manually verify that features work correctly after deployment or code changes.

## Steps

| Step | Document | Summary |
|------|----------|---------|
| 1 | [STEP_01_APP_DETECTOR.md](STEP_01_APP_DETECTOR.md) | App lifecycle detection (Cursor, VSCode, Claude) |
| 2 | [STEP_02_WORKSPACE_RESOLVER.md](STEP_02_WORKSPACE_RESOLVER.md) | Workspace root inference from app state |
| 3 | [STEP_03_AUTO_ROOT_MANAGER.md](STEP_03_AUTO_ROOT_MANAGER.md) | Automatic root discovery and watch management |
| 4 | [STEP_04_FOCUS_MANAGER_ATTRIBUTION.md](STEP_04_FOCUS_MANAGER_ATTRIBUTION.md) | Foreground context and event attribution |
| 5 | [STEP_05_SESSION_LIFECYCLE.md](STEP_05_SESSION_LIFECYCLE.md) | Session create/end automation and idle rotation |
| 6 | [STEP_06_STABILITY_NOISE_GUARDRAILS.md](STEP_06_STABILITY_NOISE_GUARDRAILS.md) | Rate limiting, coalescing, root policy, ignore filters |
| 7 | [STEP_07_ATTRIBUTION_STABILIZATION.md](STEP_07_ATTRIBUTION_STABILIZATION.md) | Heat-based attribution, PID cache, stabilization |
| 8 | [STEP_08_TELEMETRY_INTEGRITY.md](STEP_08_TELEMETRY_INTEGRITY.md) | Capabilities, confidence, health, attribution quality, root coverage |

## Prerequisites

- **macOS** (Steps 1–4, 5–7 require macOS for full functionality)
- Daemon running: `cargo run -p antidote-daemon`
- Default API: `http://127.0.0.1:17845`
- `curl` and `jq` for manual validation commands

## Quick Validation

```bash
# Health check
curl -s http://127.0.0.1:17845/health | jq .

# Capabilities (shows audit, proxy, FS status)
curl -s http://127.0.0.1:17845/capabilities | jq .
```
