# Event-Driven Design Migration

This document analyzes the current timing-driven components and proposes event-driven alternatives while maintaining best practices.

## Current State: Timing vs Event

| Component | Current | Interval | Event-Driven? |
|-----------|---------|----------|---------------|
| **FS Watcher** | notify (FSEvents) | N/A | ✅ Already event-driven |
| **Proxy** | HTTP listener | N/A | ✅ Already event-driven |
| **App Detector** | Poll process list | 2s | ❌ Timing |
| **Workspace Resolver** | Poll app state + read JSON | 5s | ❌ Timing |
| **AutoRootManager** | Debounce + min_presence timers | 2s debounce, 2s presence | ⚠️ Hybrid |
| **FocusManager** | Poll foreground app | 500ms | ❌ Timing |
| **ForegroundPoller** | Poll via osascript | 1000ms | ❌ Timing |
| **Pipeline Tick** | Periodic Tick event | 2s | ❌ Timing |
| **File Event Coalescer** | Flush ticker | 1s | ⚠️ Hybrid (events + periodic flush) |
| **Retention/Baseline** | Scheduled jobs | 60min | ❌ Background maintenance (acceptable) |

---

## Migration Opportunities

### 1. App Detector → NSWorkspace Notifications (High Impact)

**Current:** Polls `sysinfo` every 2s to diff running processes.

**Event-driven alternative:** Use macOS `NSWorkspace` notification center:
- `NSWorkspace.didLaunchApplicationNotification` → emit `AppEvent::Started`
- `NSWorkspace.didTerminateApplicationNotification` → emit `AppEvent::Exited`

**Implementation:** Requires a small Objective-C/Swift bridge or a Rust crate like `cocoa` / `objc` to register for `NSWorkspace.shared.notificationCenter` notifications. No polling needed.

**Best practice:** Keep a lightweight reconciliation poll (e.g. every 60s) as a fallback for missed notifications or daemon restart (re-discover running apps).

---

### 2. Workspace Resolver → FSEvents on Storage Dirs (High Impact)

**Current:** Every 5s, iterates app instances, reads `workspaceStorage/*/workspace.json`, `storage.json`, etc.

**Event-driven alternative:** Watch Cursor/VSCode Application Support directories with FSEvents (already have `notify`):

```
~/Library/Application Support/Cursor/User/workspaceStorage/
~/Library/Application Support/Code/User/workspaceStorage/
```

- On `Create` or `Modify` of any `workspace.json` or `storage.json` → re-resolve that app’s workspace roots
- Triggered by: user opening folder, adding workspace, switching window

**Flow:**
1. AppDetector emits `AppEvent::Started` (app, pid)
2. WorkspaceResolver subscribes; on Started for Cursor/Code, **add FSEvents watch** on that app’s storage dir
3. On `AppEvent::Exited`, remove watch
4. On FS event in storage → read affected files → emit `WorkspaceEvent::Updated`

**Best practice:** Initial scan on app start (one-time read) + event-driven updates. No poll loop.

---

### 3. AutoRootManager → Pure Event-Driven (Medium Impact)

**Current:** `WorkspaceEvent` → debounce 2s → min_presence 2s → apply. Uses timers for both.

**Event-driven alternative:**

- **Apply on first sight:** Emit `WorkspaceEvent::Updated` → apply roots immediately (with policy checks).
- **Remove on explicit “gone”:** Add `WorkspaceEvent::RootsRemoved { app, pid, roots }` when a workspace window is closed or roots are no longer present.
- **Flap protection:** Instead of min_presence timer:
  - Short grace period (e.g. 500ms) debounce to coalesce rapid changes
  - Or: apply immediately, disable root when `RootsRemoved` is seen and no other session references it

**Best practice:** Debounce (event-triggered, short) is fine. Avoid “wait N seconds before trusting” in favor of “trust events; remove when told.”

---

### 4. FocusManager / ForegroundPoller → NSWorkspace Active App (Medium Impact)

**Current:** Poll `System Events` via osascript every 500ms–1s for frontmost app.

**Event-driven alternative:** `NSWorkspace.didActivateApplicationNotification` fires when user switches apps. Emit a `ForegroundChanged { app, pid }`-style event.

**Best practice:** Poll on daemon start to get initial state; then rely on notifications. Optional infrequent poll (e.g. 30s) as reconciliation.

---

### 5. Pipeline Tick → Event-Driven Heartbeats (Low Impact)

**Current:** Process poller or a separate task emits `Tick` every 2s for aggregate rule evaluation.

**Options:**
- **A)** Keep Tick for “idle evaluation” (e.g. “no file writes for 30s” rules) — some rules need time-based triggers.
- **B)** Replace with heartbeats from active sessions: when a session gets an event, schedule a “next check” for that session. No global ticker.

**Best practice:** For purely “no activity” rules, event-driven: “last event was N seconds ago” can be evaluated when new events arrive or on a per-session lightweight tick. A single slow global ticker (e.g. 10s) for cleanup/aggregates is acceptable.

---

### 6. File Event Coalescer → Event-Triggered Flush (Low Impact)

**Current:** Events arrive on channel; coalescer batches and flushes on a 1s interval.

**Event-driven alternative:** Flush when:
- Batch size threshold (e.g. 50 events), or
- Time since first event in batch > 500ms, or
- A “flush now” sentinel event

Use a single timer that is **reset on each event** (classic debounce): first event starts 500ms timer; more events extend the window; when timer fires with no new events, flush. This is still “time-based” but driven by event arrival.

---

## Phased Migration

### Phase 1: Quick Wins (No New Dependencies) ✅ DONE

1. **AutoRootManager:** Switch to apply-on-sight + `RootsRemoved`. Remove min_presence; keep short debounce (300ms) to coalesce bursts.
2. **Workspace Resolver:** Add FSEvents watch on Cursor/Code storage dirs. Keep poll as fallback (30s) if events are sparse.

### Phase 2: Native macOS Hooks

3. **App Detector:** Add NSWorkspace observer (via `objc` / `cocoa` or a small helper binary). Reduce or remove process poll.
4. **ForegroundPoller:** Add `didActivateApplication` observer. Reduce poll to reconciliation-only.

### Phase 3: Cleanup ✅ DONE

5. **Pipeline Tick:** Evaluate which rules need Tick; replace with per-session or event-driven logic where possible.
   - Aggregate rules (r5–r13) require periodic evaluation; design accepts a slow global ticker (10s). Made interval configurable via `pipeline.tick_interval_secs` (default 10s).
6. **Coalescer:** Switch to event-triggered debounce flush.
   - Replaced fixed flush ticker with sleep until earliest pending goes stale; each new event recalculates. Batch size threshold (50) triggers early flush.

---

## Best Practices to Maintain

1. **Graceful degradation:** Keep lightweight polling as fallback for missed events or platform quirks.
2. **Reconciliation on startup:** On daemon start, do one-time scan (apps, workspaces, roots) — no events exist yet.
3. **Bounded buffers:** Use `mpsc` with backpressure; avoid unbounded queues that can hide overload.
4. **Shutdown safety:** All event loops must respect `shutdown_rx`; no tight loops that ignore cancel.
5. **Observability:** Log when switching from poll to event (e.g. “Using NSWorkspace for app lifecycle”) and when falling back to poll.
6. **Testability:** Keep injectable traits (e.g. `FileReader`, `CommandRunner`) for unit tests; event-driven code can still use them for “trigger” paths.

---

## Summary

| Component | Event-Driven Approach | Fallback |
|-----------|----------------------|----------|
| App Detector | NSWorkspace launch/terminate | 60s reconciliation poll |
| Workspace Resolver | FSEvents on storage dirs | 30s poll |
| AutoRootManager | Apply on sight, remove on RootsRemoved | Short debounce only |
| Foreground | NSWorkspace activate app | 30s poll |
| Coalescer | Event-triggered debounce flush | — |
| FS Watcher | Already FSEvents | — |

The main architectural shift: **events as the primary trigger; timers only for debounce, flush, and reconciliation.**
