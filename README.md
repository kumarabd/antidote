# Antidote – AI Activity Monitor

**Antidote** is a macOS-only Rust daemon that monitors AI-related activity (Cursor, Claude, VS Code, etc.) on your machine. It tracks process lifecycle, file changes under watched folders, and network traffic through an optional proxy—**metadata only**, no file contents, no HTTPS decryption. All data stays **local**; there are no cloud or AI/LLM calls.

Features include:

- **Session-based monitoring** – Sessions are created from watched processes; events are attributed and scored.
- **Rule engine** – Deterministic risk scoring and flags (sensitive file writes, dangerous commands, unknown domains, high egress, bulk operations, and more).
- **Behavioral baseline & anomaly detection** – Per-app baselines, z-score anomalies, drift index, and repeated-risk escalation.
- **Optional enforcement** – Block unknown domains or dangerous commands; emergency “freeze” of AI activity (experimental).
- **Local dashboard & API** – Web UI and REST API on localhost for sessions, insights, and security controls.

---

## Quick start

**Prerequisites:** Rust (stable), macOS.

```bash
git clone https://github.com/your-org/antidote.git
cd antidote
cargo build -p antidote-daemon
cargo run -p antidote-daemon
```

Then open **http://127.0.0.1:17845/ui/** in your browser. If the UI shows "UI not built", run `cd ui && npm install && npm run build` first. Add a watched root via the API so file activity is attributed:

```bash
curl -X POST http://127.0.0.1:17845/roots -H "Content-Type: application/json" -d '{"path":"/Users/you/your-project"}'
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [**User Guide**](docs/USER_GUIDE.md) | Install, run, configure, and use the dashboard and API. |
| [**Testing**](docs/TESTING.md) | How to run tests and the test script; manual verification steps. |
| [**Architecture**](docs/ARCHITECTURE.md) | What each crate does and how data flows through the system. |
| [**Contributing**](docs/CONTRIBUTING.md) | Set up dev environment, run tests, and contribute code. |

Additional references:

- **Rules config** – `rules/rules.yaml` (known domains, sensitive paths, thresholds).
- **Audit setup** (optional, Phase 4) – `scripts/audit_setup.md` for macOS audit telemetry.

---

## Project layout

```
antidote/
├── crates/
│   ├── core/         # Shared types (Event, Session, Flag, configs)
│   ├── collectors/   # Process poller, FS watcher, proxy, audit
│   ├── session/      # Session lifecycle and attribution
│   ├── ruleengine/   # Rules and risk scoring
│   ├── behavior/     # Baselines, anomaly, drift (Phase 5)
│   ├── storage/      # SQLite persistence
│   ├── api/          # HTTP API and UI
│   └── daemon/       # Main binary and pipeline
├── ui/               # Vite SPA (React + TypeScript) - Dashboard, Session Detail, Diagnostics
├── rules/rules.yaml  # Rule configuration
├── docs/             # User guide, testing, architecture, contributing
└── scripts/          # Test and verification scripts
```

---

## Testing

```bash
cargo test
```

With the daemon running in another terminal:

```bash
./test.sh
./scripts/verify_features.sh
```

See [docs/TESTING.md](docs/TESTING.md) for full details.

---

## Diagnostics export

To export a diagnostics bundle for support:

**UI:** Click "Export Diagnostics" on the Dashboard or Diagnostics page. A zip file will download.

**curl:**
```bash
curl -X POST "http://127.0.0.1:17845/support/diagnostics/export?include_logs=true&include_config=true" -o antidote-diagnostics.zip
```

The zip contains: status snapshot, health, confidence, warnings, pipeline stats, recent sessions, system info, and optionally config (redacted) and logs.

---

## Retention

By default:
- Raw events older than **7 days** are pruned
- Session summaries are kept for **90 days**
- Retention runs every **60 minutes**
- Run `GET /debug/retention` to inspect status

---

## Logging

The daemon logs to stdout. Set `RUST_LOG=antidote=info` (or `debug`) to control verbosity. If a log file is configured (e.g. `antidote.log` in the working directory), `GET /debug/log_tail?lines=200` returns the last N lines.

---

## Privacy and safety

- **No file contents** – Only paths, sizes, and timestamps are recorded.
- **No decrypted HTTPS** – The proxy sees domain and byte counts, not request/response bodies.
- **Local only** – API binds to 127.0.0.1; no data is sent off-device.
- **Enforcement is optional and experimental** – Off by default; use with caution (see [User Guide](docs/USER_GUIDE.md) and Security UI).

---

## License

MIT (or as specified in the repository).
