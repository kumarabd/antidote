# Contributing to Antidote

Thank you for considering contributing to Antidote. This document explains how to set up your environment, run tests, and follow project conventions.

## Code of conduct

- Be respectful and constructive.
- Keep discussions focused on the project and technical content.

## Prerequisites

- **Rust** stable: `rustup default stable`
- **macOS** for full functionality (some code is `#[cfg(target_os = "macos")]`)
- **curl** and **jq** for running the integration test script (optional but recommended)

## Getting started

### Clone and build

```bash
git clone https://github.com/your-org/antidote.git
cd antidote
cargo build
```

### Run tests

```bash
cargo test
```

Run tests for a single crate:

```bash
cargo test -p antidote-core
cargo test -p antidote-behavior
# etc.
```

### Lint and format

```bash
cargo fmt
cargo clippy
```

Fix Clippy suggestions where reasonable; document any intentional allowances.

### Integration test (daemon must be running)

In one terminal:

```bash
cargo run -p antidote-daemon
```

In another:

```bash
./test.sh
./scripts/verify_features.sh
```

See [docs/TESTING.md](TESTING.md) for details.

---

## Project structure

- **crates/core** – Shared types (Event, SessionSummary, Flag, configs). No I/O. Other crates depend on core.
- **crates/collectors** – Event sources (process poller, FS watcher, proxy, audit). Emit events only.
- **crates/session** – Session lifecycle and attribution (session_id resolution).
- **crates/ruleengine** – Rule evaluation and risk scoring (loads rules from YAML).
- **crates/behavior** – Baselines, anomaly detection, drift, risk memory (Phase 5).
- **crates/storage** – SQLite persistence and migrations.
- **crates/api** – HTTP API and static UI (axum).
- **crates/daemon** – Main binary, pipeline worker, and task orchestration.

See [docs/ARCHITECTURE.md](ARCHITECTURE.md) for data flow and package roles.

---

## Conventions

### Rust

- **Edition:** 2021.
- **Naming:** Standard Rust (snake_case, PascalCase). Types and modules aligned with existing style in each crate.
- **Errors:** Use `anyhow::Result` in binaries/daemon; `thiserror` or concrete types in libraries where callers need to match.
- **Async:** Prefer `async/await` and tokio; avoid blocking the runtime in hot paths.
- **macOS-only code:** Gate with `#[cfg(target_os = "macos")]` and provide fallbacks or no-ops on other platforms where applicable.

### Commits and PRs

- **Commits:** Prefer clear, atomic messages (e.g. “Add drift index to session summary”, “Fix proxy frozen check”).
- **PRs:** Describe what changed and why. Reference any related issue. Ensure `cargo test` and (if possible) `./test.sh` pass.
- **Docs:** Update [docs/](.) (and README if needed) when adding or changing user-visible behavior or APIs.

### Adding a new rule

1. Add the rule logic in **crates/ruleengine** (e.g. under `rules/` as a new module or in an existing one).
2. Register it in the rule engine’s evaluation path.
3. Use existing `Label` and `Severity` where possible; extend enums in **core** if you need a new label.
4. Update **storage** (and migrations if needed) if you persist new fields or flags.
5. Add or extend tests in the ruleengine crate (and in TESTING.md if there’s a new manual check).

### Adding a new API endpoint

1. Add the route and handler in **crates/api**.
2. Use **ApiState** for any shared data (storage, session manager, enforcement, etc.).
3. Document the endpoint in [USER_GUIDE.md](USER_GUIDE.md) (and in TESTING.md if it should be verified by the test script).

### Database changes

1. Add a new migration under **crates/storage/migrations/** (e.g. `0008_my_feature.sql`).
2. Include the new migration in the list in **storage/src/lib.rs** so it runs on init.
3. Update **storage** code to read/write the new columns/tables; keep backward compatibility (e.g. `try_get` for new columns) where appropriate.
4. Run the daemon once and confirm migrations apply cleanly.

### Testing

- **Unit tests:** In the same crate as the code, in `#[cfg(test)]` modules or `tests/` for integration-style tests.
- **Behavior crate:** Already has tests for EMA, drift, anomaly, escalation, zero variance; add tests for new behavior logic.
- **Integration:** Extend `test.sh` or `scripts/verify_features.sh` for new endpoints or flows; document in [TESTING.md](TESTING.md).

---

## Documentation

- **User-facing:** [USER_GUIDE.md](USER_GUIDE.md) – install, run, configure, use UI and API.
- **Testing:** [TESTING.md](TESTING.md) – test script, unit tests, manual verification.
- **Architecture:** [ARCHITECTURE.md](ARCHITECTURE.md) – packages and data flow.
- **Phase-specific:** Optional docs (e.g. PHASE5.md, PHASE6.md, scripts/audit_setup.md) for behavioral and enforcement details.

Keep doc and code in sync when you change behavior or APIs.

---

## Release checklist (maintainers)

- [ ] `cargo test` passes.
- [ ] `cargo clippy` passes (or documented exceptions).
- [ ] `./test.sh` passes with daemon running.
- [ ] README and docs/ are updated.
- [ ] Changelog or release notes updated (if the project keeps one).

---

## Questions

Open an issue for bugs, feature ideas, or unclear documentation. For architecture or design, refer to [ARCHITECTURE.md](ARCHITECTURE.md) and existing code in the relevant crates.
