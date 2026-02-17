#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://127.0.0.1:17845}"
PROXY_ADDR="${PROXY_ADDR:-127.0.0.1:17846}"      # host:port
TEST_ROOT="${TEST_ROOT:-/Users/abishekmini/Desktop/AI/antidote}"
VERBOSE="${VERBOSE:-0}"

RED=$'\033[0;31m'
GRN=$'\033[0;32m'
YLW=$'\033[0;33m'
BLU=$'\033[0;34m'
RST=$'\033[0m'

log()  { echo "==> $*" >&2; }
ok()   { echo "✅ $*" >&2; }
warn() { echo "⚠️ $*" >&2; }
fail() { echo "❌ $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"; }

curl_json() {
  local method="$1"; shift
  local path="$1"; shift
  local data="${1:-}"
  local url="${API_BASE}${path}"
  if [[ "$method" == "GET" ]]; then
    curl -fsS "$url"
  else
    curl -fsS -X "$method" "$url" -H "Content-Type: application/json" -d "$data"
  fi
}

endpoint_exists() {
  local path="$1"
  curl -fsS -o /dev/null "${API_BASE}${path}" >/dev/null 2>&1
}

get_capabilities() {
  if endpoint_exists "/capabilities"; then
    curl_json GET "/capabilities" | jq .
  else
    warn "/capabilities not implemented. Skipping capability checks."
    echo "{}"
  fi
}

get_sessions() {
  local limit="${1:-10}"
  if endpoint_exists "/sessions"; then
    curl -fsS "${API_BASE}/sessions?limit=${limit}&offset=0"
  else
    fail "/sessions endpoint missing; cannot continue"
  fi
}

get_latest_session_id() {
  get_sessions 5 | jq -r '.[0].session_id // empty'
}

get_active_sessions() {
  if endpoint_exists "/debug/sessions/active"; then
    curl_json GET "/debug/sessions/active"
  else
    echo "[]"
  fi
}

post_focus() {
  local sid="$1"
  if endpoint_exists "/focus"; then
    curl_json POST "/focus" "{\"session_id\":\"${sid}\"}" | jq .
    ok "Set foreground/focus session to ${sid}"
  else
    warn "/focus endpoint not implemented; skipping focus attribution test"
  fi
}

add_root() {
  if endpoint_exists "/roots"; then
    curl_json POST "/roots" "{\"path\":\"${TEST_ROOT}\"}" | jq .
    ok "Added watched root: ${TEST_ROOT}"
  else
    warn "/roots endpoint not implemented; FS watcher tests will be limited"
  fi
}

list_roots() {
  if endpoint_exists "/roots"; then
    curl_json GET "/roots" | jq .
  else
    echo "[]"
  fi
}

delete_root_if_possible() {
  if endpoint_exists "/roots"; then
    # best-effort: find root id by path and delete
    local roots
    roots="$(curl_json GET "/roots")" || return 0
    local id
    id="$(echo "$roots" | jq -r ".[] | select(.path==\"${TEST_ROOT}\") | .id" | head -n 1)"
    if [[ -n "${id:-}" && "$id" != "null" ]]; then
      if endpoint_exists "/roots/${id}"; then
        curl -fsS -X DELETE "${API_BASE}/roots/${id}" >/dev/null
      else
        # Some implementations may use DELETE /roots/:id even if endpoint_exists check fails
        curl -fsS -X DELETE "${API_BASE}/roots/${id}" >/dev/null 2>&1 || true
      fi
      ok "Deleted watched root id=${id} (best effort)"
    fi
  fi
}

emit_debug_event() {
  # For when you want to validate rules even without collectors.
  # payload: {"session_id": "...", "event_type": "NetHttp", "payload": {...}}
  if endpoint_exists "/debug/emit"; then
    curl_json POST "/debug/emit" "$1" | jq .
  else
    warn "/debug/emit not implemented"
  fi
}

get_session_summary() {
  local sid="$1"
  if endpoint_exists "/sessions/${sid}/summary"; then
    curl -fsS "${API_BASE}/sessions/${sid}/summary"
  else
    # fallback: try /sessions/:id
    curl -fsS "${API_BASE}/sessions/${sid}"
  fi
}

get_session_flags() {
  local sid="$1"
  if endpoint_exists "/sessions/${sid}/flags"; then
    curl -fsS "${API_BASE}/sessions/${sid}/flags?limit=200&offset=0"
  else
    echo "[]"
  fi
}

get_session_events() {
  local sid="$1"
  if endpoint_exists "/sessions/${sid}/events"; then
    curl -fsS "${API_BASE}/sessions/${sid}/events?limit=200&offset=0"
  else
    echo "[]"
  fi
}

print_session_report() {
  local sid="$1"
  log "Session Summary (${sid})"
  get_session_summary "$sid" | jq .

  log "Session Flags (${sid})"
  get_session_flags "$sid" | jq .

  if [[ "$VERBOSE" == "1" ]]; then
    log "Session Events (${sid})"
    get_session_events "$sid" | jq .
  fi
}

assert_contains_flag() {
  local sid="$1"
  local flag_id="$2"
  local flags
  flags="$(get_session_flags "$sid")"
  if echo "$flags" | jq -e --arg fid "$flag_id" '.[] | select(.rule_id==$fid or .id==$fid or .ruleId==$fid)' >/dev/null 2>&1; then
    ok "Found flag/rule hit: ${flag_id}"
  else
    warn "Did not find expected flag/rule: ${flag_id} (might be ok depending on implementation)"
  fi
}

wait_for_cursor_session() {
  log "Waiting for a Cursor session to appear (open Cursor now)..."
  local tries=40
  for ((i=1; i<=tries; i++)); do
    local sessions sid
    sessions="$(get_sessions 20)"
    sid="$(echo "$sessions" | jq -r '.[] | select((.app // "") | test("Cursor"; "i")) | .session_id' | head -n 1)"
    if [[ -n "${sid:-}" && "$sid" != "null" ]]; then
      ok "Detected Cursor session: ${sid}"
      echo "${sid}"          # stdout ONLY
      return 0
    fi
    sleep 2
  done
  warn "No Cursor session detected. Process poller watch list might not include Cursor process name."
  echo ""                    # stdout ONLY
}

fs_generate_activity() {
  log "Generating FS activity under ${TEST_ROOT}"
  mkdir -p "${TEST_ROOT}"

  # Normal file writes/renames/deletes
  echo "hello $(date)" > "${TEST_ROOT}/tmp_test.txt"
  echo "more $(date)" >> "${TEST_ROOT}/tmp_test.txt"
  mv "${TEST_ROOT}/tmp_test.txt" "${TEST_ROOT}/tmp_test_renamed.txt"
  rm -f "${TEST_ROOT}/tmp_test_renamed.txt"

  # Sensitive file write pattern
  echo "AWS_SECRET_ACCESS_KEY=fake" > "${TEST_ROOT}/.env"
  echo "TOKEN=fake" >> "${TEST_ROOT}/.env"

  # Bulk delete simulation
  mkdir -p "${TEST_ROOT}/bulk"
  for i in $(seq 1 25); do
    echo "x" > "${TEST_ROOT}/bulk/f${i}.txt"
  done
  for i in $(seq 1 25); do
    rm -f "${TEST_ROOT}/bulk/f${i}.txt"
  done
  rmdir "${TEST_ROOT}/bulk" 2>/dev/null || true

  ok "FS activity generated"
}

proxy_test() {
  log "Testing proxy telemetry via curl -x http://${PROXY_ADDR}"
  # Small request
  curl -fsS -x "http://${PROXY_ADDR}" https://example.com -L -o /dev/null || {
    warn "Proxy request failed. Proxy may be disabled or CONNECT not implemented."
    return 0
  }

  # Larger download to cross egress threshold (may take a moment)
  curl -fsS -x "http://${PROXY_ADDR}" https://speed.hetzner.de/10MB.bin -o /dev/null || {
    warn "Large proxy request failed (still ok)."
    return 0
  }
  ok "Proxy traffic generated (example.com + 10MB.bin)"
}

audit_expectations_note() {
  log "Audit Mode Note (Phase 4)"
  cat <<'EOF'
If audit collector is active, you should see FileRead events (metadata-only) in session timeline.
If you are NOT running with audit enabled/privileged, FileRead may be absent (expected).

To check, run:
  curl http://127.0.0.1:17845/capabilities | jq .

EOF
}

main() {
  need_cmd curl
  need_cmd jq

  log "Phase 0/1 sanity checks"
  curl -fsS "${API_BASE}/health" | jq . >/dev/null || fail "Daemon not reachable at ${API_BASE}"
  ok "Daemon /health ok"

  log "Capabilities"
  local caps
  caps="$(get_capabilities)"
  if [[ "$VERBOSE" == "1" ]]; then echo "$caps"; fi

  # Setup watched root
  log "Watched roots"
  mkdir -p "${TEST_ROOT}"
  delete_root_if_possible
  add_root
  list_roots >/dev/null || true

  # Wait for Cursor session (user must open Cursor)
  local cursor_sid
  cursor_sid="$(wait_for_cursor_session)"

  if [[ -z "${cursor_sid}" ]]; then
    warn "Proceeding without Cursor session. We'll still validate FS + proxy collectors (events may go to background session)."
  else
    # set focus if available
    post_focus "${cursor_sid}"
  fi

  # Generate FS activity
  fs_generate_activity

  # Give the daemon time to ingest/debounce/flush
  sleep 3

  # Determine which session to inspect:
  # - if cursor session exists: use it
  # - else: use latest session
  local sid_to_check="${cursor_sid}"
  if [[ -z "${sid_to_check}" ]]; then
    sid_to_check="$(get_latest_session_id)"
    if [[ -z "${sid_to_check}" ]]; then
      fail "No sessions found at all after generating activity."
    fi
    warn "Using latest session instead: ${sid_to_check}"
  fi

  print_session_report "${sid_to_check}"

  log "Validating expected FS-driven flags (best-effort)"
  # These names depend on your implementation; adapt if different.
  assert_contains_flag "${sid_to_check}" "SENSITIVE_FILE_WRITE"
  assert_contains_flag "${sid_to_check}" "BULK_DELETE"

  # Proxy tests (optional)
  if endpoint_exists "/proxy/status"; then
    log "Proxy status"
    curl_json GET "/proxy/status" | jq . || true
  fi

  proxy_test
  sleep 3

  # Re-check the same session (or latest) after proxy traffic
  local sid_after_proxy="${sid_to_check}"
  # If your attribution sends proxy traffic elsewhere, you can also inspect latest:
  local latest_sid
  latest_sid="$(get_latest_session_id)"

  log "Session report after proxy traffic (focused session)"
  print_session_report "${sid_after_proxy}"

  if [[ "${latest_sid}" != "${sid_after_proxy}" ]]; then
    log "Also checking latest session (proxy traffic might land here)"
    print_session_report "${latest_sid}"
  fi

  log "Validating expected proxy-driven flags (best-effort)"
  assert_contains_flag "${sid_after_proxy}" "UNKNOWN_DOMAIN_CONTACT"
  assert_contains_flag "${sid_after_proxy}" "HIGH_EGRESS"

  audit_expectations_note

  ok "Phase 0–4 validation script completed."
  echo
  echo "Open UI: ${API_BASE}/ui/"
  echo "Inspect session: ${API_BASE}/sessions/${sid_to_check}/summary"
  echo "Flags: ${API_BASE}/sessions/${sid_to_check}/flags?limit=200&offset=0"
  echo
}

main "$@"
