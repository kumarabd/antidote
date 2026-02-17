#!/usr/bin/env bash
# Verify Antidote API endpoints and features (daemon must be running).
# Usage: ./scripts/verify_features.sh [API_BASE]
# Example: API_BASE=http://127.0.0.1:17845 ./scripts/verify_features.sh

set -euo pipefail
API_BASE="${1:-http://127.0.0.1:17845}"
RED=$'\033[0;31m'
GRN=$'\033[0;32m'
RST=$'\033[0m'
ok()  { echo "${GRN}OK${RST} $*"; }
fail() { echo "${RED}FAIL${RST} $*"; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "Missing: $1"; }
need_cmd curl
need_cmd jq

echo "==> Using API_BASE=$API_BASE"
curl -fsS "${API_BASE}/health" | jq -e '.ok == true' >/dev/null || fail "Health check"
ok "Health"

curl -fsS "${API_BASE}/sessions?limit=1" >/dev/null || fail "Sessions list"
ok "Sessions list"

curl -fsS "${API_BASE}/roots" >/dev/null || fail "Roots list"
ok "Roots"

curl -fsS "${API_BASE}/capabilities" | jq -e '.' >/dev/null || fail "Capabilities"
ok "Capabilities"

curl -fsS "${API_BASE}/baselines" | jq -e 'type == "array"' >/dev/null || fail "Baselines"
ok "Baselines"

curl -fsS "${API_BASE}/insights" | jq -e '.baselines != null and .risk_trend_7d != null' >/dev/null || fail "Insights"
ok "Insights"

curl -fsS "${API_BASE}/enforcement" | jq -e '.frozen != null' >/dev/null || fail "Enforcement GET"
ok "Enforcement GET"

curl -fsS "${API_BASE}/proxy/status" | jq -e '.' >/dev/null || fail "Proxy status"
ok "Proxy status"

curl -fsS "${API_BASE}/debug/db" | jq -e '.' >/dev/null || fail "Debug DB"
ok "Debug DB"

echo ""
echo "All feature checks passed."
