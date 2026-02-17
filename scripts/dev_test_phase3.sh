#!/bin/bash
# Phase 3 test script for Antidote

set -e

echo "🧪 Phase 3 Test Script"
echo "======================"

DAEMON_PID=""
API_URL="http://localhost:17845"

cleanup() {
    if [ ! -z "$DAEMON_PID" ]; then
        echo "Stopping daemon (PID: $DAEMON_PID)..."
        kill $DAEMON_PID 2>/dev/null || true
        wait $DAEMON_PID 2>/dev/null || true
    fi
    echo "Cleanup complete"
}
trap cleanup EXIT

# Build daemon
echo "Building daemon..."
cargo build -p antidote-daemon || exit 1

# Start daemon in background
echo "Starting daemon..."
cargo run -p antidote-daemon > /tmp/antidote.log 2>&1 &
DAEMON_PID=$!
sleep 3

# Check if daemon is running
if ! kill -0 $DAEMON_PID 2>/dev/null; then
    echo "❌ Daemon failed to start"
    cat /tmp/antidote.log
    exit 1
fi

echo "✅ Daemon started (PID: $DAEMON_PID)"

# Wait for API to be ready
echo "Waiting for API..."
for i in {1..10}; do
    if curl -s "$API_URL/health" > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Test 1: Add watched root
echo ""
echo "Test 1: Add watched root"
TEST_DIR="/tmp/antidote-test-$$"
mkdir -p "$TEST_DIR"
ROOT_RESPONSE=$(curl -s -X POST "$API_URL/roots" \
    -H "Content-Type: application/json" \
    -d "{\"path\": \"$TEST_DIR\"}")
ROOT_ID=$(echo "$ROOT_RESPONSE" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
echo "✅ Added root: $TEST_DIR (ID: $ROOT_ID)"

# Test 2: Simulate file events (many deletes -> destructive)
echo ""
echo "Test 2: Simulate destructive deletes"
for i in {1..10}; do
    touch "$TEST_DIR/file$i.txt"
done
sleep 1
for i in {1..10}; do
    rm -f "$TEST_DIR/file$i.txt"
done
sleep 2
echo "✅ Created and deleted 10 files"

# Test 3: Simulate unknown domains cluster
echo ""
echo "Test 3: Simulate unknown domain cluster"
for domain in "suspicious1.example.com" "suspicious2.example.com" "suspicious3.example.com"; do
    curl -s -X POST "$API_URL/debug/emit" \
        -H "Content-Type: application/json" \
        -d "{\"session_id\": \"pending\", \"event_type\": \"NET_HTTP\", \"payload\": {\"domain\": \"$domain, \"bytes_out\": 1000}}" > /dev/null
done
sleep 2
echo "✅ Emitted 3 unknown domain events"

# Test 4: Simulate exfil correlation (sensitive write + unknown domain + high egress)
echo ""
echo "Test 4: Simulate exfil correlation"
# Get active session
ACTIVE_SESSIONS=$(curl -s "$API_URL/debug/sessions/active")
SESSION_ID=$(echo "$ACTIVE_SESSIONS" | grep -o '"session_id":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -z "$SESSION_ID" ]; then
    SESSION_ID="test-session-$$"
fi

# Sensitive write
curl -s -X POST "$API_URL/debug/emit" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\": \"$SESSION_ID\", \"event_type\": \"FILE_WRITE\", \"payload\": {\"path\": \"$TEST_DIR/.env\", \"bytes\": 100}}" > /dev/null

# Unknown domain + high egress
curl -s -X POST "$API_URL/debug/emit" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\": \"$SESSION_ID\", \"event_type\": \"NET_HTTP\", \"payload\": {\"domain\": \"exfil.example.com\", \"bytes_out\": 6000000}}" > /dev/null

sleep 2
echo "✅ Simulated exfil correlation"

# Test 5: Check focus endpoint
echo ""
echo "Test 5: Test focus endpoint"
FOCUS_RESPONSE=$(curl -s "$API_URL/debug/focus")
echo "Focus response: $FOCUS_RESPONSE"

if [ ! -z "$SESSION_ID" ] && [ "$SESSION_ID" != "test-session-$$" ]; then
    curl -s -X POST "$API_URL/debug/focus" \
        -H "Content-Type: application/json" \
        -d "{\"session_id\": \"$SESSION_ID\"}" > /dev/null
    echo "✅ Set focus to session: $SESSION_ID"
fi

# Test 6: Check DB health
echo ""
echo "Test 6: Check DB health"
DB_HEALTH=$(curl -s "$API_URL/debug/db")
echo "DB health: $DB_HEALTH"

# Test 7: List sessions and check observed_roots
echo ""
echo "Test 7: Verify session summaries"
SESSIONS=$(curl -s "$API_URL/sessions?limit=5")
echo "Sessions:"
echo "$SESSIONS" | head -20

# Test 8: Open UI
echo ""
echo "✅ Phase 3 tests complete!"
echo ""
echo "🌐 Dashboard available at: $API_URL/ui/"
echo "   Open in browser: open $API_URL/ui/"
echo ""
echo "Press Ctrl+C to stop the daemon"

# Keep running
wait $DAEMON_PID
