#!/bin/bash
# Phase 4 test script for Antidote (audit telemetry)

set -e

echo "🧪 Phase 4 Test Script (Audit Telemetry)"
echo "=========================================="

DAEMON_PID=""
API_URL="http://localhost:17845"
TEST_DIR="/tmp/antidote-test-phase4-$$"

cleanup() {
    if [ ! -z "$DAEMON_PID" ]; then
        echo "Stopping daemon (PID: $DAEMON_PID)..."
        kill $DAEMON_PID 2>/dev/null || true
        wait $DAEMON_PID 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR" 2>/dev/null || true
    echo "Cleanup complete"
}
trap cleanup EXIT

# Check if running as root (for audit mode)
if [ "$EUID" -eq 0 ]; then
    echo "⚠️  Running as root - audit mode should be available"
    AUDIT_MODE=true
else
    echo "ℹ️  Not running as root - audit mode will not be available (fallback to Phase 3)"
    AUDIT_MODE=false
fi

# Build daemon
echo "Building daemon..."
cargo build -p antidote-daemon || exit 1

# Start daemon in background
echo "Starting daemon..."
if [ "$AUDIT_MODE" = true ]; then
    sudo cargo run -p antidote-daemon > /tmp/antidote-phase4.log 2>&1 &
    DAEMON_PID=$!
else
    cargo run -p antidote-daemon > /tmp/antidote-phase4.log 2>&1 &
    DAEMON_PID=$!
fi
sleep 3

# Check if daemon is running
if ! kill -0 $DAEMON_PID 2>/dev/null; then
    echo "❌ Daemon failed to start"
    cat /tmp/antidote-phase4.log
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

# Test 1: Check capabilities
echo ""
echo "Test 1: Check capabilities"
CAPABILITIES=$(curl -s "$API_URL/capabilities")
echo "Capabilities: $CAPABILITIES"

AUDIT_ACTIVE=$(echo "$CAPABILITIES" | grep -o '"audit_collector_active":true' || echo "")
if [ ! -z "$AUDIT_ACTIVE" ]; then
    echo "✅ Audit collector is active (HIGH confidence)"
else
    echo "ℹ️  Audit collector not active (fallback to MED/LOW confidence)"
fi

# Test 2: Add watched root
echo ""
echo "Test 2: Add watched root"
mkdir -p "$TEST_DIR"
ROOT_RESPONSE=$(curl -s -X POST "$API_URL/roots" \
    -H "Content-Type: application/json" \
    -d "{\"path\": \"$TEST_DIR\"}")
ROOT_ID=$(echo "$ROOT_RESPONSE" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
echo "✅ Added root: $TEST_DIR (ID: $ROOT_ID)"

# Test 3: Create a file and read it (to trigger FileRead events if audit is active)
echo ""
echo "Test 3: Create and read file (to test FileRead detection)"
echo "test content" > "$TEST_DIR/test.txt"
cat "$TEST_DIR/test.txt" > /dev/null
sleep 2
echo "✅ Created and read test file"

# Test 4: Create sensitive file and read it
echo ""
echo "Test 4: Create and read sensitive file"
echo "secret=value" > "$TEST_DIR/.env"
cat "$TEST_DIR/.env" > /dev/null
sleep 2
echo "✅ Created and read sensitive file (.env)"

# Test 5: Check sessions for FileRead events
echo ""
echo "Test 5: Check sessions for FileRead events"
SESSIONS=$(curl -s "$API_URL/sessions?limit=5")
echo "Recent sessions:"
echo "$SESSIONS" | head -30

# Test 6: Check for sensitive file read flags
echo ""
echo "Test 6: Check for sensitive file read flags"
if [ ! -z "$AUDIT_ACTIVE" ]; then
    # Get latest session
    LATEST_SESSION=$(echo "$SESSIONS" | grep -o '"session_id":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ ! -z "$LATEST_SESSION" ]; then
        FLAGS=$(curl -s "$API_URL/sessions/$LATEST_SESSION/flags")
        echo "Flags for session $LATEST_SESSION:"
        echo "$FLAGS" | head -20
        
        if echo "$FLAGS" | grep -q "SENSITIVE_FILE_READ\|R14"; then
            echo "✅ Sensitive file read flag detected"
        else
            echo "ℹ️  No sensitive file read flags (may need more time or events)"
        fi
    fi
else
    echo "ℹ️  Skipping flag check (audit not active)"
fi

# Test 7: Verify telemetry confidence
echo ""
echo "Test 7: Verify telemetry confidence in session summary"
if [ ! -z "$LATEST_SESSION" ]; then
    SUMMARY=$(curl -s "$API_URL/sessions/$LATEST_SESSION/summary")
    CONFIDENCE=$(echo "$SUMMARY" | grep -o '"telemetry_confidence":"[^"]*"' | cut -d'"' -f4)
    echo "Telemetry confidence: $CONFIDENCE"
    if [ "$CONFIDENCE" = "HIGH" ]; then
        echo "✅ High confidence (audit active)"
    elif [ "$CONFIDENCE" = "MED" ]; then
        echo "✅ Medium confidence (FS watcher + proxy)"
    else
        echo "ℹ️  Low confidence (process polling only)"
    fi
fi

echo ""
echo "✅ Phase 4 tests complete!"
echo ""
echo "🌐 Dashboard available at: $API_URL/ui/"
echo "   Open in browser: open $API_URL/ui/"
echo ""
if [ "$AUDIT_MODE" = false ]; then
    echo "💡 To test with audit mode, run with sudo:"
    echo "   sudo ./scripts/dev_test_phase4.sh"
fi
echo ""
echo "Press Ctrl+C to stop the daemon"

# Keep running
wait $DAEMON_PID
