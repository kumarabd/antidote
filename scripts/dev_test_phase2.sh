#!/bin/bash
# Phase 2 dev test script for Antidote

set -e

API_URL="http://localhost:17845"
TEST_ROOT="/tmp/aimon-test"

echo "=== Antidote Phase 2 Dev Test ==="
echo ""

# Check if daemon is running
echo "1. Checking daemon health..."
if ! curl -s "$API_URL/health" > /dev/null; then
    echo "ERROR: Daemon is not running. Start it with: cargo run -p antidote-daemon"
    exit 1
fi
echo "✓ Daemon is running"
echo ""

# Create test directory
echo "2. Creating test directory..."
mkdir -p "$TEST_ROOT"
echo "✓ Test directory created: $TEST_ROOT"
echo ""

# Add watched root
echo "3. Adding watched root..."
ROOT_RESPONSE=$(curl -s -X POST "$API_URL/roots" \
  -H "Content-Type: application/json" \
  -d "{\"path\": \"$TEST_ROOT\"}")
ROOT_ID=$(echo "$ROOT_RESPONSE" | jq -r '.id // empty')
if [ -z "$ROOT_ID" ]; then
    echo "WARNING: Failed to add root or get ID"
    ROOT_ID="1"
fi
echo "✓ Added watched root (ID: $ROOT_ID)"
echo "$ROOT_RESPONSE" | jq '.'
echo ""

# List roots
echo "4. Listing watched roots..."
curl -s "$API_URL/roots" | jq '.'
echo ""

# Wait a moment for watcher to initialize
echo "5. Waiting for FS watcher to initialize..."
sleep 2
echo ""

# Create .env file (should trigger sensitive file write)
echo "6. Creating .env file (should flag R1: ConfigTampering)..."
echo "SECRET_KEY=test123" > "$TEST_ROOT/.env"
sleep 1
echo "✓ Created .env file"
echo ""

# Create and delete multiple files (should trigger bulk delete)
echo "7. Creating and deleting files (should trigger R3B/R6: DestructiveAction)..."
for i in {1..25}; do
    echo "test$i" > "$TEST_ROOT/file$i.txt"
done
sleep 1
rm -f "$TEST_ROOT/file"*.txt
sleep 1
echo "✓ Created and deleted 25 files"
echo ""

# Get sessions
echo "8. Fetching sessions..."
SESSIONS=$(curl -s "$API_URL/sessions")
SESSION_COUNT=$(echo "$SESSIONS" | jq 'length')
echo "Found $SESSION_COUNT session(s)"
echo ""

if [ "$SESSION_COUNT" -gt 0 ]; then
    SESSION_ID=$(echo "$SESSIONS" | jq -r '.[0].session_id')
    echo "Using session: $SESSION_ID"
    echo ""

    # Get session summary
    echo "9. Fetching session summary..."
    SUMMARY=$(curl -s "$API_URL/sessions/$SESSION_ID/summary")
    echo "$SUMMARY" | jq '.'
    echo ""

    RISK_SCORE=$(echo "$SUMMARY" | jq -r '.risk.score // 0')
    RISK_BUCKET=$(echo "$SUMMARY" | jq -r '.risk.bucket // "low"')
    echo "Risk Score: $RISK_SCORE"
    echo "Risk Bucket: $RISK_BUCKET"
    echo ""

    if [ "$RISK_SCORE" -gt 60 ]; then
        echo "✓ Risk score > 60 (High) - Test PASSED"
    else
        echo "⚠ Risk score <= 60 - May need more events or time"
    fi

    # List flags
    echo ""
    echo "10. Listing flags..."
    curl -s "$API_URL/sessions/$SESSION_ID/flags" | jq '.'
    echo ""

    # List events
    echo "11. Listing recent events..."
    curl -s "$API_URL/sessions/$SESSION_ID/events?limit=10" | jq '.[] | {type: .event_type, path: .payload.path}'
    echo ""
else
    echo "⚠ No sessions found. Events may be in background session."
    echo "Check: curl $API_URL/sessions"
fi

# Test proxy (if enabled)
echo "12. Checking proxy status..."
PROXY_STATUS=$(curl -s "$API_URL/proxy/status")
echo "$PROXY_STATUS" | jq '.'
echo ""

# Cleanup
echo "13. Cleaning up test directory..."
rm -rf "$TEST_ROOT"
echo "✓ Cleaned up"
echo ""

echo "=== Test Complete ==="
