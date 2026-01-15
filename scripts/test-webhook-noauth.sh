#!/usr/bin/env bash
set -euo pipefail

# Test EDA webhook without auth
# Usage:
#   EDA_WEBHOOK_URL="http://eda.example.com:5000/webhook/sdn-bgp-daemon" \
#   NODE_NAME="test-node-01" \
#   ./scripts/test-webhook-noauth.sh

EDA_WEBHOOK_URL="${EDA_WEBHOOK_URL:-}"
NODE_NAME="${NODE_NAME:-test-node-01}"

if [[ -z "$EDA_WEBHOOK_URL" ]]; then
  echo "❌ EDA_WEBHOOK_URL is required"
  echo "Example: EDA_WEBHOOK_URL=\"http://eda.example.com:5000/webhook/sdn-bgp-daemon\""
  exit 1
fi

echo "➡️  Sending test webhook (no auth) to: $EDA_WEBHOOK_URL"

curl -sS -X POST "$EDA_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d "{
    \"alertname\": \"SDNFRRBGPDaemonDown\",
    \"labels\": {
      \"component\": \"bgp\",
      \"node\": \"${NODE_NAME}\",
      \"severity\": \"critical\"
    },
    \"annotations\": {
      \"eda_action\": \"remediate_bgp\",
      \"eda_playbook\": \"restart-frr-bgp-agent.yml\"
    }
  }"

echo
echo "✅ Test webhook sent"
