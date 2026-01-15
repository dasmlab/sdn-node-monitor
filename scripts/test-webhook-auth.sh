#!/usr/bin/env bash
set -euo pipefail

# Test EDA webhook with Bearer token auth
# Usage:
#   EDA_WEBHOOK_URL="http://eda.example.com:5000/webhook/sdn-bgp-daemon" \
#   EDA_WEBHOOK_TOKEN="your-token" \
#   NODE_NAME="test-node-01" \
#   ./scripts/test-webhook-auth.sh

EDA_WEBHOOK_URL="${EDA_WEBHOOK_URL:-}"
EDA_WEBHOOK_TOKEN="${EDA_WEBHOOK_TOKEN:-}"
NODE_NAME="${NODE_NAME:-test-node-01}"

if [[ -z "$EDA_WEBHOOK_URL" ]]; then
  echo "❌ EDA_WEBHOOK_URL is required"
  echo "Example: EDA_WEBHOOK_URL=\"http://eda.example.com:5000/webhook/sdn-bgp-daemon\""
  exit 1
fi

if [[ -z "$EDA_WEBHOOK_TOKEN" ]]; then
  echo "❌ EDA_WEBHOOK_TOKEN is required"
  echo "Example: EDA_WEBHOOK_TOKEN=\"<token>\""
  exit 1
fi

echo "➡️  Sending test webhook (Bearer token) to: $EDA_WEBHOOK_URL"

curl -sS -X POST "$EDA_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${EDA_WEBHOOK_TOKEN}" \
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
