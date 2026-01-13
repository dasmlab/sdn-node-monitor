#!/usr/bin/env bash
set -euo pipefail

# pullme.sh - Pull SDN node monitor Podman image from registry
# This script pulls the latest image from GitHub Container Registry

# --- config ----------------------------------------------------
app=sdn-node-monitor
local_tag="local"          # local tag to apply after pull
repo="ghcr.io/dasmlab"     # base repo
# ---------------------------------------------------------------

# Source image (latest from registry)
src="${repo}/${app}:latest"
# Destination (local tag)
dst="${app}:${local_tag}"

echo "📥 Pulling image:"
echo "  Source: ${src}"
echo "  Local tag: ${dst}"
echo

# Pull the image
podman pull "$src"

# Tag it locally for consistency with buildme.sh
podman tag "$src" "$dst"

echo
echo "✅ Pulled and tagged:"
echo "   ${src} -> ${dst}"
