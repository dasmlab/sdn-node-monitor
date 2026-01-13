#!/usr/bin/env bash
set -euo pipefail

# pushme.sh - Push SDN node monitor Podman image to registry
# This script tags and pushes the image with version and latest tags

# --- config ----------------------------------------------------
app=sdn-node-monitor
local_tag="local"          # your local image tag (matches buildme.sh)
repo="ghcr.io/dasmlab"     # base repo
buildfile=".lastbuild"     # build counter file
token_file="/home/dasm/gh_token"  # GitHub token file
# ---------------------------------------------------------------

# ensure .lastbuild exists
if [[ ! -f "$buildfile" ]]; then
    echo "0" > "$buildfile"
fi

# read + increment build number
build=$(cat "$buildfile")
next=$((build + 1))
echo "$next" > "$buildfile"

# create version tag
tag="0.1.${next}-alpha"

# construct full names
src="${app}:${local_tag}"
dst_version="${repo}/${app}:${tag}"
dst_latest="${repo}/${app}:latest"

echo "📦 Building push:"
echo "  App:        ${app}"
echo "  Source:     ${src}"
echo "  VersionTag: ${dst_version}"
echo "  LatestTag:  ${dst_latest}"
echo

# Authenticate with GitHub Container Registry
if [[ -f "$token_file" ]]; then
    token=$(cat "$token_file" | tr -d '\n\r')
    echo "$token" | podman login ghcr.io -u lmcdasm --password-stdin || {
        echo "⚠️  Warning: Failed to authenticate with ghcr.io"
        echo "   Attempting push without authentication (may fail)..."
    }
else
    echo "⚠️  Warning: Token file not found at $token_file"
    echo "   Attempting push without authentication (may fail)..."
fi

# tag operations
podman tag "$src" "$dst_version"
podman tag "$src" "$dst_latest"

# push operations
podman push "$dst_version"
podman push "$dst_latest"

echo
echo "✅ Pushed:"
echo "   ${dst_version}"
echo "   ${dst_latest}"


