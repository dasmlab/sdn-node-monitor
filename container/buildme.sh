#!/bin/bash
set -euo pipefail

app=sdn-node-monitor
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
podman build --build-arg GIT_COMMIT="${GIT_COMMIT}" -t ${app}:local .
