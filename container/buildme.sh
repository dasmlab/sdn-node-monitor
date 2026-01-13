#!/bin/bash
set -euo pipefail

app=sdn-node-monitor
podman build -t ${app}:local .
