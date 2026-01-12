#!/bin/bash
set -euo pipefail

app=sdn-node-monitor
docker build -t ${app}:local .
