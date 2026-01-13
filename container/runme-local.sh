#!/bin/bash
set -euo pipefail

app=sdn-node-monitor
podman rm -f ${app}-local-instance || true
podman run -d \
	--name ${app}-local-instance \
	--hostname $(hostname) \
	-e NODE_NAME=$(hostname) \
	-e LOG_LEVEL=info \
	-e CHECK_INTERVAL=30s \
	-e METRICS_PORT=8080 \
	-p 8080:8080 \
	--network host \
	-v /var/run/frr:/var/run/frr \
	--restart always \
	${app}:local
