#!/bin/bash
set -euo pipefail

app=sdn-node-monitor
podman rm -f ${app}-local-instance || true

# Determine podman socket location - use user socket for rootless podman
USER_ID=$(id -u)
USER_SOCKET="/run/user/${USER_ID}/podman/podman.sock"
SOCKET_DIR="/run/user/${USER_ID}/podman"

# Ensure user socket exists by starting podman service if needed
if [ ! -S "$USER_SOCKET" ]; then
    echo "Starting podman service to create user socket..."
    podman system service --time 0 >/dev/null 2>&1 &
    sleep 1
    # Wait up to 3 seconds for socket to appear
    for i in {1..3}; do
        [ -S "$USER_SOCKET" ] && break
        sleep 1
    done
fi

if [ -S "$USER_SOCKET" ]; then
    PODMAN_SOCKET="$USER_SOCKET"
    echo "Using user podman socket: $PODMAN_SOCKET"
else
    echo "Error: Could not create or find podman socket at $USER_SOCKET"
    exit 1
fi

# Get user/group IDs to run container as same user that owns podman socket
USER_ID=$(id -u)
GROUP_ID=$(id -g)

podman run -d \
	--name ${app}-local-instance \
	--hostname $(hostname) \
	--user ${USER_ID}:${GROUP_ID} \
	--userns=keep-id \
	-e NODE_NAME=$(hostname) \
	-e LOG_LEVEL=info \
	-e CHECK_INTERVAL=30s \
	-e METRICS_PORT=8080 \
	-e CONTAINER_HOST=unix://${PODMAN_SOCKET} \
	-e XDG_CONFIG_HOME=/app/.config \
	-p 8989:8080 \
	--network host \
	-v ${PODMAN_SOCKET}:${PODMAN_SOCKET}:rw \
	-v ${SOCKET_DIR}:${SOCKET_DIR}:rw \
	--restart always \
	${app}:local
