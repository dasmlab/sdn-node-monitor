#!/bin/bash
set -euo pipefail

app=sdn-node-monitor
podman rm -f ${app}-local-instance || true

# Allow environment variable overrides
FORCE_SOCKET="${PODMAN_SOCKET:-}"
FORCE_USER="${PODMAN_USER:-}"
FORCE_PORT="${METRICS_PORT:-}"

echo "🔍 Detecting podman configuration..."

# Detect current user
CURRENT_USER=$(id -u)
CURRENT_GROUP=$(id -g)
CURRENT_USERNAME=$(whoami)

echo "  Current user: ${CURRENT_USERNAME} (${CURRENT_USER}:${CURRENT_GROUP})"

# Use forced socket if provided
if [ -n "$FORCE_SOCKET" ]; then
    if [ -S "$FORCE_SOCKET" ]; then
        PODMAN_SOCKET="$FORCE_SOCKET"
        SOCKET_DIR=$(dirname "$FORCE_SOCKET")
        echo "  ✅ Using forced socket: $PODMAN_SOCKET"
    else
        echo "  ❌ Error: Forced socket not found: $FORCE_SOCKET"
        exit 1
    fi
fi

# SIMPLEST APPROACH: Use user socket and run as that user
# This avoids all permission issues - container runs as same user as socket owner
USER_SOCKET="/run/user/${CURRENT_USER}/podman/podman.sock"
USER_SOCKET_DIR="/run/user/${CURRENT_USER}/podman"

# Ensure user socket exists
if [ ! -S "$USER_SOCKET" ]; then
    echo "  Starting podman service to create user socket..."
    podman system service --time 0 >/dev/null 2>&1 &
    sleep 2
    for i in {1..5}; do
        [ -S "$USER_SOCKET" ] && break
        sleep 1
    done
fi

if [ -S "$USER_SOCKET" ]; then
    PODMAN_SOCKET="$USER_SOCKET"
    SOCKET_DIR="$USER_SOCKET_DIR"
    RUN_AS_USER="${CURRENT_USER}:${CURRENT_GROUP}"
    echo "  ✅ Using user socket: $PODMAN_SOCKET"
    echo "  ✅ Running as user ${CURRENT_USER} (matches socket owner)"
    echo "  ℹ️  This avoids all permission issues"
else
    echo "  ❌ Error: Could not create user socket at $USER_SOCKET"
    exit 1
fi

# PODMAN_SOCKET should be set by now (user socket)
if [ -z "${PODMAN_SOCKET:-}" ]; then
    echo "  ❌ Error: Could not determine podman socket location"
    exit 1
fi

# Set user if forced
if [ -n "$FORCE_USER" ]; then
    RUN_AS_USER="$FORCE_USER"
    echo "  ✅ Using forced user: $RUN_AS_USER"
elif [ -z "${RUN_AS_USER:-}" ]; then
    # Default to current user if not set
    RUN_AS_USER="${CURRENT_USER}:${CURRENT_GROUP}"
fi

# Verify socket is accessible by testing podman connection
echo "  Testing podman socket connection..."
if podman --remote --url unix://${PODMAN_SOCKET} ps >/dev/null 2>&1; then
    echo "  ✅ Socket is accessible"
else
    echo "  ⚠️  Warning: Socket may not be fully accessible"
    echo "     Socket: $PODMAN_SOCKET"
    echo "     Owner: $(stat -c "%U:%G" "$PODMAN_SOCKET" 2>/dev/null || echo "unknown")"
    echo "     Perms: $(stat -c "%a" "$PODMAN_SOCKET" 2>/dev/null || echo "unknown")"
    echo "     This may cause issues - ensure socket permissions allow access"
fi

# Detect available port (default 8080, try alternatives if needed)
if [ -n "$FORCE_PORT" ]; then
    METRICS_PORT="$FORCE_PORT"
    echo "  ✅ Using forced port: ${METRICS_PORT}"
else
    METRICS_PORT="${METRICS_PORT:-8080}"
    if command -v ss >/dev/null 2>&1; then
        while ss -tuln | grep -q ":${METRICS_PORT} "; do
            echo "  ⚠️  Port ${METRICS_PORT} is in use, trying next port..."
            METRICS_PORT=$((METRICS_PORT + 1))
            if [ "$METRICS_PORT" -gt 8099 ]; then
                echo "  ❌ Error: Could not find available port (tried 8080-8099)"
                exit 1
            fi
        done
    fi
    echo "  ✅ Using metrics port: ${METRICS_PORT}"
fi

# Get hostname for NODE_NAME
NODE_NAME="${NODE_NAME:-$(hostname)}"
echo "  ✅ Node name: ${NODE_NAME}"

echo ""
echo "🚀 Starting ${app} container..."
echo "   Socket: ${PODMAN_SOCKET}"
echo "   User: ${RUN_AS_USER}"
echo "   Port: ${METRICS_PORT}"

# Build podman run command - run as the user that owns the socket
PODMAN_CMD="podman run -d \
	--name ${app}-local-instance \
	--hostname $(hostname) \
	--user ${RUN_AS_USER} \
	--userns=keep-id"
echo "  ℹ️  Running as user ${RUN_AS_USER} (matches socket owner)"

# Mount ONLY the socket file and podman directory (not entire /run/user/X)
# This avoids permission issues with other directories like /run/user/X/bus
PODMAN_CMD="${PODMAN_CMD} \
	-v ${PODMAN_SOCKET}:${PODMAN_SOCKET}:rw \
	-v ${SOCKET_DIR}:${SOCKET_DIR}:rw"
echo "  ℹ️  Mounting socket: ${PODMAN_SOCKET}"
echo "  ℹ️  Mounting directory: ${SOCKET_DIR}"

PODMAN_CMD="${PODMAN_CMD} \
	-e NODE_NAME=\"${NODE_NAME}\" \
	-e LOG_LEVEL=\"${LOG_LEVEL:-info}\" \
	-e CHECK_INTERVAL=\"${CHECK_INTERVAL:-30s}\" \
	-e METRICS_PORT=\"${METRICS_PORT}\" \
	-e CONTAINER_HOST=unix://${PODMAN_SOCKET} \
	-e XDG_CONFIG_HOME=/app/.config \
	-p ${METRICS_PORT}:8080 \
	--network host \
	--restart always \
	${app}:local"

eval $PODMAN_CMD

echo ""
echo "✅ Container started!"
echo "   View logs: podman logs -f ${app}-local-instance"
echo "   Metrics: http://localhost:${METRICS_PORT}/metrics"
