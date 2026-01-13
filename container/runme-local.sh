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

# Check for system socket (root podman) - skip if already set
if [ -z "${PODMAN_SOCKET:-}" ]; then
SYSTEM_SOCKET="/run/podman/podman.sock"
if [ -S "$SYSTEM_SOCKET" ]; then
    SOCKET_OWNER=$(stat -c "%U:%G" "$SYSTEM_SOCKET" 2>/dev/null || echo "unknown")
    SOCKET_PERMS=$(stat -c "%a" "$SYSTEM_SOCKET" 2>/dev/null || echo "unknown")
    echo "  Found system socket: $SYSTEM_SOCKET (owner: $SOCKET_OWNER, perms: $SOCKET_PERMS)"
    
    # If system socket exists and we're root, use it
    if [ "$CURRENT_USER" -eq 0 ]; then
        PODMAN_SOCKET="$SYSTEM_SOCKET"
        SOCKET_DIR="/run/podman"
        RUN_AS_USER="0:0"
        echo "  ✅ Using system socket (running as root)"
    elif [ "$SOCKET_OWNER" = "root:root" ]; then
        # System socket owned by root - need to run as root or use user socket
        echo "  ⚠️  System socket is root-owned, checking if we can access user socket..."
        # Will fall through to user socket check below
    elif [ "$SOCKET_OWNER" = "${CURRENT_USERNAME}:${CURRENT_USERNAME}" ] || [ "$SOCKET_OWNER" = "${CURRENT_USERNAME}:podman" ]; then
        # Check if we can actually read it (test with podman)
        if podman --remote --url unix://${SYSTEM_SOCKET} ps >/dev/null 2>&1; then
            PODMAN_SOCKET="$SYSTEM_SOCKET"
            SOCKET_DIR="/run/podman"
            RUN_AS_USER="${CURRENT_USER}:${CURRENT_GROUP}"
            echo "  ✅ Using system socket (accessible to current user)"
        else
            echo "  ⚠️  System socket exists but not accessible, trying user socket..."
        fi
    else
        echo "  ⚠️  System socket owned by different user ($SOCKET_OWNER), trying user socket..."
    fi
    fi
fi

# Check for user socket (rootless podman) - skip if already set
if [ -z "${PODMAN_SOCKET:-}" ]; then
    USER_SOCKET="/run/user/${CURRENT_USER}/podman/podman.sock"
    USER_SOCKET_DIR="/run/user/${CURRENT_USER}/podman"
    
    # Ensure user socket exists by starting podman service if needed
    if [ ! -S "$USER_SOCKET" ]; then
        echo "  Starting podman service to create user socket..."
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
        SOCKET_DIR="$USER_SOCKET_DIR"
        RUN_AS_USER="${CURRENT_USER}:${CURRENT_GROUP}"
        echo "  ✅ Using user socket: $PODMAN_SOCKET"
    else
        echo "  ❌ Error: Could not find or create podman socket"
        echo "     Tried: $SYSTEM_SOCKET"
        echo "     Tried: $USER_SOCKET"
        exit 1
    fi
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

podman run -d \
	--name ${app}-local-instance \
	--hostname $(hostname) \
	--user ${RUN_AS_USER} \
	--userns=keep-id \
	-e NODE_NAME="${NODE_NAME}" \
	-e LOG_LEVEL="${LOG_LEVEL:-info}" \
	-e CHECK_INTERVAL="${CHECK_INTERVAL:-30s}" \
	-e METRICS_PORT="${METRICS_PORT}" \
	-e CONTAINER_HOST=unix://${PODMAN_SOCKET} \
	-e XDG_CONFIG_HOME=/app/.config \
	-p ${METRICS_PORT}:8080 \
	--network host \
	-v ${PODMAN_SOCKET}:${PODMAN_SOCKET}:rw \
	-v ${SOCKET_DIR}:${SOCKET_DIR}:rw \
	--restart always \
	${app}:local

echo ""
echo "✅ Container started!"
echo "   View logs: podman logs -f ${app}-local-instance"
echo "   Metrics: http://localhost:${METRICS_PORT}/metrics"
