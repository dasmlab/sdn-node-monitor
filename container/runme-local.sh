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

# Check for system socket (root podman) - ALWAYS prefer system socket if it exists
# System socket can be accessed by root, which solves permission issues
SYSTEM_SOCKET="/run/podman/podman.sock"
if [ -S "$SYSTEM_SOCKET" ]; then
    SOCKET_OWNER=$(stat -c "%U:%G" "$SYSTEM_SOCKET" 2>/dev/null || echo "unknown")
    SOCKET_PERMS=$(stat -c "%a" "$SYSTEM_SOCKET" 2>/dev/null || echo "unknown")
    echo "  ✅ Found system socket: $SYSTEM_SOCKET (owner: $SOCKET_OWNER, perms: $SOCKET_PERMS)"
    
    # System socket exists - ALWAYS use it and run as root
    # Root can access system socket regardless of owner
    PODMAN_SOCKET="$SYSTEM_SOCKET"
    SOCKET_DIR="/run/podman"
    RUN_AS_USER="0:0"
    echo "  ✅ Using system socket (running as root for full podman access)"
    echo "  ℹ️  This allows the container to see and manage all podman containers"
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
        # If we're going to use user socket, we MUST run as that user
        # Root cannot access user sockets due to permission restrictions
        PODMAN_SOCKET="$USER_SOCKET"
        SOCKET_DIR="$USER_SOCKET_DIR"
        RUN_AS_USER="${CURRENT_USER}:${CURRENT_GROUP}"
        echo "  ✅ Using user socket: $PODMAN_SOCKET (will run as user ${CURRENT_USER})"
    else
        echo "  ❌ Error: Could not find or create podman socket"
        if [ -n "${SYSTEM_SOCKET:-}" ]; then
            echo "     Tried: $SYSTEM_SOCKET"
        fi
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

# Build podman run command - adjust user namespace based on whether we're root
PODMAN_CMD="podman run -d \
	--name ${app}-local-instance \
	--hostname $(hostname)"

# Only add --user and --userns if not running as root
if [ "$RUN_AS_USER" != "0:0" ]; then
    PODMAN_CMD="${PODMAN_CMD} \
	--user ${RUN_AS_USER} \
	--userns=keep-id"
else
    echo "  ℹ️  Running as root to access podman socket"
fi

# Mount the socket and its directory
# For user sockets, we need to mount the entire /run/user/X directory structure
# This works on both Ubuntu and RHEL
if [[ "$PODMAN_SOCKET" == /run/user/* ]]; then
    # User socket - mount the entire /run/user/X directory
    # This ensures the full path structure exists in container (works on RHEL and Ubuntu)
    USER_RUN_DIR="/run/user/$(id -u)"
    PODMAN_CMD="${PODMAN_CMD} \
	-v ${USER_RUN_DIR}:${USER_RUN_DIR}:rw"
    echo "  ℹ️  Mounting user runtime directory: ${USER_RUN_DIR}"
    echo "  ℹ️  This ensures socket path exists in container (RHEL/Ubuntu compatible)"
else
    # System socket - mount socket and directory
    PODMAN_CMD="${PODMAN_CMD} \
	-v ${PODMAN_SOCKET}:${PODMAN_SOCKET}:rw \
	-v ${SOCKET_DIR}:${SOCKET_DIR}:rw"
fi

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
