#!/bin/bash
# Diagnostic script to check podman setup on target system
# Run this on the target system to gather information

echo "=== Podman Socket Diagnostics ==="
echo ""

echo "1. Current user context:"
echo "   User: $(whoami) (UID: $(id -u), GID: $(id -g))"
echo "   Groups: $(groups)"
echo ""

echo "2. System socket check:"
SYSTEM_SOCKET="/run/podman/podman.sock"
if [ -S "$SYSTEM_SOCKET" ]; then
    echo "   ✅ EXISTS: $SYSTEM_SOCKET"
    echo "   Owner: $(stat -c "%U:%G" "$SYSTEM_SOCKET" 2>/dev/null || echo "unknown")"
    echo "   Perms: $(stat -c "%a" "$SYSTEM_SOCKET" 2>/dev/null || echo "unknown")"
    echo "   Readable by current user: $([ -r "$SYSTEM_SOCKET" ] && echo "YES" || echo "NO")"
    ls -la "$SYSTEM_SOCKET" 2>/dev/null || echo "   Cannot stat"
else
    echo "   ❌ NOT FOUND: $SYSTEM_SOCKET"
fi
echo ""

echo "3. User socket check:"
USER_SOCKET="/run/user/$(id -u)/podman/podman.sock"
if [ -S "$USER_SOCKET" ]; then
    echo "   ✅ EXISTS: $USER_SOCKET"
    echo "   Owner: $(stat -c "%U:%G" "$USER_SOCKET" 2>/dev/null || echo "unknown")"
    echo "   Perms: $(stat -c "%a" "$USER_SOCKET" 2>/dev/null || echo "unknown")"
    echo "   Readable by current user: $([ -r "$USER_SOCKET" ] && echo "YES" || echo "NO")"
    ls -la "$USER_SOCKET" 2>/dev/null || echo "   Cannot stat"
else
    echo "   ❌ NOT FOUND: $USER_SOCKET"
fi
echo ""

echo "4. Podman service status:"
systemctl is-active podman.socket 2>/dev/null && echo "   ✅ podman.socket is active" || echo "   ❌ podman.socket is not active"
systemctl status podman.socket --no-pager -l 2>/dev/null | head -5
echo ""

echo "5. Test podman connection (system socket):"
if [ -S "$SYSTEM_SOCKET" ]; then
    podman --remote --url unix://${SYSTEM_SOCKET} ps 2>&1 | head -3
    echo "   Exit code: $?"
else
    echo "   Skipped (socket not found)"
fi
echo ""

echo "6. Test podman connection (user socket):"
if [ -S "$USER_SOCKET" ]; then
    podman --remote --url unix://${USER_SOCKET} ps 2>&1 | head -3
    echo "   Exit code: $?"
else
    echo "   Skipped (socket not found)"
fi
echo ""

echo "7. Test podman connection (default):"
podman ps 2>&1 | head -3
echo "   Exit code: $?"
echo ""

echo "8. Podman info (socket path):"
podman info 2>&1 | grep -A3 "remoteSocket" || echo "   No remote socket info"
echo ""

echo "9. Running containers:"
podman ps --format "{{.Names}} ({{.ID}})" 2>&1 | head -5
echo ""

echo "10. Container 'frr' exists?"
podman ps -a --filter name=frr --format "{{.Names}} ({{.ID}})" 2>&1
echo ""

echo "11. All podman sockets on system:"
find /run /var/run -name "*podman*sock" 2>/dev/null | while read sock; do
    echo "   $sock - Owner: $(stat -c "%U:%G" "$sock" 2>/dev/null || echo "unknown"), Perms: $(stat -c "%a" "$sock" 2>/dev/null || echo "unknown")"
done
echo ""

echo "12. If container is running, check from inside:"
if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "sdn-node-monitor"; then
    CONTAINER=$(podman ps --filter name=sdn-node-monitor --format "{{.ID}}" | head -1)
    echo "   Container ID: $CONTAINER"
    echo "   Running as user: $(podman exec $CONTAINER id 2>/dev/null || echo "cannot exec")"
    echo "   Socket mounted: $(podman exec $CONTAINER ls -la ${SYSTEM_SOCKET} 2>/dev/null || podman exec $CONTAINER ls -la ${USER_SOCKET} 2>/dev/null || echo "socket not found in container")"
    echo "   /run/user/X exists: $(podman exec $CONTAINER ls -d /run/user/* 2>/dev/null | head -1 || echo "NO")"
    echo "   Can see podman: $(podman exec $CONTAINER podman ps 2>&1 | head -1 || echo "FAILED")"
    echo "   CONTAINER_HOST env: $(podman exec $CONTAINER sh -c 'echo $CONTAINER_HOST' 2>/dev/null || echo "not set")"
else
    echo "   Container not running"
fi
echo ""
echo "13. OS Information:"
cat /etc/os-release 2>/dev/null | grep -E "^(NAME|VERSION_ID)=" || echo "   Cannot determine OS"
echo ""
echo "14. SELinux status (RHEL):"
getenforce 2>/dev/null || echo "   SELinux not available (likely Ubuntu)"
