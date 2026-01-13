#!/bin/bash
set -euo pipefail

app=sdn-node-monitor
tag=local
output_file="${app}-${tag}.tar"

# Check if image exists
if ! podman image exists "${app}:${tag}" 2>/dev/null; then
    echo "Error: Image ${app}:${tag} does not exist."
    echo "Please build the image first using: ./buildme.sh"
    exit 1
fi

echo "Saving ${app}:${tag} to ${output_file}..."
podman save -o "${output_file}" "${app}:${tag}"

# Get file size for confirmation
if [ -f "${output_file}" ]; then
    size=$(du -h "${output_file}" | cut -f1)
    echo "✅ Successfully saved ${app}:${tag} to ${output_file} (${size})"
    echo ""
    echo "To load this image on another system:"
    echo "  podman load -i ${output_file}"
    echo ""
    echo "To transfer to another system:"
    echo "  scp ${output_file} user@remote-host:/path/to/destination/"
else
    echo "❌ Error: Failed to create ${output_file}"
    exit 1
fi
