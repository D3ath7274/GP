#!/usr/bin/env bash
set -euo pipefail

# Disable common segmentation/offload features that can make mirrored packets
# look truncated to Snort, producing decoder alerts such as:
#   (ipv4) IPv4 datagram length > captured length
#
# Usage:
#   sudo ./scripts/disable_capture_offloads.sh br-snort vxlan-snort ens33

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run with sudo."
    exit 1
fi

if ! command -v ethtool >/dev/null 2>&1; then
    echo "ERROR: ethtool is required. Install with: sudo apt install ethtool"
    exit 1
fi

if [[ "$#" -lt 1 ]]; then
    echo "Usage: sudo $0 <interface> [interface ...]"
    exit 1
fi

for iface in "$@"; do
    if ! ip link show "${iface}" >/dev/null 2>&1; then
        echo "SKIP: ${iface} does not exist"
        continue
    fi

    echo "Disabling capture offloads on ${iface}..."
    ethtool -K "${iface}" gro off 2>/dev/null || true
    ethtool -K "${iface}" gso off 2>/dev/null || true
    ethtool -K "${iface}" tso off 2>/dev/null || true
    ethtool -K "${iface}" lro off 2>/dev/null || true
    ethtool -K "${iface}" rx off 2>/dev/null || true
    ethtool -K "${iface}" tx off 2>/dev/null || true
done

echo "Done. Current offload state summary:"
for iface in "$@"; do
    if ip link show "${iface}" >/dev/null 2>&1; then
        echo "--- ${iface} ---"
        ethtool -k "${iface}" | grep -E 'generic-(receive|segmentation)-offload|tcp-segmentation-offload|large-receive-offload|rx-checksumming|tx-checksumming' || true
    fi
done
