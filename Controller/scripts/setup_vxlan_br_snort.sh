#!/usr/bin/env bash
set -euo pipefail

# Creates a local br-snort bridge and VXLAN interface for mirrored traffic.
# Required environment:
#   LOCAL_IP=<controller-vm-ip>
#   REMOTE_IP=<topology-vm-ip>
# Optional:
#   VXLAN_ID=42
#   VXLAN_DEV=<physical-nic>
#   BRIDGE_NAME=br-snort
#   VXLAN_NAME=vxlan-snort

LOCAL_IP="${LOCAL_IP:-}"
REMOTE_IP="${REMOTE_IP:-}"
VXLAN_ID="${VXLAN_ID:-42}"
VXLAN_DEV="${VXLAN_DEV:-}"
BRIDGE_NAME="${BRIDGE_NAME:-br-snort}"
VXLAN_NAME="${VXLAN_NAME:-vxlan-snort}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run with sudo."
    exit 1
fi

if [[ -z "${LOCAL_IP}" || -z "${REMOTE_IP}" ]]; then
    echo "ERROR: set LOCAL_IP and REMOTE_IP first."
    echo "Example: sudo LOCAL_IP=192.168.1.200 REMOTE_IP=192.168.1.201 $0"
    exit 1
fi

if [[ -z "${VXLAN_DEV}" ]]; then
    VXLAN_DEV="$(ip route get "${REMOTE_IP}" | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')"
fi

ip link show "${BRIDGE_NAME}" >/dev/null 2>&1 || ip link add "${BRIDGE_NAME}" type bridge
ip link set "${BRIDGE_NAME}" up

if ! ip link show "${VXLAN_NAME}" >/dev/null 2>&1; then
    ip link add "${VXLAN_NAME}" type vxlan id "${VXLAN_ID}" \
        local "${LOCAL_IP}" remote "${REMOTE_IP}" dev "${VXLAN_DEV}" dstport 4789
fi

ip link set "${VXLAN_NAME}" master "${BRIDGE_NAME}"
ip link set "${VXLAN_NAME}" up

echo "VXLAN mirror endpoint ready:"
echo "  bridge : ${BRIDGE_NAME}"
echo "  vxlan  : ${VXLAN_NAME}"
echo "  local  : ${LOCAL_IP}"
echo "  remote : ${REMOTE_IP}"
echo "  dev    : ${VXLAN_DEV}"
echo
echo "Capture interface for Snort: ${BRIDGE_NAME}"
