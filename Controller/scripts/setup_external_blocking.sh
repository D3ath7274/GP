#!/usr/bin/env bash
set -euo pipefail

# Optional host firewall helper for the standalone alert reader.
# It does not add DROP rules itself; snort_alert_reader.py adds per-source
# DROP rules only after trusted blocking SIDs fire.

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run with sudo."
    exit 1
fi

sysctl -w net.ipv4.ip_forward=1
iptables -N SDN_IPS_BLOCK 2>/dev/null || true
iptables -C INPUT -j SDN_IPS_BLOCK 2>/dev/null || iptables -I INPUT -j SDN_IPS_BLOCK
iptables -C FORWARD -j SDN_IPS_BLOCK 2>/dev/null || iptables -I FORWARD -j SDN_IPS_BLOCK

echo "Prepared SDN_IPS_BLOCK chain and INPUT/FORWARD hooks."
echo "Current matching rules:"
iptables -S SDN_IPS_BLOCK || true
