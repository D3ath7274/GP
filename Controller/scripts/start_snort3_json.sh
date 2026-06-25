#!/usr/bin/env bash
set -euo pipefail

SNORT_CONF="${SNORT_CONF:-/etc/snort/sdn_ips.lua}"
SNORT_IFACE="${SNORT_IFACE:-br-snort}"
SNORT_LOG_DIR="${SNORT_LOG_DIR:-/var/log/snort}"
SNORT_SNAPLEN="${SNORT_SNAPLEN:-65535}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run with sudo."
    exit 1
fi

mkdir -p "${SNORT_LOG_DIR}"
touch "${SNORT_LOG_DIR}/alert_json.txt"

exec snort -c "${SNORT_CONF}" -i "${SNORT_IFACE}" -l "${SNORT_LOG_DIR}" \
    --daq-var "snaplen=${SNORT_SNAPLEN}" -A alert_json -q
