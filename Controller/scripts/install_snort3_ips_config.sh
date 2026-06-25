#!/usr/bin/env bash
set -euo pipefail

REPO_CONTROLLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULE_SRC="${REPO_CONTROLLER_DIR}/snort3/sdn_ips_local.rules"
CONF_SRC="${REPO_CONTROLLER_DIR}/snort3/sdn_ips.lua"
SNORT_DIR="${SNORT_DIR:-/etc/snort}"
RULE_DIR="${RULE_DIR:-${SNORT_DIR}/rules}"
CONF_DST="${CONF_DST:-${SNORT_DIR}/sdn_ips.lua}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run with sudo."
    exit 1
fi

if ! command -v snort >/dev/null 2>&1; then
    echo "ERROR: snort is not installed or not in PATH."
    exit 1
fi

mkdir -p "${RULE_DIR}" /var/log/snort
install -m 0644 "${RULE_SRC}" "${RULE_DIR}/sdn_ips_local.rules"
install -m 0644 "${CONF_SRC}" "${CONF_DST}"

touch /var/log/snort/alert_json.txt /var/log/snort/alert_fast.txt
chmod 0644 /var/log/snort/alert_json.txt /var/log/snort/alert_fast.txt

echo "Installed:"
echo "  ${RULE_DIR}/sdn_ips_local.rules"
echo "  ${CONF_DST}"
echo
echo "Active rule path:"
echo "  ${CONF_DST} includes ${RULE_DIR}/sdn_ips_local.rules"
echo "  ${RULE_DIR}/local.rules is not used by this standalone integration unless you edit ${CONF_DST}."
echo
echo "Validate with:"
echo "  sudo snort -c ${CONF_DST} -T"
echo
echo "Run Snort with:"
echo "  sudo snort -c ${CONF_DST} -i <interface> -l /var/log/snort -A alert_json"
