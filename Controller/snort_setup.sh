#!/bin/bash
# =============================================================================
# Snort IDS Setup Script (Supports Snort 2.x and Snort 3)
# =============================================================================
# Installs Snort (if missing), downloads community rules, and creates
# the appropriate configuration for the SDN controller's IDS.
#
# Usage:  sudo bash snort_setup.sh [INTERFACE] [HOME_NET]
# Example: sudo bash snort_setup.sh ens33 10.0.0.0/24
# Example (multi-network): sudo bash snort_setup.sh ens33 "10.0.0.0/24,192.168.1.0/24"
# =============================================================================

set -e

# ---- Configuration ----
INTERFACE="${1:-ens33}"
HOME_NET_RAW="${2:-10.0.0.0/24,192.168.1.0/24}"
LOG_DIR="/var/log/snort"

echo "=============================================="
echo "  Snort IDS Setup"
echo "=============================================="
echo "  Interface : ${INTERFACE}"
echo "  HOME_NET  : ${HOME_NET_RAW}"
echo "=============================================="

# ---- Pre-flight checks ----
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

# ---- Step 1: Install Snort if missing ----
if ! command -v snort &> /dev/null; then
    echo "[1/5] Snort not found. Installing..."
    apt-get update -qq
    # Try installing Snort — Ubuntu repos typically have Snort 2.9.x
    DEBIAN_FRONTEND=noninteractive apt-get install -y snort || {
        echo ""
        echo "  Automatic install failed. Trying manual approach..."
        apt-get install -y snort-common snort-common-libraries snort-rules-default 2>/dev/null || true
        apt-get install -y snort 2>/dev/null || {
            echo "ERROR: Could not install Snort."
            echo "Install manually: sudo apt install snort"
            echo "Or build from source: https://www.snort.org/downloads"
            exit 1
        }
    }
    echo "  Snort installed successfully."
else
    echo "[1/5] Snort already installed."
fi

# ---- Detect Snort version ----
SNORT_VER_OUTPUT=$(snort -V 2>&1 | head -10)
echo ""
echo "Snort version detected:"
echo "${SNORT_VER_OUTPUT}"
echo ""

# Determine if Snort 2.x or Snort 3
if echo "${SNORT_VER_OUTPUT}" | grep -qi "Snort\!"; then
    # Snort 3 outputs "Snort++"
    SNORT_MAJOR=3
elif echo "${SNORT_VER_OUTPUT}" | grep -qi "Version 2"; then
    SNORT_MAJOR=2
else
    # Default to 2 for older/unknown versions
    SNORT_MAJOR=2
fi
echo "  Detected: Snort ${SNORT_MAJOR}.x"

# Check interface exists
if ! ip link show "${INTERFACE}" &> /dev/null; then
    echo "WARNING: Interface '${INTERFACE}' not found. Available interfaces:"
    ip -br link show
    echo ""
    echo "You can re-run with: sudo bash snort_setup.sh <interface> <home_net>"
fi

# ---- Step 2: Create directories ----
echo "[2/5] Creating directories..."
mkdir -p "${LOG_DIR}"

# ---- Step 3: Download community rules ----
echo "[3/5] Downloading community rules..."

if [ "${SNORT_MAJOR}" -eq 3 ]; then
    RULES_URL="https://www.snort.org/downloads/community/snort3-community-rules.tar.gz"
    SNORT_DIR="/etc/snort"
    RULES_DIR="${SNORT_DIR}/rules"
    TARBALL="/tmp/snort3-community-rules.tar.gz"
else
    RULES_URL="https://www.snort.org/downloads/community/community-rules.tar.gz"
    SNORT_DIR="/etc/snort"
    RULES_DIR="${SNORT_DIR}/rules"
    TARBALL="/tmp/snort2-community-rules.tar.gz"
fi

mkdir -p "${RULES_DIR}"

if command -v wget &> /dev/null; then
    wget -q --show-progress -O "${TARBALL}" "${RULES_URL}" || {
        echo "  Download failed. Rules URL may have changed."
        echo "  You can manually download from: https://www.snort.org/downloads"
        echo "  Continuing with existing rules (if any)..."
    }
elif command -v curl &> /dev/null; then
    curl -L -o "${TARBALL}" "${RULES_URL}" || {
        echo "  Download failed. Continuing with existing rules..."
    }
else
    echo "  WARNING: Neither wget nor curl available. Skipping rule download."
fi

# ---- Step 4: Extract rules ----
echo "[4/5] Extracting rules..."

if [ -f "${TARBALL}" ]; then
    tar -xzf "${TARBALL}" -C /tmp/ 2>/dev/null || true

    if [ "${SNORT_MAJOR}" -eq 3 ]; then
        if [ -f "/tmp/snort3-community-rules/snort3-community.rules" ]; then
            cp /tmp/snort3-community-rules/snort3-community.rules "${RULES_DIR}/"
            echo "  Rules extracted to: ${RULES_DIR}/snort3-community.rules"
        fi
        [ -f "/tmp/snort3-community-rules/sid-msg.map" ] && cp /tmp/snort3-community-rules/sid-msg.map "${RULES_DIR}/"
    else
        # Snort 2.x community rules
        FOUND_RULES=$(find /tmp/ -name "community.rules" -newer "${TARBALL}" 2>/dev/null | head -1)
        if [ -n "${FOUND_RULES}" ]; then
            cp "${FOUND_RULES}" "${RULES_DIR}/community.rules"
            echo "  Rules extracted to: ${RULES_DIR}/community.rules"
        else
            # Try any .rules file from the archive
            FOUND_ANY=$(find /tmp/ -name "*.rules" -newer "${TARBALL}" 2>/dev/null | head -1)
            if [ -n "${FOUND_ANY}" ]; then
                cp "${FOUND_ANY}" "${RULES_DIR}/community.rules"
                echo "  Rules extracted to: ${RULES_DIR}/community.rules"
            fi
        fi
        # Copy sid-msg.map if present
        FOUND_MAP=$(find /tmp/ -name "sid-msg.map" -newer "${TARBALL}" 2>/dev/null | head -1)
        [ -n "${FOUND_MAP}" ] && cp "${FOUND_MAP}" "${RULES_DIR}/"
    fi
fi

RULE_FILE=""
if [ -f "${RULES_DIR}/snort3-community.rules" ]; then
    RULE_FILE="${RULES_DIR}/snort3-community.rules"
elif [ -f "${RULES_DIR}/community.rules" ]; then
    RULE_FILE="${RULES_DIR}/community.rules"
fi

if [ -n "${RULE_FILE}" ]; then
    RULE_COUNT=$(grep -c "^alert\|^drop\|^reject\|^pass" "${RULE_FILE}" 2>/dev/null || echo "0")
    echo "  Total rules loaded: ${RULE_COUNT}"
else
    echo "  WARNING: No rules file found. Snort will run with built-in rules only."
fi

# ---- Step 5: Create/update configuration ----
echo "[5/5] Configuring Snort..."

if [ "${SNORT_MAJOR}" -eq 3 ]; then
    # ---- Snort 3 Configuration (Lua) ----
    CONF_FILE="${SNORT_DIR}/snort.lua"

    # Format HOME_NET for Snort 3
    if echo "${HOME_NET_RAW}" | grep -q ','; then
        HOME_NET="[${HOME_NET_RAW}]"
    else
        HOME_NET="${HOME_NET_RAW}"
    fi

    cat > "${CONF_FILE}" << SNORT_LUA_EOF
-- Snort 3 Configuration for SDN Controller IDS (auto-generated)
HOME_NET = '${HOME_NET}'
EXTERNAL_NET = '!\$HOME_NET'

ips =
{
    enable_builtin_rules = true,
    include = BUILTIN_RULE_PATH,
    rules = [[
        include ${RULES_DIR}/snort3-community.rules
    ]]
}

stream = { }
stream_tcp = { }
stream_udp = { }
stream_icmp = { }
http_inspect = { }
normalizer = { tcp = { ips = true } }

alert_fast =
{
    file = true,
    packet = false,
}
SNORT_LUA_EOF

    echo "  Configuration written to: ${CONF_FILE}"

else
    # ---- Snort 2.x Configuration ----
    CONF_FILE="${SNORT_DIR}/snort.conf"

    # Only create if doesn't exist (preserve user edits)
    if [ ! -f "${CONF_FILE}" ]; then
        echo "  Creating new Snort 2 config..."
    else
        echo "  Updating existing Snort 2 config..."
        cp "${CONF_FILE}" "${CONF_FILE}.bak"
    fi

    # Update HOME_NET in existing config
    if [ -f "${CONF_FILE}" ]; then
        # Format for Snort 2: ipvar HOME_NET [10.0.0.0/24,192.168.1.0/24]
        if echo "${HOME_NET_RAW}" | grep -q ','; then
            HOME_NET="[${HOME_NET_RAW}]"
        else
            HOME_NET="${HOME_NET_RAW}"
        fi
        sed -i "s|^ipvar HOME_NET .*|ipvar HOME_NET ${HOME_NET}|" "${CONF_FILE}" 2>/dev/null || true
        sed -i "s|^var HOME_NET .*|var HOME_NET ${HOME_NET}|" "${CONF_FILE}" 2>/dev/null || true

        # Add community rules include if not already present
        if ! grep -q "community.rules" "${CONF_FILE}" 2>/dev/null; then
            echo "include \$RULE_PATH/community.rules" >> "${CONF_FILE}"
            echo "  Added community.rules include to config."
        fi
    fi

    echo "  Configuration: ${CONF_FILE}"
fi

# ---- Cleanup ----
rm -f "${TARBALL}"
rm -rf /tmp/snort3-community-rules/ /tmp/community-rules/ 2>/dev/null

echo ""
echo "=============================================="
echo "  ✅ Snort ${SNORT_MAJOR} setup complete!"
echo "=============================================="
echo ""
echo "To test Snort manually:"
if [ "${SNORT_MAJOR}" -eq 3 ]; then
    echo "  sudo snort -c ${CONF_FILE} -i ${INTERFACE} -l ${LOG_DIR} -A alert_fast"
else
    echo "  sudo snort -c ${CONF_FILE} -i ${INTERFACE} -l ${LOG_DIR} -A console"
fi
echo ""
echo "To use with the SDN controller:"
echo "  sudo ryu-manager Controller.py"
echo ""
echo "Snort will be started automatically by the controller."
echo ""
