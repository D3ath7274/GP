#!/bin/bash
# =============================================================================
# TLS Certificate Generator for SDN-IPS Framework
# =============================================================================
# Generates a self-signed CA and certificates for the OpenFlow channel:
#   1. Root CA (ca.crt, ca.key)
#   2. Controller certificate (controller.crt, controller.key)
#   3. Switch certificate (switch.crt, switch.key)
#
# Usage:
#   chmod +x generate_certs.sh
#   ./generate_certs.sh
#
# After running, copy switch.crt, switch.key, and ca.crt to the topology VM.
# =============================================================================

set -e

CERT_DIR="./certs"
DAYS=3650  # 10 years
KEY_SIZE=2048

# Certificate subject fields
COUNTRY="EG"
STATE="Cairo"
ORG="SDN-IPS"
CA_CN="SDN-IPS Root CA"
CONTROLLER_CN="sdn-ips-controller"
SWITCH_CN="sdn-ips-switch"

echo "============================================"
echo "  SDN-IPS TLS Certificate Generator"
echo "============================================"
echo ""

# Create output directory
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# --- Step 1: Generate Root CA ---
echo "[1/3] Generating Root CA..."
openssl genrsa -out ca.key $KEY_SIZE 2>/dev/null
openssl req -new -x509 -days $DAYS -key ca.key -out ca.crt \
    -subj "/C=$COUNTRY/ST=$STATE/O=$ORG/CN=$CA_CN" 2>/dev/null
echo "  ✅ ca.key, ca.crt"

# --- Step 2: Generate Controller Certificate ---
echo "[2/3] Generating Controller certificate..."
openssl genrsa -out controller.key $KEY_SIZE 2>/dev/null
openssl req -new -key controller.key -out controller.csr \
    -subj "/C=$COUNTRY/ST=$STATE/O=$ORG/CN=$CONTROLLER_CN" 2>/dev/null
openssl x509 -req -days $DAYS -in controller.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out controller.crt 2>/dev/null
rm -f controller.csr
echo "  ✅ controller.key, controller.crt"

# --- Step 3: Generate Switch Certificate ---
echo "[3/3] Generating Switch certificate..."
openssl genrsa -out switch.key $KEY_SIZE 2>/dev/null
openssl req -new -key switch.key -out switch.csr \
    -subj "/C=$COUNTRY/ST=$STATE/O=$ORG/CN=$SWITCH_CN" 2>/dev/null
openssl x509 -req -days $DAYS -in switch.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out switch.crt 2>/dev/null
rm -f switch.csr
echo "  ✅ switch.key, switch.crt"

# Clean up serial file
rm -f ca.srl

# Set permissions
chmod 600 *.key
chmod 644 *.crt

echo ""
echo "============================================"
echo "  Certificates generated in $CERT_DIR/"
echo "============================================"
echo ""
echo "  Files:"
ls -la *.key *.crt 2>/dev/null
echo ""
echo "  Next steps:"
echo "  1. Keep ca.key, controller.key, controller.crt on the controller (t530)"
echo "  2. Copy switch.key, switch.crt, and ca.crt to the topology VM"
echo "  3. On the topology VM, configure OVS:"
echo "     sudo ovs-vsctl set-ssl /path/switch.key /path/switch.crt /path/ca.crt"
echo "  4. Change controller target to: ssl:<controller_ip>:6633"
echo ""
echo "  To verify:"
echo "     openssl verify -CAfile ca.crt controller.crt"
echo "     openssl verify -CAfile ca.crt switch.crt"
echo ""

# Verify the certificates
echo "  Verification:"
openssl verify -CAfile ca.crt controller.crt
openssl verify -CAfile ca.crt switch.crt

echo ""
echo "  ✅ All certificates valid"
echo "============================================"
