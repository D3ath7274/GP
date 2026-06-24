#!/usr/bin/env bash
set -euo pipefail

RYU_BASE="${RYU_BASE:-http://127.0.0.1:8080}"
BRIDGE_BASE="${BRIDGE_BASE:-http://127.0.0.1:9000}"

echo "[1/4] Ryu IPS status"
curl -fsS "${RYU_BASE}/ips/status"
echo

echo "[2/4] Ryu connected switches"
curl -fsS "${RYU_BASE}/ips/switches"
echo

echo "[3/4] Bridge health"
curl -fsS "${BRIDGE_BASE}/health"
echo

echo "[4/4] Current blocked IPs"
curl -fsS "${RYU_BASE}/ips/blocked"
echo
