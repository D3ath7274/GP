#!/usr/bin/env bash
set -euo pipefail

# Starts the standalone Ryu IPS app from this repo.
# Run from the Controller VM after the topology switch can reach TCP/6633.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTROLLER_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${CONTROLLER_DIR}"
exec ryu-manager ryu_ips_app.py --observe-links
