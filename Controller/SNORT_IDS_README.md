# Snort 3 IDS Integration for SDN Controller

Integrates Snort 3 with community rules into the Ryu SDN controller to monitor all network traffic on the controller machine and report detected attacks in real-time.

## Architecture (Traffic Mirroring)

All data-plane traffic (10.0.0.x Mininet + 192.168.1.x management) is mirrored to the controller:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Ubuntu Controller Machine                         │
│                                                                      │
│   OpenFlow switch ──> Packet-In (every packet) ──> TrafficMirror     │
│        │                                    │           │            │
│        │                                    │           v            │
│        v                                    │    ┌──────────────┐    │
│   Flow rules with Output(CONTROLLER)        │    │ TAP snort_tap│    │
│   so ALL packets are copied to controller   │    └──────┬───────┘    │
│                                              │           │            │
│   ┌──────────────┐     ┌────────────────────┴───────────┴───────┐   │
│   │ Ryu SDN      │     │ Snort 3 IDS (multi-interface)          │   │
│   │ Controller   │     │  - ens33 (192.168.1.x physical)        │   │
│   │ SnortManager │<────│  - snort_tap (mirrored 10.0.0.x)       │   │
│   └──────────────┘     │  - alert_fast output → ML-ready        │   │
│                        └────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Machine Setup

| Machine | IP | Role |
|---------|-----|------|
| **Controller** | 192.168.1.11 | Ryu + Snort IDS + traffic mirror |
| **Mininet-wifi** | 192.168.1.13 | Topology, hosts, APs, switches |

## Prerequisites

**On Controller (192.168.1.11):**

1. **Ubuntu**
2. **Snort 3** installed:
   ```bash
   # Option A: From package manager
   sudo apt update && sudo apt install snort

   # Option B: Build from source (see https://www.snort.org/downloads)
   ```
3. **Ryu SDN Framework** installed:
   ```bash
   pip install ryu
   ```
4. **Root/sudo access** (Snort + TAP need raw packet capture)
5. **TUN/TAP kernel module** (for traffic mirroring):
   ```bash
   sudo modprobe tun
   ```

## Quick Start

### Step 1: Download Rules & Configure Snort

**Machine: Controller (192.168.1.11)**

```bash
cd Controller/
sudo bash snort_setup.sh ens33 "10.0.0.0/24,192.168.1.0/24"
```

Or single network only:
```bash
sudo bash snort_setup.sh ens33 10.0.0.0/24
```

This will:
- Download community rules from `https://www.snort.org/downloads/community/snort3-community-rules.tar.gz`
- Extract rules to `/etc/snort/rules/snort3-community.rules`
- Create config at `/etc/snort/snort.lua`
- Validate the configuration

### Step 2: Start the Controller (with Snort)

**Machine: Controller (192.168.1.11)**

```bash
sudo ryu-manager "Controller network only .py"
```

The controller will automatically:
1. Start Snort 3 on `ens33`
2. Begin monitoring `/var/log/snort/alert_fast.txt`
3. Log any detected attacks to the controller output

### Step 3: Start Mininet-wifi Topology

**Machine: Mininet-wifi (192.168.1.13)**

```bash
sudo python3 "SDN Topology/topology .py"
```

**Traffic visibility (forced mirroring):** All traffic is now mirrored to the controller:
- **10.0.0.x** (Mininet data-plane): Every packet is sent to the controller via OpenFlow `Output(OFPP_CONTROLLER)`, injected into a TAP interface, and analyzed by Snort.
- **192.168.1.x** (management): Snort captures directly on the physical interface.
- The controller creates a TAP device (`snort_tap`) at startup. Snort monitors both the physical NIC and the TAP.

## Testing with Simulated Attacks

**Machine: Mininet-wifi (192.168.1.13)** — from a Mininet host (e.g. `mininet> sta1`) or from the host:

```bash
# SYN Flood (replace 192.168.1.11 with controller IP if different)
sudo hping3 -S --flood -p 80 192.168.1.11

# Port Scan
nmap -sS 192.168.1.11

# SQL Injection payload via HTTP
curl "http://192.168.1.11/?id=1' OR '1'='1"

# Ping Flood
sudo hping3 --icmp --flood 192.168.1.11
```

### Expected Output in Controller Logs

```
╔══════════════════════════════════════════════════════════╗
║  🚨 IDS ALERT: SYN flood attack                        ║
╠══════════════════════════════════════════════════════════╣
║  Attack : SYN flood attack                               ║
║  Source : 10.0.0.2:12345                                 ║
║  Target : 192.168.1.101:80                               ║
║  Proto  : TCP                                            ║
║  Rule   : SID 1000001                                    ║
╚══════════════════════════════════════════════════════════╝
```

## File Structure

```
Controller/
├── Controller network only .py   # Ryu controller (modified with Snort integration)
├── snort_monitor.py              # SnortManager module (process + alert parsing)
├── snort_setup.sh                # Setup script (downloads rules, creates config)
└── SNORT_IDS_README.md           # This file
```

## Configuration

### Changing the Network Interface

**Machine: Controller (192.168.1.11)** — Edit `Controller network only .py`, line with `_physical_interface`:
```python
self._physical_interface = 'ens33'
```

### Changing HOME_NET

**Machine: Controller (192.168.1.11)**

Re-run setup with your subnet(s):
```bash
# Single network
sudo bash snort_setup.sh ens33 192.168.1.0/24

# Multiple networks (controller + Mininet)
sudo bash snort_setup.sh ens33 "10.0.0.0/24,192.168.1.0/24"
```

### Standalone Snort Monitor Test

**Machine: Controller (192.168.1.11)**

Test the alert parser without the Ryu controller:
```bash
python3 snort_monitor.py           # Parse sample alerts
sudo python3 snort_monitor.py monitor ens33  # Live monitoring
```

## Attack Types Detected

The system classifies ~50 attack categories including:

| Category | Examples |
|----------|----------|
| SQL Injection | `SQL injection attack detected from X` |
| XSS | `XSS (Cross-Site Scripting) attack detected from X` |
| DoS/DDoS | `SYN flood attack detected from X` |
| Port Scanning | `Nmap scan detected from X`, `Port scan detected from X` |
| Malware | `Trojan activity detected from X`, `Backdoor detected from X` |
| Exploits | `Buffer overflow exploit from X`, `Shellcode execution from X` |
| Brute Force | `Brute force login attempt from X` |
| Protocol Attacks | `ARP spoofing from X`, `DNS amplification from X` |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Snort binary not found" | Install Snort 3: `sudo apt install snort` |
| "Permission denied" | Run with `sudo`: `sudo ryu-manager ...` |
| "Config not found" | Run `sudo bash snort_setup.sh` first |
| No alerts appearing | Check `/var/log/snort/alert_fast.txt` has content |
| Snort crashes on start | Validate config: `snort -c /etc/snort/snort.lua --warn-all` |
