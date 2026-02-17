# Snort 3 IDS Integration for SDN Controller

Integrates Snort 3 with community rules into the Ryu SDN controller to monitor all network traffic on the controller machine and report detected attacks in real-time.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                Ubuntu Controller Machine                 │
│                                                          │
│   ┌──────────────┐     ┌──────────────────────────┐     │
│   │ Ryu SDN      │     │ Snort 3 IDS              │     │
│   │ Controller   │────>│  - Community Rules        │     │
│   │              │     │  - Listening on ens33     │     │
│   │ SnortManager │<────│  - alert_fast output      │     │
│   │ (monitors    │     └──────────────────────────┘     │
│   │  alerts)     │                                       │
│   └──────────────┘                                       │
│          │                                               │
│          ▼                                               │
│   Logs: "SQL injection attack detected from 10.0.0.5"   │
│   Logs: "SYN flood attack detected from 10.0.0.2"       │
└─────────────────────────────────────────────────────────┘
          ▲
          │ All traffic (physical + Mininet-wifi virtual)
          │
    ┌─────┴──────┐
    │   ens33    │
    └────────────┘
```

## Prerequisites

1. **Ubuntu** (controller machine)
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
4. **Root/sudo access** (Snort needs raw packet capture)

## Quick Start

### Step 1: Download Rules & Configure Snort

```bash
cd Controller/
sudo bash snort_setup.sh ens33 10.0.0.0/24
```

This will:
- Download community rules from `https://www.snort.org/downloads/community/snort3-community-rules.tar.gz`
- Extract rules to `/etc/snort/rules/snort3-community.rules`
- Create config at `/etc/snort/snort.lua`
- Validate the configuration

### Step 2: Start the Controller (with Snort)

```bash
sudo ryu-manager "Controller network only .py"
```

The controller will automatically:
1. Start Snort 3 on `ens33`
2. Begin monitoring `/var/log/snort/alert_fast.txt`
3. Log any detected attacks to the controller output

### Step 3: Start Mininet-wifi Topology (on another machine or terminal)

```bash
sudo python3 "SDN Topology/topology .py"
```

All Mininet-wifi traffic flows through the controller's `ens33` interface and is monitored by Snort.

## Testing with Simulated Attacks

From another terminal or a Mininet host, try:

```bash
# SYN Flood
sudo hping3 -S --flood -p 80 <controller-ip>

# Port Scan
nmap -sS <controller-ip>

# SQL Injection payload via HTTP
curl "http://<controller-ip>/?id=1' OR '1'='1"

# Ping Flood
sudo hping3 --icmp --flood <controller-ip>
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

Edit `Controller network only .py`, line with `interface='ens33'`:
```python
self.snort_manager = SnortManager(
    interface='eth0',  # Change to your interface
    ...
)
```

### Changing HOME_NET

Re-run setup with your subnet:
```bash
sudo bash snort_setup.sh ens33 192.168.1.0/24
```

### Standalone Snort Monitor Test

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
