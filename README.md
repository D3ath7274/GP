# SDN IoT Intrusion Prevention System

An SDN-based intrusion detection and prevention system for IoT networks. Uses a Ryu OpenFlow controller with Snort IDS, behavioral anomaly detection, and OpenFlow DROP rules to detect and block attacks in real time.

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│              Controller VM (Ubuntu)               │
│  ┌──────────────────────────────────────────┐     │
│  │  Ryu Controller (Controller.py)          │     │
│  │  ├── Snort IDS (snort_monitor.py)        │     │
│  │  ├── Traffic Mirror (traffic_mirror.py)  │     │
│  │  ├── Traffic Capture (traffic_capture.py)│     │
│  │  └── OpenFlow DROP Rules                 │     │
│  └──────────────────────────────────────────┘     │
└──────────────────────────────────────────────────┘
                      │ OpenFlow (TCP 6633)
┌──────────────────────────────────────────────────┐
│              Topology VM (Ubuntu)                 │
│  ┌──────────────────────────────────────────┐     │
│  │  Mininet-wifi (topology .py)             │     │
│  │  ├── sta1 (10.0.0.1) ─ WiFi             │     │
│  │  ├── sta2 (10.0.0.2) ─ WiFi             │     │
│  │  ├── h1 (10.0.0.3)   ─ Wired            │     │
│  │  ├── h2 (10.0.0.4)   ─ Wired            │     │
│  │  └── IoT devices (dynamically added)     │     │
│  └──────────────────────────────────────────┘     │
└──────────────────────────────────────────────────┘
```

---

## Prerequisites

### Controller VM
- Ubuntu 20.04+
- Python 3.8+
- Ryu SDN Framework
- Snort 2.x or 3 with community rules

### Topology VM
- Ubuntu 20.04+
- Mininet-wifi
- `hping3` (for attack simulation)

---

## Installation

### 1. Controller VM Setup

```bash
# Install Ryu
pip3 install ryu

# Install Snort (automated)
cd Controller/
chmod +x snort_setup.sh
sudo ./snort_setup.sh

# Verify Snort
snort -V
```

### 2. Topology VM Setup

```bash
# Install Mininet-wifi
git clone https://github.com/intrig-unicamp/mininet-wifi
cd mininet-wifi
sudo util/install.sh -Wnfvl

# Install attack tools
sudo apt install hping3 dsniff nmap -y
```

### 3. Network Configuration

Both VMs must be on the same network. Update the controller IP in `topology .py`:

```python
c0 = net.addController('c0', controller=RemoteController,
                       ip='192.168.1.19', port=6633)  # ← Your controller VM IP
```

---

## Usage

### Step 1: Start the Controller

On the **Controller VM**:

```bash
cd Controller/
sudo ryu-manager Controller.py
```

Expected output:
```
Traffic mirror TAP 'snort_tap' started.
Starting Snort IDS on interface ens33...
Snort on ens33 started (PID: XXXX)
Traffic capture started → dataset.csv (window: 5.0s)
```

### Step 2: Start the Topology

On the **Topology VM**:

```bash
cd "SDN Topology/"
sudo python3 "topology .py"
```

Expected output:
```
*** Creating nodes
*** Configuring WiFi nodes
*** Creating links
*** Starting network
*** Hostname registered: sta1
*** Hostname registered: sta2
*** Hostname registered: h1
*** Hostname registered: h2
*** All hostnames registered with controller
*** Running CLI
mininet-wifi>
```

### Step 3: Verify Connectivity

```bash
mininet-wifi> pingall
```

No attack alerts should appear — this is normal traffic.

### Step 4: Dynamically Add IoT Devices

```bash
# Register a temperature sensor
mininet-wifi> py net.register_iot_device(net, 'TempSensor', '10.0.0.5/24', '00:0a:95:54:f1:02', 's1', 'IOT:TempSensor')

# Connect a passive device (discovered via ARP)
mininet-wifi> py net.connect_iot_device(net, 'cam1', '10.0.0.6/24', '00:11:22:33:44:55', 's1')
```

---

## Attack Simulation & Detection

### ICMP Flood
```bash
mininet-wifi> h1 hping3 --icmp --flood 10.0.0.1
```

### SYN Flood
```bash
mininet-wifi> h1 hping3 -S --flood -p 80 10.0.0.2
```

### UDP Flood
```bash
mininet-wifi> h1 hping3 --udp --flood -p 53 10.0.0.2
```

### Port Scan
```bash
mininet-wifi> h1 nmap -sS -p 1-1000 10.0.0.2
```

### ARP Spoofing
```bash
# First establish real ARP bindings
mininet-wifi> pingall

# Then spoof — h1 claims to be sta1 (10.0.0.1)
mininet-wifi> h1 arpspoof -i h1-eth0 -t 10.0.0.2 10.0.0.1 &
```

### Expected Detection Flow

1. **Within 5 seconds** — controller logs `[⚠] SUSPECTED ATTACK` and installs a 30-second DROP rule
2. **If attack persists past 30 seconds** — controller logs `[!] ATTACKER CONFIRMED` and installs a 120-second DROP rule

Example controller output:
```
╔══════════════════════════════════════════════════════════╗
║  🚫 ATTACKER RATE-LIMITED                                ║
╠══════════════════════════════════════════════════════════╣
║  Time      : 2026-03-23 17:45:12                         ║
║  Latency   : 0.003s (detection → response)               ║
║  Device    : h1 (10.0.0.3)                               ║
║  IP        : 10.0.0.3                                    ║
║  MAC       : 9e:8e:c6:8d:10:57                           ║
║  Target    : 10.0.0.2                                    ║
║  Attack    : UDP Flood                                   ║
║  Action    : DROP rule for 30s                           ║
╚══════════════════════════════════════════════════════════╝
```

---

## Detection Thresholds (per 5-second window)

| Attack Type | Primary Detection | Threshold |
|---|---|---|
| ICMP Flood | Per-host ICMP counter | >100 packets |
| SYN Flood | Per-host SYN-only counter | >50 packets |
| UDP Flood | Per-host UDP counter | >200 packets |
| Port Scan | Unique dst ports per host | >25 ports |
| ARP Spoofing | IP→MAC binding mismatch | 1 mismatch |

A secondary Z-score behavioral analysis (threshold 8.0) catches attacks that stay just below these counters.

---

## Output Files

| File | Location | Contents |
|---|---|---|
| `dataset.csv` | Controller directory | Per-flow features with attack labels for ML training |
| `snort_stdout.log` | `/var/log/snort/` | Snort standard output |
| `snort_stderr.log` | `/var/log/snort/` | Snort errors |

---

## Project Structure

```
GP/
├── Controller/
│   ├── Controller.py          # Ryu SDN controller (main)
│   ├── traffic_capture.py     # Behavioral analysis + dataset generation
│   ├── traffic_mirror.py      # TAP interface for Snort
│   ├── snort_monitor.py       # Snort process management + alert parsing
│   ├── snort_setup.sh         # Automated Snort installation
│   └── SNORT_IDS_README.md    # Snort-specific documentation
├── SDN Topology/
│   └── topology .py           # Mininet-wifi network topology
├── progression up till now.md # Technical changelog
└── README.md                  # This file
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| No alerts during flood attacks | Verify `Controller.py` on the VM has `OFPP_CONTROLLER, 0xffff` (not `0`) |
| Snort fails to start | Run `sudo ./snort_setup.sh` and check `/var/log/snort/snort_stderr.log` |
| `pingall` triggers false alerts | Should not happen — ICMP threshold is 100/window, `pingall` sends ~5 |
| ARP spoof not detected | Ensure the real device has sent traffic first (binding must exist) |
| Hostname shows as `Host 10.0.0.X` | Topology hostname registration may not have reached the controller — check network connectivity |
