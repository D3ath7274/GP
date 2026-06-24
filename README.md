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

There are two supported run modes:

- **Team integrated mode**: `Controller/Controller.py` starts Snort monitoring,
  TAP mirroring, traffic capture, ML inference hooks, and dataset generation.
- **Standalone Snort/Ryu IPS mode**: `Controller/ryu_ips_app.py`,
  `snort_ryu_bridge.py`, and `snort_alert_reader.py` run as separate processes
  and use Snort 3 JSON alerts to push REST block commands into Ryu.

Use only one active blocking path at a time unless you are intentionally testing
both. The existing ML/dataset files and topology remain unchanged.

See `docs/SNORT_RYU_INTEGRATION.md` for the standalone Snort 3 + Ryu startup
order and verification commands.
See `Controller/STANDALONE_SNORT_RYU_FILES.md` for the exact standalone files.

### Standalone Snort 3 + Ryu IPS Startup Order

1. Start topology on the Topology VM:

```bash
cd /path/to/GP/SDN\ Topology
sudo python3 topology.py
```

2. Start Ryu controller on the Controller VM:

```bash
cd /path/to/GP/Controller
./scripts/start_snort_ryu_ips.sh
```

3. Start the Snort-to-Ryu bridge:

```bash
cd /path/to/GP/Controller
python3 snort_ryu_bridge.py
```

4. Start the Snort alert reader:

```bash
cd /path/to/GP/Controller
sudo python3 snort_alert_reader.py
```

5. Install and start Snort 3 JSON alerting:

```bash
cd /path/to/GP/Controller
sudo ./scripts/install_snort3_ips_config.sh
sudo snort -c /etc/snort/sdn_ips.lua -T
sudo SNORT_IFACE=br-snort ./scripts/start_snort3_json.sh
```

The standalone config installs to `/etc/snort/sdn_ips.lua` and loads
`/etc/snort/rules/sdn_ips_local.rules`. Do not update only
`/etc/snort/rules/local.rules` for this mode unless you also change
`sdn_ips.lua` to include it.

6. Verify:

```bash
cd /path/to/GP/Controller
./scripts/verify_snort_ryu_ips.sh
tail -f /var/log/snort/alert_json.txt
```

If VXLAN mirroring is needed first:

```bash
cd /path/to/GP/Controller
sudo LOCAL_IP=<controller-vm-ip> REMOTE_IP=<topology-vm-ip> ./scripts/setup_vxlan_br_snort.sh
```

### Team Integrated Controller Mode

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

To ensure high-fidelity dataset generation, the system currently operates as a **Passive Monitoring Engine**. Attacks are detected, logged, and labeled in the dataset, but OpenFlow DROP rules are bypassed to avoid disrupting the network simulation layer.

1. **Within 5 seconds** — controller logs `[⚠] SUSPECTED ATTACK window 1/3`.
2. **Consecutive Confirmation** — If the attack persists for 3 consecutive windows, it logs `[⛔] ATTACK CONFIRMED` and is rate-limited purely at the Python controller level (Backlog Ignore Cache) to preserve system stability.

Example controller output:
```
╔══════════════════════════════════════════════════════════╗
║  🚨 DETECTION MODE: ON                                    ║
║  Anomaly detection + blocking ACTIVE.                   ║
║  Attacks will be detected and blocked.                  ║
╚══════════════════════════════════════════════════════════╝

[⚠] SUSPECTED ATTACK from 10.0.0.3
    Suspected : UDP Flood (Spike: 24500 detected)
    Target    : 10.0.0.2
    Window    : 1/3 consecutive required
    Action    : Monitoring only (no block yet)

[⛔] ATTACK CONFIRMED — Rate-limiting 10.0.0.3 for 30s
    Attack  : UDP Flood
    Target  : 10.0.0.2
    Evidence: 3 consecutive windows strictly exceeded thresholds.
```

---

## Detection Thresholds (per 5-second window)

| Attack Type | Primary Detection | Threshold |
|---|---|---|
| ICMP Flood | Per-host ICMP counter | >15,000 packets |
| SYN Flood | Per-host SYN-only counter | >5,000 packets |
| UDP Flood | Per-host UDP counter | >15,000 packets |
| Port Scan | Unique dst ports per host | >100 ports |
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
│   ├── ryu_ips_app.py         # Standalone Snort/Ryu IPS controller
│   ├── snort_ryu_bridge.py    # JSON alert bridge to Ryu REST API
│   ├── snort_alert_reader.py  # Snort 3 alert_json reader/blocker
│   ├── traffic_capture.py     # Behavioral analysis + dataset generation
│   ├── traffic_mirror.py      # TAP interface for Snort
│   ├── snort_monitor.py       # Snort process management + alert parsing
│   ├── snort_setup.sh         # Automated Snort installation
│   ├── snort3/                # Standalone Snort 3 local rules/config
│   ├── scripts/               # Setup/start/verification helper scripts
│   └── SNORT_IDS_README.md    # Snort-specific documentation
├── SDN Topology/
│   └── topology .py           # Mininet-wifi network topology
├── docs/
│   └── SNORT_RYU_INTEGRATION.md
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
| External ICMP reaches `br-snort` but no SID 1000001 alert | Verify `/etc/snort/sdn_ips.lua` includes `/etc/snort/rules/sdn_ips_local.rules` and that SID 1000001 is `alert icmp any any -> any any (msg:"ICMP Flood"; itype:8; detection_filter:track by_src, count 10, seconds 5; sid:1000001; rev:2;)` |
| Snort alerts but the target still receives external packets | Run `snort_alert_reader.py` with sudo and verify the working reader added a DROP rule: `sudo iptables -S INPUT | grep <ip>` |
| Snort shows SID 6 `(ipv4) IPv4 datagram length > captured length` | Disable offloads on the capture path with `sudo ./scripts/disable_capture_offloads.sh br-snort vxlan-snort <physical-nic>` and start Snort with `SNORT_SNAPLEN=65535` |
