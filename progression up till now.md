# Progression Report: SDN IoT Intrusion Detection System

---

## 1. Traffic Capture & Dataset Generation (`traffic_capture.py`)

### Window-Wide Label Inheritance
- Two-pass processing per 5-second flush window
- Pass 1: identifies attacker IPs via Snort alerts or behavioral anomalies
- Pass 2: all flows from that IP inherit the attack label — no "normal" rows mid-attack

### Baseline Integrity
- Attack flows are excluded from `DeviceProfile` volume averages (PPS, BPS, payload size)
- Prevents attackers from slowly shifting the baseline to evade detection

### Per-Host Rate Counters (Primary Detection)
- 4 counters accumulated per source IP per window:
  - `_host_icmp_count` — ICMP Flood if >100/window
  - `_host_syn_count` — SYN Flood if >50 SYN-only (no ACK)/window
  - `_host_udp_count` — UDP Flood if >200/window
  - `_host_dst_ports` — Port Scan if >25 unique dst ports/window
- Checked before Z-score analysis — more reliable, no baseline dependency

### Z-Score Behavioral Analysis (Fallback)
- Threshold raised to 8.0 (from 6.0) — rate counters handle most floods
- 180-second stabilization period for new devices
- Minimum 20 flows before behavioral labeling begins

### Two-Stage Attack Detection
- **Stage 1** — first anomaly detected → logs `[⚠] SUSPECTED ATTACK`, installs 30-second OpenFlow DROP rule on the attacker's MAC
- **Stage 2** — anomaly persists past 30 seconds → logs `[!] ATTACKER CONFIRMED`, installs 120-second OpenFlow DROP rule
- Both stages call `controller.block_attacker()` with full metadata

### IP → MAC Tracking
- `_ip_to_mac` dict populated from every `record_packet` call
- Passed to `block_attacker()` for OpenFlow rule installation

---

## 2. Controller (`Controller.py`)

### ARP Spoofing Detection (DAI Equivalent)
- `_arp_bindings` dict stores first-seen IP → MAC from ARP packets
- If a different MAC claims an already-bound IP → `⚠ ARP SPOOFING DETECTED (DAI)` warning logged
- Alert forwarded to `traffic_capture.record_alert()` for CSV labeling as `attack_type='ARP Spoofing'`

### OpenFlow Attacker Blocking (`block_attacker()`)
- Installs high-priority (65000) OpenFlow DROP rule matching `dl_src=attacker_mac` with `hard_timeout`
- Installed on **all known switches** via `_datapaths` dict
- Empty action list = DROP at switch level (hardware speed)

### Attack Logging
- Formatted box log with:
  - Timestamp of the attack
  - Detection → response latency (in seconds)
  - Device name (dynamically learned), IP address, MAC address
  - Target IP, attack type, detection method
  - DROP rule duration and number of switches affected

### Dynamic Device Name Learning
- `_discovered_names` dict populated from 3 sources:
  1. `REGISTER:NAME:<hostname>` packets from topology (e.g., `sta1 (10.0.0.1)`)
  2. `REGISTER:IOT:<type>` packets (e.g., `IoT:TempSensor`)
  3. First IP packet from any device (fallback: `MAC (IP)`)
- Names used in attack logs — no hardcoded values

### Traffic Mirroring Fix
- Changed `OFPP_CONTROLLER` max_len from `0` to `0xffff`
- `max_len=0` was sending 0 bytes of packet data for flow-rule matches → flood packets couldn't be parsed
- Now sends full packet data to controller for all matched flows

### Registration Priority & Passive Discovery
- Explicit UDP registration (port 9999) overrides passive OUI-based discovery
- `discovery_logged_macs` set prevents log flooding
- Large DPIDs displayed in hexadecimal

---

## 3. Snort IDS Integration (`snort_monitor.py`)

### Pipe Buffer Fix
- Snort stdout/stderr redirected to log files instead of Python pipes
- Prevents controller freeze from full pipe buffers

### Version Compatibility
- Auto-detects Snort 2.x vs Snort 3
- Falls back to `/etc/snort/snort.conf` for Snort 2

### Blocked SIDs
- SIDs 399, 401, 449, 485 added to `_blocked_sids` — ICMP informational messages that caused false positives

---

## 4. Topology Script (`topology .py`)

### Automatic Hostname Registration
- Background thread sends `REGISTER:NAME:<hostname>` from every host (sta1, sta2, h1, h2) at startup
- Controller maps IP → device name for attack logs

### Dynamic Device Addition
- `register_iot_device()` — adds host, links to switch, sends `REGISTER:IOT:type` packet
- `connect_iot_device()` — passive mode, waits for ARP/DHCP to trigger discovery
- Both available via Mininet CLI: `py net.register_iot_device(...)`

### Non-Blocking Registration
- Daemon threads for registration to keep CLI responsive
