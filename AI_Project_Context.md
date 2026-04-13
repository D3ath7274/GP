# Comprehensive Project Context: SDN-based IoT Intrusion Prevention System (IPS)

**Purpose of this Document:** This document is designed to be fed as a master context file to any LLM or AI agent. It details the complete architecture, features, workflow, and core programming paradigms of the Graduation Project up to its current state. Provide this file to an AI to give it 100% complete memory of our project structure.

---

## 1. System Architecture
The project runs across two Ubuntu Virtual Machines bridged on the same physical network:

**1. Controller VM (e.g., IP 192.168.1.19)**
* **Ryu SDN Controller** (`Controller.py`): The brain of the network, acting as an OpenFlow 1.0 Layer 2 learning switch.
* **Snort IDS** (`snort_monitor.py`): Monitors the physical interface and a virtual TAP interface to evaluate simulated data-plane traffic against community rules.
* **Traffic Capture Engine** (`traffic_capture.py`): A parallel thread compiling 49+ behavioral network telemetry features per flow to generate `dataset.csv` for future Machine Learning models.

**2. Topology VM**
* **Mininet-WiFi** (`topology.py`): Emulates the network Layer 2 data plane. Features 2 WiFi stations (`sta1`, `sta2`), 1 Access Point (`ap1`), 2 Wired Hosts (`h1`, `h2`), and 1 OpenFlow Switch (`s1`).
* Serves as the origin point for dynamically simulated IoT sensors and network attacks (e.g., via `hping3`, `nmap`, and `arpspoof`).

---

## 2. Core Operational Capabilities & Quality of Life Perks

### A. Fully Mirrored SDN to Snort Pipeline
* By definition, an external Snort process cannot see inside a Mininet software switch data plane. 
* **The Perk:** The controller duplicates **every single** data-plane packet via `OFPP_CONTROLLER` (`max_len=0xffff`) and writes them directly into a virtual Linux TUN/TAP interface (`snort_tap`). Snort simultaneously monitors both the physical port and this TAP interface, seeing the whole emulated world natively.

### B. "Out-of-Band" UDP Control Channels
* **The Perk:** Registration and detection commands bypass the Mininet OpenFlow queuing logic completely! 
* The topology script uses standard Python `socket` logic to shoot physical UDP packets directly out of the host OS explicitly to the Controller VM port `9999`. 
* **The Benefit:** Even if the Mininet topology is paralyzed by a 150,000 PPS broadcast flood, administration commands (e.g., `CONTROL:UNBLOCK:10.0.0.3` or `REGISTER:IOT`) still reach the python controller instantly over the real-world NIC.

### C. Zero-Trust IoT Discovery & Visual Identity Mapping
* **Dynamic Name Binding:** Populates a `_discovered_names` registry via UDP registration (`REGISTER:NAME:h1`). When generating alerts, logs gracefully print hostnames (e.g., `10.0.0.3 (h1)`) instead of cryptic raw IPs.
* **Passive Device Discovery:** The controller natively cracks open DHCP/ARP payloads and cross-references hardware MAC OUI prefixes against known manufacturer hardware addresses (e.g., Philips Hue, IKEA TRADFRI gateways).

---

## 3. The 3-Tier Security Identification Engine

### Tier 1: Snort Signature Matching
* Real-time tailing of Snort's `alert_fast.txt` with auto-translation from raw SIDs to readable attack names.
* **The Perk (Noise Cancellation):** We automatically filter completely benign `pingall` loops and TAP cloning artifacts (SIDs 366, 384, 408, 527) out of the engine, ensuring 0% false positives on standard operations.

### Tier 2: Extreme-Volume Rate Counters
* Custom Python dictionaries meticulously summing protocol traffic per 5-second window.
* **The Perk (Simulation Tolerance):** Because Mininet naturally creates broadcast storms during legitimate `pingall` commands (generating up to 6,000 cloned tracking packets), the thresholds are logically raised to account for duplication parameters:
    * ICMP / UDP Flood: `> 15,000 packets/window`
    * SYN Flood: `> 5,000 packets/window` (Analyzes low ACK ratios)
    * Port Scan: `> 100 unique target ports/window`

### Tier 3: Statistical Z-Score Behavioral Profiling (Anomaly Detection)
* Maintains a permanent statistical baseline for every unique IP using Welford's online variation algorithm.
* Requires a minimum of 20 flows & 180 seconds stabilization time. Triggers at an extremely conservative Z-score deviation of `8.0`.
* **The Perk (Traffic Drop Guard):** Employs a specific math block (`curr_pps < 10`) ensuring that when an attacker suddenly *stops* an active flood, the massive drop to 0 PPS isn't falsely prosecuted as a new anomaly.

---

## 4. Uninterrupted Machine Learning Dataset Pipeline (`dataset.csv`)

### A. Passive IDS Architecture for Pristine Threat Datasets
* Active blocking (hardware switch OpenFlow `DROP` rules) has been deliberately suppressed. Instead, the Controller employs a Python-layer **Virtual Backlog Ignore Cache** to drop backlogged calculations to save RAM.
* **The Benefit:** The actual Layer 2 network switch remains unbothered. This allows full volumetric attack lifecycles to complete inside the simulation natively while the controller flawlessly records the extreme `Label 2` variations into `dataset.csv`. 

### B. Robust Escalation Flow & Permanent Lock-In
* To eliminate random single-window lag spikes triggering false red-flags, suspicious flows enter a monitoring state (`Window 1/3`).
* If sustained for 3 consecutive 5-second windows, the Controller issues exactly **one** `[⛔] ATTACK CONFIRMED` console warning.
* **The Perk (Permanent Lock-in):** Once confirmed, the offending IP traverses into `_confirmed_attackers`. For the rest of the node's uptime, the internal labeling algorithm quietly and forcefully overwrites their traffic directly to `Label: 2 (Attack)` into `dataset.csv` infinitely. It kills console spam permanently while seamlessly delivering a perfect unbroken dataset chain.
* **Manual Override:** The permanent dataset label-lock is only broken when an operator issues an Out-of-Band clearance CLI command: `py net.unblock_attacker(net, '10.0.0.3')`.

### C. 2-Pass Inheritance Labeling System
* **The Perk:** Completely halts the "Dilution Effect." It buffers the window's traffic internally. If `10.0.0.4` is caught flooding in pass 1, pass 2 loops backward and inherits the `Label: 2` state across **every single normal flow** originating from `10.0.0.4` during that timeframe, ensuring there are absolutely no 'Normal' rows mingled mid-attack.

### D. Mathematical Baseline Sandbox
* Flows tagged as `Label 1` or `Label 2` are deliberately barred from entering volume calculations in the `DeviceProfile` metrics.
* **The Benefit:** An attacker cannot execute a slow-drip saturation attack to manually shift a device's baseline to a higher average point to evade detection. The algorithm's concept of what is "normal" remains entirely preserved.
