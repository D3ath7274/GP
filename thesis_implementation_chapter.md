# Implementation and System Development

After successfully installing the Ryu SDN framework and Mininet-WiFi on two separate Ubuntu virtual machines, and verifying basic OpenFlow connectivity between them, the following implementation work was carried out to build the complete SDN-based IoT Intrusion Prevention System.

---

## 1. Network Topology Design

### 1.1 Topology Architecture

The system employs a two-machine architecture. The first virtual machine hosts the Mininet-WiFi network emulator, which creates a software-defined network consisting of both wireless and wired nodes. The second virtual machine runs the Ryu SDN controller, which manages all forwarding decisions and integrates the security modules.

The emulated network topology consists of:
- Two wireless stations (`sta1` at 10.0.0.1, `sta2` at 10.0.0.2) connected through an IEEE 802.11g access point (`ap1`).
- Two wired hosts (`h1` at 10.0.0.3, `h2` at 10.0.0.4) connected through an OpenFlow switch (`s1`).
- The access point is linked to the switch, creating a unified Layer 2 domain.
- A remote controller (`c0`) connected to the Ryu instance running on the controller VM via OpenFlow protocol on TCP port 6633.

### 1.2 Remote Controller Configuration

The topology script configures the controller as a `RemoteController` pointing to the controller VM's IP address (e.g., 192.168.1.19). Both VMs reside on the same bridged network segment, allowing the OpenFlow control channel to be established over the physical network infrastructure. Upon starting the topology, the switch and access point connect to the remote controller, which then installs flow rules to manage packet forwarding.

### 1.3 Connectivity Verification

After launching both the controller and the topology, the `pingall` command was executed within the Mininet-WiFi CLI. All four hosts (sta1, sta2, h1, h2) successfully communicated with each other, confirming that the OpenFlow controller was correctly learning MAC addresses and installing appropriate forwarding rules across both the wireless and wired segments.

---

## 2. SDN Controller Development

### 2.1 L2 Learning Switch with OpenFlow 1.0

The controller application (`Controller.py`) is built upon the Ryu framework's `app_manager.RyuApp` base class and implements OpenFlow Protocol version 1.0. The core forwarding logic operates as a Layer 2 learning switch: when a packet arrives at the controller via a `packet_in` event, the controller records the source MAC address and its associated ingress port in a per-switch MAC-to-port table (`mac_to_port`). If the destination MAC address is already known, the controller installs a flow rule directing future matching packets to the correct output port. If the destination is unknown, the packet is flooded to all ports.

### 2.2 Full Packet Mirroring to Controller

A critical design decision was made to mirror all data-plane traffic to the controller for security analysis. Each flow rule installed by the controller includes two output actions: one directing traffic to the learned destination port, and one sending a copy of the full packet to the controller (`OFPP_CONTROLLER` with `max_len=0xffff`). This ensures that every packet transiting the network is available for inspection by the IDS and traffic capture modules, at the cost of increased control-plane load.

During testing, it was discovered that setting `max_len=0` (the default in some OpenFlow implementations) caused the controller to receive empty packet payloads for flow-rule-matched traffic. This was corrected to `0xffff`, which sends the full packet data, enabling proper parsing by Snort and the behavioral analysis engine.

### 2.3 Dynamic Device Name Learning

The controller maintains a `_discovered_names` dictionary that maps IP addresses to human-readable device names. Device names are populated from three sources, in order of priority:

1. **Explicit hostname registration:** The topology script sends `REGISTER:NAME:<hostname>` UDP packets from each host at startup. For example, `h1` sends `REGISTER:NAME:h1`, causing the controller to store the mapping `10.0.0.3 → h1`.
2. **IoT device registration:** When an IoT device is dynamically registered, the controller stores the device type (e.g., `IoT:TempSensor`).
3. **Automatic learning:** As a fallback, when a device's first packet is observed, the controller creates a placeholder entry using the IP address.

These names are displayed in all attack detection logs, allowing the operator to immediately identify which device is involved in an incident without manual IP-to-device lookups.

### 2.4 Detection Mode Toggle

To support clean dataset generation for machine learning model training, the controller implements a detection mode toggle. The system starts in **capture-only mode** (`_detection_enabled = False`), where all traffic is recorded to the dataset CSV with the label `normal`. This prevents the behavioral detection engine from generating labels during the baseline data collection phase.

When the operator is ready to test attack detection, a `CONTROL:DETECT:ON` UDP control packet is sent from the topology CLI, switching the system into active detection mode. In this mode, the behavioral anomaly engine and the Snort IDS actively label suspicious traffic and install DROP rules. The toggle can be reversed at any time by sending `CONTROL:DETECT:OFF`.

---

## 3. Traffic Mirroring for IDS

### 3.1 TAP Interface Design

Snort IDS operates by capturing packets from a network interface. However, in the SDN architecture, data-plane traffic (10.0.0.x subnet) flows within the Mininet-WiFi emulation and is not directly visible on any physical interface of the controller VM. To bridge this gap, the `TrafficMirror` module (`traffic_mirror.py`) creates a virtual TAP interface (`snort_tap`) on the controller machine using the Linux TUN/TAP kernel facility (`/dev/net/tun`).

### 3.2 Packet Injection Pipeline

Every packet that arrives at the controller via OpenFlow `packet_in` events is injected into the TAP interface as a raw Ethernet frame. The injection pipeline uses a producer-consumer pattern with a thread-safe queue (maximum capacity: 50,000 packets). A dedicated background writer thread drains the queue and writes frames to the TAP file descriptor. If the queue fills up during traffic spikes, excess packets are silently dropped to prevent backpressure on the controller's main thread.

### 3.3 Multi-Interface Monitoring

With the TAP interface active, Snort is configured to monitor two interfaces simultaneously:
- `ens33` — the physical network interface, capturing management traffic on the 192.168.1.x subnet.
- `snort_tap` — the virtual TAP interface, capturing mirrored Mininet data-plane traffic on the 10.0.0.x subnet.

This design ensures that Snort has visibility into all network traffic passing through the controller, regardless of whether it originates from the emulated SDN network or the physical management plane.

---

## 4. Snort IDS Integration

### 4.1 Automated Installation and Configuration

An automated setup script (`snort_setup.sh`) handles Snort installation, community rule download, and configuration generation. The script performs the following steps:
1. Detects whether Snort is already installed; if not, installs it via the system package manager.
2. Auto-detects the Snort version (2.x or 3.x) and adjusts the configuration format accordingly (`.conf` for Snort 2, `.lua` for Snort 3).
3. Downloads the latest community rules from the official Snort website.
4. Extracts and installs the rules to `/etc/snort/rules/`.
5. Generates or updates the configuration file with the correct `HOME_NET` variable (defaulting to `10.0.0.0/24,192.168.1.0/24`) and `alert_fast` output mode.

### 4.2 Snort Process Management

The `SnortManager` class (`snort_monitor.py`) manages the lifecycle of Snort processes. For each configured interface, it spawns a separate Snort process in IDS mode, redirecting standard output and standard error to log files to prevent pipe buffer deadlocks that were observed during early testing. The manager monitors process health and provides graceful shutdown via `SIGTERM`, with a fallback `SIGKILL` if the process does not terminate within 10 seconds.

### 4.3 Real-Time Alert Parsing

Each Snort process writes alerts to an `alert_fast.txt` file. A dedicated background thread per interface tails this file in real-time, parsing each new line using regular expressions. The parser supports both Snort 3's alert_fast format and Snort 2's simpler format, with a fallback IP extraction mechanism for non-standard entries.

Parsed alerts are classified into human-readable attack types using a keyword-matching system. The classification map covers over 30 attack categories including SYN Flood, Port Scan, ICMP Flood, ARP Spoofing, SQL Injection, XSS, Malware, Brute Force, and Exploit Attempts. For example, an alert containing the keyword "nmap" is classified as "Port Scan," while one containing "sql injection" is classified as "SQL Injection."

### 4.4 False Positive Suppression

During testing, it was found that normal network operations (e.g., `pingall`, ARP resolution, TLS negotiation) triggered numerous Snort alerts from informational rules. To prevent these from polluting the dataset and triggering false blocks, a hard blocklist of SIDs (Snort rule identifiers) was implemented. The blocked SIDs include:
- SID 366, 384, 408 — ICMP Ping and Echo Reply (triggered by `pingall`).
- SID 399, 401, 449, 485 — ICMP Destination Unreachable and TTL Exceeded (normal routing events).
- SID 527 — BAD-TRAFFIC same source/destination (artifact of TAP mirroring).
- SID 1917, 1923 — UPnP/SSDP service discovery (legitimate multicast).
- SID 2657 — SSLv2 Client Hello (TLS negotiation).

Alerts matching blocked SIDs are silently discarded before reaching the callback, the alert ring buffer, or the CSV labeler.

### 4.5 Alert Integration with Controller

When a valid alert passes the blocklist, the `SnortManager` invokes a callback function registered by the controller. The controller logs the alert in a formatted box display showing the attack type, source and target addresses, protocol, and Snort rule SID. The alert is also forwarded to the traffic capture module for dataset labeling.

---

## 5. Packet Capture and ML Dataset Generation

### 5.1 Traffic Capture Architecture

The `TrafficCapture` module (`traffic_capture.py`) is the core component responsible for generating the machine learning dataset. It operates as a parallel thread within the controller, receiving packet metadata from every `packet_in` event and aggregating it into per-flow feature vectors.

The module uses a flow accumulator keyed by the tuple *(source IP, destination IP, destination port, protocol)*. Each incoming packet is appended to its corresponding flow entry with metadata including packet size, TCP flags, source port, and timestamp. A background flush thread processes the accumulated flows every 5 seconds (configurable), computing features, applying labels, and appending rows to the output CSV file.

### 5.2 Feature Engineering

The dataset contains 45+ features organized into three categories:

**Flow-Level Features (21 columns):** These capture the mechanics of individual network flows, including timestamp, source/destination IP and port, protocol type, flow duration, total packets and bytes, average/minimum/maximum packet size, packets per second (PPS), bytes per second (BPS), TCP flag counts (SYN, ACK, FIN, RST, PSH), and the number of unique source and destination ports.

**Device Behavioral Profile Features (16 columns):** For each source IP, the system maintains a `DeviceProfile` object that tracks running behavioral statistics using exponential moving averages (EMA) with a smoothing factor of α = 0.1 and Welford's online algorithm for variance computation. Features include:
- `device_avg_pkt_rate` and `device_pkt_rate_deviation`: the device's historical average packet rate and the current flow's Z-score deviation from that average.
- `device_avg_byte_rate` and `device_byte_rate_deviation`: similarly for byte throughput.
- `device_avg_payload_size` and `device_payload_size_deviation`: for payload size anomaly detection.
- `device_protocol_dist_tcp/udp/icmp`: the device's historical protocol distribution, indicating its typical communication pattern.
- `device_new_dst_ratio`: the ratio of new destination IPs to total destinations in the current window, designed to detect lateral movement and network scanning.
- `device_unique_dst_ips` and `device_unique_dst_ports`: destination diversity metrics.
- `is_registered_iot` and `is_gateway`: binary flags indicating whether the device was explicitly registered as an IoT device or detected as a gateway.
- `device_age_seconds`: time since the device was first observed, used to gate behavioral analysis during a stabilization period.

**Network Context Features (10 columns):** These provide a global view of network state during each analysis window: number of active flows, total network-wide PPS and BPS, count of unique source and destination IPs, average flow duration, Shannon entropy of source IPs and destination ports, number of active Snort alerts, and count of distinct alert types.

### 5.3 Dataset Labeling

Each row in the dataset is labeled with three columns:
- `label`: `0` for normal traffic, `1` for known attacks matched by Snort rules, `2` for behavioral anomalies detected by the statistical analysis engine.
- `attack_type`: a descriptive string (e.g., "SYN Flood", "Port Scan", "normal").
- `snort_sid`: the Snort rule ID if the label was assigned by Snort, otherwise empty.

### 5.4 Window-Wide Label Inheritance

A two-pass processing approach ensures label consistency within each 5-second window. In the first pass, the system identifies all flows that trigger either a Snort alert or a behavioral anomaly, recording their source IPs as attackers. In the second pass, all flows originating from an identified attacker IP in that window inherit the attack label. This prevents mixed labeling where some flows from an active attacker might be labeled `normal` simply because they did not individually exceed a threshold.

### 5.5 Baseline Integrity

To prevent attackers from contaminating the behavioral baseline, the update strategy distinguishes between normal and attack traffic. Only flows labeled as `normal` (label = 0) contribute to the `DeviceProfile`'s volume averages (PPS, BPS, payload size). Attack flows only update metadata (destination tracking, protocol distribution) without affecting the statistical baseline. This ensures that a sustained flood attack cannot gradually shift the device's "normal" profile, which would cause the Z-score deviation to diminish over time and eventually evade detection.

### 5.6 Testing and Validation

The traffic capture module was tested in two phases:

1. **Clean traffic collection:** With detection mode OFF, a `pingall` was executed and the resulting `dataset.csv` was inspected. All rows were correctly labeled as `normal` with `label = 0`. The flow features (packet size ~98 bytes for ICMP, protocol = ICMP) matched expected values for ping traffic.

2. **Attack traffic collection:** With detection mode ON, simulated flood attacks were launched using `hping3`. The dataset correctly showed `label = 2` (behavioral anomaly) for the attacking host's flows, with `attack_type` values matching the simulated attack. The `device_pkt_rate_deviation` values spiked significantly (Z-scores > 8.0) during flood attacks, demonstrating the effectiveness of the behavioral profiling.

---

## 6. IoT Device Discovery and Registration

### 6.1 Explicit Registration Mechanism

The topology script provides a function `register_iot_device()` that can be invoked from the Mininet-WiFi CLI at runtime. When called, it dynamically creates a new host node, establishes a link to the specified switch, configures the interface, and then sends two UDP registration packets to the controller on port 9999:
1. `REGISTER:IOT:<device_type>` — registers the device type (e.g., `IOT:TempSensor`).
2. `REGISTER:NAME:<hostname>` — registers the device's display name for log identification.

The registration logic executes in a background daemon thread with a 2-second delay to allow the OpenFlow connection to stabilize. This non-blocking design keeps the CLI responsive during device addition.

### 6.2 Passive Discovery

For devices that do not run a registration agent, the controller implements passive discovery through two mechanisms:
- **DHCP-based discovery:** When a device sends a DHCP request (UDP source port 68 or destination port 67), the controller inspects the source MAC address against known IoT OUI (Organizationally Unique Identifier) prefixes and gateway OUI prefixes. Matched devices are automatically classified and registered.
- **ARP-based discovery:** The controller monitors ARP packets and cross-references the source MAC against the same OUI prefix lists. This covers scenarios where devices use static IP configuration and skip DHCP.

### 6.3 OUI-Based Device Classification

The controller maintains configurable lists of MAC address prefixes for device classification:
- `iot_mac_prefixes`: OUI prefixes known to belong to IoT device manufacturers.
- `gateway_mac_prefixes`: OUI prefixes for common IoT gateways (e.g., Philips Hue Bridge, IKEA TRADFRI, Cisco).
- `iot_exclude_prefixes`: OUI prefixes to explicitly exclude (e.g., Mininet virtual interfaces at `42:00:00`, standard Mininet hosts at `00:00:00`).

The exclusion list prevents Mininet-generated virtual network devices from being misclassified as IoT devices, which was a common source of log noise during early testing.

### 6.4 Passive Connection Mode

A second function, `connect_iot_device()`, simulates connecting a device to the network without sending any registration packet. The device is silently added to the topology, and the controller discovers it only through its natural network behavior (ARP, DHCP, or the first IP packet). This mode is useful for testing the passive discovery pipeline and for simulating real-world scenarios where devices cannot run custom registration software.

### 6.5 Automatic Hostname Registration at Startup

Upon topology startup, a background thread sends `REGISTER:NAME:<hostname>` packets from each of the pre-configured hosts (sta1, sta2, h1, h2) to the controller. This ensures that the controller's name mapping table is populated within the first few seconds of operation, and all subsequent attack logs display meaningful device names rather than raw IP addresses.

---

## 7. ARP Spoofing Detection

### 7.1 Dynamic ARP Inspection (DAI) Equivalent

The controller implements a software-based equivalent of Dynamic ARP Inspection (DAI). An `_arp_bindings` dictionary stores the first-seen binding of each IP address to its MAC address, derived from ARP packets. When a new ARP packet is observed:
- If the IP address has not been seen before, the binding is recorded as authoritative.
- If the IP address already has a binding, and the incoming MAC address differs from the recorded MAC, an ARP spoofing attempt is detected.

### 7.2 Detection and Logging

When a spoofing attempt is detected, the controller generates a formatted warning log showing the attacker's MAC address, the claimed IP address, the real owner's MAC address, and the switch/port where the spoofed packet was received. The alert is also forwarded to the traffic capture module, where all flows associated with the spoofed IP are labeled with `attack_type = 'ARP Spoofing'` and `label = 1`.

### 7.3 Testing

ARP spoofing was tested using the `arpspoof` tool from the `dsniff` package. After establishing normal ARP bindings via a preliminary `pingall`, the command `h1 arpspoof -i h1-eth0 -t 10.0.0.2 10.0.0.1` was executed, causing h1 to claim sta1's IP address. The controller immediately detected the mismatch and generated the ARP Spoofing alert.

---

## 8. Attack Detection and Response

### 8.1 Per-Host Rate Counter Detection (Primary)

The primary attack detection mechanism uses absolute per-host rate counters accumulated within each 5-second analysis window. Four counters are maintained per source IP:

| Counter | Accumulates | Threshold | Attack Type |
|---|---|---|---|
| `_host_icmp_count` | ICMP packets | > 15,000/window | ICMP Flood |
| `_host_syn_count` | TCP SYN-only packets (low ACK ratio) | > 5,000/window | SYN Flood |
| `_host_udp_count` | UDP packets | > 15,000/window | UDP Flood |
| `_host_dst_ports` | Unique destination ports | > 100/window | Port Scan |

These thresholds were dynamically calibrated strictly to accommodate the controller's heavy data-plane mirroring layout. Because the ML architecture explicitly replicates every `OFPP_FLOOD` packet upwards via `OFPP_CONTROLLER` actions, a normal network routine like `pingall` consistently drives a broadcast sequence of ~6,000 copied tracking packets to Python. Raising boundaries to 15,000 allows benign simulation activities and environment mapping loops to seamlessly drop out with 0% false positive labels, natively accelerating identification toward confirmed `hping3` threat variants producing highly destructive 150,000+ volume metrics.

### 8.2 Z-Score Behavioral Analysis (Secondary)

When per-host rate counters are unavailable or for attack patterns not covered by rate counters (such as payload anomalies or host sweeps), the system falls back to Z-score behavioral analysis. This mechanism compares the current flow's metrics against the device's historical baseline using the DeviceProfile's Welford-based variance tracking.

Four safeguards prevent false positives:
1. **Minimum flow count:** Z-score analysis is disabled until a device has accumulated at least 20 flows.
2. **Stabilization period:** New devices are given a 180-second grace period during which behavioral labeling is suppressed.
3. **High threshold:** The Z-score threshold is set to 8.0, significantly above the typical statistical threshold of 3.0, ensuring only extreme deviations trigger alerts.
4. **Traffic Drop Guard:** A distinct `curr_pps < 10` filter negates false deviations generated when an attacker aborts a volumetric sequence, securing historical baselines against anomalous mathematical shifts toward zero traffic.

### 8.3 Passive Monitoring Engine and Escalation

To facilitate the continuous generation of pure machine learning datasets without halting network simulations or blocking threat deployments midway, the active IPS was transitioned into a **Passive IDS Monitoring Engine**. When an anomaly is detected, the system records it to `dataset.csv` with a Label 2 and relies on a consecutive confirmation design rather than disconnecting the interface immediately:

**Stage 1 — Suspected Window (1/3):** The first violent detection logs `[⚠] SUSPECTED ATTACK` but takes no action. This prevents instantaneous network spikes from corrupting the verification pipeline.

**Stage 2 — Confirmation (3/3):** If an attack completely exceeds tolerances for 3 consecutive analytical frames, it officially triggers a `[⛔] ATTACK CONFIRMED` flag to officially mark the actor definitively on the tracking backend.

### 8.4 Controller-Level Backlog Ignore Cache

Refusing to drop traffic on switch architecture ensures seamless dataset extraction but leaves the administrative backend highly vulnerable to Python queue exhaustion. To safeguard internal controller integrity, an `_active_blocks` **Backlog Ignore Cache** tracks confirmed offenders silently. 

Upon confirmation, any future `packet_in` messages trailing behind the offender are automatically discarded by the control plane *before feature calculations or database updates*. This permits extreme volumetric floods to travel unimpeded cross-topology without bottlenecking memory logic.

### 8.5 Out-of-Band Control Signaling

To preserve full structural durability throughout major dataset attacks, control instructions historically routed on the Layer 2 Data plane (`REGISTER:IOT` and `CONTROL:DETECT`) were completely decoupled. Emulated nodes within the Mininet script directly export registration payloads over standard, out-of-band physical UDP sockets to the Controller container IP port (`192.168.1.19:9999`). 

This architecture guarantees administration channels remain permanently insulated from emulation broadcast storms and OpenFlow saturation.

### 8.6 Attack Simulation and Testing

The system was tested with the following simulated attacks launched from the Mininet-WiFi CLI using the `hping3` and `nmap` tools:

1. **ICMP Flood:** `h1 hping3 --icmp --flood 10.0.0.1` — Detected via `_host_icmp_count` exceeding 100.
2. **SYN Flood:** `h1 hping3 -S --flood -p 80 10.0.0.2` — Detected via `_host_syn_count` exceeding 50.
3. **UDP Flood:** `h1 hping3 --udp --flood -p 53 10.0.0.2` — Detected via `_host_udp_count` exceeding 200.
4. **Port Scan:** `h1 nmap -sS -p 1-1000 10.0.0.2` — Detected via `_host_dst_ports` exceeding 25 unique ports.
5. **ARP Spoofing:** `h1 arpspoof -i h1-eth0 -t 10.0.0.2 10.0.0.1` — Detected via ARP binding mismatch.

In each test case, the controller produced the expected detection logs, installed DROP rules on all switches, and the dataset CSV correctly labeled the attack flows. The detection-to-response latency (measured from the first anomalous packet to the DROP rule installation) was consistently under 20 seconds, including the 15-second mandatory monitoring period.

### 8.6 Attack Log Format

Each blocking action is logged in a structured format showing the timestamp, detection-to-response latency, device name (resolved from `_discovered_names`), IP and MAC addresses, target IP, attack type, detection method, DROP rule duration, and the number of switches where the rule was installed. This format provides operators with a comprehensive incident record without requiring manual log parsing.

---

## 9. System Integration Summary

The complete system integrates all modules into a cohesive pipeline:

```
Mininet-WiFi (Topology VM)             Ryu Controller (Controller VM)
┌─────────────────────┐                ┌──────────────────────────────┐
│ sta1, sta2 (WiFi)   │   OpenFlow     │  Controller.py               │
│ h1, h2 (Wired)      │──────────────→│  ├── L2 Learning Switch      │
│ ap1, s1              │   TCP 6633    │  ├── Device Registration     │
│ IoT devices (dynamic)│               │  ├── ARP Spoofing Detection  │
└─────────────────────┘                │  │                            │
                                        │  ├── TrafficMirror → TAP     │
                                        │  │       ↓                    │
                                        │  ├── Snort IDS (ens33 + TAP) │
                                        │  │       ↓ alerts             │
                                        │  ├── TrafficCapture           │
                                        │  │   ├── Feature Extraction   │
                                        │  │   ├── Behavioral Profiling │
                                        │  │   ├── Anomaly Detection    │
                                        │  │   └── → dataset.csv        │
                                        │  │                            │
                                        │  └── block_attacker()         │
                                        │      └── OpenFlow DROP rules  │
                                        └──────────────────────────────┘
```

All modules operate concurrently using daemon threads, ensuring that packet forwarding, traffic mirroring, IDS monitoring, feature extraction, and dataset writing proceed in parallel without blocking the controller's main event loop.
