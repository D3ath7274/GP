# Developer Prompt: traffic_capture.py — Dataset Enrichment & Behavioral Feature Engineering

---

## Project Context & Constraints

You are working inside an SDN-based IoT Intrusion Prevention System built as a graduation project. The system runs across two Ubuntu VMs bridged on the same physical network:

- **Controller VM**: Runs `Controller.py` (Ryu SDN Controller, OpenFlow 1.0), `snort_monitor.py` (Snort IDS), and `traffic_capture.py` (the file you are modifying).
- **Topology VM**: Runs `topology.py` (Mininet-WiFi), which emulates the Layer 2 data plane with 2 WiFi stations, 1 Access Point, 2 wired hosts, and 1 OpenFlow switch.

The Controller receives a **full mirror of every data-plane packet** via `OFPP_CONTROLLER (max_len=0xffff)` — meaning `traffic_capture.py` has access to the complete raw packet stream in real time.

The system already has a **3-Tier Security Engine**:
- Tier 1: Snort signature matching
- Tier 2: Extreme-volume rate counters (per 5-second window)
- Tier 3: Z-score behavioral profiling using Welford's online algorithm (requires 20 flows + 180s stabilization, triggers at Z = 8.0)

The existing `traffic_capture.py` already compiles **49+ behavioral features per flow** into `dataset.csv`. Your task is to **extend** it — not rewrite it. Preserve all existing logic, naming conventions, data structures, and the current CSV schema. Only append new columns and new computation blocks.

---

## Your Objective

Extend `traffic_capture.py` to capture a significantly richer behavioral fingerprint per flow window such that the resulting `dataset.csv` becomes a publication-quality dataset capable of exposing the DNA of the following attack types even to a model that has never seen them before:

- SYN Flood
- ICMP Flood
- UDP Flood
- Port Scan (nmap)
- ARP Spoofing (arpspoof)

The approach must be **purely feature engineering** — no ML model integration, no detection logic, no blocking. This script's sole responsibility is passive observation and measurement. Detection is handled upstream by the 3-tier engine and future ML models consuming the CSV.

---

## Critical Environmental Constraints You Must Respect

These are non-negotiable and must be reflected in your implementation:

1. **Mininet broadcast storms are normal.** During legitimate `pingall` operations, the system generates up to 6,000 cloned tracking packets. Any feature that would spike abnormally during pingall must either be normalized, gated, or accompanied by a dedicated `is_broadcast_dst` / `broadcast_ratio` companion column so downstream consumers can distinguish pingall from real floods.

2. **The TAP interface duplicates every packet.** Because all data-plane packets are mirrored to `snort_tap`, every packet appears twice in the capture stream. Your feature calculations must either deduplicate by interface tag or mathematically account for the 2x duplication factor. Do not let raw counts be inflated by TAP mirroring.

3. **The Z-score baseline sandbox must not be violated.** The existing `DeviceProfile` baseline excludes Label 1 and Label 2 flows from statistical calculations. Any new per-device baseline or rolling average you introduce must follow the same rule — attack-labeled flows must never pollute a device's normal behavioral profile.

4. **The 5-second window is the atomic unit.** All features must be computed per 5-second window per source IP, consistent with the existing architecture. Do not introduce per-packet features or features that require longer time horizons than what fits in memory for a single window.

5. **The `curr_pps < 10` traffic drop guard already exists.** Do not reimplement it. However, any new rate-based feature you add must be similarly guarded against false spikes caused by traffic stopping suddenly.

6. **Performance matters.** The Controller VM processes high-volume packet streams in real time. All new computation must use O(1) or O(n) complexity at most per window. Avoid nested loops over packet lists where a running counter or reservoir approach achieves the same result.

---

## Feature Groups to Implement

Implement all of the following feature groups. For each group, you have full freedom to decide the most Pythonically elegant and computationally efficient approach. Use running accumulators, counters, or reservoir sampling as appropriate — do not buffer entire packet lists in memory if avoidable.

---

### Group 1 — Timing & Inter-Arrival Rhythm Features

**Purpose:** Attack tools generate traffic at machine-like regularity. Human-generated traffic is irregular. These features expose the inhuman rhythm of automated attack tools.

Features to add per flow window:
- `inter_arrival_mean` — arithmetic mean of time deltas between consecutive packets
- `inter_arrival_std` — standard deviation of those deltas
- `inter_arrival_cv` — coefficient of variation (std / mean). Values near 0 indicate robotic regularity. This is one of the strongest universal attack indicators.
- `inter_arrival_min` — minimum observed inter-arrival gap (fastest consecutive packet pair)
- `inter_arrival_max` — maximum observed inter-arrival gap (slowest consecutive packet pair)
- `burst_count` — number of times within the window that the instantaneous PPS exceeded 3x the window's mean PPS
- `burst_duration_avg` — average duration in milliseconds of each identified burst episode

Implementation note: Use Welford's online algorithm or a two-pass approach over a lightweight timestamp list. Cap the timestamp buffer at a reasonable size (e.g., 2000 entries) using reservoir sampling if the window exceeds that threshold.

---

### Group 2 — Directionality & Asymmetry Features

**Purpose:** Attacks are almost entirely one-directional. The victim receives floods but cannot meaningfully respond. These features measure traffic asymmetry.

Features to add per flow window:
- `fwd_packet_count` — packets traveling toward the destination
- `bwd_packet_count` — packets traveling back toward the source
- `fwd_bwd_packet_ratio` — fwd / (bwd + 1). Floods push this toward very large values.
- `fwd_bwd_bytes_ratio` — same ratio computed over bytes instead of packet counts
- `fwd_avg_packet_size` — mean size in bytes of forward-direction packets
- `bwd_avg_packet_size` — mean size in bytes of backward-direction packets
- `reply_rate` — percentage of outgoing packets that received a corresponding reply within the window

Implementation note: Direction is determined by comparing the packet's source IP against the flow's canonical source IP as registered at the first packet of the window.

---

### Group 3 — TCP Session Completeness Features

**Purpose:** Legitimate TCP traffic completes handshakes (SYN → SYN-ACK → ACK) and terminates cleanly (FIN). SYN floods send enormous volumes of SYN with no ACK. Scanners generate RST storms. These features expose incomplete and aborted sessions.

Features to add per flow window:
- `syn_count` — total TCP SYN flags observed
- `ack_count` — total TCP ACK flags observed
- `fin_count` — total TCP FIN flags observed
- `rst_count` — total TCP RST flags observed
- `syn_ack_ratio` — syn_count / (ack_count + 1). Approaches very large values during SYN floods.
- `completed_sessions` — flows where SYN, ACK, and FIN were all observed (session opened and cleanly closed)
- `incomplete_ratio` — (total_sessions - completed_sessions) / (total_sessions + 1)
- `avg_session_duration` — mean duration in seconds of sessions that did complete

Implementation note: Track session state in a lightweight per-(src_ip, dst_ip, dst_port) dictionary. Expire sessions older than the window boundary. Only non-broadcast, non-ARP flows contribute to these counters.

---

### Group 4 — Shannon Entropy Features

**Purpose:** Floods concentrate all traffic on a single port or produce identically-sized packets — both result in near-zero entropy. Port scanners hit many unique ports — high entropy. These features quantify traffic diversity.

Implement a single reusable entropy function:

```python
from collections import Counter
import math

def shannon_entropy(values):
    if not values:
        return 0.0
    counts = Counter(values)
    total = sum(counts.values())
    return -sum((c / total) * math.log2(c / total) for c in counts.values())
```

Features to add per flow window using this function:
- `dst_port_entropy` — entropy of all destination ports contacted this window. Near 0 = flood to one port. High = scan across many ports.
- `src_port_entropy` — entropy of all source ports used by this IP
- `payload_size_entropy` — entropy of all observed packet sizes. Near 0 = all packets identical (attack tool signature).
- `src_ip_entropy` — entropy of source IPs seen in this window (computed globally per window, not per flow). Near 0 = single attacker. High = distributed attack.
- `dst_ip_entropy` — entropy of destination IPs contacted from this source this window
- `icmp_type_entropy` — entropy of ICMP type codes seen. ICMP floods use only type 8 (echo request), collapsing this to 0.

---

### Group 5 — ARP-Specific Behavioral Features

**Purpose:** ARP spoofing has a fingerprint invisible to generic flow features. Legitimate devices send very few ARPs. Spoofers send unsolicited replies, claim multiple IPs, and change MAC-to-IP bindings frequently.

Features to add — computed per source MAC address per window:
- `arp_reply_rate` — ARP reply packets per second from this MAC
- `arp_request_rate` — ARP request packets per second from this MAC
- `arp_reply_request_ratio` — replies / (requests + 1). Spoofers send replies without prior requests, pushing this high.
- `gratuitous_arp_count` — ARP packets where sender protocol address == target protocol address (self-announcement, used in spoofing)
- `unsolicited_arp_count` — ARP replies observed with no matching ARP request from the destination IP within the window
- `mac_ip_binding_changes` — number of times this MAC address was observed claiming a different IP than in a prior window
- `ip_mac_binding_changes` — number of distinct MACs observed claiming this IP address within the window

Implementation note: Maintain a persistent `_arp_binding_table` dictionary outside the window scope (similar to how `_confirmed_attackers` is maintained) to track MAC-to-IP bindings across windows. Only reset on operator command or system restart.

---

### Group 6 — Packet Size & Volume Distribution Features

**Purpose:** Attack tools generate unnaturally uniform packet sizes. SYN packets are always tiny (~60 bytes). UDP floods often use maximum-size payloads. These features measure size distribution.

Features to add per flow window:
- `pkt_size_mean` — mean packet size in bytes
- `pkt_size_std` — standard deviation of packet sizes. Near 0 = all packets identical.
- `pkt_size_min` — smallest packet observed
- `pkt_size_max` — largest packet observed
- `pkt_size_variance` — variance of packet sizes (std²)
- `bytes_per_second` — total bytes transferred divided by window duration
- `packets_per_second` — total packets divided by window duration (already likely exists — confirm or add)
- `small_pkt_ratio` — fraction of packets under 100 bytes. SYN and scan packets are consistently small.
- `large_pkt_ratio` — fraction of packets over 1000 bytes

---

### Group 7 — Port Behavior Features

**Purpose:** Floods target one port relentlessly. Scanners sweep many ports in predictable patterns. These features expose both extremes and the pattern in between.

Features to add per flow window:
- `unique_dst_ports` — count of distinct destination ports contacted
- `unique_src_ports` — count of distinct source ports used
- `top_dst_port` — the single most frequently targeted destination port (integer value)
- `top_dst_port_ratio` — fraction of all packets going to that top port. Near 1.0 = focused flood.
- `dst_port_std` — standard deviation of destination port numbers. 0 = flood to one port. High = scan.
- `well_known_port_ratio` — fraction of traffic targeting ports below 1024
- `ephemeral_port_ratio` — fraction of traffic targeting ports above 49152
- `sequential_port_score` — measure of how sequentially ordered the destination ports are. Compute as the fraction of consecutive port pairs (p_i, p_{i+1}) where |p_{i+1} - p_i| <= 2. nmap default scan = high sequential score.

---

### Group 8 — Protocol Distribution Features

**Purpose:** Legitimate IoT devices have predictable protocol mixes. A device that suddenly shifts from 95% MQTT (TCP) to 100% ICMP is exhibiting attack behavior. These features capture that shift.

Features to add per flow window:
- `tcp_ratio` — fraction of total packets that are TCP
- `udp_ratio` — fraction of total packets that are UDP
- `icmp_ratio` — fraction of total packets that are ICMP
- `arp_ratio` — fraction of total packets that are ARP
- `other_protocol_ratio` — fraction of packets using any other protocol
- `icmp_type_entropy` — (already listed in Group 4, do not duplicate the column)
- `dominant_protocol` — string label of the protocol with highest packet count this window (e.g., `"TCP"`, `"ICMP"`)

---

### Group 9 — Broadcast & Multicast Environment Features

**Purpose:** Mininet's pingall generates legitimate broadcast storms. These features allow downstream consumers to statistically distinguish Mininet operational artifacts from real flood attacks, preventing false positives.

Features to add per window (global, not per-flow):
- `is_broadcast_dst` — integer flag (0 or 1): destination is `255.255.255.255` or `ff:ff:ff:ff:ff:ff`
- `broadcast_ratio` — fraction of all packets in this window whose destination is a broadcast address
- `multicast_ratio` — fraction of all packets whose destination is a multicast address (224.0.0.0/4 or 33:33:xx prefix for IPv6)
- `arp_broadcast_ratio` — fraction of ARP packets specifically that are broadcast. During pingall this is high but expected. During ARP spoof it is also high but combined with `unsolicited_arp_count`.

---

### Group 10 — Flow-Level Context & Device History Features

**Purpose:** A brand new device that has never been seen before will look anomalous by definition. These features give the dataset temporal context so a model can learn to be appropriately lenient on newly discovered devices.

Features to add per flow window:
- `flow_age_seconds` — how many seconds ago this source IP was first observed by the controller
- `is_baseline_mature` — integer flag (0 or 1): has this IP accumulated at least 20 flows AND 180 seconds of observation time (matching the existing Z-score stabilization threshold exactly)
- `flows_per_window` — how many distinct flow entries this source IP generated this window
- `new_destinations_per_window` — count of destination IPs this source contacted for the first time this window (never seen in prior windows)
- `repeated_dst_ratio` — fraction of this window's flows going to a destination this source has contacted before

---

## Label Schema Enhancement

Extend the existing label column from a binary (0 = normal, 2 = attack) to a **multi-class schema** without breaking backward compatibility. Add a second column `attack_type` alongside the existing `Label` column:

| Label | attack_type | Meaning |
|-------|-------------|---------|
| 0 | `normal` | Legitimate traffic |
| 1 | `suspicious` | Under monitoring, not yet confirmed |
| 2 | `syn_flood` | Confirmed SYN flood |
| 2 | `icmp_flood` | Confirmed ICMP flood |
| 2 | `udp_flood` | Confirmed UDP flood |
| 2 | `port_scan` | Confirmed port scan |
| 2 | `arp_spoof` | Confirmed ARP spoofing |

The `Label` column retains its existing integer values for backward compatibility. The `attack_type` string column is additive. The attack type must be inferred from whichever Tier (1, 2, or 3) confirmed the attack and what protocol/pattern triggered it.

---

## Metadata Columns to Add (Non-Feature, For Dataset Validation)

Add the following columns to every CSV row. These are not input features for any model — they are audit and reproducibility metadata. Prefix them with `meta_` to make this distinction clear to any downstream consumer:

- `meta_timestamp` — ISO 8601 datetime string of the window start
- `meta_window_id` — monotonically increasing integer counter across all windows since system start
- `meta_src_ip` — source IP of this flow (already likely exists, confirm naming)
- `meta_src_mac_oui` — first 3 octets of source MAC address (manufacturer fingerprint, e.g., `b8:27:eb` for Raspberry Pi)
- `meta_device_name` — hostname from `_discovered_names` registry if available, otherwise `unknown`
- `meta_attack_tool` — string populated manually or via a new UDP control message from topology.py when an attack is started. Values: `hping3`, `nmap`, `arpspoof`, `none`. Implement a new control message format: `ATTACK_START:tool_name:src_ip` and `ATTACK_STOP:src_ip` on the existing UDP port 9999 channel.
- `meta_attack_intensity` — PPS rate at which the attack tool was configured, populated from the `ATTACK_START` message payload
- `meta_mininet_event` — string flag for the current Mininet operational state. Values: `pingall`, `normal`, `topology_change`. Implement via a new control message: `MININET_EVENT:event_name` on port 9999.

---

## Implementation Guidelines

These are architectural decisions you must respect. The actual code structure, class design, helper function names, and module organization are your decision.

- All new features must appear as new columns appended to the right of existing columns in `dataset.csv`. Never reorder or rename existing columns.
- All new running accumulators must be reset at the start of each 5-second window, consistent with existing behavior.
- All persistent cross-window state (ARP binding table, device first-seen timestamps, flow age tracking) must be stored in module-level dictionaries following the same pattern as the existing `_confirmed_attackers` and `_discovered_names` registries.
- The new `ATTACK_START`, `ATTACK_STOP`, and `MININET_EVENT` UDP control messages must be parsed inside the existing UDP listener on port 9999 without spawning new threads or sockets.
- If a feature cannot be computed for a given window (e.g., no TCP traffic means no `syn_ack_ratio`), write `0.0` as the default. Never write `NaN` or leave the field empty — this ensures the CSV is always ML-ready without a cleaning pass.
- Add a single constant at the top of the file: `TIMESTAMP_BUFFER_MAX = 2000`. Use this as the cap for any list-based accumulator that stores per-packet timestamps or sizes, implementing reservoir sampling beyond this threshold.

---

## Deliverable

A fully modified `traffic_capture.py` that:

1. Preserves 100% of existing functionality and column order
2. Appends all new feature columns described above
3. Appends the `attack_type` label column
4. Appends all `meta_` metadata columns
5. Handles the three new UDP control message types
6. Maintains the ARP binding table and device age tracking as persistent cross-window state
7. Includes brief inline comments on each new feature group explaining what behavioral signal it captures and which attack type it is primarily designed to expose
