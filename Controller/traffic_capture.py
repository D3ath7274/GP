"""
Traffic Capture Module for ML/DL Anomaly & Zero-Day Detection
=============================================================
Captures per-flow network features from OpenFlow packet_in events,
enriches them with device behavioral profiles and network context,
and writes rows to dataset.csv for ML/DL model training.

Features are designed to detect:
  - Known attacks (labeled by Snort IDS alerts)
  - Zero-day attacks (via behavioral deviation from learned baselines)
  - Post-authentication compromise (device profile changes)

Feature Groups (see feature_engineering_rationale_cited.md):
  Group 1:  Timing & Inter-Arrival Rhythm (7 features)
  Group 2:  Directionality & Asymmetry (7 features)
  Group 3:  TCP Session Completeness (4 features)
  Group 4:  Per-Flow Entropy (3 features)
  Group 5:  ARP-Specific Behavioral (7 features)
  Group 6:  Packet Size Distribution (4 features)
  Group 7:  Port Behavior Patterns (6 features)
  Group 8:  Broadcast & Multicast Context (4 features)
  Group 9:  Flow-Level Context (1 feature)
  Group 10: Metadata — audit only, stripped before DL training (8 features)
  Base:     Flow mechanics (21), Device Profile (17), Network Context (13), Labels (3)

Usage (integrated with Ryu controller):
    from traffic_capture import TrafficCapture
    capture = TrafficCapture(snort_manager=self.snort_manager, logger=self.logger)
    capture.start()
    # In packet_in handler:
    capture.record_packet(pkt_info)
    # On Snort alert:
    capture.record_alert(alert)
    # On shutdown:
    capture.stop()
"""

import os
import csv
import math
import time
import statistics
import threading
from collections import defaultdict, Counter, deque
from datetime import datetime


# =========================================================================
# Constants
# =========================================================================

# Maximum per-flow timestamp/size buffer before reservoir sampling kicks in.
# Prevents memory exhaustion during sustained floods.
TIMESTAMP_BUFFER_MAX = 2000


# =========================================================================
# CSV Column Definitions
# =========================================================================

FLOW_COLUMNS = [
    # --- Base Flow Mechanics (21 features) ---
    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
    'flow_duration', 'total_packets', 'total_bytes',
    'avg_packet_size', 'min_packet_size', 'max_packet_size',
    'packets_per_second', 'bytes_per_second',
    'syn_count', 'ack_count', 'fin_count', 'rst_count', 'psh_count',
    'unique_src_ports', 'unique_dst_ports',
    # --- Group 1: Timing & Inter-Arrival Rhythm (7 features) ---
    # Rationale III: inter_arrival_cv captures robotic regularity of attack tools
    # regardless of attack volume — strongest universal discriminator.
    'inter_arrival_mean', 'inter_arrival_std', 'inter_arrival_cv',
    'inter_arrival_min', 'inter_arrival_max',
    'burst_count', 'burst_duration_avg',
    # --- Group 2: Directionality & Asymmetry (7 features) ---
    # Rationale IV: Attacks are asymmetric by definition. Ratio-based features
    # are immune to Mininet's 2x TAP amplification.
    'fwd_packet_count', 'bwd_packet_count',
    'fwd_bwd_packet_ratio', 'fwd_bwd_bytes_ratio',
    'fwd_avg_packet_size', 'bwd_avg_packet_size', 'reply_rate',
    # --- Group 3: TCP Session Completeness (4 features) ---
    # Rationale V: Operationalizes the TCP lifecycle contract (RFC 793/9293).
    # incomplete_ratio is a category-level zero-day indicator.
    'syn_ack_ratio', 'completed_sessions', 'incomplete_ratio', 'avg_session_duration',
    # --- Group 4: Per-Flow Entropy (3 features) ---
    # Rationale VI: Entropy captures distribution diversity as categorical measure,
    # invariant to port number magnitude. Multi-dimensional per Lakhina et al.
    'payload_size_entropy', 'src_port_entropy', 'icmp_type_entropy',
    # --- Group 6: Packet Size Distribution (4 features) ---
    # Rationale VIII: Attack tools produce near-zero pkt_size_std.
    # small_pkt_ratio encodes SYN flood physical characteristics (RFC 793).
    'pkt_size_std', 'pkt_size_variance', 'small_pkt_ratio', 'large_pkt_ratio',
    # --- Group 7: Port Behavior Patterns (6 features) ---
    # Rationale IX: Floods and scans occupy opposite extremes of port diversity.
    # sequential_port_score detects nmap default sequential scanning.
    'top_dst_port', 'top_dst_port_ratio', 'dst_port_std',
    'well_known_port_ratio', 'ephemeral_port_ratio', 'sequential_port_score',
    # --- Group 8: Broadcast Context (per-flow flag) ---
    # Rationale X: Distinguishes Mininet pingall storms from real floods.
    'is_broadcast_dst',
    # --- Group 9: Flow-Level Context (1 feature) ---
    # Rationale XI.B: Detects connection flooding and horizontal network scanning.
    'flows_per_window',
]

DEVICE_COLUMNS = [
    'device_total_flows', 'device_avg_pkt_rate', 'device_pkt_rate_deviation',
    'device_avg_byte_rate', 'device_byte_rate_deviation',
    'device_unique_dst_ips', 'device_unique_dst_ports',
    'device_new_dst_ratio',
    'device_protocol_dist_tcp', 'device_protocol_dist_udp',
    'device_protocol_dist_icmp',
    'device_avg_payload_size', 'device_payload_size_deviation',
    'is_registered_iot', 'is_gateway', 'device_age_seconds',
    # Rationale XI.A: Gates Z-score features on cold-start reliability.
    # 1 if device has >=20 flows AND >=180s age.
    'is_baseline_mature',
]

NETWORK_COLUMNS = [
    'network_active_flows', 'network_total_pps', 'network_total_bps',
    'network_unique_src_ips', 'network_unique_dst_ips',
    'network_avg_flow_duration', 'network_entropy_src_ip',
    'network_entropy_dst_port',
    'active_snort_alerts', 'distinct_alert_types',
    # --- Group 8: Broadcast & Multicast Environment (network-level) ---
    # Rationale X: Environment-specific but necessary for operational accuracy.
    'broadcast_ratio', 'multicast_ratio', 'arp_broadcast_ratio',
]

ARP_COLUMNS = [
    # --- Group 5: ARP-Specific Behavioral (7 features) ---
    # Rationale VII: Dedicated ARP group addresses the visibility gap in generic
    # flow features. Absent from CIC-IDS2017 and UNSW-NB15.
    'arp_reply_rate', 'arp_request_rate', 'arp_reply_request_ratio',
    'arp_gratuitous_count', 'arp_unsolicited_count',
    'mac_ip_binding_changes', 'ip_mac_binding_changes',
]

LABEL_COLUMNS = [
    'label', 'attack_type', 'snort_sid',
]

META_COLUMNS = [
    # --- Group 10: Metadata — audit/reproducibility only ---
    # Rationale XII: MUST be stripped before DL training (data leakage).
    'meta_window_id', 'meta_src_mac_oui', 'meta_device_name',
    'meta_attack_tool', 'meta_attack_intensity', 'meta_mininet_event',
    # Rationale XII.C: Flush computation time — if >5000ms, feature set needs profiling.
    'meta_controller_load',
    'meta_backlog_drops',
]

ALL_COLUMNS = FLOW_COLUMNS + DEVICE_COLUMNS + NETWORK_COLUMNS + ARP_COLUMNS + LABEL_COLUMNS + META_COLUMNS


# =========================================================================
# Helpers
# =========================================================================

def _shannon_entropy(counter_dict):
    """Compute Shannon entropy from a {value: count} dictionary.
    Rationale VI: Treats values as categorical identifiers, invariant to magnitude."""
    total = sum(counter_dict.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counter_dict.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _safe_div(a, b, default=0.0):
    return a / b if b else default


def _is_broadcast(ip, mac=''):
    """Check if an IP or MAC is a broadcast/multicast address."""
    if ip in ('255.255.255.255', '0.0.0.0'):
        return True
    if mac and mac.lower() in ('ff:ff:ff:ff:ff:ff',):
        return True
    return False


def _is_multicast(ip):
    """Check if an IP is a multicast address (224.0.0.0/4)."""
    try:
        first_octet = int(ip.split('.')[0])
        return 224 <= first_octet <= 239
    except (ValueError, IndexError):
        return False


# =========================================================================
# Device Profile Tracker
# =========================================================================

class DeviceProfile:
    """
    Maintains a running behavioral profile for a single device (by IP).
    Used to compute deviation features so the ML model can detect
    zero-day attacks and post-authentication compromise.

    Rationale XIII: Device deviation features measure *relative* behavioral
    change from a device's own historical baseline, not absolute values.
    This is the mathematical foundation for zero-day detection via autoencoder.
    """

    MIN_FLOWS = 20
    STABILIZATION_SEC = 180

    def __init__(self, ip, first_seen):
        self.ip = ip
        self.first_seen = first_seen

        # Running statistics (exponential moving averages for efficiency)
        self.total_flows = 0
        self._ema_pkt_rate = 0.0
        self._ema_byte_rate = 0.0
        self._ema_payload_size = 0.0
        self._alpha = 0.1  # EMA smoothing factor

        # Variance trackers (Welford's online algorithm)
        self._pkt_rate_m2 = 0.0
        self._pkt_rate_mean = 0.0
        self._byte_rate_m2 = 0.0
        self._byte_rate_mean = 0.0
        self._payload_m2 = 0.0
        self._payload_mean = 0.0

        # Destination tracking (recent window for new-destination ratio)
        self.all_dst_ips = set()
        self.recent_dst_ips = set()
        self.recent_dst_ports = set()

        # Protocol distribution
        self.proto_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'OTHER': 0}
        self.total_proto = 0

        # IoT / Gateway classification (set externally)
        self.is_iot = 0
        self.is_gateway = 0

    def update(self, pkt_rate, byte_rate, avg_payload, dst_ip, dst_port, protocol):
        """Update profile with a new flow observation (affects baseline)."""
        self.total_flows += 1
        n = self.total_flows

        # --- EMA updates ---
        self._ema_pkt_rate = self._alpha * pkt_rate + (1 - self._alpha) * self._ema_pkt_rate
        self._ema_byte_rate = self._alpha * byte_rate + (1 - self._alpha) * self._ema_byte_rate
        self._ema_payload_size = self._alpha * avg_payload + (1 - self._alpha) * self._ema_payload_size

        # --- Welford online variance for pkt_rate ---
        delta = pkt_rate - self._pkt_rate_mean
        self._pkt_rate_mean += delta / n
        delta2 = pkt_rate - self._pkt_rate_mean
        self._pkt_rate_m2 += delta * delta2

        # --- byte_rate variance ---
        delta = byte_rate - self._byte_rate_mean
        self._byte_rate_mean += delta / n
        delta2 = byte_rate - self._byte_rate_mean
        self._byte_rate_m2 += delta * delta2

        # --- payload variance ---
        delta = avg_payload - self._payload_mean
        self._payload_mean += delta / n
        delta2 = avg_payload - self._payload_mean
        self._payload_m2 += delta * delta2

        self.update_metadata(dst_ip, dst_port, protocol)

    def update_metadata(self, dst_ip, dst_port, protocol):
        """Update destinations and protocol without affecting volume averages."""
        if dst_ip:
            self.all_dst_ips.add(dst_ip)
            self.recent_dst_ips.add(dst_ip)
        if dst_port is not None:
            self.recent_dst_ports.add(dst_port)

        proto_key = protocol.upper() if protocol else 'OTHER'
        if proto_key not in self.proto_counts:
            proto_key = 'OTHER'
        self.proto_counts[proto_key] += 1
        self.total_proto += 1

    def _z_score(self, value, mean, m2, n):
        """Compute z-score from Welford variance."""
        if n < 2:
            return 0.0
        variance = m2 / (n - 1)
        std = math.sqrt(variance) if variance > 0 else 0.0
        if std == 0:
            return 0.0
        return round((value - mean) / std, 4)

    @property
    def is_mature(self):
        """Rationale XI.A: Whether baseline is statistically reliable."""
        age = time.time() - self.first_seen
        return self.total_flows >= self.MIN_FLOWS and age >= self.STABILIZATION_SEC

    def get_features(self, current_pkt_rate, current_byte_rate, current_payload):
        """Return device behavioral features as a dict."""
        n = self.total_flows
        new_count = len(self.recent_dst_ips - (self.all_dst_ips - self.recent_dst_ips))
        total_recent = len(self.recent_dst_ips) if self.recent_dst_ips else 1

        return {
            'device_total_flows': n,
            'device_avg_pkt_rate': round(self._ema_pkt_rate, 4),
            'device_pkt_rate_deviation': self._z_score(
                current_pkt_rate, self._pkt_rate_mean, self._pkt_rate_m2, n
            ),
            'device_avg_byte_rate': round(self._ema_byte_rate, 4),
            'device_byte_rate_deviation': self._z_score(
                current_byte_rate, self._byte_rate_mean, self._byte_rate_m2, n
            ),
            'device_unique_dst_ips': len(self.recent_dst_ips),
            'device_unique_dst_ports': len(self.recent_dst_ports),
            'device_new_dst_ratio': round(
                _safe_div(new_count, total_recent), 4
            ),
            'device_protocol_dist_tcp': round(
                _safe_div(self.proto_counts['TCP'], self.total_proto), 4
            ),
            'device_protocol_dist_udp': round(
                _safe_div(self.proto_counts['UDP'], self.total_proto), 4
            ),
            'device_protocol_dist_icmp': round(
                _safe_div(self.proto_counts['ICMP'], self.total_proto), 4
            ),
            'device_avg_payload_size': round(self._ema_payload_size, 4),
            'device_payload_size_deviation': self._z_score(
                current_payload, self._payload_mean, self._payload_m2, n
            ),
            'is_registered_iot': self.is_iot,
            'is_gateway': self.is_gateway,
            'device_age_seconds': round(time.time() - self.first_seen, 2),
            'is_baseline_mature': 1 if self.is_mature else 0,
        }

    def reset_recent(self):
        """Reset per-window destination tracking (called each flush)."""
        self.recent_dst_ips = set()
        self.recent_dst_ports = set()


# =========================================================================
# Main Traffic Capture Class
# =========================================================================

class TrafficCapture:
    """
    Captures OpenFlow packet_in events and aggregates them into per-flow
    feature rows enriched with device behavioral profiles, network context,
    and Snort-based labels. Periodically flushes to a CSV file.

    Parameters:
        output_path (str): Path to the output CSV file.
        window_seconds (float): Aggregation window duration.
        snort_manager: SnortManager instance for alert queries.
        controller: Ryu controller instance (for IoT/gateway info).
        logger: Logger instance.
    """

    def __init__(self, output_path='dataset.csv', window_seconds=5.0,
                 snort_manager=None, controller=None, logger=None):
        self.output_path = output_path
        self.window_seconds = window_seconds
        self.snort_manager = snort_manager
        self.controller = controller
        self.logger = logger

        # --- Flow accumulator ---
        # Key: (src_ip, dst_ip, dst_port, protocol)
        # Value: dict of packet list and metadata
        self._flows = defaultdict(lambda: {
            'packets': [],       # list of (size, tcp_flags_dict, src_port, timestamp)
            'first_seen': 0.0,
            'last_seen': 0.0,
        })
        self._flow_lock = threading.Lock()

        # --- ML evidence capture (best-effort .pcap of a flagged source) ---
        # When the RF flags a flow in the 0.80-0.90 "suspect" band (no block), we
        # dump that source's recent raw frames to a .pcap plus its features to
        # flagged.csv and a line to ml_flags.txt. Frames are buffered per src_ip
        # only while ML is active, capped, and cleared every window.
        self._ml_pcap_enabled = True
        self._raw_frames = defaultdict(lambda: deque(maxlen=500))  # src_ip -> [(ts, raw_bytes)]
        self._flagged_dir = os.path.join(
            os.path.dirname(os.path.abspath(self.output_path)) or '.', 'flagged')

        # --- Device profiles ---
        self._devices = {}  # ip -> DeviceProfile
        self._device_lock = threading.Lock()

        # --- Snort alert buffer (recent alerts for labeling) ---
        self._recent_alerts = deque(maxlen=5000)
        self._alert_lock = threading.Lock()

        # --- Network-wide counters (per window) ---
        self._net_src_ips = defaultdict(int)
        self._net_dst_ips = defaultdict(int)
        self._net_dst_ports = defaultdict(int)
        self._net_total_packets = 0
        self._net_total_bytes = 0

        # --- Broadcast/Multicast counters (per window, Group 8) ---
        self._net_broadcast_count = 0
        self._net_multicast_count = 0
        self._net_arp_total = 0
        self._net_arp_broadcast = 0

        # --- State ---
        self._running = False
        self._flush_thread = None
        self._window_start = time.time()
        self._csv_initialized = False
        self._rows_written = 0
        self._window_id = 0

        # --- Attacker Identification (one-time log per IP/Type) ---
        self._logged_attackers = set()  # Set of (ip, attack_type)

        # --- Per-Attack-Type Confirmation Tracking ---
        # Key: (src_ip, attack_type)  Value: dict with consecutive window count
        # An attack is only confirmed after N consecutive windows exceed threshold.
        self._attack_confirmations = {}  # (ip, type) -> {consecutive, first_seen, escalated, ...}
        self._confirmed_attackers = {}   # src_ip -> attack_type (Permanent until manually unblocked)
        self._active_blocks = {}         # ip -> block_expiration_time
        self.RATE_LIMIT_SECONDS = 30
        self.REQUIRED_CONSECUTIVE = {
            'ICMP Flood': 3,   # 15 seconds sustained
            'SYN Flood': 2,    # 10 seconds sustained
            'UDP Flood': 3,    # 15 seconds sustained
            'Port Scan': 2,    # 10 seconds sustained
        }

        # --- Per-Host, Per-Window Rate Counters (for precise attack detection) ---
        self._host_icmp_count = defaultdict(int)    # src_ip -> ICMP packets this window
        self._host_syn_count = defaultdict(int)     # src_ip -> SYN-only packets (no ACK)
        self._host_ack_count = defaultdict(int)     # src_ip -> ACK packets (for SYN/ACK ratio)
        self._host_udp_count = defaultdict(int)     # src_ip -> UDP packets this window
        self._host_dst_ports = defaultdict(set)     # src_ip -> set of unique dst_ports

        # --- ICMP Type Tracking (for icmp_type_entropy, Group 4) ---
        self._host_icmp_types = defaultdict(lambda: defaultdict(int))
        # src_ip -> {icmp_type_int: count}

        # --- ARP Tracking (Group 5) ---
        # Per-window: keyed by source MAC
        self._arp_requests = defaultdict(int)       # src_mac -> request count this window
        self._arp_replies = defaultdict(int)         # src_mac -> reply count this window
        self._arp_gratuitous = defaultdict(int)      # src_mac -> gratuitous count this window
        self._arp_request_targets = defaultdict(set) # dst_ip -> set of src_ips that requested it
        self._arp_reply_sources = defaultdict(list)  # dst_ip -> list of (src_mac, claimed_ip)
        # Persistent across windows (Rationale VII.C: slow-poisoning detection)
        self._mac_to_ip_history = defaultdict(set)   # src_mac -> set of IPs ever claimed
        self._ip_to_mac_history = defaultdict(set)   # ip -> set of MACs ever claiming it

        # --- DAI Baseline Binding Table (FIX: P9) ---
        # Frozen snapshot of IP->MAC bindings learned during DETECT:OFF.
        # When detection turns ON, these become the "known good" bindings.
        # Any ARP reply claiming an IP with a different MAC than baseline = spoof.
        self._dai_baseline_bindings = {}  # ip -> mac (frozen when detect ON)

        # --- IP to MAC mapping (for block_attacker calls) ---
        self._ip_to_mac = {}  # src_ip -> eth_src MAC address

        # --- Detection Mode ---
        # OFF = capture only (all labels = normal, clean dataset)
        # ON  = full anomaly detection + blocking
        self._detection_enabled = False

        # --- Manual Label Override (for stealthy attacks below detection thresholds) ---
        # Rationale: Slow attacks (nmap -T1, 1000 PPS SYN) deliberately evade thresholds.
        # Without override, stealthy attack traffic gets labeled 'normal' — corrupted training data.
        self._label_overrides = {}  # src_ip -> attack_type string

        # --- Unblock Cooldown (prevents residual traffic re-confirmation) ---
        self._unblock_cooldowns = {}  # src_ip -> expiry_timestamp

        # --- Metadata Signals (Group 10) ---
        self._meta_attack_tool = 'none'
        self._meta_attack_intensity = 0
        self._meta_mininet_event = 'normal'
        self._meta_backlog_drops = 0

        # --- Per-window UNIQUE FLOW count per src_ip (Group 9) ---
        # FIX P12: Changed from counter (int) to set of flow keys
        self._flows_per_src = defaultdict(set)

        # --- Feature-schema mode (v1 vs v2) ---
        # The capture bug-fixes (reverse-flow directionality ratios + host-level
        # port diversity) change MODEL-VISIBLE features (fwd_bwd_*_ratio,
        # unique_dst_ports, well_known_port_ratio). The friend's v1 model
        # (final_rf_model.joblib / full_ml_pipeline.joblib) was trained on the
        # OLD behaviour, where backward traffic was always 0 (so fwd_bwd ratios
        # equalled the raw forward count). Feeding it the corrected values makes
        # it miss attacks. Default OFF = v1-compatible so the friend's model can
        # be verified. Set env IPS_V2_FEATURES=1 when collecting data to RETRAIN
        # a v2 model on the corrected, physically-meaningful features.
        self._v2_features = os.environ.get('IPS_V2_FEATURES', '0') == '1'
        self._log('info', "Feature schema mode: %s",
                  "v2 (corrected)" if self._v2_features else "v1-compatible (legacy)")

    # ---- Logging helpers ----

    def _log(self, level, msg, *args):
        if self.logger:
            getattr(self.logger, level)(msg, *args)
        else:
            print(f"[TrafficCapture-{level.upper()}] {msg % args if args else msg}")

    # ---- Public API ----

    def set_detection_mode(self, enabled):
        """Toggle anomaly detection on/off. When off, all traffic is labeled 'normal'."""
        self._detection_enabled = enabled
        if enabled:
            # Reset ALL tracking state for fresh detection — prevents stale
            # traffic accumulated during detection-OFF from triggering alerts.
            self._attack_confirmations = {}
            self._active_blocks = {}
            self._logged_attackers = set()
            with self._flow_lock:
                self._host_icmp_count = defaultdict(int)
                self._host_syn_count = defaultdict(int)
                self._host_ack_count = defaultdict(int)
                self._host_udp_count = defaultdict(int)
                self._host_dst_ports = defaultdict(set)
            # FIX P9: Freeze DAI baseline bindings from traffic learned during DETECT:OFF
            # These are the "known good" IP->MAC mappings.
            self._dai_baseline_bindings = dict(self._ip_to_mac)
            baseline_count = len(self._dai_baseline_bindings)
            self._log('info',
                f'Detection mode ENABLED — anomaly detection active '
                f'(counters reset, DAI baseline: {baseline_count} bindings frozen)')
        else:
            self._log('info', 'Detection mode DISABLED — capture only, all labels = normal')

    def set_label_override(self, src_ip, attack_type):
        """
        Force all flows from src_ip to be labeled with attack_type.
        Used for stealthy attacks that stay below detection thresholds.
        Call with attack_type='clear' to remove the override.
        """
        if attack_type == 'clear':
            if src_ip in self._label_overrides:
                del self._label_overrides[src_ip]
                self._log('info',
                    f"[OVERRIDE] Label override cleared for {src_ip} — "
                    f"returning to automatic detection")
        else:
            self._label_overrides[src_ip] = attack_type
            self._log('info',
                f"[OVERRIDE] Label override SET: {src_ip} → {attack_type} "
                f"(all flows from this IP will be labeled as attack)")

    def set_attack_metadata(self, tool, intensity=0):
        """Set metadata for ATTACK_START signaling."""
        self._meta_attack_tool = tool
        self._meta_attack_intensity = intensity
        self._log('info', f"[META] Attack metadata set: tool={tool}, intensity={intensity}")

    def clear_attack_metadata(self):
        """Clear metadata for ATTACK_STOP signaling."""
        self._meta_attack_tool = 'none'
        self._meta_attack_intensity = 0
        self._log('info', "[META] Attack metadata cleared")

    def set_mininet_event(self, event):
        """Set metadata for MININET_EVENT signaling."""
        self._meta_mininet_event = event
        self._log('info', f"[META] Mininet event set: {event}")

    def start(self):
        """Start the background flush thread."""
        if self._running:
            return

        # Start every capture run with a FRESH file. The CSV is opened in append
        # mode, so writing into a pre-existing dataset.csv (especially one from an
        # older column schema) silently corrupts the dataset: a stale header makes
        # every new row misalign, and per-run headers add duplicate header rows.
        # Rotate any existing file aside (non-destructive) so each run is clean.
        if os.path.exists(self.output_path):
            backup = f"{self.output_path}.bak-{int(time.time())}"
            try:
                os.replace(self.output_path, backup)
                self._log('warning',
                          "Existing %s rotated to %s — starting a fresh capture file",
                          self.output_path, backup)
            except OSError as e:
                self._log('error', "Could not rotate existing %s (%s); "
                                   "DELETE it manually before collecting", self.output_path, e)
        self._csv_initialized = False

        self._running = True
        self._window_start = time.time()
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            name='TrafficCaptureFlush',
            daemon=True,
        )
        self._flush_thread.start()
        self._log('info', "Traffic capture started → %s (window: %ss)",
                  self.output_path, self.window_seconds)

    def stop(self):
        """Stop capture and flush remaining data."""
        self._running = False
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=10)
        # Final flush
        self._flush_flows()
        self._log('info', "Traffic capture stopped. Total rows written: %d",
                  self._rows_written)

    def rotate(self, new_name):
        """Save the current dataset.csv under new_name and start a fresh capture
        file. Used by the automated collection harness between sessions. The
        in-flight window's rows may land in either file — benign during the
        inter-session settle. Returns the rows saved, or -1 on failure."""
        saved = self._rows_written
        try:
            if os.path.exists(self.output_path):
                os.replace(self.output_path, new_name)
                self._log('warning', "[COLLECT] session saved: %s (%d rows)", new_name, saved)
            else:
                self._log('warning', "[COLLECT] rotate: %s did not exist (0 rows)",
                          self.output_path)
                saved = 0
        except OSError as e:
            self._log('error', "[COLLECT] rotate to %s failed: %s", new_name, e)
            return -1
        self._csv_initialized = False
        self._rows_written = 0
        return saved

    def record_packet(self, pkt_info, raw_data=None):
        """
        Record a single packet from a packet_in event.

        raw_data (optional): the raw Ethernet frame bytes (msg.data). Buffered
        per-source for best-effort ML evidence .pcap export — only while ML is
        active, so dataset-collection runs pay no cost.

        pkt_info dict should contain:
            src_ip, dst_ip, src_port, dst_port, protocol,
            packet_size, eth_src, eth_dst, tcp_flags (dict),
            dpid, in_port, icmp_type (optional), icmp_code (optional),
            arp_op (optional), arp_spa (optional), arp_tpa (optional)
        """
        if not self._running:
            return

        src_ip = pkt_info.get('src_ip', '')

        # --- Backlog Ignore / Blacklist Cache ---
        if src_ip in self._active_blocks:
            if time.time() < self._active_blocks[src_ip]:
                self._meta_backlog_drops += 1
                return  # Drop packet from ML / tracking pipeline
            else:
                del self._active_blocks[src_ip]

        with self._flow_lock:
            protocol = pkt_info.get('protocol', 'OTHER')
        dst_ip = pkt_info.get('dst_ip', '')
        dst_port = pkt_info.get('dst_port', 0)
        packet_size = pkt_info.get('packet_size', 0)
        src_port = pkt_info.get('src_port', 0)
        tcp_flags = pkt_info.get('tcp_flags', {})
        eth_src = pkt_info.get('eth_src', '')
        eth_dst = pkt_info.get('eth_dst', '')
        now = time.time()

        if not src_ip and not dst_ip:
            return

        flow_key = (src_ip, dst_ip, dst_port, protocol)

        with self._flow_lock:
            # --- Flow Aggregation Cap ---
            # Victim response traffic creates thousands of flow keys per window
            # (each RST/SYN-ACK to attacker's random port = unique flow key).
            # Cap at MAX_FLOWS_PER_PAIR: once exceeded, redirect to aggregate
            # flow with dst_port=0. Preserves first 50 real port flows.
            MAX_FLOWS_PER_PAIR = 50
            pair_key = (src_ip, dst_ip, protocol)
            if flow_key not in self._flows:
                # Count existing flows for this (src, dst, proto) pair
                if not hasattr(self, '_pair_flow_count'):
                    self._pair_flow_count = defaultdict(int)
                if self._pair_flow_count[pair_key] >= MAX_FLOWS_PER_PAIR:
                    # Redirect to aggregate overflow flow
                    flow_key = (src_ip, dst_ip, 0, protocol)
                else:
                    self._pair_flow_count[pair_key] += 1

            flow = self._flows[flow_key]
            if not flow['packets']:
                flow['first_seen'] = now
            flow['last_seen'] = now
            flow['eth_dst'] = eth_dst  # FIX(B): retain L2 dst for broadcast detection
            flow['packets'].append((packet_size, tcp_flags, src_port, now))

            # Buffer the raw frame for best-effort ML evidence pcap (only while ML
            # detection is active; bounded per-source; cleared each window).
            if (raw_data is not None and self._ml_pcap_enabled and src_ip
                    and self.controller is not None
                    and getattr(self.controller, '_ml_mode', 'OFF') != 'OFF'):
                self._raw_frames[src_ip].append((now, raw_data))

            # Update network-wide counters
            self._net_src_ips[src_ip] += 1
            self._net_dst_ips[dst_ip] += 1
            if dst_port:
                self._net_dst_ports[dst_port] += 1
            self._net_total_packets += 1
            self._net_total_bytes += packet_size

            # --- Broadcast/Multicast counters (Group 8) ---
            if _is_broadcast(dst_ip, eth_dst):
                self._net_broadcast_count += 1
            if _is_multicast(dst_ip):
                self._net_multicast_count += 1

            # --- Per-host rate counters (for attack detection) ---
            if protocol == 'ICMP':
                # Count only Echo Request (type=8) for flood detection.
                # Echo replies from victims should not trigger attacker detection.
                icmp_type = pkt_info.get('icmp_type')
                if icmp_type == 8:
                    self._host_icmp_count[src_ip] += 1
                # Track ICMP type for entropy (Group 4)
                if icmp_type is not None:
                    self._host_icmp_types[src_ip][icmp_type] += 1
            elif protocol == 'UDP':
                self._host_udp_count[src_ip] += 1
            elif protocol == 'TCP':
                # Count SYN-only packets (SYN set, ACK not set) — hallmark of SYN flood
                if tcp_flags.get('SYN') and not tcp_flags.get('ACK'):
                    self._host_syn_count[src_ip] += 1
                # Count ACK packets for SYN/ACK ratio guard
                if tcp_flags.get('ACK'):
                    self._host_ack_count[src_ip] += 1
            elif protocol == 'ARP':
                # --- ARP tracking (Group 5) ---
                arp_op = pkt_info.get('arp_op', 0)
                arp_spa = pkt_info.get('arp_spa', '')  # sender protocol address
                arp_tpa = pkt_info.get('arp_tpa', '')  # target protocol address
                self._net_arp_total += 1
                if _is_broadcast(dst_ip, eth_dst):
                    self._net_arp_broadcast += 1
                if arp_op == 1:  # ARP Request
                    self._arp_requests[eth_src] += 1
                    if arp_tpa:
                        self._arp_request_targets[arp_tpa].add(src_ip)
                elif arp_op == 2:  # ARP Reply
                    self._arp_replies[eth_src] += 1
                    if arp_spa:
                        self._arp_reply_sources[arp_spa].append((eth_src, src_ip))
                # Gratuitous ARP: sender claims its own IP
                if arp_spa and arp_tpa and arp_spa == arp_tpa:
                    self._arp_gratuitous[eth_src] += 1
                # Persistent binding tracking
                if eth_src and arp_spa:
                    self._mac_to_ip_history[eth_src].add(arp_spa)
                    self._ip_to_mac_history[arp_spa].add(eth_src)

            if dst_port and src_ip:
                self._host_dst_ports[src_ip].add(dst_port)

            # Unique flow count per src_ip (Group 9) — FIX P12
            # Counts unique flow keys, not packets
            self._flows_per_src[src_ip].add(flow_key)

        # Track IP → MAC mapping
        if src_ip and eth_src:
            self._ip_to_mac[src_ip] = eth_src

        # Ensure device profile exists
        with self._device_lock:
            if src_ip and src_ip not in self._devices:
                profile = DeviceProfile(src_ip, now)
                # Tag IoT/gateway if controller is available
                if self.controller:
                    if hasattr(self.controller, 'is_iot') and self.controller.is_iot(eth_src):
                        profile.is_iot = 1
                    if hasattr(self.controller, 'is_gateway') and self.controller.is_gateway(eth_src):
                        profile.is_gateway = 1
                    if eth_src in getattr(self.controller, 'iot_devices', {}):
                        profile.is_iot = 1
                    if eth_src.lower() in getattr(self.controller, 'discovered_gateways', {}):
                        profile.is_gateway = 1
                self._devices[src_ip] = profile

    def record_alert(self, alert):
        """
        Record a Snort alert for flow labeling.
        Called from the controller's _handle_snort_alert callback.
        """
        with self._alert_lock:
            self._recent_alerts.append({
                'timestamp': time.time(),
                'src_ip': alert.get('src_ip', ''),
                'dst_ip': alert.get('dst_ip', ''),
                'attack_type': alert.get('attack_type', 'Unknown'),
                'sid': alert.get('sid', ''),
            })

    # ---- Internal ----

    def _flush_loop(self):
        """Background thread: flush flows every window_seconds."""
        while self._running:
            time.sleep(self.window_seconds)
            try:
                self._flush_flows()
            except Exception as e:
                self._log('error', "Flush error: %s", str(e))

    def _flush_flows(self):
        """Aggregate accumulated flows, compute features, write to CSV."""
        flush_start = time.time()
        self._window_id += 1

        # Snapshot and reset flows
        with self._flow_lock:
            if not self._flows:
                return
            flows_snapshot = dict(self._flows)
            self._flows = defaultdict(lambda: {
                'packets': [],
                'first_seen': 0.0,
                'last_seen': 0.0,
            })
            net_src_ips = dict(self._net_src_ips)
            net_dst_ips = dict(self._net_dst_ips)
            net_dst_ports = dict(self._net_dst_ports)
            net_total_packets = self._net_total_packets
            net_total_bytes = self._net_total_bytes
            self._net_src_ips = defaultdict(int)
            self._net_dst_ips = defaultdict(int)
            self._net_dst_ports = defaultdict(int)
            self._net_total_packets = 0
            self._net_total_bytes = 0

            # Snapshot and reset per-host rate counters
            host_icmp = dict(self._host_icmp_count)
            host_syn = dict(self._host_syn_count)
            host_ack = dict(self._host_ack_count)
            host_udp = dict(self._host_udp_count)
            host_ports = {ip: set(ports) for ip, ports in self._host_dst_ports.items()}
            self._host_icmp_count = defaultdict(int)
            self._host_syn_count = defaultdict(int)
            self._host_ack_count = defaultdict(int)
            self._host_udp_count = defaultdict(int)
            self._host_dst_ports = defaultdict(set)
            self._pair_flow_count = defaultdict(int)  # Reset flow aggregation cap

            # Snapshot ICMP types
            host_icmp_types = dict(self._host_icmp_types)
            self._host_icmp_types = defaultdict(lambda: defaultdict(int))

            # Snapshot ARP counters
            arp_requests = dict(self._arp_requests)
            arp_replies = dict(self._arp_replies)
            arp_gratuitous = dict(self._arp_gratuitous)
            arp_request_targets = dict(self._arp_request_targets)
            arp_reply_sources = dict(self._arp_reply_sources)
            self._arp_requests = defaultdict(int)
            self._arp_replies = defaultdict(int)
            self._arp_gratuitous = defaultdict(int)
            self._arp_request_targets = defaultdict(set)
            self._arp_reply_sources = defaultdict(list)

            # Snapshot broadcast/multicast counters
            broadcast_count = self._net_broadcast_count
            multicast_count = self._net_multicast_count
            arp_total = self._net_arp_total
            arp_broadcast = self._net_arp_broadcast
            self._net_broadcast_count = 0
            self._net_multicast_count = 0
            self._net_arp_total = 0
            self._net_arp_broadcast = 0

            # Snapshot flows-per-src
            flows_per_src = {ip: len(keys) for ip, keys in self._flows_per_src.items()}
            self._flows_per_src = defaultdict(set)

            # Snapshot backlog drops
            backlog_drops = self._meta_backlog_drops
            self._meta_backlog_drops = 0

        # Snapshot alerts
        with self._alert_lock:
            cutoff = time.time() - self.window_seconds * 2
            alerts = [a for a in self._recent_alerts if a['timestamp'] > cutoff]

        # Compute network context (shared across all rows in this window)
        window_duration = self.window_seconds
        network_ctx = self._compute_network_context(
            flows_snapshot, net_src_ips, net_dst_ips, net_dst_ports,
            net_total_packets, net_total_bytes, window_duration, alerts,
            broadcast_count, multicast_count, arp_total, arp_broadcast
        )

        # --- Reverse-direction aggregates (FIX C): directionality & session features ---
        # The flow key is uni-directional (src->dst->port), so a flow never sees its own
        # reply traffic. Aggregate every flow into (src, dst, proto) totals here so that
        # _build_flow_row can look up the reverse pair (dst, src, proto) to populate
        # bwd_*, reply_rate, and TCP session-completeness features within the window.
        reverse_agg = {}
        for _fk, _fd in flows_snapshot.items():
            _s, _d, _port, _proto = _fk
            _a = reverse_agg.get((_s, _d, _proto))
            if _a is None:
                _a = {'pkts': 0, 'bytes': 0, 'syn': 0, 'ack': 0}
                reverse_agg[(_s, _d, _proto)] = _a
            for _size, _flags, _sport, _ts in _fd['packets']:
                _a['pkts'] += 1
                _a['bytes'] += _size
                if _flags.get('SYN'):
                    _a['syn'] += 1
                if _flags.get('ACK'):
                    _a['ack'] += 1

        # Pass 1: Identify "Attacker" IPs in this window
        window_attackers = {}  # ip -> (label, attack_type, sid)

        flow_metadata = []
        for flow_key, flow_data in flows_snapshot.items():
            if not flow_data['packets']:
                continue

            src_ip = flow_key[0]
            duration = max(flow_data['last_seen'] - flow_data['first_seen'], 0.001)
            total_packets = len(flow_data['packets'])
            pps = total_packets / duration
            bps = sum(p[0] for p in flow_data['packets']) / duration
            avg_size = bps / pps if pps else 0

            with self._device_lock:
                profile = self._devices.get(src_ip)

            protocol = flow_key[3]
            host_counters = {
                'icmp': host_icmp.get(src_ip, 0),
                'syn': host_syn.get(src_ip, 0),
                'ack': host_ack.get(src_ip, 0),
                'udp': host_udp.get(src_ip, 0),
                'unique_ports': len(host_ports.get(src_ip, set())),
            }
            label, attack_type, sid = self._compute_label(
                src_ip, flow_key[1], alerts, profile, pps, bps, avg_size, protocol,
                host_counters
            )

            if label > 0:
                if src_ip not in window_attackers or label == 1:
                    window_attackers[src_ip] = (label, attack_type, sid)

            flow_metadata.append((flow_key, flow_data, pps, bps, avg_size))

        # --- Consecutive-window tracking & Escalation ---
        detected_this_window = {}
        for src_ip, (label, attack_type, _) in window_attackers.items():
            if label == 2:
                detected_this_window[(src_ip, attack_type)] = None

        for flow_key, flow_data, _, _, _ in flow_metadata:
            key = (flow_key[0], window_attackers.get(flow_key[0], (0, '', ''))[1])
            if key in detected_this_window and detected_this_window[key] is None:
                detected_this_window[key] = flow_key[1]

        # Throttle-resilient miss handling (was: hard reset on any miss).
        # Low-cardinality floods (e.g. ICMP, single-port UDP) collapse to one
        # MAC-flow that OVS offloads to the kernel datapath; the control channel
        # then starves and a window can dip below threshold even though the flood
        # is ongoing. A hard reset there made such attacks never reach the
        # consecutive requirement ("detected once, never confirmed"). Tolerate up
        # to MISS_TOLERANCE non-detecting windows before discarding progress — the
        # multi-window "sustained" requirement is preserved, but a single throttle
        # gap no longer wipes it.
        MISS_TOLERANCE = 2
        for key in list(self._attack_confirmations.keys()):
            if key not in detected_this_window:
                conf = self._attack_confirmations[key]
                conf['misses'] = conf.get('misses', 0) + 1
                if conf['misses'] > MISS_TOLERANCE:
                    del self._attack_confirmations[key]

        for key, dst_ip in detected_this_window.items():
            src_ip, attack_type = key

            if src_ip in self._confirmed_attackers:
                continue

            required = self.REQUIRED_CONSECUTIVE.get(attack_type, 3)
            attacker_mac = self._ip_to_mac.get(src_ip, 'unknown')

            trigger_val = 'N/A'
            if 'ICMP' in attack_type: trigger_val = host_icmp.get(src_ip, 0)
            elif 'UDP' in attack_type: trigger_val = host_udp.get(src_ip, 0)
            elif 'SYN' in attack_type: trigger_val = host_syn.get(src_ip, 0)
            elif 'Port' in attack_type: trigger_val = len(host_ports.get(src_ip, set()))

            if key not in self._attack_confirmations:
                self._attack_confirmations[key] = {
                    'consecutive': 1,
                    'misses': 0,
                    'first_seen': time.time(),
                    'target': dst_ip,
                    'escalated': False,
                    'escalated_time': 0,
                }
                self._log('warning',
                    f"\n[\u26a0] SUSPECTED ATTACK from {src_ip}\n"
                    f"    Suspected : {attack_type} (Spike: {trigger_val} detected)\n"
                    f"    Target    : {dst_ip}\n"
                    f"    Window    : 1/{required} consecutive required\n"
                    f"    Action    : Monitoring only (no block yet)\n"
                )
            else:
                conf = self._attack_confirmations[key]
                conf['misses'] = 0          # detected again — clear the gap counter
                conf['consecutive'] += 1
                windows = conf['consecutive']
                elapsed = time.time() - conf['first_seen']
                now = time.time()

                if not conf.get('escalated') and windows >= required:
                    conf['escalated'] = True
                    conf['escalated_time'] = now
                    self._confirmed_attackers[src_ip] = attack_type

                    device_name = "Unknown"
                    if self.controller and hasattr(self.controller, '_discovered_names'):
                        device_name = self.controller._discovered_names.get(src_ip, "Unknown")
                    name_str = f" ({device_name})" if device_name != "Unknown" else ""

                    self._log('warning',
                        f"\n[\u26d4] ATTACK CONFIRMED — Classified {src_ip}{name_str} as attacker\n"
                        f"    Attack  : {attack_type} (Sustained ~{trigger_val}/window)\n"
                        f"    Target  : {dst_ip}\n"
                        f"    Evidence: {windows} consecutive windows in {elapsed:.0f}s\n"
                        f"    Action  : Host represents a persistent threat. Label locked-in indefinitely.\n"
                    )

                    # Fast-tier mitigation: in AUTHORIZE mode the rate-counter
                    # confirmation now BLOCKS (previously only the ML tier did).
                    # Principled fast blocker — correct source + canonical class,
                    # low FP, and it honours the consecutive-window requirement.
                    if (self.controller is not None and
                            getattr(self.controller, '_ml_mode', 'OFF') == 'AUTHORIZE'):
                        attacker_mac = self._ip_to_mac.get(src_ip, '')
                        if attacker_mac:
                            try:
                                self.controller.block_attacker(
                                    src_ip=src_ip, src_mac=attacker_mac,
                                    attack_type=attack_type, timeout=30,
                                    detection_time=now, target_ip=dst_ip,
                                    reason=f'rate-counter-{windows}w')
                                self._log('warning',
                                    "[RATE] BLOCKED %s (%s) — confirmed over %d windows",
                                    src_ip, attack_type, windows)
                            except Exception as e:
                                self._log('error', "rate-counter block_attacker failed: %s", e)

                else:
                    self._log('info',
                        f"[\u26a0] {src_ip}: {attack_type} window {windows}/{required} (Spike: {trigger_val})"
                    )

        # Pass 2: Build Rows with Inheritance
        rows = []
        for flow_key, flow_data, pps, bps, avg_size in flow_metadata:
            src_ip = flow_key[0]
            inherited = window_attackers.get(src_ip)
            # Protocol-consistency guard: an attacker's label is tracked per-host,
            # but it must only spread to flows whose protocol matches the attack
            # category. Without this, an active/confirmed SYN attacker's ICMP/ARP/
            # UDP flows inherit "SYN Flood" (measured: 101 ICMP + 51 ARP + 7 UDP
            # mislabels in one SYN session). Mismatched-protocol flows fall back to
            # independent scoring (normal unless they trip their own detector).
            if inherited and not self._attack_protocol_matches(inherited[1], flow_key[3]):
                inherited = None
            row = self._build_flow_row(
                flow_key, flow_data, network_ctx, alerts,
                pps, bps, avg_size,
                inherited_label=inherited,
                host_icmp_types=host_icmp_types,
                arp_requests=arp_requests,
                arp_replies=arp_replies,
                arp_gratuitous=arp_gratuitous,
                arp_request_targets=arp_request_targets,
                arp_reply_sources=arp_reply_sources,
                flows_per_src=flows_per_src,
                backlog_drops=backlog_drops,
                flush_start=flush_start,
                host_ports=host_ports,
                reverse_agg=reverse_agg,
            )
            if row:
                rows.append(row)

        # Reset device recent tracking
        with self._device_lock:
            for profile in self._devices.values():
                profile.reset_recent()

        # =====================================================================
        # ML Tier 4: Per-Flow RF Inference (mode OBSERVE or AUTHORIZE)
        # =====================================================================
        # Runs AFTER row building, only on rows not already flagged by earlier
        # tiers (label==0). Two confidence bands (thresholds set on the controller):
        #   conf >= block_threshold (0.90) -> ATTACK (label 2); AUTHORIZE installs an
        #                                     OpenFlow DROP on this SINGLE window.
        #   flag_threshold (0.80) <= conf < block -> FLAG: best-effort evidence
        #                                     (.pcap + flagged.csv + ml_flags.txt),
        #                                     NO block.
        #   conf < flag_threshold          -> no action.
        # Blocking is done ONLY by ML (RF) / AE — the rate-counter tier only labels.
        # =====================================================================
        if (rows and self.controller and
                getattr(self.controller, '_ml_mode', 'OFF') in ('OBSERVE', 'AUTHORIZE') and
                getattr(self.controller, '_ml_engine', None) and
                self.controller._ml_engine.is_loaded):

            ml_mode = self.controller._ml_mode
            block_thr = getattr(self.controller, '_ml_block_threshold', 0.90)
            flag_thr = getattr(self.controller, '_ml_flag_threshold', 0.80)
            ml_engine = self.controller._ml_engine
            ml_blocked_this_window = set()  # Avoid duplicate blocks per IP per window

            for row in rows:
                # Skip rows already labeled as attacks by Snort / rate counters
                # (Commented out for debugging: allow ML to score continuously)
                # if str(row.get('label', '0')) != '0':
                #     continue

                try:
                    ml_label, ml_type, ml_conf = ml_engine.predict(row)
                except Exception:
                    continue

                if ml_label == 0 or ml_type == 'normal':
                    continue
                src_ip = row.get('src_ip', '?')
                dst_ip = row.get('dst_ip', '?')
                band = ('BLOCK' if ml_conf >= block_thr
                        else 'FLAG' if ml_conf >= flag_thr else 'below-thresh')

                # OBSERVE: surface EVERY non-normal verdict + confidence, regardless
                # of band (incl. below the flag threshold), so the model can be
                # judged before authorizing blocking.
                if ml_mode == 'OBSERVE':
                    self._log('info',
                        "[ML-OBSERVE] %s → %s  verdict=%s  conf=%.2f  band=%s",
                        src_ip, dst_ip, ml_type, ml_conf, band)

                if ml_conf >= block_thr:
                    # --- BLOCK band ---
                    row['label'] = 2          # attack label (project scheme)
                    row['attack_type'] = ml_type
                    if ml_mode == 'AUTHORIZE':
                        self._log('warning',
                            "[ML] ATTACK (block) %s → %s  type=%s conf=%.2f — blocking",
                            src_ip, dst_ip, ml_type, ml_conf)
                        if (src_ip not in ml_blocked_this_window and
                                src_ip not in self._confirmed_attackers):
                            attacker_mac = self._ip_to_mac.get(src_ip, '')
                            if attacker_mac and self.controller:
                                try:
                                    self.controller.block_attacker(
                                        src_ip=src_ip,
                                        src_mac=attacker_mac,
                                        attack_type=ml_type,
                                        timeout=30,
                                        detection_time=time.time(),
                                        target_ip=dst_ip,
                                        reason=f'ml-{ml_conf:.2f}'
                                    )
                                    ml_blocked_this_window.add(src_ip)
                                except Exception as e:
                                    self._log('error', "ML block_attacker failed: %s", e)

                elif ml_conf >= flag_thr:
                    # --- FLAG band: capture evidence, never block ---
                    if ml_mode == 'AUTHORIZE':
                        self._log('warning',
                            "[ML] FLAGGED (no block) %s → %s  type=%s conf=%.2f — evidence captured",
                            src_ip, dst_ip, ml_type, ml_conf)
                    self._capture_evidence(row, ml_type, ml_conf, flag_thr, block_thr)
                # else conf < flag_thr: ignore (OBSERVE already surfaced it above)

        # =====================================================================
        # AE Tier 4: Per-Flow Autoencoder anomaly scoring (CONCURRENT with the RF)
        # =====================================================================
        # Scores EVERY window row with its own opinion, independent of the RF.
        # confidence = normalised reconstruction error. Bands (set on controller):
        #   conf >= ae_block (0.73) -> anomaly; AUTHORIZE installs an OpenFlow DROP.
        #   ae_flag (0.60) <= conf < ae_block -> flag + alert (no block).
        #   conf < ae_flag -> SILENT (so normal traffic does not flood the log).
        # The AE has no attack-type; it labels 'Anomaly (AE)' (unknown / zero-day).
        # Disabled automatically when ae_bundle.joblib is absent (engine not loaded).
        # =====================================================================
        if (rows and self.controller and
                getattr(self.controller, '_ml_mode', 'OFF') in ('OBSERVE', 'AUTHORIZE') and
                getattr(self.controller, '_ae_engine', None) and
                self.controller._ae_engine.is_loaded):

            ae_mode = self.controller._ml_mode
            ae_block_thr = getattr(self.controller, '_ae_block_threshold', 0.73)
            ae_flag_thr = getattr(self.controller, '_ae_flag_threshold', 0.60)
            ae_engine = self.controller._ae_engine
            ae_blocked_this_window = set()

            for row in rows:
                try:
                    is_anom, ae_conf, ae_err = ae_engine.score(row)
                except Exception:
                    continue
                if ae_conf < ae_flag_thr:
                    continue                       # silent: well-reconstructed (normal) window
                src_ip = row.get('src_ip', '?')
                dst_ip = row.get('dst_ip', '?')
                band = 'BLOCK' if ae_conf >= ae_block_thr else 'FLAG'

                if ae_mode == 'OBSERVE':
                    self._log('info',
                        "[AE-OBSERVE] %s → %s  anomaly conf=%.2f  err=%.4f  band=%s",
                        src_ip, dst_ip, ae_conf, ae_err, band)

                if ae_conf >= ae_block_thr:
                    if str(row.get('label', '0')) == '0':   # don't overwrite RF/rate label
                        row['label'] = 2
                        row['attack_type'] = 'Anomaly (AE)'
                    if ae_mode == 'AUTHORIZE':
                        self._log('warning',
                            "[AE] ANOMALY (block) %s → %s  conf=%.2f — blocking (zero-day net)",
                            src_ip, dst_ip, ae_conf)
                        if (src_ip not in ae_blocked_this_window and
                                src_ip not in self._confirmed_attackers):
                            attacker_mac = self._ip_to_mac.get(src_ip, '')
                            if attacker_mac and self.controller:
                                try:
                                    self.controller.block_attacker(
                                        src_ip=src_ip, src_mac=attacker_mac,
                                        attack_type='Anomaly (AE)', timeout=30,
                                        detection_time=time.time(), target_ip=dst_ip,
                                        reason=f'ae-{ae_conf:.2f}')
                                    ae_blocked_this_window.add(src_ip)
                                except Exception as e:
                                    self._log('error', "AE block_attacker failed: %s", e)
                elif ae_mode == 'AUTHORIZE':
                    self._log('warning',
                        "[AE] FLAGGED (no block) %s → %s  conf=%.2f", src_ip, dst_ip, ae_conf)

        # Drop the raw-frame evidence buffer for this window (bounded memory).
        if self._raw_frames:
            with self._flow_lock:
                self._raw_frames.clear()

        # Write to CSV
        if rows:
            self._write_csv(rows)


    def _build_flow_row(self, flow_key, flow_data, network_ctx, alerts,
                        pps, bps, avg_size, inherited_label=None,
                        host_icmp_types=None, arp_requests=None,
                        arp_replies=None, arp_gratuitous=None,
                        arp_request_targets=None, arp_reply_sources=None,
                        flows_per_src=None, backlog_drops=0, flush_start=0,
                        host_ports=None, reverse_agg=None):
        """Build a single CSV row from a flow with all 10 feature groups."""
        src_ip, dst_ip, dst_port, protocol = flow_key
        packets = flow_data['packets']
        first_seen = flow_data['first_seen']
        last_seen = flow_data['last_seen']
        eth_src = self._ip_to_mac.get(src_ip, '')

        # --- Base Flow-level features ---
        duration = max(last_seen - first_seen, 0.001)
        total_packets = len(packets)
        sizes = [p[0] for p in packets]
        total_bytes = sum(sizes)
        min_size = min(sizes) if sizes else 0
        max_size = max(sizes) if sizes else 0

        # TCP flags
        syn_count = sum(1 for p in packets if p[1].get('SYN', False))
        ack_count = sum(1 for p in packets if p[1].get('ACK', False))
        fin_count = sum(1 for p in packets if p[1].get('FIN', False))
        rst_count = sum(1 for p in packets if p[1].get('RST', False))
        psh_count = sum(1 for p in packets if p[1].get('PSH', False))

        # Port diversity
        src_ports_set = set(p[2] for p in packets if p[2])
        dst_ports_set = {dst_port} if dst_port else set()

        # =====================================================================
        # GROUP 1: Timing & Inter-Arrival Rhythm (7 features)
        # Rationale III: CV near 0 = robotic regularity (attack tool).
        # CV >> 0 = natural irregularity (human/application traffic).
        # =====================================================================
        timestamps = [p[3] for p in packets]
        if len(timestamps) >= 2:
            # Cap at TIMESTAMP_BUFFER_MAX for memory safety
            if len(timestamps) > TIMESTAMP_BUFFER_MAX:
                import random as _rng
                timestamps = sorted(_rng.sample(timestamps, TIMESTAMP_BUFFER_MAX))
            timestamps.sort()
            deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            ia_mean = statistics.mean(deltas) if deltas else 0.0
            ia_std = statistics.stdev(deltas) if len(deltas) >= 2 else 0.0
            ia_cv = _safe_div(ia_std, ia_mean) if ia_mean > 0 else 0.0
            ia_min = min(deltas) if deltas else 0.0
            ia_max = max(deltas) if deltas else 0.0
        else:
            ia_mean = ia_std = ia_cv = ia_min = ia_max = 0.0

        # Burst detection: periods where instantaneous PPS > 3x window mean
        burst_count = 0
        burst_durations = []
        if len(timestamps) >= 3 and pps > 0:
            burst_threshold = pps * 3
            in_burst = False
            burst_start_t = 0
            for i in range(len(timestamps) - 1):
                dt = timestamps[i+1] - timestamps[i]
                inst_pps = 1.0 / dt if dt > 0 else 0
                if inst_pps > burst_threshold:
                    if not in_burst:
                        in_burst = True
                        burst_start_t = timestamps[i]
                else:
                    if in_burst:
                        burst_durations.append(timestamps[i] - burst_start_t)
                        burst_count += 1
                        in_burst = False
            if in_burst:
                burst_durations.append(timestamps[-1] - burst_start_t)
                burst_count += 1
        burst_duration_avg = (statistics.mean(burst_durations) * 1000) if burst_durations else 0.0

        # =====================================================================
        # GROUP 2: Directionality & Asymmetry (7 features)
        # Rationale IV: Attacks are asymmetric — attacker floods, victim silent.
        # Ratio-based features immune to TAP 2x amplification (Rationale II.B).
        # =====================================================================
        # FIX(C) [v2 only]: Reverse-direction traffic lives in the pair (dst, src,
        # proto), a separate flow key. Look it up in reverse_agg so the
        # directionality features (Rationale IV) are populated instead of pinned to 0.
        # GATED: this changes fwd_bwd_*_ratio, which the v1 model relies on. In v1
        # mode backward traffic stays 0 (the legacy behaviour the v1 model trained on).
        fwd_pkt_count = len(packets)
        fwd_bytes = total_bytes
        if self._v2_features:
            rev = (reverse_agg or {}).get((dst_ip, src_ip, protocol), {})
            fwd_pair = (reverse_agg or {}).get((src_ip, dst_ip, protocol), {})
            bwd_pkt_count = rev.get('pkts', 0)
            bwd_bytes = rev.get('bytes', 0)
            fwd_pair_pkts = fwd_pair.get('pkts', fwd_pkt_count)
        else:
            rev = {}
            bwd_pkt_count = 0
            bwd_bytes = 0
            fwd_pair_pkts = fwd_pkt_count

        fwd_bwd_pkt_ratio = round(_safe_div(fwd_pkt_count, bwd_pkt_count + 1), 4)
        fwd_bwd_bytes_ratio = round(_safe_div(fwd_bytes, bwd_bytes + 1), 4)
        fwd_avg_size = round(_safe_div(fwd_bytes, fwd_pkt_count), 2)
        bwd_avg_size = round(_safe_div(bwd_bytes, bwd_pkt_count), 2)
        # reply_rate: destination responsiveness = reverse pkts / forward pkts
        # (Rationale IV.C). 0 in v1 mode (legacy), real value in v2 mode.
        reply_rate = round(_safe_div(bwd_pkt_count, fwd_pair_pkts), 4) if self._v2_features else 0.0

        # =====================================================================
        # GROUP 3: TCP Session Completeness (4 features)
        # Rationale V: SYN floods violate the TCP lifecycle contract (RFC 793).
        # incomplete_ratio is a category-level zero-day indicator.
        # =====================================================================
        # FIX(C): Session completeness now uses reverse-direction evidence within the
        # window. A completed handshake needs the forward SYN, a reverse SYN-ACK (the
        # reverse flow shows both SYN and ACK), and a forward ACK. This remains a
        # within-window approximation (Rationale II.C, V) but is no longer pinned to 0.
        syn_ack_ratio = round(_safe_div(syn_count, ack_count + 1), 4)
        rev_syn = rev.get('syn', 0)
        rev_ack = rev.get('ack', 0)
        has_syn = syn_count > 0
        handshake_done = has_syn and rev_syn > 0 and rev_ack > 0 and ack_count > 0
        completed = 1 if handshake_done else 0
        total_sessions = 1 if has_syn else 0
        incomplete_ratio = round(_safe_div(total_sessions - completed, total_sessions + 1), 4)
        avg_session_dur = round(duration, 4) if completed else 0.0

        # =====================================================================
        # GROUP 4: Per-Flow Entropy (3 features)
        # Rationale VI: Entropy = diversity measure, invariant to port magnitude.
        # Near 0 = concentrated (flood). High = diverse (scan/normal).
        # =====================================================================
        size_counter = Counter(sizes)
        payload_size_entropy = _shannon_entropy(dict(size_counter))

        src_port_counter = Counter(p[2] for p in packets if p[2])
        src_port_entropy = _shannon_entropy(dict(src_port_counter))

        # ICMP type entropy — uses per-host accumulator for this window
        if protocol == 'ICMP' and host_icmp_types:
            icmp_type_counter = host_icmp_types.get(src_ip, {})
            icmp_type_entropy = _shannon_entropy(dict(icmp_type_counter))
        else:
            icmp_type_entropy = 0.0

        # =====================================================================
        # GROUP 6: Packet Size Distribution (4 features)
        # Rationale VIII: Attack tools produce near-zero pkt_size_std.
        # =====================================================================
        if len(sizes) >= 2:
            pkt_size_std = round(statistics.stdev(sizes), 4)
            pkt_size_var = round(statistics.variance(sizes), 4)
        else:
            pkt_size_std = 0.0
            pkt_size_var = 0.0
        # FIX P13: Lowered from 100→64 bytes. Normal ICMP=84 bytes (no longer "small"),
        # but SYN flood=40 bytes and ARP=42 bytes remain "small" → better discrimination.
        small_pkt_ratio = round(_safe_div(sum(1 for s in sizes if s < 64), total_packets), 4)
        large_pkt_ratio = round(_safe_div(sum(1 for s in sizes if s > 1000), total_packets), 4)

        # =====================================================================
        # GROUP 7: Port Behavior Patterns (6 features)
        # Rationale IX: Floods target one port (ratio~1). Scans sweep many.
        # =====================================================================
        all_dst_ports_list = [dst_port] * total_packets if dst_port else []
        if all_dst_ports_list:
            port_counter = Counter(all_dst_ports_list)
            top_port, top_count = port_counter.most_common(1)[0]
            top_dst_port = top_port
            top_dst_port_ratio = round(_safe_div(top_count, total_packets), 4)
        else:
            top_dst_port = 0
            top_dst_port_ratio = 0.0

        # FIX(B) [v2 only]: Port-diversity is a HOST behaviour, not a single-flow
        # property (Rationale IX). The flow key pins each flow to one dst_port, so
        # per-flow spread is always 0. In v2 use the source host's full set of dst
        # ports this window. GATED: this changes unique_dst_ports / well_known_port_ratio,
        # which the v1 model uses, so v1 mode keeps the legacy single-port behaviour.
        if self._v2_features:
            host_port_set = (host_ports or {}).get(src_ip, set())
            if not host_port_set and dst_port:
                host_port_set = {dst_port}
            unique_dst_list = sorted(p for p in host_port_set if p)
        else:
            unique_dst_list = sorted(dst_ports_set)  # legacy: this flow's single dst_port
        host_unique_dst_ports = len(unique_dst_list)

        if len(unique_dst_list) >= 2:
            dst_port_std = round(statistics.stdev(unique_dst_list), 4)
            sequential_pairs = sum(
                1 for i in range(len(unique_dst_list) - 1)
                if abs(unique_dst_list[i+1] - unique_dst_list[i]) <= 2
            )
            sequential_port_score = round(
                _safe_div(sequential_pairs, len(unique_dst_list) - 1), 4
            )
        else:
            dst_port_std = 0.0
            sequential_port_score = 0.0

        if unique_dst_list:
            well_known = sum(1 for p in unique_dst_list if p < 1024)
            ephemeral = sum(1 for p in unique_dst_list if p > 49152)
            well_known_port_ratio = round(_safe_div(well_known, len(unique_dst_list)), 4)
            ephemeral_port_ratio = round(_safe_div(ephemeral, len(unique_dst_list)), 4)
        else:
            well_known_port_ratio = 0.0
            ephemeral_port_ratio = 0.0

        # =====================================================================
        # GROUP 8: Broadcast Context (per-flow flag)
        # =====================================================================
        # FIX(B) [v2 only]: use the flow's retained L2 destination MAC so real
        # broadcasts (eth_dst = ff:ff:ff:ff:ff:ff, e.g. ARP requests) are flagged.
        # is_broadcast_dst is dropped by the v1 pipeline, but gate it anyway to keep
        # v1-mode datasets byte-faithful to training (where it was always 0).
        flow_eth_dst = flow_data.get('eth_dst', '') if self._v2_features else ''
        is_broadcast_dst = 1 if _is_broadcast(dst_ip, flow_eth_dst) else 0

        # =====================================================================
        # GROUP 9: Flow Context
        # =====================================================================
        flow_count_this_window = flows_per_src.get(src_ip, 1) if flows_per_src else 1

        # =====================================================================
        # Build flow_features dict
        # =====================================================================
        flow_features = {
            'timestamp': datetime.fromtimestamp(first_seen).isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': list(src_ports_set)[0] if len(src_ports_set) == 1 else 0,
            'dst_port': dst_port or 0,
            'protocol': protocol,
            'flow_duration': round(duration, 4),
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'avg_packet_size': round(avg_size, 2),
            'min_packet_size': min_size,
            'max_packet_size': max_size,
            'packets_per_second': round(pps, 4),
            'bytes_per_second': round(bps, 4),
            'syn_count': syn_count,
            'ack_count': ack_count,
            'fin_count': fin_count,
            'rst_count': rst_count,
            'psh_count': psh_count,
            'unique_src_ports': len(src_ports_set),
            'unique_dst_ports': host_unique_dst_ports,  # FIX(B): host-level port diversity
            # Group 1
            'inter_arrival_mean': round(ia_mean, 6),
            'inter_arrival_std': round(ia_std, 6),
            'inter_arrival_cv': round(ia_cv, 4),
            'inter_arrival_min': round(ia_min, 6),
            'inter_arrival_max': round(ia_max, 6),
            'burst_count': burst_count,
            'burst_duration_avg': round(burst_duration_avg, 4),
            # Group 2
            'fwd_packet_count': fwd_pkt_count,
            'bwd_packet_count': bwd_pkt_count,
            'fwd_bwd_packet_ratio': fwd_bwd_pkt_ratio,
            'fwd_bwd_bytes_ratio': fwd_bwd_bytes_ratio,
            'fwd_avg_packet_size': fwd_avg_size,
            'bwd_avg_packet_size': bwd_avg_size,
            'reply_rate': reply_rate,
            # Group 3
            'syn_ack_ratio': syn_ack_ratio,
            'completed_sessions': completed,
            'incomplete_ratio': incomplete_ratio,
            'avg_session_duration': avg_session_dur,
            # Group 4
            'payload_size_entropy': payload_size_entropy,
            'src_port_entropy': src_port_entropy,
            'icmp_type_entropy': round(icmp_type_entropy, 4),
            # Group 6
            'pkt_size_std': pkt_size_std,
            'pkt_size_variance': pkt_size_var,
            'small_pkt_ratio': small_pkt_ratio,
            'large_pkt_ratio': large_pkt_ratio,
            # Group 7
            'top_dst_port': top_dst_port,
            'top_dst_port_ratio': top_dst_port_ratio,
            'dst_port_std': dst_port_std,
            'well_known_port_ratio': well_known_port_ratio,
            'ephemeral_port_ratio': ephemeral_port_ratio,
            'sequential_port_score': sequential_port_score,
            # Group 8
            'is_broadcast_dst': is_broadcast_dst,
            # Group 9
            'flows_per_window': flow_count_this_window,
        }

        # --- Device behavior features ---
        with self._device_lock:
            profile = self._devices.get(src_ip)
            if profile:
                # FIX(D): IoT/gateway classification was previously sampled only once
                # at device-creation, leaving is_registered_iot/is_gateway stuck at 0.
                # Refresh each window. Primary signal is the controller's explicit
                # by-IP registry (REGISTER:IOT:<ip>:<type>), since the IoT devices'
                # MAC OUI (00:00:00) is not recognised by OUI-prefix detection.
                if self.controller:
                    try:
                        reg_ips = getattr(self.controller, 'iot_registered_ips', {})
                        iot_macs = getattr(self.controller, 'iot_devices', {})
                        if (src_ip in reg_ips) \
                                or (eth_src and eth_src in iot_macs) \
                                or (eth_src and hasattr(self.controller, 'is_iot')
                                    and self.controller.is_iot(eth_src)):
                            profile.is_iot = 1
                        if eth_src and (
                                (hasattr(self.controller, 'is_gateway') and self.controller.is_gateway(eth_src))
                                or eth_src.lower() in getattr(self.controller, 'discovered_gateways', {})):
                            profile.is_gateway = 1
                    except Exception:
                        pass
                device_features = profile.get_features(pps, bps, avg_size)
            else:
                device_features = {col: 0 for col in DEVICE_COLUMNS}

        # =====================================================================
        # GROUP 5: ARP-Specific Behavioral (7 features)
        # Rationale VII: Addresses the visibility gap in generic flow features.
        # Persistent binding table enables slow-poisoning detection.
        # =====================================================================
        if protocol == 'ARP' and eth_src:
            req_count = (arp_requests or {}).get(eth_src, 0)
            rep_count = (arp_replies or {}).get(eth_src, 0)
            grat_count = (arp_gratuitous or {}).get(eth_src, 0)
            arp_reply_rate_val = round(_safe_div(rep_count, duration), 4)
            arp_request_rate_val = round(_safe_div(req_count, duration), 4)
            arp_rr_ratio = round(_safe_div(rep_count, req_count + 1), 4)

            # FIX P10: Unsolicited replies — count ARP replies from this MAC
            # for IPs that don't match the DAI baseline binding.
            # arpspoof sends replies claiming to be an IP that belongs to a
            # different MAC in the baseline. This catches exactly that.
            unsolicited = 0
            if arp_reply_sources:
                for claimed_ip, sources in (arp_reply_sources or {}).items():
                    for reply_mac, reply_ip in sources:
                        if reply_mac == eth_src:
                            # Check 1: Reply for IP nobody requested this window
                            if claimed_ip not in (arp_request_targets or {}):
                                unsolicited += 1
                            # Check 2: Reply claiming IP that belongs to a different
                            # MAC in the DAI baseline (the core arpspoof indicator)
                            elif claimed_ip in self._dai_baseline_bindings:
                                baseline_mac = self._dai_baseline_bindings[claimed_ip]
                                if baseline_mac and reply_mac != baseline_mac:
                                    unsolicited += 1

            # Binding changes from persistent history
            mac_ip_changes = max(0, len(self._mac_to_ip_history.get(eth_src, set())) - 1)
            ip_mac_changes = max(0, len(self._ip_to_mac_history.get(src_ip, set())) - 1)

            arp_features = {
                'arp_reply_rate': arp_reply_rate_val,
                'arp_request_rate': arp_request_rate_val,
                'arp_reply_request_ratio': arp_rr_ratio,
                'arp_gratuitous_count': grat_count,
                'arp_unsolicited_count': unsolicited,
                'mac_ip_binding_changes': mac_ip_changes,
                'ip_mac_binding_changes': ip_mac_changes,
            }
        else:
            arp_features = {col: 0 for col in ARP_COLUMNS}

        # --- Labels ---
        if inherited_label:
            label, attack_type, snort_sid = inherited_label
        else:
            label, attack_type, snort_sid = self._compute_label(
                src_ip, dst_ip, alerts, profile, pps, bps, avg_size
            )

        # Update Device Profile statistics (Baseline Integrity)
        # Rationale: Attack flows excluded from DeviceProfile volume averages
        # to prevent attackers from shifting the baseline.
        with self._device_lock:
            if profile:
                if label == 0:
                    profile.update(pps, bps, avg_size, dst_ip, dst_port, protocol)
                else:
                    profile.update_metadata(dst_ip, dst_port, protocol)

        label_features = {
            'label': label,
            'attack_type': attack_type,
            'snort_sid': snort_sid,
        }

        # =====================================================================
        # GROUP 10: Metadata Columns (Non-Feature, For Dataset Validation)
        # Rationale XII: Audit/reproducibility fields. MUST be stripped before
        # DL training — including them would constitute data leakage.
        # =====================================================================
        flush_duration_ms = round((time.time() - flush_start) * 1000, 2) if flush_start else 0
        meta_features = {
            'meta_window_id': self._window_id,
            'meta_src_mac_oui': eth_src[:8] if len(eth_src) >= 8 else eth_src,
            'meta_device_name': (
                self.controller._discovered_names.get(src_ip, 'unknown')
                if self.controller and hasattr(self.controller, '_discovered_names') else 'unknown'
            ),
            'meta_attack_tool': self._meta_attack_tool,
            'meta_attack_intensity': self._meta_attack_intensity,
            'meta_mininet_event': self._meta_mininet_event,
            'meta_controller_load': flush_duration_ms,
            'meta_backlog_drops': backlog_drops,
        }

        # Merge all features
        row = {}
        row.update(flow_features)
        row.update(device_features)
        row.update(network_ctx)
        row.update(arp_features)
        row.update(label_features)
        row.update(meta_features)
        return row

    def _compute_network_context(self, flows, src_ips, dst_ips, dst_ports,
                                  total_pkts, total_bytes, duration, alerts,
                                  broadcast_count=0, multicast_count=0,
                                  arp_total=0, arp_broadcast=0):
        """Compute network-wide context features."""
        active_flows = len(flows)
        total_durations = []
        for fd in flows.values():
            d = fd['last_seen'] - fd['first_seen']
            total_durations.append(max(d, 0.001))

        avg_flow_dur = _safe_div(sum(total_durations), len(total_durations))

        alert_types = set()
        for a in alerts:
            alert_types.add(a.get('attack_type', ''))

        return {
            'network_active_flows': active_flows,
            'network_total_pps': round(_safe_div(total_pkts, duration), 4),
            'network_total_bps': round(_safe_div(total_bytes, duration), 4),
            'network_unique_src_ips': len(src_ips),
            'network_unique_dst_ips': len(dst_ips),
            'network_avg_flow_duration': round(avg_flow_dur, 4),
            'network_entropy_src_ip': _shannon_entropy(src_ips),
            'network_entropy_dst_port': _shannon_entropy(dst_ports),
            'active_snort_alerts': len(alerts),
            'distinct_alert_types': len(alert_types),
            # Group 8 (network-level): Rationale X
            'broadcast_ratio': round(_safe_div(broadcast_count, total_pkts), 4) if total_pkts else 0.0,
            'multicast_ratio': round(_safe_div(multicast_count, total_pkts), 4) if total_pkts else 0.0,
            'arp_broadcast_ratio': round(_safe_div(arp_broadcast, arp_total), 4) if arp_total else 0.0,
        }

    def manual_unblock(self, src_ip):
        """Manually clear an IP from confirmed attacker blocks.
        Includes a 30-second cooldown to prevent immediate re-confirmation
        from residual traffic still flowing through kernel buffers."""
        device_name = "Unknown"
        if self.controller and hasattr(self.controller, '_discovered_names'):
            device_name = self.controller._discovered_names.get(src_ip, "Unknown")

        self._log('info', f"[\u2705] ADMIN MANUAL UNBLOCK: {src_ip} ({device_name}) has been cleared of attacker status.")

        if src_ip in self._confirmed_attackers:
            del self._confirmed_attackers[src_ip]

        keys_to_del = [k for k in self._attack_confirmations.keys() if k[0] == src_ip]
        for k in keys_to_del:
            del self._attack_confirmations[k]

        keys_to_del2 = [k for k in self._logged_attackers if k[0] == src_ip]
        self._logged_attackers.difference_update(keys_to_del2)

        # FIX: Clear rate counters for this IP to flush residual attack traffic
        with self._flow_lock:
            self._host_icmp_count.pop(src_ip, None)
            self._host_syn_count.pop(src_ip, None)
            self._host_ack_count.pop(src_ip, None)
            self._host_udp_count.pop(src_ip, None)
            self._host_dst_ports.pop(src_ip, None)

        # FIX: Set cooldown — suppress re-detection for 30 seconds
        self._unblock_cooldowns[src_ip] = time.time() + 30
        self._log('info', f"  Cooldown set: {src_ip} immune to re-detection for 30s")

    def clear_detection_state(self, src_ip=None, cooldown=0):
        """Release confirmed-attacker and in-progress suspicion state.

        DATA-COLLECTION USE ONLY. The collection harness sends CONTROL:CLEAR[:ip]
        between attacks (right after ATTACK_STOP) so a source that has stopped
        attacking is no longer treated as a confirmed attacker — otherwise its
        benign background traffic keeps inheriting the attack label for the rest
        of the session (e.g. a confirmed SYN attacker's normal TCP, or a confirmed
        ICMP attacker's keepalive pings), corrupting the dataset.

        It does NOT touch the DAI baseline or device profiles. In PRODUCTION
        confirmed attackers stay locked in indefinitely (admin-only unblock) — this
        method is not part of the live detection path; it only runs when the
        collection harness explicitly asks for it.

        Args:
            src_ip: clear only this source; None clears ALL confirmed/suspicion state.
            cooldown: if >0 (per-IP only), suppress re-detection of src_ip for this
                many seconds. CRITICAL for collection: after ATTACK_STOP the flood's
                control-channel backlog keeps draining for several seconds, and the
                rate counter + miss-tolerance decay would otherwise RE-CONFIRM the
                host we just released — which then never gets cleared again and
                mislabels its later traffic (esp. victim RST/SYN-ACK back-scatter when
                it is targeted in a subsequent pair). The cooldown spans the drain and
                auto-expires well before the host's next scheduled attack.
        """
        if src_ip:
            released = 1 if src_ip in self._confirmed_attackers else 0
            self._confirmed_attackers.pop(src_ip, None)
            for k in [k for k in self._attack_confirmations if k[0] == src_ip]:
                del self._attack_confirmations[k]
            self._label_overrides.pop(src_ip, None)
            self._logged_attackers = {t for t in self._logged_attackers if t[0] != src_ip}
            with self._flow_lock:
                self._host_icmp_count.pop(src_ip, None)
                self._host_syn_count.pop(src_ip, None)
                self._host_ack_count.pop(src_ip, None)
                self._host_udp_count.pop(src_ip, None)
                self._host_dst_ports.pop(src_ip, None)
            if cooldown > 0:
                self._unblock_cooldowns[src_ip] = time.time() + cooldown
        else:
            released = len(self._confirmed_attackers)
            self._confirmed_attackers.clear()
            self._attack_confirmations.clear()
            self._label_overrides.clear()
            self._logged_attackers.clear()
        cd_note = f", {cooldown}s drain-cooldown" if (src_ip and cooldown > 0) else ""
        self._log('info',
                  "[COLLECT] Detection state cleared for %s — %d confirmed attacker(s) released%s",
                  src_ip or 'ALL', released, cd_note)

    # ---- ML flag-band evidence capture (best-effort) -----------------------
    @staticmethod
    def _write_pcap(path, frames):
        """Write (ts, raw_ethernet_bytes) tuples to a libpcap file (LINKTYPE_ETHERNET)."""
        import struct
        with open(path, 'wb') as f:
            # global header: magic, ver 2.4, thiszone, sigfigs, snaplen, network=1 (Ethernet)
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for ts, data in frames:
                if not data:
                    continue
                sec = int(ts)
                usec = int((ts - sec) * 1_000_000)
                f.write(struct.pack('<IIII', sec, usec, len(data), len(data)))
                f.write(data)

    def _capture_evidence(self, row, pred_type, confidence, flag_thr, block_thr):
        """For a FLAG-band detection (no block): dump the source's recent frames to
        a .pcap (best-effort), append features to flagged.csv, and log a report line
        to ml_flags.txt. Never raises — evidence capture must not disrupt detection."""
        try:
            os.makedirs(self._flagged_dir, exist_ok=True)
            src_ip = str(row.get('src_ip', 'unknown'))
            dst_ip = str(row.get('dst_ip', '?'))
            proto = str(row.get('protocol', '?'))
            ts = int(time.time())
            safe_type = str(pred_type).replace(' ', '_').replace('/', '_')

            # 1) .pcap of the source's recent raw frames (best-effort)
            if self._ml_pcap_enabled:
                try:
                    with self._flow_lock:
                        frames = list(self._raw_frames.get(src_ip, []))
                    if frames:
                        pcap_path = os.path.join(self._flagged_dir,
                                                 f"{ts}_{src_ip}_{safe_type}.pcap")
                        self._write_pcap(pcap_path, frames)
                except Exception as e:
                    self._log('warning', "[ML-FLAG] pcap capture failed (best-effort): %s", e)

            # 2) flagged.csv — the flow's full feature row + ML verdict
            try:
                rec = dict(row)
                rec['ml_predicted_type'] = pred_type
                rec['ml_confidence'] = round(float(confidence), 4)
                csv_path = os.path.join(self._flagged_dir, 'flagged.csv')
                new_file = not os.path.exists(csv_path)
                with open(csv_path, 'a', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=list(rec.keys()))
                    if new_file:
                        writer.writeheader()
                    writer.writerow(rec)
            except Exception as e:
                self._log('warning', "[ML-FLAG] flagged.csv write failed: %s", e)

            # 3) ml_flags.txt — human-readable report
            try:
                txt_path = os.path.join(self._flagged_dir, 'ml_flags.txt')
                with open(txt_path, 'a') as f:
                    f.write(
                        f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] FLAGGED (no block)  "
                        f"src={src_ip} dst={dst_ip} proto={proto}  "
                        f"predicted={pred_type}  confidence={float(confidence):.3f}  "
                        f"band=[{flag_thr:.2f},{block_thr:.2f})\n")
            except Exception as e:
                self._log('warning', "[ML-FLAG] ml_flags.txt write failed: %s", e)
        except Exception as e:
            self._log('error', "[ML-FLAG] evidence capture error: %s", e)

    # The six canonical attack classes in our scheme. Snort alerts whose
    # attack_type is not one of these are treated as signature noise for labelling.
    CANONICAL_ATTACKS = {
        'ICMP Flood', 'SYN Flood', 'UDP Flood', 'Port Scan',
        'ARP Spoofing', 'Control Plane Saturation',
    }

    @staticmethod
    def _attack_protocol_matches(attack_type, protocol):
        """Return True when a flow protocol is compatible with attack type."""
        if not attack_type:
            return False
        if attack_type in ('SYN Flood', 'Port Scan'):
            return protocol == 'TCP'
        if attack_type in ('ICMP Flood',):
            return protocol == 'ICMP'
        if attack_type in ('UDP Flood', 'Control Plane Saturation'):
            return protocol == 'UDP'
        if attack_type in ('ARP Spoofing',):
            return protocol == 'ARP'
        # Snort-native alert names: allow all protocols unless explicitly known.
        return True

    def _compute_label(self, src_ip, dst_ip, alerts, device_profile,
                       curr_pps=0, curr_bps=0, curr_avg_size=0, protocol='OTHER',
                       host_counters=None):
        """
        Determine the label for a flow. Goal: 0% False Positives.
          0 = normal
          1 = known attack (Snort/DAI alert matches this flow's IPs)
          2 = suspicious behavioral deviation (rate counter or profile anomaly)
        """
        # --- 0. Manual Label Override (highest priority) ---
        # Rationale: Slow/stealthy attacks evade all thresholds.
        # Override injects correct ground-truth during data collection.
        if src_ip in self._label_overrides:
            return 2, self._label_overrides[src_ip], 'manual_override'

        # --- 1. Detection Mode Gate ---
        if not self._detection_enabled:
            return 0, 'normal', 'none'

        # --- 1b. Cooldown Gate — skip detection for recently-unblocked IPs ---
        if src_ip in self._unblock_cooldowns:
            if time.time() < self._unblock_cooldowns[src_ip]:
                return 0, 'normal', 'none'
            else:
                del self._unblock_cooldowns[src_ip]  # Cooldown expired

        # .get() (not 'in' + index): the collection harness can clear this dict
        # from the UDP-listener thread between attacks, so avoid a TOCTOU KeyError.
        confirmed_type = self._confirmed_attackers.get(src_ip)
        if confirmed_type is not None:
            if self._attack_protocol_matches(confirmed_type, protocol):
                return 2, confirmed_type, "none"

        # --- 2a. Known Attacks (Snort alerts) ---
        # IMPORTANT: Only match if the FLOW's src_ip is the ALERT's src_ip.
        # Previous logic matched on any IP overlap (including dst_ip), which
        # caused victim response flows to inherit attack labels from Snort.
        # Example: Snort fires "SNMP request" for 10.0.0.4:80→10.0.0.3:161
        # (victim responding to SYN flood) — we must NOT label all 10.0.0.4 flows.
        response_sids = {'524', '1418', '1420', '1421', '503', '504'}
        matching_alerts = []
        for a in alerts:
            if a.get('src_ip') != src_ip:
                continue
            if str(a.get('sid', '')) in response_sids:
                continue
            alert_type = a.get('attack_type', '')
            alert_proto = str(a.get('proto', '')).upper()
            # FIX: canonical-taxonomy guard. snort_monitor.classify_attack() falls
            # back to the raw Snort message when no keyword matches, so generic
            # signatures (e.g. "SNMP trap tcp", "BAD-TRAFFIC tcp port 0", "MISC ...")
            # leak in as attack_type and pollute the labels (the SYN-flood session
            # ended up mostly labelled "SNMP trap tcp"). Only accept Snort alerts
            # that map to one of our six canonical classes; let the rate-counter /
            # DAI tiers assign the canonical label otherwise.
            if alert_type not in self.CANONICAL_ATTACKS:
                continue
            # FIX: protocol-aware label guard. Snort frequently reports proto='?'
            # (see snort_monitor parse_alert_line), which previously bypassed the
            # check below and let an ICMP-flood alert label the attacker's TCP/ARP
            # background traffic as "ICMP Flood" (label-spread poisoning). Require
            # the flow's protocol to be compatible with the alert's attack category.
            if not self._attack_protocol_matches(alert_type, protocol):
                continue
            if alert_proto and alert_proto != '?' and protocol and alert_proto != protocol.upper():
                continue
            matching_alerts.append(a)
        if matching_alerts:
            alert = matching_alerts[-1]
            return 1, alert['attack_type'], str(alert.get('sid', 'none'))

        # --- 2b. DAI Baseline Violation (FIX P9: persistent detection) ---
        # During ARP traffic, check if this source MAC is claiming an IP
        # that belongs to a different MAC in the frozen baseline.
        # Unlike the original DAI check which only fired once on binding change,
        # this fires EVERY window the violation persists.
        if protocol == 'ARP' and self._dai_baseline_bindings:
            eth_src_mac = self._ip_to_mac.get(src_ip, '')
            if eth_src_mac:
                # Check all IPs this MAC has ever claimed
                claimed_ips = self._mac_to_ip_history.get(eth_src_mac, set())
                for claimed_ip in claimed_ips:
                    if claimed_ip in self._dai_baseline_bindings:
                        baseline_mac = self._dai_baseline_bindings[claimed_ip]
                        if baseline_mac and eth_src_mac != baseline_mac:
                            return 1, 'ARP Spoofing', 'DAI'

        # --- 3. Per-Host Rate Counter Detection with Context Guards ---
        # THRESHOLD CALIBRATION NOTE (2026-04):
        # hping3 --icmp --flood sends ~25K pkt/sec, but the controller
        # only sees ~600 pkt/sec through the OpenFlow control channel.
        # OVS fast-paths matched flows through the kernel datapath;
        # the TCP control channel to Ryu saturates and drops overflow.
        # Observed rates (from dataset11.csv analysis):
        #   Normal ICMP per host per 5s window: 5-30 packets
        #   Flood ICMP per host per 5s window:  50-3000 packets
        # Thresholds are set at ~15x above max normal to avoid FPs.
        detected_type = None
        if host_counters:
            icmp_cnt = host_counters.get('icmp', 0)
            syn_cnt  = host_counters.get('syn', 0)
            ack_cnt  = host_counters.get('ack', 0)
            udp_cnt  = host_counters.get('udp', 0)
            ports    = host_counters.get('unique_ports', 0)

            # ICMP Flood: >500 ICMP packets from one host in 5 seconds
            if icmp_cnt > 500:
                detected_type = 'ICMP Flood'
            # Port Scan: >100 unique destination ports AND sending SYN-only traffic.
            # Guard: ack_cnt < 50 ensures this host is INITIATING connections,
            # not a VICTIM responding with SYN-ACK/RST to an attacker's random ports.
            elif ports > 100 and syn_cnt > 100 and ack_cnt < 50:
                detected_type = 'Port Scan'
            # SYN Flood: >300 SYN-only packets AND low ACK AND low port diversity
            # (flood hammers 1-2 ports; scan spreads across hundreds)
            elif syn_cnt > 300 and ack_cnt < 50 and ports <= 10:
                detected_type = 'SYN Flood'
            # Control Plane Saturation: high UDP + high port diversity
            # (many tiny UDP packets to incrementing ports → each creates a
            # new flow → Packet-In to controller → overwhelms control plane)
            # Distinguishes from UDP Flood (one port) and Port Scan (TCP SYN)
            elif udp_cnt > 500 and ports > 100:
                detected_type = 'Control Plane Saturation'
            # UDP Flood: >500 UDP packets to few ports (one port hammered)
            elif udp_cnt > 500:
                detected_type = 'UDP Flood'

        if detected_type and self._attack_protocol_matches(detected_type, protocol):
            return 2, detected_type, 'none'

        # --- 4. Z-Score Behavioral Analysis (Secondary / Fallback) ---
        if not device_profile:
            return 0, 'normal', 'none'

        # Guard: If traffic drops to 0 or is extremely low, it cannot be a flood.
        if curr_pps < 10:
            return 0, 'normal', 'none'

        MIN_FLOWS = 20
        STABILIZATION_SEC = 180
        Z_THRESHOLD = 8.0

        age = time.time() - device_profile.first_seen
        if device_profile.total_flows < MIN_FLOWS or age < STABILIZATION_SEC:
            return 0, 'normal', 'none'

        features = device_profile.get_features(curr_pps, curr_bps, curr_avg_size)
        pkt_dev = abs(features.get('device_pkt_rate_deviation', 0))
        byte_dev = abs(features.get('device_byte_rate_deviation', 0))
        payload_dev = abs(features.get('device_payload_size_deviation', 0))
        new_dst_ratio = features.get('device_new_dst_ratio', 0)
        ips_count = features.get('device_unique_dst_ips', 0)

        proto_upper = protocol.upper() if protocol else 'OTHER'

        # Volumetric spike
        if pkt_dev > Z_THRESHOLD or byte_dev > Z_THRESHOLD:
            if proto_upper == 'ICMP':
                return 2, 'ICMP Flood', 'none'
            elif proto_upper == 'UDP':
                return 2, 'UDP Flood', 'none'
            elif proto_upper == 'TCP':
                return 2, 'SYN Flood', 'none'

        # Payload anomaly
        if payload_dev > Z_THRESHOLD:
            return 2, 'UDP Flood', 'none'

        # Host sweep
        if new_dst_ratio > 0.9 and ips_count > 10:
            return 2, 'Port Scan', 'none'

        return 0, 'normal', 'none'

    def _write_csv(self, rows):
        """Append rows to the CSV file. Create with headers if first time."""
        if not rows:
            return

        file_exists = os.path.exists(self.output_path)
        write_header = not file_exists or not self._csv_initialized

        try:
            with open(self.output_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=ALL_COLUMNS,
                                        extrasaction='ignore')
                if write_header:
                    writer.writeheader()
                    self._csv_initialized = True
                writer.writerows(rows)
                self._rows_written += len(rows)

            if self._rows_written % 100 < len(rows):
                self._log('info', "Traffic capture: %d rows written to %s",
                          self._rows_written, self.output_path)
        except Exception as e:
            self._log('error', "CSV write error: %s", str(e))


# =========================================================================
# Standalone Test
# =========================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("  Traffic Capture Module — Standalone Test")
    print(f"  Expected columns: {len(ALL_COLUMNS)}")
    print("=" * 60)

    capture = TrafficCapture(output_path='test_dataset.csv', window_seconds=3)
    capture.start()

    # Simulate some packets
    import random
    protocols = ['TCP', 'UDP', 'ICMP']
    for i in range(50):
        pkt = {
            'src_ip': f'10.0.0.{random.randint(1, 4)}',
            'dst_ip': f'10.0.0.{random.randint(1, 4)}',
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 22, 8080]),
            'protocol': random.choice(protocols),
            'packet_size': random.randint(64, 1500),
            'eth_src': '42:00:00:00:00:01',
            'eth_dst': '42:00:00:00:01:00',
            'tcp_flags': {
                'SYN': random.random() < 0.2,
                'ACK': random.random() < 0.5,
                'FIN': random.random() < 0.05,
                'RST': random.random() < 0.02,
                'PSH': random.random() < 0.3,
            },
            'icmp_type': 8 if random.random() < 0.5 else 0,
            'icmp_code': 0,
            'dpid': 1,
            'in_port': 1,
        }
        capture.record_packet(pkt)
        time.sleep(0.05)

    # Simulate a Snort alert
    capture.record_alert({
        'src_ip': '10.0.0.2',
        'dst_ip': '10.0.0.1',
        'attack_type': 'SYN flood attack',
        'sid': '1000001',
    })

    # More packets after alert
    for i in range(20):
        pkt = {
            'src_ip': '10.0.0.2',
            'dst_ip': '10.0.0.1',
            'src_port': random.randint(1024, 65535),
            'dst_port': 80,
            'protocol': 'TCP',
            'packet_size': 64,
            'eth_src': '42:00:00:00:01:00',
            'eth_dst': '42:00:00:00:00:01',
            'tcp_flags': {'SYN': True, 'ACK': False, 'FIN': False, 'RST': False, 'PSH': False},
            'dpid': 1,
            'in_port': 2,
        }
        capture.record_packet(pkt)

    print("\nWaiting for flush...")
    time.sleep(5)
    capture.stop()

    # Show results
    if os.path.exists('test_dataset.csv'):
        with open('test_dataset.csv', 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            print(f"\n✅ Generated {len(rows)} rows")
            print(f"   Columns: {len(reader.fieldnames)}")
            print(f"   Expected: {len(ALL_COLUMNS)}")
            col_match = "✅ MATCH" if len(reader.fieldnames) == len(ALL_COLUMNS) else "❌ MISMATCH"
            print(f"   Status: {col_match}")
            print(f"   Normal:  {sum(1 for r in rows if r['label'] == '0')}")
            print(f"   Attack:  {sum(1 for r in rows if r['label'] == '1')}")
            print(f"   Suspicious: {sum(1 for r in rows if r['label'] == '2')}")

            # Check for empty cells
            empty_cols = set()
            for row in rows:
                for k, v in row.items():
                    if v == '' or v is None:
                        empty_cols.add(k)
            if empty_cols:
                print(f"   ⚠ Columns with empty values: {sorted(empty_cols)}")
            else:
                print(f"   ✅ No empty cells — all features populated")

            print(f"\n   Sample row:")
            if rows:
                for k, v in list(rows[0].items())[:10]:
                    print(f"     {k}: {v}")
                print(f"     ... ({len(rows[0]) - 10} more columns)")
    else:
        print("❌ CSV file not created")
