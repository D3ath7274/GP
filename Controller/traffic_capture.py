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
import random
import threading
from collections import defaultdict, deque
from datetime import datetime


# =========================================================================
# Constants
# =========================================================================
TIMESTAMP_BUFFER_MAX = 2000  # Cap for per-flow timestamp buffers (reservoir sampling beyond this)


# =========================================================================
# CSV Column Definitions
# =========================================================================

FLOW_COLUMNS = [
    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
    'flow_duration', 'total_packets', 'total_bytes',
    'avg_packet_size', 'min_packet_size', 'max_packet_size',
    'packets_per_second', 'bytes_per_second',
    'syn_count', 'ack_count', 'fin_count', 'rst_count', 'psh_count',
    'unique_src_ports', 'unique_dst_ports',
    # --- Timing & Inter-Arrival Rhythm (Group 1) ---
    'inter_arrival_mean', 'inter_arrival_std', 'inter_arrival_cv',
    'inter_arrival_min', 'inter_arrival_max',
    'burst_count', 'burst_duration_avg',
    # --- Directionality & Asymmetry (Group 2) ---
    'fwd_packet_count', 'bwd_packet_count',
    'fwd_bwd_packet_ratio', 'fwd_bwd_bytes_ratio',
    'fwd_avg_packet_size', 'bwd_avg_packet_size', 'reply_rate',
    # --- Session Completeness (Group 3) ---
    'syn_ack_ratio', 'completed_sessions', 'incomplete_ratio', 'avg_session_duration',
    # --- Per-Flow Entropy (Group 4) ---
    'payload_size_entropy', 'src_port_entropy', 'icmp_type_entropy',
    # --- Packet Size Distribution (Group 6) ---
    'pkt_size_std', 'pkt_size_variance', 'small_pkt_ratio', 'large_pkt_ratio',
    # --- Port Behavior (Group 7) ---
    'top_dst_port', 'top_dst_port_ratio', 'dst_port_std',
    'well_known_port_ratio', 'ephemeral_port_ratio', 'sequential_port_score',
    # --- Broadcast (Group 8) ---
    'is_broadcast_dst',
    # --- Flow Context (Group 9) ---
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
    'is_baseline_mature',
]

NETWORK_COLUMNS = [
    'network_active_flows', 'network_total_pps', 'network_total_bps',
    'network_unique_src_ips', 'network_unique_dst_ips',
    'network_avg_flow_duration', 'network_entropy_src_ip',
    'network_entropy_dst_port',
    'active_snort_alerts', 'distinct_alert_types',
    # --- Broadcast & Multicast Environment (Group 8) ---
    'broadcast_ratio', 'multicast_ratio', 'arp_broadcast_ratio',
]

ARP_COLUMNS = [
    'arp_reply_rate', 'arp_request_rate', 'arp_reply_request_ratio',
    'arp_gratuitous_count', 'arp_unsolicited_count',
    'mac_ip_binding_changes', 'ip_mac_binding_changes',
]

LABEL_COLUMNS = [
    'label', 'attack_type', 'snort_sid',
]

META_COLUMNS = [
    'meta_window_id', 'meta_src_mac_oui', 'meta_device_name',
    'meta_attack_tool', 'meta_attack_intensity', 'meta_mininet_event',
]

ALL_COLUMNS = FLOW_COLUMNS + DEVICE_COLUMNS + NETWORK_COLUMNS + ARP_COLUMNS + LABEL_COLUMNS + META_COLUMNS


# =========================================================================
# Helpers
# =========================================================================

def _shannon_entropy(counter_dict):
    """Compute Shannon entropy from a {value: count} dictionary."""
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


# =========================================================================
# Device Profile Tracker
# =========================================================================

class DeviceProfile:
    """
    Maintains a running behavioral profile for a single device (by IP).
    Used to compute deviation features so the ML model can detect
    zero-day attacks and post-authentication compromise.
    """

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
            'is_baseline_mature': 1 if (self.total_flows >= 20 and
                                        (time.time() - self.first_seen) >= 180) else 0,
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

        # --- State ---
        self._running = False
        self._flush_thread = None
        self._window_start = time.time()
        self._csv_initialized = False
        self._rows_written = 0

        # --- Attacker Identification (one-time log per IP/Type) ---
        self._logged_attackers = set() # Set of (ip, attack_type)

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

        # --- ARP Behavioral Tracking (Group 5) ---
        # Per-window ARP counters (reset each flush)
        self._arp_reply_count = defaultdict(int)      # eth_src -> ARP replies this window
        self._arp_request_count = defaultdict(int)    # eth_src -> ARP requests this window
        self._arp_gratuitous_count = defaultdict(int) # eth_src -> gratuitous ARP count
        self._arp_unsolicited_count = defaultdict(int)# eth_src -> unsolicited replies
        self._arp_pending_requests = defaultdict(set) # target_ip -> set of requester src_ips
        # Persistent cross-window ARP binding tables (never auto-reset)
        self._mac_to_ip_history = defaultdict(set)    # eth_src -> set of all IPs ever claimed
        self._ip_to_mac_history = defaultdict(set)    # ip -> set of all MACs that claimed it

        # --- IP to MAC mapping (for block_attacker calls) ---
        self._ip_to_mac = {}  # src_ip -> eth_src MAC address

        # --- Detection Mode ---
        # OFF = capture only (all labels = normal, clean dataset)
        # ON  = full anomaly detection + blocking
        self._detection_enabled = False

        # --- Metadata State (Group 10) ---
        self._window_id = 0                  # Monotonically increasing window counter
        self._meta_attack_tool = 'none'      # Set via UDP: ATTACK_START:tool:pps
        self._meta_attack_intensity = 0      # PPS rate of active attack tool
        self._meta_mininet_event = 'normal'  # Set via UDP: MININET_EVENT:event_name

        # --- Auto-delete old CSV if schema has changed ---
        if os.path.exists(self.output_path):
            try:
                with open(self.output_path, 'r', encoding='utf-8') as f:
                    header = f.readline().strip()
                expected_header = ','.join(ALL_COLUMNS)
                if header != expected_header:
                    os.remove(self.output_path)
                    self._log('info', 'Old dataset.csv schema mismatch — deleted for clean start')
            except Exception:
                pass

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
            self._log('info', 'Detection mode ENABLED — anomaly detection active (counters reset)')
        else:
            self._log('info', 'Detection mode DISABLED — capture only, all labels = normal')

    def start(self):
        """Start the background flush thread."""
        if self._running:
            return
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

    def record_packet(self, pkt_info):
        """
        Record a single packet from a packet_in event.

        pkt_info dict should contain:
            src_ip, dst_ip, src_port, dst_port, protocol,
            packet_size, eth_src, eth_dst, tcp_flags (dict),
            dpid, in_port
        """
        if not self._running:
            return
            
        src_ip = pkt_info.get('src_ip', '')
        
        # --- Backlog Ignore / Blacklist Cache ---
        # If the switch is physically dropping this IP because we blocked it,
        # we must ignore packets from this IP in our controller's backlog queue,
        # otherwise old stale packets will continuously re-trigger false alarms.
        if src_ip in self._active_blocks:
            if time.time() < self._active_blocks[src_ip]:
                return  # Drop packet from ML / tracking pipeline
            else:
                del self._active_blocks[src_ip]

        with self._flow_lock:
            # We use an identical 5-tuple + protocol flow mapping
            protocol = pkt_info.get('protocol', 'OTHER')
        dst_ip = pkt_info.get('dst_ip', '')
        dst_port = pkt_info.get('dst_port', 0)
        packet_size = pkt_info.get('packet_size', 0)
        src_port = pkt_info.get('src_port', 0)
        tcp_flags = pkt_info.get('tcp_flags', {})
        now = time.time()

        if not src_ip and not dst_ip:
            return

        flow_key = (src_ip, dst_ip, dst_port, protocol)

        with self._flow_lock:
            flow = self._flows[flow_key]
            if not flow['packets']:
                flow['first_seen'] = now
            flow['last_seen'] = now
            flow['packets'].append((packet_size, tcp_flags, src_port, now))

            # Update network-wide counters
            self._net_src_ips[src_ip] += 1
            self._net_dst_ips[dst_ip] += 1
            if dst_port:
                self._net_dst_ports[dst_port] += 1
            self._net_total_packets += 1
            self._net_total_bytes += packet_size

            # --- Per-host rate counters (for attack detection) ---
            if protocol == 'ICMP':
                self._host_icmp_count[src_ip] += 1
            elif protocol == 'UDP':
                self._host_udp_count[src_ip] += 1
            elif protocol == 'TCP':
                # Count SYN-only packets (SYN set, ACK not set) — hallmark of SYN flood
                if tcp_flags.get('SYN') and not tcp_flags.get('ACK'):
                    self._host_syn_count[src_ip] += 1
                # Count ACK packets for SYN/ACK ratio guard
                if tcp_flags.get('ACK'):
                    self._host_ack_count[src_ip] += 1
            if dst_port and src_ip:
                self._host_dst_ports[src_ip].add(dst_port)

            # --- ARP Behavioral Tracking (Group 5) ---
            # NOTE: Requires Controller.py to pass arp_op, arp_spa, arp_tpa in pkt_info
            if protocol == 'ARP':
                arp_op = pkt_info.get('arp_op', 0)      # 1 = request, 2 = reply
                arp_spa = pkt_info.get('arp_spa', '')   # sender protocol address (IP)
                arp_tpa = pkt_info.get('arp_tpa', '')   # target protocol address (IP)
                eth_src_arp = pkt_info.get('eth_src', '')

                if arp_op == 1:  # ARP Request
                    self._arp_request_count[eth_src_arp] += 1
                    self._arp_pending_requests[arp_tpa].add(eth_src_arp)
                elif arp_op == 2:  # ARP Reply
                    self._arp_reply_count[eth_src_arp] += 1
                    # Gratuitous: sender and target IP are the same (self-announcement)
                    if arp_spa == arp_tpa and arp_spa:
                        self._arp_gratuitous_count[eth_src_arp] += 1
                    # Unsolicited: reply with no matching prior request from this target
                    if eth_src_arp not in self._arp_pending_requests.get(arp_spa, set()):
                        self._arp_unsolicited_count[eth_src_arp] += 1

                # Update persistent binding tables
                if eth_src_arp and arp_spa:
                    self._mac_to_ip_history[eth_src_arp].add(arp_spa)
                    self._ip_to_mac_history[arp_spa].add(eth_src_arp)

        # Track IP → MAC mapping
        eth_src = pkt_info.get('eth_src', '')
        if src_ip and eth_src:
            self._ip_to_mac[src_ip] = eth_src

        # Ensure device profile exists
        with self._device_lock:
            if src_ip and src_ip not in self._devices:
                profile = DeviceProfile(src_ip, now)
                # Tag IoT/gateway if controller is available
                if self.controller:
                    eth_src = pkt_info.get('eth_src', '')
                    if hasattr(self.controller, 'is_iot') and self.controller.is_iot(eth_src):
                        profile.is_iot = 1
                    if hasattr(self.controller, 'is_gateway') and self.controller.is_gateway(eth_src):
                        profile.is_gateway = 1
                    # Check discovered lists as well
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

            # Snapshot and reset per-window ARP counters (persistent tables NOT reset)
            arp_reply_snap = dict(self._arp_reply_count)
            arp_request_snap = dict(self._arp_request_count)
            arp_gratuitous_snap = dict(self._arp_gratuitous_count)
            arp_unsolicited_snap = dict(self._arp_unsolicited_count)
            self._arp_reply_count = defaultdict(int)
            self._arp_request_count = defaultdict(int)
            self._arp_gratuitous_count = defaultdict(int)
            self._arp_unsolicited_count = defaultdict(int)
            self._arp_pending_requests = defaultdict(set)

        # Pre-compute flows_per_src for Group 9
        flows_per_src = defaultdict(int)
        for fk in flows_snapshot:
            flows_per_src[fk[0]] += 1

        # Snapshot alerts
        with self._alert_lock:
            cutoff = time.time() - self.window_seconds * 2
            alerts = [a for a in self._recent_alerts if a['timestamp'] > cutoff]

        # Compute network context (shared across all rows in this window)
        window_duration = self.window_seconds
        network_ctx = self._compute_network_context(
            flows_snapshot, net_src_ips, net_dst_ips, net_dst_ports,
            net_total_packets, net_total_bytes, window_duration, alerts
        )

        # Pass 1: Identify "Attacker" IPs in this window
        # An IP is an attacker if ANY of its flows trigger Snort or Behavioral rules.
        window_attackers = {} # ip -> (label, attack_type, sid)
        
        # We need to compute individual flow labels first to find attackers
        flow_metadata = []
        for flow_key, flow_data in flows_snapshot.items():
            if not flow_data['packets']:
                continue
            
            src_ip = flow_key[0]
            # Basic stats for detection pass
            duration = max(flow_data['last_seen'] - flow_data['first_seen'], 0.001)
            total_packets = len(flow_data['packets'])
            pps = total_packets / duration
            bps = sum(p[0] for p in flow_data['packets']) / duration
            avg_size = bps / pps if pps else 0
            
            with self._device_lock:
                profile = self._devices.get(src_ip)
            
            # Compute flow's intrinsic label
            protocol = flow_key[3]  # (src_ip, dst_ip, dst_port, protocol)
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
                # If multiple attacks found, prioritize Snort (1) over Behavioral (2)
                if src_ip not in window_attackers or label == 1:
                    window_attackers[src_ip] = (label, attack_type, sid)
            
            flow_metadata.append((flow_key, flow_data, pps, bps, avg_size))

        # --- Consecutive-window tracking & Escalation ---
        # This runs ONCE per window, not per flow.
        # 1. Collect which (src_ip, attack_type) were detected this window
        # 2. Increment consecutive counter for those (once per window)
        # 3. Reset counter for those NOT detected (attack stopped)
        # 4. Run escalation if consecutive threshold is met
        detected_this_window = {}  # (src_ip, type) -> dst_ip
        for src_ip, (label, attack_type, _) in window_attackers.items():
            if label == 2:
                detected_this_window[(src_ip, attack_type)] = None  # dst_ip filled below

        # Fill dst_ip from flow metadata
        for flow_key, flow_data, _, _, _ in flow_metadata:
            key = (flow_key[0], window_attackers.get(flow_key[0], (0, '', ''))[1])
            if key in detected_this_window and detected_this_window[key] is None:
                detected_this_window[key] = flow_key[1]  # dst_ip

        # Update consecutive counters (once per window per key)
        for key in list(self._attack_confirmations.keys()):
            if key not in detected_this_window:
                # Source was clean this window → reset tracking
                del self._attack_confirmations[key]

        for key, dst_ip in detected_this_window.items():
            src_ip, attack_type = key
            
            # If already permanently confirmed, skip new escalation logs. It will write to dataset silently forever.
            if src_ip in self._confirmed_attackers:
                continue

            required = self.REQUIRED_CONSECUTIVE.get(attack_type, 3)
            attacker_mac = self._ip_to_mac.get(src_ip, 'unknown')
            
            # Fetch the actual count from host_counters to show in log
            trigger_val = 'N/A'
            if 'ICMP' in attack_type: trigger_val = host_icmp.get(src_ip, 0)
            elif 'UDP' in attack_type: trigger_val = host_udp.get(src_ip, 0)
            elif 'SYN' in attack_type: trigger_val = host_syn.get(src_ip, 0)
            elif 'Port' in attack_type: trigger_val = len(host_ports.get(src_ip, set()))

            if key not in self._attack_confirmations:
                # First window → start tracking
                self._attack_confirmations[key] = {
                    'consecutive': 1,
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
                conf['consecutive'] += 1
                windows = conf['consecutive']
                elapsed = time.time() - conf['first_seen']
                now = time.time()

                if not conf.get('escalated') and windows >= required:
                    # Consecutive threshold met → Classify completely
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

                else:
                    # Below consecutive threshold, log progress
                    self._log('info',
                        f"[\u26a0] {src_ip}: {attack_type} window {windows}/{required} (Spike: {trigger_val})"
                    )

        # Pass 2: Build Rows with Inheritance
        # All flows from an identified attacker in this window will inherit the attack label.
        rows = []
        for flow_key, flow_data, pps, bps, avg_size in flow_metadata:
            src_ip = flow_key[0]
            inherited = window_attackers.get(src_ip)
            row = self._build_flow_row(
                flow_key, flow_data, network_ctx, alerts,
                pps, bps, avg_size,
                inherited_label=inherited,
                host_dst_ports=host_ports.get(src_ip, set()),
                flows_per_window=flows_per_src.get(src_ip, 1),
                arp_reply_snap=arp_reply_snap,
                arp_request_snap=arp_request_snap,
                arp_gratuitous_snap=arp_gratuitous_snap,
                arp_unsolicited_snap=arp_unsolicited_snap,
            )
            if row:
                rows.append(row)

        # Reset device recent tracking
        with self._device_lock:
            for profile in self._devices.values():
                profile.reset_recent()

        # Write to CSV
        if rows:
            self._write_csv(rows)

    def _build_flow_row(self, flow_key, flow_data, network_ctx, alerts,
                        pps, bps, avg_size, inherited_label=None,
                        host_dst_ports=None, flows_per_window=1,
                        arp_reply_snap=None, arp_request_snap=None,
                        arp_gratuitous_snap=None, arp_unsolicited_snap=None):
        """Build a single CSV row from a flow, enriched with all feature groups."""
        src_ip, dst_ip, dst_port, protocol = flow_key
        packets = flow_data['packets']
        first_seen = flow_data['first_seen']
        last_seen = flow_data['last_seen']

        # --- Flow-level features ---
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
        src_ports = set(p[2] for p in packets if p[2])
        dst_ports = {dst_port} if dst_port else set()

        # =====================================================================
        # GROUP 1: Timing & Inter-Arrival Rhythm Features
        # Exposes the inhuman regularity of flood tools. Values near 0 for CV
        # indicate robotic traffic. Burst metrics capture volumetric spikes.
        # =====================================================================
        timestamps = [p[3] for p in packets]
        if len(timestamps) > TIMESTAMP_BUFFER_MAX:
            timestamps = sorted(random.sample(timestamps, TIMESTAMP_BUFFER_MAX))

        if len(timestamps) >= 2:
            inter_arrivals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            ia_mean = sum(inter_arrivals) / len(inter_arrivals)
            ia_var = sum((x - ia_mean)**2 for x in inter_arrivals) / len(inter_arrivals)
            ia_std = ia_var ** 0.5
            inter_arrival_mean = round(ia_mean, 8)
            inter_arrival_std = round(ia_std, 8)
            inter_arrival_cv = round(ia_std / ia_mean, 4) if ia_mean > 0 else 0.0
            inter_arrival_min = round(min(inter_arrivals), 8)
            inter_arrival_max = round(max(inter_arrivals), 8)

            # Burst detection: intervals where instantaneous rate > 3x mean PPS
            burst_threshold = 3.0 * pps if pps > 0 else float('inf')
            burst_flags = []
            for d in inter_arrivals:
                burst_flags.append(1 if (d > 0 and (1.0 / d) > burst_threshold) else 0)

            # Count burst episodes (consecutive runs of 1s)
            burst_episodes = []
            i = 0
            while i < len(burst_flags):
                if burst_flags[i] == 1:
                    start = i
                    while i < len(burst_flags) and burst_flags[i] == 1:
                        i += 1
                    burst_episodes.append(sum(inter_arrivals[start:i]))
                else:
                    i += 1
            burst_count = len(burst_episodes)
            burst_duration_avg = round(sum(burst_episodes) / len(burst_episodes), 6) if burst_episodes else 0.0
        else:
            inter_arrival_mean = inter_arrival_std = inter_arrival_cv = 0.0
            inter_arrival_min = inter_arrival_max = 0.0
            burst_count = 0
            burst_duration_avg = 0.0

        # =====================================================================
        # GROUP 2: Directionality & Asymmetry Features
        # Attacks are one-directional. Floods push fwd/bwd ratio to extreme
        # values. Victims can't respond. ACK-only packets proxy backward traffic.
        # =====================================================================
        fwd_packet_count = total_packets
        # Approximate backward packets as ACK-only (no SYN) — indicates response traffic
        bwd_packet_count = sum(1 for p in packets if p[1].get('ACK') and not p[1].get('SYN')) if protocol == 'TCP' else 0
        fwd_bwd_packet_ratio = round(fwd_packet_count / (bwd_packet_count + 1), 4)
        est_bwd_bytes = bwd_packet_count * avg_size if avg_size > 0 else 0
        fwd_bwd_bytes_ratio = round(total_bytes / (est_bwd_bytes + 1), 4)
        fwd_avg_packet_size = round(avg_size, 2)
        bwd_avg_packet_size = 0.0  # Exact reverse flow data not available within single flow key
        reply_rate = round(bwd_packet_count / (total_packets + 1), 4)

        # =====================================================================
        # GROUP 3: Session Completeness Features
        # SYN floods generate massive SYN with no ACK. Scans generate RST storms.
        # These ratios immediately expose incomplete and aborted sessions.
        # =====================================================================
        syn_ack_ratio = round(syn_count / (ack_count + 1), 4)
        completed_sessions = 1 if (syn_count > 0 and ack_count > 0 and fin_count > 0) else 0
        incomplete_ratio = 1.0 if (syn_count > 0 and fin_count == 0 and rst_count == 0) else 0.0
        avg_session_duration = round(duration, 4) if completed_sessions == 1 else 0.0

        # =====================================================================
        # GROUP 4: Per-Flow Shannon Entropy Features
        # Floods produce near-zero payload size entropy (all identical packets).
        # Scans produce high source port entropy. ICMP floods collapse type entropy.
        # =====================================================================
        size_counter = {}
        for s in sizes:
            size_counter[s] = size_counter.get(s, 0) + 1
        payload_size_entropy = _shannon_entropy(size_counter)

        sport_counter = {}
        for p in packets:
            if p[2]:
                sport_counter[p[2]] = sport_counter.get(p[2], 0) + 1
        src_port_entropy = _shannon_entropy(sport_counter)

        icmp_type_entropy = 0.0  # Placeholder: requires icmp_type in pkt_info (future enhancement)

        # =====================================================================
        # GROUP 6: Packet Size Distribution Features
        # Attack tools generate unnaturally uniform sizes. SYN packets are ~60B.
        # Near-zero std reveals tool-generated uniformity.
        # =====================================================================
        if len(sizes) >= 2:
            size_mean = sum(sizes) / len(sizes)
            pkt_size_std = round((sum((s - size_mean)**2 for s in sizes) / len(sizes)) ** 0.5, 4)
        else:
            pkt_size_std = 0.0
        pkt_size_variance = round(pkt_size_std ** 2, 4)
        small_pkt_ratio = round(sum(1 for s in sizes if s < 100) / total_packets, 4) if total_packets else 0.0
        large_pkt_ratio = round(sum(1 for s in sizes if s > 1000) / total_packets, 4) if total_packets else 0.0

        # =====================================================================
        # GROUP 7: Port Behavior Features
        # Floods target one port (ratio = 1.0). Scanners sweep many ports
        # sequentially (high sequential_port_score). These shape features
        # distinguish focused attacks from scanning patterns.
        # =====================================================================
        hdp = host_dst_ports if host_dst_ports else set()
        top_dst_port = dst_port if len(hdp) <= 1 else 0
        top_dst_port_ratio = round(1.0 / len(hdp), 4) if hdp else 0.0
        if len(hdp) >= 2:
            port_list = sorted(hdp)
            port_mean = sum(port_list) / len(port_list)
            dst_port_std = round((sum((p_val - port_mean)**2 for p_val in port_list) / len(port_list)) ** 0.5, 2)
            seq_pairs = sum(1 for j in range(len(port_list)-1) if abs(port_list[j+1] - port_list[j]) <= 2)
            sequential_port_score = round(seq_pairs / (len(port_list) - 1), 4)
        else:
            dst_port_std = 0.0
            sequential_port_score = 0.0
        well_known_port_ratio = round(sum(1 for p_val in hdp if p_val < 1024) / (len(hdp) + 1), 4) if hdp else 0.0
        ephemeral_port_ratio = round(sum(1 for p_val in hdp if p_val > 49152) / (len(hdp) + 1), 4) if hdp else 0.0

        # =====================================================================
        # GROUP 8 (per-flow): Broadcast Detection Flag
        # Allows downstream ML to distinguish Mininet pingall broadcast storms
        # from real flood attacks.
        # =====================================================================
        is_broadcast_dst = 1 if dst_ip == '255.255.255.255' else 0

        # --- Build the complete flow features dict ---
        flow_features = {
            'timestamp': datetime.fromtimestamp(first_seen).isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': list(src_ports)[0] if len(src_ports) == 1 else 0,
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
            'unique_src_ports': len(src_ports),
            'unique_dst_ports': len(dst_ports),
            # Group 1 — Timing
            'inter_arrival_mean': inter_arrival_mean,
            'inter_arrival_std': inter_arrival_std,
            'inter_arrival_cv': inter_arrival_cv,
            'inter_arrival_min': inter_arrival_min,
            'inter_arrival_max': inter_arrival_max,
            'burst_count': burst_count,
            'burst_duration_avg': burst_duration_avg,
            # Group 2 — Directionality
            'fwd_packet_count': fwd_packet_count,
            'bwd_packet_count': bwd_packet_count,
            'fwd_bwd_packet_ratio': fwd_bwd_packet_ratio,
            'fwd_bwd_bytes_ratio': fwd_bwd_bytes_ratio,
            'fwd_avg_packet_size': fwd_avg_packet_size,
            'bwd_avg_packet_size': bwd_avg_packet_size,
            'reply_rate': reply_rate,
            # Group 3 — Session Completeness
            'syn_ack_ratio': syn_ack_ratio,
            'completed_sessions': completed_sessions,
            'incomplete_ratio': incomplete_ratio,
            'avg_session_duration': avg_session_duration,
            # Group 4 — Entropy
            'payload_size_entropy': payload_size_entropy,
            'src_port_entropy': src_port_entropy,
            'icmp_type_entropy': icmp_type_entropy,
            # Group 6 — Size Distribution
            'pkt_size_std': pkt_size_std,
            'pkt_size_variance': pkt_size_variance,
            'small_pkt_ratio': small_pkt_ratio,
            'large_pkt_ratio': large_pkt_ratio,
            # Group 7 — Port Behavior
            'top_dst_port': top_dst_port,
            'top_dst_port_ratio': top_dst_port_ratio,
            'dst_port_std': dst_port_std,
            'well_known_port_ratio': well_known_port_ratio,
            'ephemeral_port_ratio': ephemeral_port_ratio,
            'sequential_port_score': sequential_port_score,
            # Group 8 — Broadcast
            'is_broadcast_dst': is_broadcast_dst,
            # Group 9 — Flow Context
            'flows_per_window': flows_per_window,
        }

        # --- Device behavior features ---
        with self._device_lock:
            profile = self._devices.get(src_ip)
            if profile:
                device_features = profile.get_features(pps, bps, avg_size)
            else:
                device_features = {col: 0 for col in DEVICE_COLUMNS}

        # =====================================================================
        # GROUP 5: ARP-Specific Behavioral Features
        # ARP spoofing is invisible to generic flow features. Spoofers send
        # unsolicited replies, claim multiple IPs, and change MAC-IP bindings.
        # =====================================================================
        eth_src = self._ip_to_mac.get(src_ip, '')
        window_dur = self.window_seconds or 1.0
        if protocol == 'ARP' and arp_reply_snap is not None:
            arp_replies = arp_reply_snap.get(eth_src, 0)
            arp_requests = arp_request_snap.get(eth_src, 0)
            arp_features = {
                'arp_reply_rate': round(arp_replies / window_dur, 4),
                'arp_request_rate': round(arp_requests / window_dur, 4),
                'arp_reply_request_ratio': round(arp_replies / (arp_requests + 1), 4),
                'arp_gratuitous_count': arp_gratuitous_snap.get(eth_src, 0),
                'arp_unsolicited_count': arp_unsolicited_snap.get(eth_src, 0),
                'mac_ip_binding_changes': max(len(self._mac_to_ip_history.get(eth_src, set())) - 1, 0),
                'ip_mac_binding_changes': max(len(self._ip_to_mac_history.get(src_ip, set())) - 1, 0),
            }
        else:
            arp_features = {col: 0.0 for col in ARP_COLUMNS}

        # --- Labels ---
        if inherited_label:
            label, attack_type, snort_sid = inherited_label
        else:
            label, attack_type, snort_sid = self._compute_label(
                src_ip, dst_ip, alerts, profile, pps, bps, avg_size
            )

        # Update Device Profile statistics (Baseline Integrity)
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
        # These are audit/reproducibility fields, not ML inputs.
        # =====================================================================
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
                                  total_pkts, total_bytes, duration, alerts):
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

        # --- Broadcast & Multicast ratios (Group 8 — network level) ---
        total_flow_count = max(len(flows), 1)
        _mcast_prefixes = tuple(str(i) + '.' for i in range(224, 240))  # 224.0.0.0/4
        bcast_count = sum(1 for k in flows if k[1] == '255.255.255.255')
        mcast_count = sum(1 for k in flows if k[1].startswith(_mcast_prefixes))
        arp_flows_keys = [k for k in flows if k[3] == 'ARP']
        arp_bcast = sum(1 for k in arp_flows_keys if k[1] == '255.255.255.255')

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
            'broadcast_ratio': round(bcast_count / total_flow_count, 4),
            'multicast_ratio': round(mcast_count / total_flow_count, 4),
            'arp_broadcast_ratio': round(arp_bcast / (len(arp_flows_keys) + 1), 4),
        }



    def manual_unblock(self, src_ip):
        """Manually clear an IP from confirmed attacker blocks."""
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

    def set_attack_metadata(self, tool, intensity_pps):
        """Called by Controller when ATTACK_START:tool:pps UDP message is received."""
        self._meta_attack_tool = tool
        self._meta_attack_intensity = int(intensity_pps)

    def clear_attack_metadata(self):
        """Called by Controller when ATTACK_STOP UDP message is received."""
        self._meta_attack_tool = 'none'
        self._meta_attack_intensity = 0

    def set_mininet_event(self, event):
        """Called by Controller when MININET_EVENT:event_name UDP message is received."""
        self._meta_mininet_event = event  # 'pingall', 'normal', 'topology_change'

    def _compute_label(self, src_ip, dst_ip, alerts, device_profile, 
                       curr_pps=0, curr_bps=0, curr_avg_size=0, protocol='OTHER',
                       host_counters=None):
        """
        Determine the label for a flow. Goal: 0% False Positives.
          0 = normal
          1 = known attack (Snort/DAI alert matches this flow's IPs)
          2 = suspicious behavioral deviation (rate counter or profile anomaly)
        """
        # --- 1. Detection Mode Gate ---
        # When detection is OFF, force everything to normal for clean dataset capture
        if not self._detection_enabled:
            return 0, 'normal', ''

        if src_ip in self._confirmed_attackers:
            return 2, self._confirmed_attackers[src_ip], ""

        # --- 2. Known Attacks (Snort + DAI) ---
        matching_alerts = [
            a for a in alerts
            if a['src_ip'] == src_ip or a['dst_ip'] == dst_ip
            or a['src_ip'] == dst_ip or a['dst_ip'] == src_ip
        ]
        if matching_alerts:
            alert = matching_alerts[-1]
            return 1, alert['attack_type'], str(alert.get('sid', ''))

        # --- 3. Per-Host Rate Counter Detection with Context Guards ---
        detected_type = None
        if host_counters:
            icmp = host_counters.get('icmp', 0)
            syn  = host_counters.get('syn', 0)
            ack  = host_counters.get('ack', 0)
            udp  = host_counters.get('udp', 0)
            ports = host_counters.get('unique_ports', 0)

            # ICMP Flood: >1000 ICMP packets from one host in 5 seconds
            # Raised significantly: a real flood generates 10,000+ pkts.
            # Mininet pingall could somehow trigger 150 due to broadcast storms.
            # ICMP Flood: >15000 ICMP packets from one host in 5 seconds
            # Raised over 10k to comfortably ignore intense Mininet broadcast loops
            # like pingall (which can hit ~6k in some topologies).
            if icmp > 15000:
                detected_type = 'ICMP Flood'

            # SYN Flood: >5000 SYN-only packets AND low ACK count
            elif syn > 5000 and ack < 50:
                detected_type = 'SYN Flood'

            # UDP Flood: >15000 UDP packets from one host in 5 seconds
            elif udp > 15000:
                detected_type = 'UDP Flood'

            # Port Scan: >100 unique destination ports from one host in 5 seconds
            elif ports > 100:
                detected_type = 'Port Scan'

        if detected_type:
            return 2, detected_type, ''

        # --- 4. Z-Score Behavioral Analysis (Secondary / Fallback) ---
        if not device_profile:
            return 0, 'normal', ''

        # Guard: If traffic drops to 0 or is extremely low, it cannot mathematically
        # be a flood. This prevents the Z-score deviation from treating a sudden
        # drop in traffic as a massive "anomaly".
        if curr_pps < 10:
            return 0, 'normal', ''

        MIN_FLOWS = 20
        STABILIZATION_SEC = 180
        Z_THRESHOLD = 8.0

        age = time.time() - device_profile.first_seen
        if device_profile.total_flows < MIN_FLOWS or age < STABILIZATION_SEC:
            return 0, 'normal', ''

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
                return 2, 'ICMP Flood', ''
            elif proto_upper == 'UDP':
                return 2, 'UDP Flood', ''
            elif proto_upper == 'TCP':
                return 2, 'SYN Flood', ''

        # Payload anomaly
        if payload_dev > Z_THRESHOLD:
            return 2, 'UDP Flood', ''

        # Host sweep
        if new_dst_ratio > 0.9 and ips_count > 10:
            return 2, 'Port Scan', ''

        return 0, 'normal', ''

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
    print("  Traffic Capture Module — Standalone Test (Enhanced)")
    print(f"  Expected columns: {len(ALL_COLUMNS)}")
    print("=" * 60)

    # Clean up old test file
    if os.path.exists('test_dataset.csv'):
        os.remove('test_dataset.csv')

    capture = TrafficCapture(output_path='test_dataset.csv', window_seconds=3)
    capture.start()

    # Simulate mixed traffic: TCP, UDP, ICMP, ARP
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
            'dpid': 1,
            'in_port': 1,
        }
        capture.record_packet(pkt)
        time.sleep(0.05)

    # Simulate ARP traffic (Group 5 test)
    for i in range(10):
        arp_pkt = {
            'src_ip': '10.0.0.1',
            'dst_ip': '255.255.255.255',
            'src_port': 0,
            'dst_port': 0,
            'protocol': 'ARP',
            'packet_size': 42,
            'eth_src': '42:00:00:00:00:01',
            'eth_dst': 'ff:ff:ff:ff:ff:ff',
            'tcp_flags': {},
            'arp_op': 1,       # ARP Request
            'arp_spa': '10.0.0.1',
            'arp_tpa': '10.0.0.2',
            'dpid': 1,
            'in_port': 1,
        }
        capture.record_packet(arp_pkt)

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
            col_count = len(reader.fieldnames)
            expected = len(ALL_COLUMNS)
            status = "✅" if col_count == expected else "❌"
            print(f"\n{status} Generated {len(rows)} rows")
            print(f"   Columns: {col_count} (expected {expected})")
            print(f"   Normal:  {sum(1 for r in rows if r['label'] == '0')}")
            print(f"   Attack:  {sum(1 for r in rows if r['label'] == '2')}")

            # Check for empty cells
            empty_count = 0
            for row in rows:
                for k, v in row.items():
                    if v == '' or v is None:
                        empty_count += 1
            print(f"   Empty cells: {empty_count} {'✅' if empty_count == 0 else '❌'}")

            # Show new feature columns from first row
            if rows:
                print(f"\n   --- New Feature Samples (first row) ---")
                new_cols = [
                    'inter_arrival_mean', 'inter_arrival_cv', 'burst_count',
                    'fwd_bwd_packet_ratio', 'reply_rate', 'syn_ack_ratio',
                    'payload_size_entropy', 'pkt_size_std', 'small_pkt_ratio',
                    'top_dst_port_ratio', 'sequential_port_score',
                    'is_broadcast_dst', 'flows_per_window', 'is_baseline_mature',
                    'broadcast_ratio', 'meta_window_id', 'meta_device_name',
                ]
                for col in new_cols:
                    val = rows[0].get(col, 'MISSING')
                    print(f"     {col}: {val}")
    else:
        print("❌ CSV file not created")

