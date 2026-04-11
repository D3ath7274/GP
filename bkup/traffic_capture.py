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
import threading
from collections import defaultdict, deque
from datetime import datetime


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
]

NETWORK_COLUMNS = [
    'network_active_flows', 'network_total_pps', 'network_total_bps',
    'network_unique_src_ips', 'network_unique_dst_ips',
    'network_avg_flow_duration', 'network_entropy_src_ip',
    'network_entropy_dst_port',
    'active_snort_alerts', 'distinct_alert_types',
]

LABEL_COLUMNS = [
    'label', 'attack_type', 'snort_sid',
]

ALL_COLUMNS = FLOW_COLUMNS + DEVICE_COLUMNS + NETWORK_COLUMNS + LABEL_COLUMNS


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

        # --- IP to MAC mapping (for block_attacker calls) ---
        self._ip_to_mac = {}  # src_ip -> eth_src MAC address

        # --- Detection Mode ---
        # OFF = capture only (all labels = normal, clean dataset)
        # ON  = full anomaly detection + blocking
        self._detection_enabled = False

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
            # Reset tracking state for fresh detection
            self._attack_confirmations = {}
            self._logged_attackers = set()
            self._log('info', 'Detection mode ENABLED — anomaly detection active')
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
        dst_ip = pkt_info.get('dst_ip', '')
        dst_port = pkt_info.get('dst_port', 0)
        protocol = pkt_info.get('protocol', 'OTHER')
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

        # --- Consecutive-window reset ---
        # If an (src_ip, attack_type) was being tracked but did NOT exceed its
        # threshold this window, reset the consecutive counter (attack stopped).
        detected_this_window = set()
        for src_ip, (label, attack_type, _) in window_attackers.items():
            if label == 2:
                detected_this_window.add((src_ip, attack_type))
        for key in list(self._attack_confirmations.keys()):
            if key not in detected_this_window:
                del self._attack_confirmations[key]

        # Pass 2: Build Rows with Inheritance
        # All flows from an identified attacker in this window will inherit the attack label.
        rows = []
        for flow_key, flow_data, pps, bps, avg_size in flow_metadata:
            src_ip = flow_key[0]
            
            # Use inherited label if IP was identified as attacker in Pass 1
            inherited = window_attackers.get(src_ip)
            
            row = self._build_flow_row(
                flow_key, flow_data, network_ctx, alerts,
                pps, bps, avg_size,
                inherited_label=inherited
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
                        pps, bps, avg_size, inherited_label=None):
        """Build a single CSV row from a flow."""
        src_ip, dst_ip, dst_port, protocol = flow_key
        packets = flow_data['packets']
        first_seen = flow_data['first_seen']
        last_seen = flow_data['last_seen']

        # --- Flow-level features ---
        duration = max(last_seen - first_seen, 0.001)
        total_packets = len(packets)
        sizes = [p[0] for p in packets]
        total_bytes = sum(sizes)
        # pps, bps, avg_size passed from caller for efficiency
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
        }

        # --- Device behavior features ---
        with self._device_lock:
            profile = self._devices.get(src_ip)
            if profile:
                # Get features using historical baseline (pre-update)
                device_features = profile.get_features(pps, bps, avg_size)
            else:
                device_features = {col: 0 for col in DEVICE_COLUMNS}

        # --- Labels ---
        if inherited_label:
            label, attack_type, snort_sid = inherited_label
        else:
            # Fallback (Pass 1 should have caught most)
            label, attack_type, snort_sid = self._compute_label(
                src_ip, dst_ip, alerts, profile, pps, bps, avg_size
            )

        # Update Device Profile statistics (Baseline Integrity)
        with self._device_lock:
            if profile:
                # Only update volume baseline if flow is fully NORMAL
                # This ensures the model learns true normal even if attack is strong.
                if label == 0:
                    profile.update(pps, bps, avg_size, dst_ip, dst_port, protocol)
                else:
                    profile.update_metadata(dst_ip, dst_port, protocol)

        label_features = {
            'label': label,
            'attack_type': attack_type,
            'snort_sid': snort_sid,
        }

        # --- Per-Attack-Type Escalation ---
        # Uses _attack_confirmations which tracks consecutive windows per (src_ip, type).
        # Stage 1: Consecutive windows building up → log "SUSPECTED"
        # Stage 2: Consecutive threshold met → rate-limit DROP (30s)
        # Stage 3: Attack persists beyond rate-limit → full block DROP (120s)

        if label in [1, 2]:
            now = time.time()
            conf_key = (src_ip, attack_type)
            reason = "IDS/Snort" if label == 1 else "Behavioral Anomaly"
            attacker_mac = self._ip_to_mac.get(src_ip, 'unknown')
            required = self.REQUIRED_CONSECUTIVE.get(attack_type, 3)

            if conf_key not in self._attack_confirmations:
                # First window detecting this (src_ip, attack_type) → start tracking
                self._attack_confirmations[conf_key] = {
                    'consecutive': 1,
                    'first_seen': now,
                    'target': dst_ip,
                    'escalated': False,
                    'escalated_time': 0,
                }
                self._log('warning',
                    f"\n[\u26a0] SUSPECTED ATTACK from {src_ip}\n"
                    f"    Suspected : {attack_type}\n"
                    f"    Target    : {dst_ip}\n"
                    f"    Detected via: {reason}\n"
                    f"    Window    : 1/{required} consecutive required\n"
                    f"    Action    : Monitoring only (no block yet)\n"
                )
            else:
                conf = self._attack_confirmations[conf_key]
                # consecutive is incremented in _flush_flows via detected_this_window;
                # here we just handle escalation decisions
                windows = conf['consecutive']
                elapsed = now - conf['first_seen']

                if not conf.get('escalated') and windows >= required:
                    # Consecutive threshold met → Stage 2: rate-limit DROP
                    conf['escalated'] = True
                    conf['escalated_time'] = now
                    self._log('warning',
                        f"\n[\u26d4] ATTACK CONFIRMED — Rate-limiting {src_ip} for {self.RATE_LIMIT_SECONDS}s\n"
                        f"    Attack  : {attack_type}\n"
                        f"    Target  : {dst_ip}\n"
                        f"    Evidence: {windows} consecutive windows in {elapsed:.0f}s\n"
                    )
                    if self.controller and hasattr(self.controller, 'block_attacker'):
                        try:
                            self.controller.block_attacker(
                                src_ip=src_ip,
                                src_mac=attacker_mac,
                                attack_type=attack_type,
                                timeout=self.RATE_LIMIT_SECONDS,
                                detection_time=conf['first_seen'],
                                target_ip=dst_ip,
                                reason='rate-limit',
                            )
                        except Exception as e:
                            self._log('error', f"Failed to install rate-limit rule: {e}")

                elif conf.get('escalated'):
                    rate_limit_elapsed = now - conf.get('escalated_time', now)
                    if rate_limit_elapsed >= self.RATE_LIMIT_SECONDS:
                        # Stage 3: Attack persists beyond rate-limit → full block
                        if conf_key not in self._logged_attackers:
                            self._logged_attackers.add(conf_key)
                            block_duration = 120
                            self._log('warning',
                                f"\n[!] ATTACKER CONFIRMED — {src_ip} persisted beyond rate-limit\n"
                                f"    Type    : {attack_type}\n"
                                f"    Target  : {dst_ip}\n"
                                f"    Evidence: {windows} consecutive windows in {elapsed:.0f}s\n"
                            )
                            if self.controller and hasattr(self.controller, 'block_attacker'):
                                try:
                                    self.controller.block_attacker(
                                        src_ip=src_ip,
                                        src_mac=attacker_mac,
                                        attack_type=attack_type,
                                        timeout=block_duration,
                                        detection_time=conf['first_seen'],
                                        target_ip=dst_ip,
                                        reason='block',
                                    )
                                except Exception as e:
                                    self._log('error', f"Failed to install block rule: {e}")
                # else: below consecutive threshold, still monitoring

        # Merge all features
        row = {}
        row.update(flow_features)
        row.update(device_features)
        row.update(network_ctx)
        row.update(label_features)
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
        }

    def _compute_label(self, src_ip, dst_ip, alerts, device_profile, 
                       curr_pps=0, curr_bps=0, curr_avg_size=0, protocol='OTHER',
                       host_counters=None):
        """
        Determine the label for a flow.
          0 = normal
          1 = known attack (Snort/DAI alert matches this flow's IPs)
          2 = suspicious behavioral deviation (confirmed by consecutive windows)

        When detection is OFF: all labels = 0 (clean dataset capture).
        When detection is ON: the system decides the label based on
          rate counters, context guards, and consecutive-window confirmation.
        """
        # --- 1. Detection Mode Gate ---
        if not self._detection_enabled:
            return 0, 'normal', ''

        # --- 2. Known Attacks (Snort + DAI) — always authoritative ---
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

            # ICMP Flood: >150 ICMP packets from one host in 5 seconds
            # (pingall with 20 hosts ≈ 20/window; genuine flood = thousands)
            if icmp > 150:
                detected_type = 'ICMP Flood'

            # SYN Flood: >80 SYN-only packets AND low ACK count
            # Context guard: if host also sends many ACKs, it's completing
            # TCP handshakes (e.g., iperf, web crawl) → NOT a flood
            elif syn > 80 and ack < 20:
                detected_type = 'SYN Flood'

            # UDP Flood: >300 UDP packets from one host in 5 seconds
            # (IoT telemetry bursts ≈ 50–100; DNS queries ≈ 10–20)
            elif udp > 300:
                detected_type = 'UDP Flood'

            # Port Scan: >30 unique destination ports from one host in 5 seconds
            # (service discovery ≈ 3–5 ports; nmap = 100+)
            elif ports > 30:
                detected_type = 'Port Scan'

        # --- 4. Consecutive-Window Confirmation ---
        # A single window exceeding the threshold is NOT enough to label as attack.
        # The anomaly must persist for N consecutive windows to be confirmed.
        if detected_type:
            conf_key = (src_ip, detected_type)
            required = self.REQUIRED_CONSECUTIVE.get(detected_type, 3)

            if conf_key not in self._attack_confirmations:
                # First window — start counting but label as suspicious
                self._attack_confirmations[conf_key] = {
                    'consecutive': 1,
                    'first_seen': time.time(),
                    'target': dst_ip,
                    'escalated': False,
                    'escalated_time': 0,
                }
                # Detection ON: label=2 so dataset captures the anomaly,
                # but escalation won't fire until consecutive threshold is met
                return 2, detected_type, ''
            else:
                conf = self._attack_confirmations[conf_key]
                conf['consecutive'] += 1
                # Always label=2 when detection is ON and counter exceeded
                return 2, detected_type, ''

        # --- 5. Z-Score Behavioral Analysis (Secondary / Fallback) ---
        # ONLY used when rate counters didn't detect anything, for patterns
        # that rate counters don't cover (payload anomaly, host sweep).
        if not device_profile:
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

        # Volumetric spike — but ONLY if rate counters didn't already clear this protocol.
        if pkt_dev > Z_THRESHOLD or byte_dev > Z_THRESHOLD:
            if not host_counters:
                # No rate counters available — fall back to Z-score
                if proto_upper == 'ICMP':
                    return 2, 'ICMP Flood', ''
                elif proto_upper == 'UDP':
                    return 2, 'UDP Flood', ''
                elif proto_upper == 'TCP':
                    return 2, 'SYN Flood', ''
            # else: rate counters checked and cleared — trust them

        # Payload anomaly (not covered by rate counters)
        if payload_dev > Z_THRESHOLD:
            return 2, 'UDP Flood', ''

        # Host sweep (not covered by rate counters)
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
    print("  Traffic Capture Module — Standalone Test")
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
            print(f"   Normal:  {sum(1 for r in rows if r['label'] == '0')}")
            print(f"   Attack:  {sum(1 for r in rows if r['label'] == '1')}")
            print(f"   Suspicious: {sum(1 for r in rows if r['label'] == '2')}")
            print(f"\n   Sample row:")
            if rows:
                for k, v in rows[0].items():
                    print(f"     {k}: {v}")
    else:
        print("❌ CSV file not created")
