# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib import hub  # eventlet hub primitives (spawn/sleep) — for the block worker
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp  # Added
from ryu.lib.packet import icmp # Added
from ryu.lib.packet import arp as arp_lib  # ARP Spoofing Detection

# Snort 3 IDS Integration + Traffic Mirroring
import os
import sys
import time
import threading
import queue as _queue_lib  # thread-safe handoff queue (block requests -> hub greenlet)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snort_monitor import SnortManager
from traffic_mirror import TrafficMirror
from traffic_capture import TrafficCapture  # Added
from ml_inference import MLInferenceEngine  # ML Inference Engine (RF, Tier 3)
from ae_inference import AEInferenceEngine  # Autoencoder anomaly engine (Tier 4)

# REST API (merged from ryu_ips_app.py) — exposes /ips/block etc. on :8080 so an
# external Snort flow (snort_alert_reader.py -> snort_ryu_bridge.py) can push IP
# blocks while the team Snort/rate/RF/AE tiers run at the same time.
import json
import ipaddress
import socket as _socket_lib
import struct as _struct_lib
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

IPS_INSTANCE_NAME = 'controller_main_ips'


# =============================================================================
# COLLECTION_MODE: Set to True during dataset collection.
# When True, rate limiting / active blocking is bypassed so that ground-truth
# attack features are recorded at full intensity. A clipped flood produces
# corrupted feature values — the model would learn the threshold, not the attack.
# Set to False ONLY after dataset_training.csv is finalized and the system
# moves into live detection / deployment.
# =============================================================================
COLLECTION_MODE = True


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    # WSGI context (merged from ryu_ips_app.py): ryu-manager starts the REST
    # server on :8080 and passes the wsgi app in kwargs.
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self._datapaths = {}   # dpid -> datapath (for sending flow mods outside packet_in)
        self._blocked_ips = {} # ip -> {'mac':, 'until':, 'attack_type':}
        # REST-API blocks (merged from ryu_ips_app.py), tracked separately from the
        # MAC-based tier blocks above. The WSGI REST server runs on :8080.
        self._rest_blocked_ips = {}  # ip -> {'reason':, 'mode': 'mac'|'ip', ...}
        _wsgi = kwargs.get('wsgi')
        if _wsgi is not None:
            _wsgi.register(IPSRestController, {IPS_INSTANCE_NAME: self})
            self.logger.info(
                "REST IPS API on :8080  (POST /ips/block, DELETE /ips/block/<ip>, "
                "GET /ips/blocked, /ips/switches, /ips/status)")

        # ===================================================================
        # Traffic Mirroring: All data-plane traffic (10.0.0.x + 192.168.1.x)
        # is mirrored to the controller via OpenFlow and injected into a TAP
        # so Snort can detect malicious behavior. Prepares for ML anomaly detection.
        # ===================================================================
        self._physical_interface = os.environ.get('SNORT_PHYS_IFACE', 'ens33')
        self._tap_name = 'snort_tap'

        # Two mirror options for feeding Snort:
        #   (a) OpenFlow TAP (default): packets are injected into snort_tap here.
        #   (b) VXLAN br-snort bridge (install runbook): OVS mirrors s1/ap1 over VXLAN
        #       to the controller's br-snort; the TAP is then redundant.
        # Pick (b) on the static-IP / t530 deployment with:
        #   SNORT_IFACES=ens33,br-snort  IPS_NO_TAP=1
        # SNORT_IFACES overrides the monitored interface list; IPS_NO_TAP=1 disables
        # the in-process TAP mirror (avoids double-feeding Snort). Defaults preserve
        # the original TAP behavior.
        _use_tap = os.environ.get('IPS_NO_TAP', '0') != '1'
        _ifaces_env = os.environ.get('SNORT_IFACES', '').strip()
        if _use_tap:
            self.traffic_mirror = TrafficMirror(tap_name=self._tap_name, logger=self.logger)
            mirror_ok = self.traffic_mirror.start()
        else:
            self.traffic_mirror = None
            mirror_ok = False

        if _ifaces_env:
            snort_ifaces = [s.strip() for s in _ifaces_env.split(',') if s.strip()]
        else:
            snort_ifaces = ([self._physical_interface, self._tap_name] if mirror_ok
                            else [self._physical_interface])

        # Snort 3 (sdn_ips.lua + alert_json). With the VXLAN bridge, br-snort carries
        # the mirrored 10.0.0.x data plane; otherwise snort_tap does (via OpenFlow).
        self.snort_manager = SnortManager(
            interfaces=snort_ifaces,
            config_path='/etc/snort/sdn_ips.lua',
            log_dir='/var/log/snort',
            logger=self.logger,
            on_alert=self._handle_snort_alert
        )
        snort_started = self.snort_manager.start_snort()
        if snort_started:
            self.snort_manager.start_monitoring()
        else:
            self.logger.error(
                "Snort IDS failed to start! Install the curated config first: "
                "sudo ./scripts/install_snort3_ips_config.sh. "
                "Controller will continue without IDS."
            )

        # Traffic Capture Module for ML Dataset Generation
        self.traffic_capture = TrafficCapture(
            output_path='dataset.csv',
            window_seconds=5.0,
            snort_manager=self.snort_manager,
            controller=self,  # Pass controller for IoT/Gateway context
            logger=self.logger
        )
        self.traffic_capture.start()

        # IoT configuration
        # Vendor/OUI prefixes (lowercase) commonly used by IoT devices.
        self.iot_mac_prefixes = ['00:11:22', 'aa:bb:cc']
        # Excluded prefixes: Mininet-wifi, virtual interfaces, known non-IoT.
        self.iot_exclude_prefixes = [
            '42:00:00', '0a:f7:8a', '16:ca:de', '3a:10:75', '92:01:13', 'ba:e2:67', 'aa:45:c7',
            '00:00:00', # Standard Mininet stations
            '32:46:1b', '2e:d7:13'  # Generic virtual interfaces
        ]
        
        # Tracking set to prevent log flooding (discovery only logged once per session)
        self.discovery_logged_macs = set()
        # Explicit IoT device MAC -> type mapping (example):
        # {'00:11:22:33:44:55': 'home_sensor'}
        self.iot_devices = {}
        # IoT devices registered explicitly by IP via REGISTER:IOT:<ip>:<type>.
        # Keyed by IP because the UDP registration carries the device IP (not its
        # MAC), and traffic_capture profiles devices by IP. Used to set
        # is_registered_iot reliably even when the device's OUI is unknown.
        self.iot_registered_ips = {}
        # IoT gateway mapping per switch datapath id: { dpid: {'port': <port_no>, 'mac': '<mac>'} }
        # Populate this mapping to route unknown IoT device traffic to a gateway port.
        self.iot_gateways = {}
        # Gateway OUI prefixes for automatic gateway detection.
        # Common gateways: Zigbee hubs, Thread borders, LoRaWAN gateways, Bluetooth mesh, etc.
        self.gateway_mac_prefixes = [
            '00:0d:6f',  # Philips Hue Bridge
            '00:21:4b',  # Lutron
            '00:25:86',  # Xia Xiaomi (Zigbee Gateway)
            'f0:fe:6b',  # IKEA TRADFRI Gateway (Zigbee)
            '5c:f3:70',  # Sonos
            '00:0a:95',  # Cisco
        ]
        # Discovered gateways: { 'mac': {'dpid': <id>, 'port': <port>, 'first_seen': <timestamp>} }
        self.discovered_gateways = {}

        # ===================================================================
        # ARP Spoofing Detection (SDN equivalent of Dynamic ARP Inspection)
        # ===================================================================
        # Binding table: IP -> {'mac': <first_seen_mac>, 'dpid': <dpid>, 'port': <port>}
        self._arp_bindings = {}
        self._arp_spoof_logged = set()  # (attacker_mac, victim_ip) — log once per pair

        # ===================================================================
        # Dynamic Device Names — learned from traffic (registration, DHCP, etc.)
        # ===================================================================
        self._discovered_names = {}  # IP -> device name (populated dynamically)

        # ===================================================================
        # Detection Mode Toggle
        # ===================================================================
        # OFF = capture traffic normally, label everything as 'normal' (clean dataset)
        # ON  = full anomaly detection + blocking active
        self._detection_enabled = False

        # ===================================================================
        # ML Inference Engine
        # ===================================================================
        # Loads trained models from ml_models/ for real-time classification.
        # Three authorization modes:
        #   OFF       — ML disabled (dataset collection mode)
        #   OBSERVE   — ML predicts + logs, NO blocking (verify accuracy first)
        #   AUTHORIZE — ML predicts + blocks via OpenFlow DROP if confidence ≥ threshold
        self._ml_mode = 'OFF'  # Start in OFF mode; switch via CONTROL:ML:OBSERVE/AUTHORIZE
        # Two-band confidence policy (RF):
        #   conf >= block threshold  -> attack; AUTHORIZE blocks (single window)
        #   flag <= conf < block     -> flag + capture evidence (.pcap/csv/txt), no block
        #   conf < flag threshold    -> no action
        self._ml_block_threshold = 0.90   # set via CONTROL:ML:AUTHORIZE:<thr>
        self._ml_flag_threshold = 0.80
        # Autoencoder (Tier 4) confidence bands — runs CONCURRENTLY with the RF.
        #   conf >= ae_block -> anomaly (block in AUTHORIZE); ae_flag <= conf < ae_block -> flag
        #   conf < ae_flag   -> silent.  (AE blocks lower than RF: it is the zero-day net.)
        self._ae_block_threshold = 0.73
        self._ae_flag_threshold = 0.60
        # src_ip -> expiry; dedups the instant Snort-alert blocker (Snort fires
        # per-packet, so block a source at most once per DROP-timeout window).
        self._snort_blocked = {}

        # ===================================================================
        # Block handoff queue (fixes the AUTHORIZE hang)
        # ===================================================================
        # OpenFlow I/O (datapath.send_msg) lives in the eventlet hub on the MAIN
        # thread. But block_attacker() is invoked from OFF-hub OS threads — the
        # 5s feature-flush thread (RF/AE/rate tiers in traffic_capture.py) and the
        # Snort monitor thread. Calling send_msg from those threads operates the
        # hub's GREEN send queue cross-thread and deadlocks the whole controller
        # (the symptom: it hangs the instant AUTHORIZE first crosses a block band;
        # OBSERVE never blocks, so it never hung). Fix: off-hub callers ENQUEUE a
        # block request here (queue.Queue.put is OS-thread-safe) and a hub greenlet
        # (_block_worker) performs the actual send_msg ON the hub thread.
        self._block_q = _queue_lib.Queue()
        self._block_worker_gt = hub.spawn(self._block_worker)
        ml_model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ml_models')
        if os.path.isdir(ml_model_dir):
            self._ml_engine = MLInferenceEngine(ml_model_dir, logger=self.logger)
            # AE (Tier 4): loads ae_bundle.joblib if present, else disables gracefully.
            self._ae_engine = AEInferenceEngine(ml_model_dir, logger=self.logger)
        else:
            self._ml_engine = None
            self._ae_engine = None
            self.logger.warning(
                "ml_models/ directory not found at %s — ML inference disabled. "
                "Place rf_model.joblib in this directory to enable it.", ml_model_dir
            )

        self.logger.info(
            "\n"
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  🛡 DETECTION MODE: OFF (Capture Only)                    ║\n"
            "║  Traffic is being recorded. All labels = normal.        ║\n"
            "║  Send CONTROL:DETECT:ON to enable attack detection.     ║\n"
            "║  Send CONTROL:ML:OBSERVE to enable ML (log only).       ║\n"
            "║  Send CONTROL:ML:AUTHORIZE:0.80 to enable ML blocking.  ║\n"
            "╚══════════════════════════════════════════════════════════╝"
        )

        # ===================================================================
        # UDP Command Listener (receives commands over the physical network)
        # ===================================================================
        # Mininet hosts (10.0.0.x) cannot route to the controller (192.168.1.x),
        # so the topology VM sends CONTROL/REGISTER commands directly to the
        # controller's physical IP on UDP port 9999.
        import socket as _socket
        self._udp_sock = None
        try:
            self._udp_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            self._udp_sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            self._udp_sock.bind(('0.0.0.0', 9999))
            self._udp_listener = threading.Thread(
                target=self._udp_command_listener,
                name='UDPCommandListener',
                daemon=True,
            )
            self._udp_listener.start()
            self.logger.info("UDP command listener started on port 9999")
        except Exception as e:
            self.logger.warning("UDP listener failed to start: %s (commands via OpenFlow only)", e)

    # ===================================================================
    # Snort IDS Alert Handler
    # ===================================================================
    def _handle_snort_alert(self, alert):
        """
        Called by SnortManager for each new Snort alert.
        Forwards the alert to TrafficCapture for CSV flow labeling.

        NOTE: Console logging is handled by snort_monitor.py with
        rate-limited deduplication (same SID+src logs at most once/30s).
        Do NOT add logging here — it would bypass deduplication and
        flood the terminal during attacks (200K+ alerts/sec).
        """
        # Forward alert to traffic capture for labeling anomalous flows
        if hasattr(self, 'traffic_capture') and self.traffic_capture:
            self.traffic_capture.record_alert(alert)

            # Fast-tier mitigation: INSTANT block on a CANONICAL Snort alert in
            # AUTHORIZE mode. Snort fires sub-second on the packet stream — the only
            # truly real-time tier. Guards: only canonical attack classes (filters
            # BAD-TRAFFIC/MISC/SNMP noise and victim-response SIDs), and at most once
            # per source per DROP-timeout window (Snort fires per-packet).
            if getattr(self, '_ml_mode', 'OFF') == 'AUTHORIZE':
                atype = alert.get('attack_type', '')
                src = alert.get('src_ip', '')
                if src and atype in getattr(self.traffic_capture, 'CANONICAL_ATTACKS', set()):
                    now = time.time()
                    if now >= self._snort_blocked.get(src, 0):
                        mac = self.traffic_capture._ip_to_mac.get(src, '')
                        if mac:
                            try:
                                self.block_attacker(
                                    src_ip=src, src_mac=mac, attack_type=atype,
                                    timeout=30, detection_time=now,
                                    target_ip=alert.get('dst_ip', ''),
                                    reason=f"snort-{alert.get('sid', '?')}")
                                self._snort_blocked[src] = now + 30
                                self.logger.warning(
                                    "[SNORT] BLOCKED %s (%s) — instant signature match",
                                    src, atype)
                            except Exception as e:
                                self.logger.error("Snort block_attacker failed: %s", e)

    def close(self):
        """Clean up: stop Snort, traffic mirror, and UDP listener when the controller shuts down."""
        self.logger.info("Controller shutting down — stopping Snort IDS...")
        self.snort_manager.stop_snort()
        if hasattr(self, 'traffic_capture') and self.traffic_capture:
            self.traffic_capture.stop()
        if hasattr(self, 'traffic_mirror') and self.traffic_mirror:
            self.traffic_mirror.stop()
        if hasattr(self, '_udp_sock') and self._udp_sock:
            try:
                self._udp_sock.close()
            except Exception:
                pass
        super(SimpleSwitch, self).close()

    # ===================================================================
    # UDP Command Listener (direct physical network commands)
    # ===================================================================
    def _udp_command_listener(self):
        """
        Listen on UDP port 9999 for CONTROL and REGISTER commands sent
        directly over the physical network from the topology VM.
        """
        self.logger.info("UDP command listener running on 0.0.0.0:9999")
        while True:
            try:
                data, addr = self._udp_sock.recvfrom(4096)
                message = data.decode('utf-8', errors='ignore').strip()
                sender_ip = addr[0]
                self.logger.info("UDP command received from %s: %s", sender_ip, message)

                if message.startswith("CONTROL:"):
                    parts = message.split(':')
                    if len(parts) >= 3 and parts[1] == 'DETECT':
                        mode = parts[2].strip().upper()
                        if mode == 'ON':
                            self._detection_enabled = True
                            if hasattr(self, 'traffic_capture') and self.traffic_capture:
                                self.traffic_capture.set_detection_mode(True)
                            self.logger.warning(
                                "\n"
                                "╔══════════════════════════════════════════════════════════╗\n"
                                "║  🚨 DETECTION MODE: ON                                    ║\n"
                                "║  Anomaly detection + blocking ACTIVE.                   ║\n"
                                "║  Attacks will be detected and blocked.                  ║\n"
                                "╚══════════════════════════════════════════════════════════╝"
                            )
                        elif mode == 'OFF':
                            self._detection_enabled = False
                            if hasattr(self, 'traffic_capture') and self.traffic_capture:
                                self.traffic_capture.set_detection_mode(False)
                    elif len(parts) >= 2 and parts[1] == 'CLEAR':
                        # CONTROL:CLEAR or CONTROL:CLEAR:<ip>
                        # DATA-COLLECTION reset: release a source's confirmed/
                        # suspicion state (no cooldown) so its benign background is
                        # not labelled as the attack after it stops. The collection
                        # harness sends this between attacks. NOT a production action
                        # (production keeps attackers locked until admin UNBLOCK).
                        clear_ip = parts[2].strip() if len(parts) >= 3 and parts[2].strip() else None
                        if hasattr(self, 'traffic_capture') and self.traffic_capture:
                            # 30 s drain-suppression cooldown for a per-IP clear so the
                            # post-ATTACK_STOP control-channel backlog cannot re-confirm
                            # the released source (which would then mislabel its later
                            # traffic for the rest of the session). No cooldown on a
                            # full (no-IP) reset.
                            self.traffic_capture.clear_detection_state(
                                clear_ip, cooldown=30 if clear_ip else 0)
                    elif len(parts) >= 3 and parts[1] == 'ROTATE':
                        # CONTROL:ROTATE:<filename>[:<ExpectedAttackType>]
                        # Save the current dataset.csv under <filename>, start a fresh
                        # file, then best-effort validate it and log the verdict. Used
                        # by the automated collection harness between sessions.
                        # Filenames starting with '_' are discards (no validation).
                        fname = parts[2].strip()
                        expect = parts[3].strip() if len(parts) >= 4 else ''
                        if hasattr(self, 'traffic_capture') and self.traffic_capture and fname:
                            saved = self.traffic_capture.rotate(fname)
                            if saved >= 0 and not fname.startswith('_'):
                                try:
                                    import subprocess
                                    here = os.path.dirname(os.path.abspath(__file__))
                                    cmd = ['python3', os.path.join(here, 'validate_dataset.py'), fname]
                                    if expect:
                                        cmd.append(expect)
                                    # inherit the process cwd (where dataset.csv / the
                                    # rotated session files live)
                                    r = subprocess.run(cmd, capture_output=True,
                                                       text=True, timeout=180)
                                    verdict = 'PASS ✅' if r.returncode == 0 else 'ISSUES ❌'
                                    self.logger.warning("[COLLECT] %s validation → %s", fname, verdict)
                                    for ln in r.stdout.splitlines():
                                        if any(k in ln for k in ('RESULT', 'rows=', 'launched from',
                                                                  'RATE BLEED', 'PROTO MISMATCH',
                                                                  'NOTE:', '  - ')):
                                            self.logger.info("    %s", ln.rstrip())
                                except Exception as e:
                                    self.logger.error("[COLLECT] validation failed for %s: %s",
                                                      fname, e)
                    elif len(parts) >= 3 and parts[1] == 'UNBLOCK':
                        target_ip = parts[2].strip()
                        if hasattr(self, 'traffic_capture') and self.traffic_capture:
                            self.traffic_capture.manual_unblock(target_ip)
                            self.logger.info("ADMIN: Unblocked attacker %s", target_ip)
                            self.logger.warning(
                                "\n"
                                "╔══════════════════════════════════════════════════════════╗\n"
                                "║  🛡 DETECTION MODE: OFF (Capture Only)                    ║\n"
                                "║  Traffic is being recorded. All labels = normal.        ║\n"
                                "╚══════════════════════════════════════════════════════════╝"
                            )
                    elif len(parts) >= 3 and parts[1] == 'ML':
                        # -------------------------------------------------------
                        # ML Authorization Control
                        # CONTROL:ML:OFF       — disable ML inference
                        # CONTROL:ML:OBSERVE   — ML predicts + logs, no blocking
                        # CONTROL:ML:AUTHORIZE — ML predicts + blocks attackers
                        # CONTROL:ML:AUTHORIZE:0.80 — with custom threshold
                        # -------------------------------------------------------
                        ml_cmd = parts[2].strip().upper()
                        if ml_cmd == 'OFF':
                            self._ml_mode = 'OFF'
                            self.logger.warning(
                                "\n"
                                "╔══════════════════════════════════════════════════════════╗\n"
                                "║  🤖 ML MODE: OFF                                         ║\n"
                                "║  ML inference disabled. Rate counters still active.     ║\n"
                                "╚══════════════════════════════════════════════════════════╝"
                            )
                        elif ml_cmd == 'OBSERVE':
                            self._ml_mode = 'OBSERVE'
                            self.logger.warning(
                                "\n"
                                "╔══════════════════════════════════════════════════════════╗\n"
                                "║  🤖 ML MODE: OBSERVE                                     ║\n"
                                "║  ML predicts + logs every flow. NO blocking.            ║\n"
                                "║  Watch output to verify accuracy before authorizing.    ║\n"
                                "╚══════════════════════════════════════════════════════════╝"
                            )
                        elif ml_cmd == 'AUTHORIZE':
                            self._ml_mode = 'AUTHORIZE'
                            if len(parts) >= 4:
                                try:
                                    self._ml_block_threshold = float(parts[3])
                                except ValueError:
                                    pass
                            self.logger.warning(
                                "\n"
                                "╔══════════════════════════════════════════════════════════╗\n"
                                "║  🤖 ML MODE: AUTHORIZE                                   ║\n"
                                "║  ML predicts + BLOCKS attackers via OpenFlow DROP.      ║\n"
                                "║  Confidence threshold: %-33s ║\n"
                                "║  ⚠  AI is now authorized to block network devices.      ║\n"
                                "╚══════════════════════════════════════════════════════════╝",
                                f"{self._ml_block_threshold:.2f}"
                            )
                        elif ml_cmd == 'STATS':
                            # CONTROL:ML:STATS — print inference statistics
                            if self._ml_engine and self._ml_engine.is_loaded:
                                stats = self._ml_engine.get_stats()
                                self.logger.info(
                                    "ML Stats: %d predictions, %d attacks detected, "
                                    "avg %.2fms/prediction",
                                    stats['total_predictions'],
                                    stats['total_attacks_detected'],
                                    stats['avg_inference_ms']
                                )
                            else:
                                self.logger.warning("ML engine not loaded")
                        elif ml_cmd == 'FLAG' and len(parts) >= 4:
                            # CONTROL:ML:FLAG:<thr> — tune the flag (evidence) threshold live
                            try:
                                self._ml_flag_threshold = float(parts[3])
                                self.logger.warning("ML flag threshold set to %.2f",
                                                    self._ml_flag_threshold)
                            except ValueError:
                                pass
                        elif ml_cmd == 'BLOCK' and len(parts) >= 4:
                            # CONTROL:ML:BLOCK:<thr> — tune the block threshold live
                            try:
                                self._ml_block_threshold = float(parts[3])
                                self.logger.warning("ML block threshold set to %.2f",
                                                    self._ml_block_threshold)
                            except ValueError:
                                pass

                elif message.startswith("LABEL_OVERRIDE:"):
                    # Format: LABEL_OVERRIDE:ip:attack_type
                    # e.g. LABEL_OVERRIDE:10.0.0.3:Port Scan
                    # Clear: LABEL_OVERRIDE:10.0.0.3:clear
                    parts = message.split(':', 2)
                    if len(parts) >= 3:
                        target_ip = parts[1].strip()
                        attack_type = parts[2].strip()
                        if hasattr(self, 'traffic_capture') and self.traffic_capture:
                            self.traffic_capture.set_label_override(target_ip, attack_type)
                            self.logger.warning(
                                "LABEL_OVERRIDE: %s → %s", target_ip, attack_type
                            )

                elif message.startswith("ATTACK_START:"):
                    # Format: ATTACK_START:tool_name:intensity
                    # e.g. ATTACK_START:hping3:flood
                    parts = message.split(':', 2)
                    tool = parts[1].strip() if len(parts) >= 2 else 'unknown'
                    intensity = parts[2].strip() if len(parts) >= 3 else '0'
                    if hasattr(self, 'traffic_capture') and self.traffic_capture:
                        self.traffic_capture.set_attack_metadata(tool, intensity)
                    self.logger.warning("META: Attack started — tool=%s, intensity=%s", tool, intensity)

                elif message == "ATTACK_STOP" or message.startswith("ATTACK_STOP"):
                    if hasattr(self, 'traffic_capture') and self.traffic_capture:
                        self.traffic_capture.clear_attack_metadata()
                    self.logger.warning("META: Attack stopped")

                elif message.startswith("MININET_EVENT:"):
                    # Format: MININET_EVENT:event_name
                    # e.g. MININET_EVENT:pingall or MININET_EVENT:normal
                    parts = message.split(':', 1)
                    event = parts[1].strip() if len(parts) >= 2 else 'normal'
                    if hasattr(self, 'traffic_capture') and self.traffic_capture:
                        self.traffic_capture.set_mininet_event(event)
                    self.logger.info("META: Mininet event set to '%s'", event)

                elif message.startswith("REGISTER:"):
                    try:
                        _, type_str, info = message.split(':', 2)
                        if type_str == 'NAME':
                            # Format: REGISTER:NAME:hostname:ip
                            # e.g. REGISTER:NAME:h1:10.0.0.3
                            if ':' in info:
                                hostname, host_ip = info.rsplit(':', 1)
                                self._discovered_names[host_ip] = hostname.strip()
                                self.logger.info("Registered hostname (UDP): %s → %s", host_ip, hostname.strip())
                            else:
                                self.logger.info("REGISTER:NAME received but no IP: %s", info)
                        elif type_str == 'IOT':
                            # New format: REGISTER:IOT:<ip>:<device_type>
                            #   e.g. REGISTER:IOT:10.0.0.5:IOT:TempSensor
                            # Register the device as IoT by IP so is_registered_iot
                            # is set reliably regardless of its MAC OUI. Falls back
                            # to log-only for the legacy (no-IP) form.
                            first, sep, rest = info.partition(':')
                            if sep and first.count('.') == 3:   # looks like an IPv4
                                iot_ip = first.strip()
                                iot_type = rest.strip() or 'IOT'
                                self.iot_registered_ips[iot_ip] = iot_type
                                self.logger.info("IoT registered by IP: %s → %s", iot_ip, iot_type)
                            else:
                                self.logger.info("IoT registration via UDP from %s: %s "
                                                 "(no IP — is_registered_iot will not be set; "
                                                 "use REGISTER:IOT:<ip>:<type>)", sender_ip, info)
                    except ValueError:
                        pass

            except OSError:
                break  # Socket closed
            except Exception as e:
                self.logger.error("UDP listener error: %s", e)

    # ===================================================================
    # REST API block helpers (merged from ryu_ips_app.py)
    # ===================================================================
    # External tools (the friend's snort_alert_reader.py -> snort_ryu_bridge.py,
    # or any HTTP client) POST {"src_ip": ...} to /ips/block. We resolve the MAC
    # and reuse the proven MAC-based block_attacker() (OpenFlow 1.0 dl_src DROP);
    # if the MAC is unknown we fall back to an IP-based (nw_src) OF 1.0 DROP.
    # These run ALONGSIDE the controller's own Snort/rate/RF/AE tiers.
    @staticmethod
    def _ip_to_int(ip_str):
        return _struct_lib.unpack('!I', _socket_lib.inet_aton(ip_str))[0]

    def _resolve_mac(self, ip):
        """Best-effort IP -> MAC from the controller's learned mappings."""
        mac = ''
        if hasattr(self, 'traffic_capture') and self.traffic_capture:
            mac = getattr(self.traffic_capture, '_ip_to_mac', {}).get(ip, '')
        if not mac and ip in self._arp_bindings:
            mac = self._arp_bindings[ip].get('mac', '')
        return mac

    def rest_block_ip(self, src_ip, reason='', idle_timeout=0, hard_timeout=600):
        """Block a source IP via the REST API. Returns a JSON-able dict."""
        try:
            ipaddress.ip_address(src_ip)
        except ValueError:
            return {'status': 'error', 'message': f'Invalid IP: {src_ip}'}
        if not self._datapaths:
            return {'status': 'error', 'message': 'No switches connected'}

        mac = self._resolve_mac(src_ip)
        if mac:
            try:
                # REST runs on the hub thread (WSGI greenlet) and must return a
                # synchronous status, so call the real installer directly — safe here.
                self._do_block_attacker(
                    src_ip=src_ip, src_mac=mac, attack_type='REST/Snort',
                    timeout=hard_timeout or 600, detection_time=time.time(),
                    target_ip='', reason=reason or 'rest-api')
                self._rest_blocked_ips[src_ip] = {'reason': reason, 'mac': mac, 'mode': 'mac'}
                return {'status': 'blocked', 'src_ip': src_ip, 'mac': mac,
                        'mode': 'mac', 'reason': reason}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}

        # MAC unknown -> IP-based OF 1.0 DROP (dl_type=IP, nw_src=<ip>)
        pushed = []
        for dpid, datapath in self._datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(dl_type=0x0800, nw_src=self._ip_to_int(src_ip))
            mod = parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=idle_timeout,
                hard_timeout=hard_timeout, priority=64000,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=[])  # [] = DROP
            datapath.send_msg(mod)
            pushed.append(str(dpid))
        self._rest_blocked_ips[src_ip] = {'reason': reason, 'mode': 'ip', 'switches': pushed}
        self.logger.warning("[REST-IPS] DROP %s (IP-match) on %d switch(es) | %s",
                            src_ip, len(pushed), reason)
        return {'status': 'blocked', 'src_ip': src_ip, 'mode': 'ip',
                'reason': reason, 'switches': pushed}

    def rest_unblock_ip(self, src_ip):
        """Remove a REST/tier block for src_ip (both MAC- and IP-based DROPs)."""
        info = self._rest_blocked_ips.pop(src_ip, None)
        # MAC-based unblock (deletes the dl_src DROP installed by block_attacker)
        if hasattr(self, 'traffic_capture') and self.traffic_capture:
            try:
                self.traffic_capture.manual_unblock(src_ip)
            except Exception:
                pass
        self._blocked_ips.pop(src_ip, None)
        # IP-based DROP cleanup (fallback rules)
        for dpid, datapath in self._datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(dl_type=0x0800, nw_src=self._ip_to_int(src_ip))
            mod = parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_NONE, priority=64000)
            datapath.send_msg(mod)
        self.logger.info("[REST-IPS] Unblocked %s", src_ip)
        return {'status': 'unblocked' if info else 'cleared', 'src_ip': src_ip}

    def get_blocked_list(self):
        """All currently blocked sources (REST + tier)."""
        out = [{'ip': ip, 'kind': 'rest', **info} for ip, info in self._rest_blocked_ips.items()]
        out += [{'ip': ip, 'kind': 'tier', **info} for ip, info in self._blocked_ips.items()]
        return out

    # ===================================================================
    # Attacker Blocking (OpenFlow DROP Rule)
    # ===================================================================
    def block_attacker(self, src_ip, src_mac, attack_type, timeout,
                       detection_time=None, target_ip='', reason=''):
        """Thread-safe entry point: ENQUEUE a block so the actual OpenFlow
        send_msg runs on the eventlet hub thread (see _block_worker).

        Callable from ANY thread — the RF/AE/rate tiers (flush thread) and the
        Snort monitor thread all reach this. NEVER calls send_msg here; doing so
        off the hub thread deadlocks the controller (the AUTHORIZE-mode hang).
        The REST path is already on the hub thread and calls _do_block_attacker
        directly for a synchronous result.
        """
        now = time.time()
        # Dedup: skip if this IP already has an unexpired block (prevents the queue
        # from filling with repeats for the same attacker across flood windows, and
        # avoids redundant rule re-installs on the weak t530). A provisional marker
        # is set immediately so concurrent windows see the block before the worker
        # installs it; _do_block_attacker overwrites it with the full record.
        existing = self._blocked_ips.get(src_ip)
        if existing and existing.get('until', 0) > now:
            return
        self._blocked_ips[src_ip] = {
            'mac': src_mac, 'until': now + timeout, 'attack_type': attack_type,
        }
        self._block_q.put({
            'src_ip': src_ip, 'src_mac': src_mac, 'attack_type': attack_type,
            'timeout': timeout, 'detection_time': detection_time,
            'target_ip': target_ip, 'reason': reason,
        })

    def _block_worker(self):
        """Hub greenlet: drain the block queue and install DROP rules ON the hub
        thread (where datapath.send_msg is safe). Polls the OS-thread-safe queue
        non-blockingly and yields cooperatively so the hub keeps serving OpenFlow,
        the REST API, and the UDP control listener."""
        while True:
            try:
                while True:
                    req = self._block_q.get_nowait()
                    try:
                        self._do_block_attacker(**req)
                    except Exception as e:
                        self.logger.error("block worker: _do_block_attacker failed: %s", e)
            except _queue_lib.Empty:
                pass
            hub.sleep(0.05)

    def _do_block_attacker(self, src_ip, src_mac, attack_type, timeout,
                           detection_time=None, target_ip='', reason=''):
        """
        Install a high-priority OpenFlow DROP rule for an attacker.
        MUST run on the eventlet hub thread (via _block_worker or the REST path).

        Args:
            src_ip: Attacker's IP address
            src_mac: Attacker's MAC address
            attack_type: Type of attack detected
            timeout: hard_timeout in seconds for the DROP rule
            detection_time: timestamp when attack was first detected
            target_ip: Target of the attack
            reason: 'rate-limit' or 'block'
        """
        import datetime
        now = time.time()
        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        latency = (now - detection_time) if detection_time else 0.0

        # Resolve device name: discovered names → IoT registry → gateways → Host IP
        device_name = self._discovered_names.get(src_ip, None)
        mac_lower = src_mac.lower() if src_mac else ''
        if not device_name:
            for mac_key, info in self.iot_devices.items():
                if mac_key.lower() == mac_lower:
                    device_name = str(info)
                    break
        if not device_name and mac_lower in self.discovered_gateways:
            device_name = 'Gateway'
        if not device_name:
            device_name = f'Host {src_ip}'

        # Install DROP rule on all known switches
        rules_installed = 0
        for dpid, datapath in self._datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Match on source MAC (works for all traffic types including ARP)
            match = parser.OFPMatch(
                dl_src=haddr_to_bin(src_mac)
            )
            # No actions = DROP
            mod = parser.OFPFlowMod(
                datapath=datapath,
                match=match,
                cookie=0,
                command=ofproto.OFPFC_ADD,
                idle_timeout=0,
                hard_timeout=timeout,
                priority=65000,  # Higher than any learning rule
                flags=ofproto.OFPFF_SEND_FLOW_REM,
                actions=[]  # Empty = DROP
            )
            datapath.send_msg(mod)
            rules_installed += 1

        self._blocked_ips[src_ip] = {
            'mac': src_mac,
            'until': now + timeout,
            'attack_type': attack_type,
        }

        # --- Formatted Attack Log ---
        action_label = 'RATE-LIMITED' if reason == 'rate-limit' else 'BLOCKED'
        self.logger.warning(
            "\n"
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  🚫 ATTACKER %s%s║\n"
            "╠══════════════════════════════════════════════════════════╣\n"
            "║  Time      : %-42s ║\n"
            "║  Latency   : %-42s ║\n"
            "║  Device    : %-42s ║\n"
            "║  IP        : %-42s ║\n"
            "║  MAC       : %-42s ║\n"
            "║  Target    : %-42s ║\n"
            "║  Attack    : %-42s ║\n"
            "║  Detection : %-42s ║\n"
            "║  Action    : DROP rule for %-30s ║\n"
            "║  Switches  : %-42s ║\n"
            "╚══════════════════════════════════════════════════════════╝",
            action_label, ' ' * (46 - len(action_label)),
            now_str,
            f"{latency:.3f}s (detection → response)",
            device_name,
            src_ip,
            src_mac,
            target_ip,
            attack_type,
            reason,
            f"{timeout}s",
            f"{rules_installed} switch(es)",
        )

    def add_flow(self, datapath, in_port, dst, src, actions, idle_timeout=0, hard_timeout=0, priority=None):
        ofproto = datapath.ofproto
        if priority is None:
            priority = ofproto.OFP_DEFAULT_PRIORITY

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=idle_timeout, hard_timeout=hard_timeout,
            priority=priority,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def is_iot(self, mac):
        if not mac:
            return False
        m = mac.lower().replace(':', '')
        # Exclude known non-IoT (Mininet, virtual, etc.)
        for p in getattr(self, 'iot_exclude_prefixes', []):
            if m.startswith(p.lower().replace(':', '')):
                return False
        # exact device match (only if explicitly registered)
        if any(m == k.lower().replace(':', '') for k in self.iot_devices.keys()):
            return True
        # prefix/OUI match
        for p in self.iot_mac_prefixes:
            if m.startswith(p.lower().replace(':', '')):
                return True
        return False

    def is_gateway(self, mac):
        """Detect if a MAC address matches known gateway OUI prefixes."""
        if not mac:
            return False
        m = mac.lower()
        for p in self.gateway_mac_prefixes:
            lp = p.lower()
            if m.replace(':', '').startswith(lp.replace(':', '')):
                return True
        return False

    def register_gateway_dynamic(self, mac, dpid, port):
        """Dynamically register a discovered gateway."""
        if not mac:
            return
        mac_lower = mac.lower()
        if mac_lower not in self.discovered_gateways:
            self.discovered_gateways[mac_lower] = {}
        self.discovered_gateways[mac_lower]['dpid'] = dpid
        self.discovered_gateways[mac_lower]['port'] = port
        
        # Also update the primary gateway mapping for this switch (use the first discovered gateway per switch)
        if dpid not in self.iot_gateways:
            self.iot_gateways[dpid] = {'port': port, 'mac': mac}
            # Display long DPIDs in hex for readability (like in Mininet ap1)
            dpid_str = hex(dpid) if dpid > 0xffff else str(dpid)
            self.logger.info("Gateway discovered and registered: %s on dpid %s port %d", mac, dpid_str, port)
        else:
            self.logger.debug("Gateway already registered for dpid %s, skipping %s", dpid, mac)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            # ignore lldp packet
            return

        # --- Feature Extraction for ML ---
        packet_info = {
            'packet_size': len(msg.data),
            'dpid': datapath.id,
            'in_port': msg.in_port,
            'eth_src': eth.src,
            'eth_dst': eth.dst,
            'src_ip': '',
            'dst_ip': '',
            'src_port': 0,
            'dst_port': 0,
            'protocol': 'OTHER',
            'tcp_flags': {}
        }
        
        # Parse L3/L4 headers if present
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                packet_info['src_ip'] = ip_pkt.src
                packet_info['dst_ip'] = ip_pkt.dst
                
                if ip_pkt.proto == 6: # TCP
                    packet_info['protocol'] = 'TCP'
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    if tcp_pkt:
                        packet_info['src_port'] = tcp_pkt.src_port
                        packet_info['dst_port'] = tcp_pkt.dst_port
                        # Extract flags
                        packet_info['tcp_flags'] = {
                            'SYN': (tcp_pkt.bits & tcp.TCP_SYN) != 0,
                            'ACK': (tcp_pkt.bits & tcp.TCP_ACK) != 0,
                            'FIN': (tcp_pkt.bits & tcp.TCP_FIN) != 0,
                            'RST': (tcp_pkt.bits & tcp.TCP_RST) != 0,
                            'PSH': (tcp_pkt.bits & tcp.TCP_PSH) != 0,
                        }
                elif ip_pkt.proto == 17: # UDP
                    packet_info['protocol'] = 'UDP'
                    udp_pkt = pkt.get_protocol(udp.udp)
                    if udp_pkt:
                        packet_info['src_port'] = udp_pkt.src_port
                        packet_info['dst_port'] = udp_pkt.dst_port
                elif ip_pkt.proto == 1: # ICMP
                    packet_info['protocol'] = 'ICMP'
                    icmp_pkt = pkt.get_protocol(icmp.icmp)
                    if icmp_pkt:
                        packet_info['icmp_type'] = icmp_pkt.type
                        packet_info['icmp_code'] = icmp_pkt.code
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
             packet_info['protocol'] = 'ARP'
             arp_pkt_for_info = pkt.get_protocol(arp_lib.arp)
             if arp_pkt_for_info:
                 packet_info['arp_op'] = arp_pkt_for_info.opcode
                 packet_info['arp_spa'] = arp_pkt_for_info.src_ip
                 packet_info['arp_tpa'] = arp_pkt_for_info.dst_ip
                 packet_info['src_ip'] = arp_pkt_for_info.src_ip
                 packet_info['dst_ip'] = arp_pkt_for_info.dst_ip

        # --- Dynamic Device Name Learning ---
        # Learn device name from ANY packet with a source IP.
        # Cross-references IP ↔ MAC from the traffic itself.
        pkt_src_ip = packet_info.get('src_ip', '')
        pkt_src_mac = eth.src
        if pkt_src_ip and pkt_src_ip not in self._discovered_names:
            # Auto-learned placeholder — will be replaced by REGISTER:NAME
            self._discovered_names[pkt_src_ip] = f'Host ({pkt_src_ip})'
            self.logger.debug("Learned device: %s → %s", pkt_src_ip, pkt_src_mac)

        # Record packet for ML dataset
        if hasattr(self, 'traffic_capture') and self.traffic_capture:
            # Filter out non-IP/ARP traffic if desired, or keep all
            if packet_info['protocol'] != 'OTHER':
                self.traffic_capture.record_packet(packet_info, raw_data=msg.data)



        # Inject packet into TAP for Snort (mirrors all data-plane traffic)
        if hasattr(self, 'traffic_mirror') and self.traffic_mirror:
            self.traffic_mirror.inject(msg.data)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self._datapaths[dpid] = datapath  # Store for block_attacker()

        self.logger.debug("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        # --- Dynamic Registration Logic ---
        
        # 1. Explicit UDP Registration (Port 9999)
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt.proto == 17:  # UDP
                udp_pkt = pkt.get_protocol(udp.udp)
                # Ensure it's not DHCP (67/68) before interpreting as custom registration
                if udp_pkt and udp_pkt.dst_port == 9999:
                    try:
                        payload_data = msg.data[14+20+8:] # Approximate offset
                        message = payload_data.decode('utf-8', errors='ignore').strip()
                        if message.startswith("CONTROL:"):
                            # Control commands: CONTROL:DETECT:ON / CONTROL:DETECT:OFF
                            parts = message.split(':')
                            if len(parts) >= 3 and parts[1] == 'DETECT':
                                mode = parts[2].strip().upper()
                                if mode == 'ON':
                                    self._detection_enabled = True
                                    if hasattr(self, 'traffic_capture') and self.traffic_capture:
                                        self.traffic_capture.set_detection_mode(True)
                                    self.logger.warning(
                                        "\n"
                                        "╔══════════════════════════════════════════════════════════╗\n"
                                        "║  🚨 DETECTION MODE: ON                                    ║\n"
                                        "║  Anomaly detection ACTIVE.                             ║\n"
                                        "║  Attacks will be detected and labeled.                  ║\n"
                                        "╚══════════════════════════════════════════════════════════╝"
                                    )
                                elif mode == 'OFF':
                                    self._detection_enabled = False
                                    if hasattr(self, 'traffic_capture') and self.traffic_capture:
                                        self.traffic_capture.set_detection_mode(False)
                                    self.logger.warning(
                                        "\n"
                                        "╔══════════════════════════════════════════════════════════╗\n"
                                        "║  🛡 DETECTION MODE: OFF (Capture Only)                    ║\n"
                                        "║  Traffic is being recorded. All labels = normal.        ║\n"
                                        "╚══════════════════════════════════════════════════════════╝"
                                    )
                            return  # Don't process control packets further

                        if message.startswith("REGISTER:"):
                            _, type_str, info = message.split(':', 2)
                            self.logger.info("Explicit registration received from %s", src)
                            if type_str == "IOT":
                                self.iot_devices[src] = info
                                # Ensure it's not marked as gateway if it's explicitly IoT
                                mac_lower = src.lower()
                                if mac_lower in self.discovered_gateways:
                                    del self.discovered_gateways[mac_lower]
                                # Also remove from switch-port mapping for all DPIDs
                                for dpid_id in list(self.iot_gateways.keys()):
                                    if self.iot_gateways[dpid_id].get('mac', '').lower() == mac_lower:
                                        del self.iot_gateways[dpid_id]
                                self.logger.info("Registered IoT Device: %s (Type: %s)", src, info)
                                # Learn device name from registration
                                if ip_pkt:
                                    self._discovered_names[ip_pkt.src] = f'IoT:{info}'
                            elif type_str == "NAME":
                                # Hostname registration: REGISTER:NAME:sta1
                                if ip_pkt:
                                    self._discovered_names[ip_pkt.src] = info.strip()
                                    self.logger.info("Registered hostname: %s → %s", ip_pkt.src, info.strip())
                            elif type_str == "GATEWAY":
                                self.register_gateway_dynamic(src, dpid, msg.in_port)
                                self.logger.info("Registered Gateway: %s (Info: %s)", src, info)
                            return # Stop processing explicit registration packet
                    except Exception:
                        pass
                
                # 2. Passive Discovery via DHCP (Port 67 - BootP Server / Port 68 - BootP Client)
                # Devices request IP on connection. We can catch this.
                if udp_pkt and (udp_pkt.src_port == 68 or udp_pkt.dst_port == 67):
                    # Check if already registered
                    if src not in self.iot_devices and src not in self.discovered_gateways:
                        # Register as unknown/potential IoT
                        is_iot_oui = self.is_iot(src) # Checks prefixes
                        is_gw_oui = self.is_gateway(src)
                        
                        if is_gw_oui:
                            self.register_gateway_dynamic(src, dpid, msg.in_port)
                            if src not in self.discovery_logged_macs:
                                self.logger.info("Passive Discovery: Gateway detected via DHCP %s", src)
                                self.discovery_logged_macs.add(src)
                        elif is_iot_oui:
                             self.iot_devices[src] = "IOT:known_OUI"
                             if src not in self.discovery_logged_macs:
                                 self.logger.info("Passive Discovery: IoT Device detected via DHCP %s", src)
                                 self.discovery_logged_macs.add(src)
                        elif self.is_iot(src):
                             self.iot_devices[src] = "IOT:Detected_DHCP"
                             if src not in self.discovery_logged_macs:
                                 self.logger.info("Passive Discovery: IoT Device detected via DHCP %s", src)
                                 self.discovery_logged_macs.add(src)
                        else:
                             # Not IoT, still record to prevent re-checking
                             self.discovery_logged_macs.add(src)

        # 3. Passive Discovery via ARP + ARP Spoofing Detection
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
             arp_pkt = pkt.get_protocol(arp_lib.arp)
             if arp_pkt:
                 arp_src_ip = arp_pkt.src_ip
                 arp_src_mac = arp_pkt.src_mac
                 
                 # --- ARP Spoofing Detection (DAI equivalent) ---
                 if arp_src_ip and arp_src_mac:
                     if arp_src_ip in self._arp_bindings:
                         bound = self._arp_bindings[arp_src_ip]
                         if bound['mac'].lower() != arp_src_mac.lower():
                             # SPOOF DETECTED: different MAC claiming same IP
                             spoof_key = (arp_src_mac, arp_src_ip)
                             if spoof_key not in self._arp_spoof_logged:
                                 self._arp_spoof_logged.add(spoof_key)
                                 self.logger.warning(
                                     "\n"
                                     "╔══════════════════════════════════════════════════════════╗\n"
                                     "║  ⚠ ARP SPOOFING DETECTED (DAI)                          ║\n"
                                     "╠══════════════════════════════════════════════════════════╣\n"
                                     "║  Attacker MAC : %-40s ║\n"
                                     "║  Claims IP    : %-40s ║\n"
                                     "║  Real Owner   : %-40s ║\n"
                                     "║  Switch/Port  : dpid %s port %-26s ║\n"
                                     "╚══════════════════════════════════════════════════════════╝",
                                     arp_src_mac,
                                     arp_src_ip,
                                     bound['mac'],
                                     str(dpid), str(msg.in_port)
                                 )
                                 # Forward as alert to traffic capture for CSV labeling
                                 if hasattr(self, 'traffic_capture') and self.traffic_capture:
                                     self.traffic_capture.record_alert({
                                         'src_ip': arp_src_ip,
                                         'dst_ip': arp_src_ip,
                                         'attack_type': 'ARP Spoofing',
                                         'sid': 'DAI',
                                     })
                     else:
                         # First time seeing this IP — bind it
                         self._arp_bindings[arp_src_ip] = {
                             'mac': arp_src_mac,
                             'dpid': dpid,
                             'port': msg.in_port,
                         }
                         # Auto-learn device name from first ARP
                         if arp_src_ip not in self._discovered_names:
                             self._discovered_names[arp_src_ip] = f'Host ({arp_src_ip})'

             # Passive device discovery (existing logic)
             if src not in self.iot_devices and src not in self.discovered_gateways:
                 if self.is_gateway(src):
                     self.register_gateway_dynamic(src, dpid, msg.in_port)
                     if src not in self.discovery_logged_macs:
                         self.logger.info("Passive Discovery: Gateway detected via ARP %s", src)
                         self.discovery_logged_macs.add(src)
                 elif self.is_iot(src):
                     self.iot_devices[src] = "IOT:Unknown_OUI"
                     if src not in self.discovery_logged_macs:
                         self.logger.info("Passive Discovery: IoT Device detected via ARP %s", src)
                         self.discovery_logged_macs.add(src)
                 else:
                     self.discovery_logged_macs.add(src)

        # ----------------------------------

        # Dynamic gateway discovery (Legacy Check)
        # ONLY if not already known as an IoT device
        if src not in self.iot_devices:
            is_gateway_src = self.is_gateway(src)
            if is_gateway_src:
                self.register_gateway_dynamic(src, dpid, msg.in_port)

        is_iot_src = self.is_iot(src)
        is_iot_dst = self.is_iot(dst)
        if is_iot_src:
            self.logger.debug("IoT device traffic: %s on dpid %s port %s", src, dpid, msg.in_port)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            # If source is an IoT device and there is a configured gateway for this switch,
            # prefer sending unknown-destination IoT traffic to the gateway port instead of flooding.
            gw = self.iot_gateways.get(dpid)
            if is_iot_src and gw and 'port' in gw:
                out_port = gw['port']
                self.logger.info("Routing unknown IoT traffic from %s to gateway port %s on dpid %s", src, out_port, dpid)
            else:
                out_port = ofproto.OFPP_FLOOD

        # Forward to destination AND send copy to controller (for IDS/ML monitoring)
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        actions.append(datapath.ofproto_parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, 0xffff  # Send full packet data to controller for IDS/ML
        ))

        # ── AMPLIFICATION GUARD ──────────────────────────────────────
        # When a flow rule has output:CONTROLLER in its actions, every
        # matching packet is forwarded by the flow rule AND a copy is
        # sent here as packet_in with reason=OFPR_ACTION.
        #
        # If we send a PacketOut for these, the switch delivers the
        # packet AGAIN (duplicate) AND sends ANOTHER copy to the
        # controller (infinite loop). This caused:
        #   - 319 duplicate ICMP replies for 20 pings (~17x per seq)
        #   - False "ICMP Flood" detection during normal baseline
        #   - 1830-5581 phantom packet counts per 5s window
        #
        # Fix: if the packet was already forwarded by a flow rule
        # (reason=OFPR_ACTION), we've already recorded it above for
        # traffic_capture and Snort. Do NOT re-forward or re-install.
        if msg.reason == ofproto.OFPR_ACTION:
            return

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # IoT devices (Wi-Fi/home devices or factory sensors) use shorter idle timeouts
            # so we keep controller visibility for mobility and security purposes.
            if is_iot_src or is_iot_dst:
                try:
                    self.add_flow(datapath, msg.in_port, dst, src, actions, idle_timeout=60, priority=ofproto.OFP_DEFAULT_PRIORITY + 1)
                except Exception:
                    # Fallback to default call if switch parser differs
                    self.add_flow(datapath, msg.in_port, dst, src, actions)
            else:
                self.add_flow(datapath, msg.in_port, dst, src, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        # debug-level: Mininet churns ports constantly (flows install/expire on s1 AND ap1),
        # and at info this floods stdout — through the `tee` pipe that can back-pressure and
        # stall the controller. Keep it for debugging only.
        if reason == ofproto.OFPPR_ADD:
            self.logger.debug("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.debug("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.debug("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)


# =============================================================================
# REST controller (merged from ryu_ips_app.py). Same routes/JSON as the friend's
# standalone IPS, so snort_ryu_bridge.py (RYU_API_URL=http://127.0.0.1:8080/ips/block)
# works unchanged against this combined controller.
# =============================================================================
class IPSRestController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(IPSRestController, self).__init__(req, link, data, **config)
        self.app = data[IPS_INSTANCE_NAME]

    @route('ips', '/ips/block', methods=['POST'])
    def block_ip(self, req, **kwargs):
        try:
            body = req.json if req.body else {}
        except Exception:
            return self._json({'status': 'error', 'message': 'Invalid JSON'}, 400)
        src_ip = body.get('src_ip', '')
        reason = body.get('reason', 'Snort alert')
        try:
            idle = int(body.get('idle_timeout', 0))
            hard = int(body.get('hard_timeout', 600))
        except (TypeError, ValueError):
            idle, hard = 0, 600
        if not src_ip:
            return self._json({'status': 'error', 'message': 'src_ip required'}, 400)
        result = self.app.rest_block_ip(src_ip, reason, idle, hard)
        code = 200 if result.get('status') == 'blocked' else 500
        return self._json(result, code)

    @route('ips', '/ips/block/{src_ip}', methods=['DELETE'])
    def unblock_ip(self, req, src_ip, **kwargs):
        return self._json(self.app.rest_unblock_ip(src_ip))

    @route('ips', '/ips/blocked', methods=['GET'])
    def list_blocked(self, req, **kwargs):
        return self._json({'blocked': self.app.get_blocked_list()})

    @route('ips', '/ips/switches', methods=['GET'])
    def list_switches(self, req, **kwargs):
        switches = [{'dpid': str(d)} for d in self.app._datapaths]
        return self._json({'switches': switches, 'count': len(switches)})

    @route('ips', '/ips/status', methods=['GET'])
    def status(self, req, **kwargs):
        return self._json({
            'status': 'running',
            'switches': len(self.app._datapaths),
            'detection_enabled': self.app._detection_enabled,
            'ml_mode': self.app._ml_mode,
            'rest_blocked': len(self.app._rest_blocked_ips),
            'tier_blocked': len(self.app._blocked_ips),
        })

    @route('ips', '/ips/metrics', methods=['GET'])
    def metrics(self, req, **kwargs):
        """Aggregate state for the dashboard (read-only)."""
        app = self.app
        sm = getattr(app, 'snort_manager', None)
        tc = getattr(app, 'traffic_capture', None)
        last60 = 0
        if sm:
            try:
                import datetime as _dt
                cutoff = _dt.datetime.now() - _dt.timedelta(seconds=60)
                for a in sm.get_recent_alerts(200):
                    ts = a.get('detected_at', '')
                    if ts and _dt.datetime.fromisoformat(ts) >= cutoff:
                        last60 += 1
            except Exception:
                last60 = 0
        ram = cpu = disk = None
        try:
            import psutil
            ram = psutil.virtual_memory().percent
            cpu = psutil.cpu_percent(interval=0.0)   # non-blocking; real value from 2nd poll on
            disk = psutil.disk_usage('/').percent
        except Exception:
            pass
        return self._json({
            'snort_running': bool(sm and getattr(sm, '_snort_processes', None)),
            'rf_loaded': bool(getattr(getattr(app, '_ml_engine', None), 'is_loaded', False)),
            'ae_loaded': bool(getattr(getattr(app, '_ae_engine', None), 'is_loaded', False)),
            'detection_enabled': app._detection_enabled,
            'ml_mode': app._ml_mode,
            'alerts_total': sm.get_alert_count() if sm else 0,
            'alerts_last_60s': last60,
            'confirmed_attackers': len(getattr(tc, '_confirmed_attackers', {}) or {}),
            'by_attack': sm.get_alerts_by_type() if sm else {},
            'by_tier': {
                'snort': sm.get_alert_count() if sm else 0,
                'rate_dai': len(getattr(tc, '_confirmed_attackers', {}) or {}),
            },
            'ram_pct': ram,
            'cpu_pct': cpu,
            'disk_pct': disk,
            'switches': len(app._datapaths),
            'rest_blocked': len(app._rest_blocked_ips),
            'tier_blocked': len(app._blocked_ips),
        })

    @route('ips', '/ips/alerts', methods=['GET'])
    def alerts(self, req, **kwargs):
        """Recent Snort alerts for the dashboard timeline (read-only)."""
        sm = getattr(self.app, 'snort_manager', None)
        raw = sm.get_recent_alerts(50) if sm else []
        out = [{'time': a.get('detected_at', ''), 'src_ip': a.get('src_ip'),
                'dst_ip': a.get('dst_ip'), 'attack_type': a.get('attack_type'),
                'tier': 'snort', 'sid': a.get('sid'),
                'confidence': a.get('confidence')} for a in raw]
        return self._json({'alerts': out})

    @route('ips', '/', methods=['GET'])
    def dashboard(self, req, **kwargs):
        """Serve the dashboard same-origin (no CORS): http://<controller>:<wsapi-port>/."""
        import os as _os
        path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                             '..', 'Dashboard', 'index.html')
        try:
            with open(path, 'rb') as f:
                return Response(content_type='text/html', body=f.read())
        except Exception:
            return self._json({'status': 'error',
                               'message': 'Dashboard/index.html not found'}, 404)

    def _json(self, data, status=200):
        return Response(content_type='application/json',
                        body=json.dumps(data).encode('utf-8'), status=status)