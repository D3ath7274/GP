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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snort_monitor import SnortManager
from traffic_mirror import TrafficMirror
from traffic_capture import TrafficCapture  # Added
from ml_inference import MLInferenceEngine  # ML Inference Engine


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

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self._datapaths = {}   # dpid -> datapath (for sending flow mods outside packet_in)
        self._blocked_ips = {} # ip -> {'mac':, 'until':, 'attack_type':}

        # ===================================================================
        # Traffic Mirroring: All data-plane traffic (10.0.0.x + 192.168.1.x)
        # is mirrored to the controller via OpenFlow and injected into a TAP
        # so Snort can detect malicious behavior. Prepares for ML anomaly detection.
        # ===================================================================
        self._physical_interface = 'ens33'
        self._tap_name = 'snort_tap'

        self.traffic_mirror = TrafficMirror(
            tap_name=self._tap_name,
            logger=self.logger
        )
        mirror_ok = self.traffic_mirror.start()

        # Snort monitors both: physical (192.168.1.x) + TAP (mirrored 10.0.0.x)
        self.snort_manager = SnortManager(
            interfaces=[self._physical_interface, self._tap_name] if mirror_ok
                       else [self._physical_interface],
            config_path='/etc/snort/snort.lua',
            log_dir='/var/log/snort',
            logger=self.logger,
            on_alert=self._handle_snort_alert
        )
        snort_started = self.snort_manager.start_snort()
        if snort_started:
            self.snort_manager.start_monitoring()
        else:
            self.logger.error(
                "Snort IDS failed to start! Run snort_setup.sh first. "
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
        self._ml_confidence_threshold = 0.80  # Calibrate on t530 in Phase 5
        ml_model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ml_models')
        if os.path.isdir(ml_model_dir):
            self._ml_engine = MLInferenceEngine(ml_model_dir, logger=self.logger)
        else:
            self._ml_engine = None
            self.logger.warning(
                "ml_models/ directory not found at %s — ML inference disabled. "
                "Place full_ml_pipeline.joblib in this directory to enable it.", ml_model_dir
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
                            self.traffic_capture.clear_detection_state(clear_ip)
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
                                    self._ml_confidence_threshold = float(parts[3])
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
                                f"{self._ml_confidence_threshold:.2f}"
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
    # Attacker Blocking (OpenFlow DROP Rule)
    # ===================================================================
    def block_attacker(self, src_ip, src_mac, attack_type, timeout,
                       detection_time=None, target_ip='', reason=''):
        """
        Install a high-priority OpenFlow DROP rule for an attacker.
        
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
                self.traffic_capture.record_packet(packet_info)



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
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)