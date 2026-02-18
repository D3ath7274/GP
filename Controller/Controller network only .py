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

# Snort 3 IDS Integration + Traffic Mirroring
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snort_monitor import SnortManager
from traffic_mirror import TrafficMirror


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # ===================================================================
        # Traffic Mirroring: All data-plane traffic (10.0.0.x + 192.168.1.x)
        # is mirrored to the controller via OpenFlow and injected into a TAP
        # so Snort can detect malicious behavior. Prepares for ML anomaly detection.
        # ===================================================================
        self._physical_interface = 'ens33'  # Edit: eth0, ens33, or your NIC (ip link show)
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

        # IoT configuration
        # Vendor/OUI prefixes (lowercase, without separators) commonly used by IoT devices.
        # Edit these prefixes or populate `self.iot_devices` with exact MACs as needed.
        self.iot_mac_prefixes = ['00:11:22', 'aa:bb:cc']
        # Explicit IoT device MAC -> type mapping (example):
        # {'00:11:22:33:44:55': 'home_sensor'}
        self.iot_devices = {}
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
    # Snort IDS Alert Handler
    # ===================================================================
    def _handle_snort_alert(self, alert):
        """
        Called by SnortManager for each new Snort alert.
        Logs the attack type and source to the Ryu controller output.
        
        This covers traffic on ALL controller ports including:
        - Physical interface (ens33)
        - Any Mininet-wifi virtual network traffic routed through the controller
        """
        self.logger.warning(
            "\n"
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  🚨 IDS ALERT: %-40s ║\n"
            "╠══════════════════════════════════════════════════════════╣\n"
            "║  Attack : %-46s ║\n"
            "║  Source : %-46s ║\n"
            "║  Target : %-46s ║\n"
            "║  Proto  : %-46s ║\n"
            "║  Rule   : SID %-42s ║\n"
            "╚══════════════════════════════════════════════════════════╝",
            alert.get('attack_type', 'Unknown')[:40],
            alert.get('attack_type', 'Unknown'),
            '%s:%s' % (alert.get('src_ip', '?'), alert.get('src_port', '?')),
            '%s:%s' % (alert.get('dst_ip', '?'), alert.get('dst_port', '?')),
            alert.get('proto', '?'),
            alert.get('sid', '?'),
        )

    def close(self):
        """Clean up: stop Snort and traffic mirror when the controller shuts down."""
        self.logger.info("Controller shutting down — stopping Snort IDS...")
        self.snort_manager.stop_snort()
        if hasattr(self, 'traffic_mirror') and self.traffic_mirror:
            self.traffic_mirror.stop()
        super(SimpleSwitch, self).close()

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
        m = mac.lower()
        # exact device match
        if any(m == k.lower() for k in self.iot_devices.keys()):
            return True
        # prefix/OUI match (support colon-separated MACs)
        for p in self.iot_mac_prefixes:
            lp = p.lower()
            if m.replace(':', '').startswith(lp.replace(':', '')):
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
            self.logger.info("Gateway discovered and registered: %s on dpid %s port %s", mac, dpid, port)
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
            return

        # Inject packet into TAP for Snort (mirrors all data-plane traffic)
        if hasattr(self, 'traffic_mirror') and self.traffic_mirror:
            self.traffic_mirror.inject(msg.data)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

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
                        if message.startswith("REGISTER:"):
                            _, type_str, info = message.split(':', 2)
                            self.logger.info("Registration request received from %s", src)
                            if type_str == "IOT":
                                self.iot_devices[src] = info
                                self.logger.info("Registered IoT Device: %s (Type: %s)", src, info)
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
                            self.logger.info("Passive Discovery: Gateway detected via DHCP %s", src)
                        elif is_iot_oui:
                             self.iot_devices[src] = "IOT:known_OUI"
                             self.logger.info("Passive Discovery: IoT Device detected via DHCP %s", src)
                        else:
                             # Should we register ALL unknown devices? Maybe as Generic host?
                             # For this task "IoT devices", let's be generous and assume unknown MACs on this network might be new sensors.
                             # Or stick to strict OUI check.
                             # If user connects a REAL device, we might not know its OUI prefix.
                             # Let's add it as "Potential IoT".
                             self.iot_devices[src] = "IOT:Detected_DHCP"
                             self.logger.info("Passive Discovery: New Device detected via DHCP %s", src)

        # 3. Passive Discovery via ARP
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
             if src not in self.iot_devices and src not in self.discovered_gateways:
                 if self.is_gateway(src):
                     self.register_gateway_dynamic(src, dpid, msg.in_port)
                     self.logger.info("Passive Discovery: Gateway detected via ARP %s", src)
                 elif self.is_iot(src): # strict check?
                     self.iot_devices[src] = "IOT:Unknown_OUI"
                     self.logger.info("Passive Discovery: IoT Device detected via ARP %s", src)
                 else:
                     # For demonstration, register any new device seen via ARP as potentially IoT
                     self.iot_devices[src] = "IOT:Detected_ARP"
                     self.logger.info("Passive Discovery: New Device detected via ARP %s", src)

        # ----------------------------------

        # Dynamic gateway discovery (Legacy Check)
        is_gateway_src = self.is_gateway(src)
        if is_gateway_src:
            self.register_gateway_dynamic(src, dpid, msg.in_port)

        is_iot_src = self.is_iot(src)
        is_iot_dst = self.is_iot(dst)
        if is_iot_src:
            self.logger.info("IoT device detected: %s on dpid %s port %s", src, dpid, msg.in_port)

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
            ofproto.OFPP_CONTROLLER, 0  # 0 = send full packet
        ))

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