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
from ryu.lib.packet import ether_types


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
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
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        # Dynamic gateway discovery
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

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

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