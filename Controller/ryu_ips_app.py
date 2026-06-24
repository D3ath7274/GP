#!/usr/bin/env python3
"""
ryu_ips_app.py
--------------
Ryu SDN Application with:
  1. L2 Learning Switch (baseline forwarding)
  2. REST API endpoint to receive block commands from the Snort bridge
  3. OpenFlow 1.3 DROP flow rules pushed to all connected switches

Run with:
    ryu-manager ryu_ips_app.py --observe-links

REST API exposed on: http://0.0.0.0:8080
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, arp
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import hub

import json
import logging
import ipaddress
from datetime import datetime
from webob import Response

log = logging.getLogger("ryu.app.ips")

IPS_INSTANCE_NAME     = "ryu_ips_app"
IDLE_TIMEOUT_DEFAULT  = 300
HARD_TIMEOUT_DEFAULT  = 600
DROP_FLOW_PRIORITY    = 200
NORMAL_FLOW_PRIORITY  = 100
TABLE_MISS_PRIORITY   = 0


class RyuIPSApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.blocked_ips  = {}
        self.datapaths    = {}

        wsgi = kwargs["wsgi"]
        wsgi.register(IPSRestController, {IPS_INSTANCE_NAME: self})
        log.info("Ryu IPS App started. REST API on :8080")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        log.info(f"Switch connected: DPID={datapath.id:#x}")
        self._install_table_miss(datapath)

    def _install_table_miss(self, datapath):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, TABLE_MISS_PRIORITY, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match["in_port"]
        dpid     = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        dst_mac = eth.dst
        src_mac = eth.src

        if eth.ethertype == 0x88cc:
            return

        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 and ip4.src in self.blocked_ips:
            log.info(f"[BLOCKED] Dropping packet from {ip4.src}")
            return

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        out_port = (self.mac_to_port[dpid].get(dst_mac)
                    if dst_mac in self.mac_to_port.get(dpid, {})
                    else ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_dst=dst_mac,
                                    eth_src=src_mac)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(datapath, NORMAL_FLOW_PRIORITY, match, actions,
                               buffer_id=msg.buffer_id)
                return
            else:
                self._add_flow(datapath, NORMAL_FLOW_PRIORITY, match, actions)

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out  = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id

        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)

    def block_ip(self, src_ip, reason="",
                 idle_timeout=IDLE_TIMEOUT_DEFAULT,
                 hard_timeout=HARD_TIMEOUT_DEFAULT):
        try:
            ipaddress.ip_address(src_ip)
        except ValueError:
            return {"status": "error", "message": f"Invalid IP: {src_ip}"}

        if not self.datapaths:
            return {"status": "error", "message": "No switches connected"}

        self.blocked_ips[src_ip] = {
            "timestamp": datetime.utcnow().isoformat(),
            "reason": reason,
            "switches": []
        }

        pushed_to = []
        for dpid, datapath in self.datapaths.items():
            parser  = datapath.ofproto_parser
            match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            actions = []
            self._add_flow(datapath, DROP_FLOW_PRIORITY, match, actions,
                           idle_timeout=idle_timeout,
                           hard_timeout=hard_timeout)
            pushed_to.append(f"{dpid:#x}")
            log.warning(f"[IPS] DROP rule: {src_ip} on switch {dpid:#x} | {reason}")

        self.blocked_ips[src_ip]["switches"] = pushed_to
        return {
            "status": "blocked",
            "src_ip": src_ip,
            "reason": reason,
            "switches": pushed_to,
            "idle_timeout": idle_timeout,
            "hard_timeout": hard_timeout,
        }

    def unblock_ip(self, src_ip):
        if src_ip not in self.blocked_ips:
            return {"status": "not_found", "src_ip": src_ip}

        for dpid, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser  = datapath.ofproto_parser
            match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=DROP_FLOW_PRIORITY,
                match=match
            )
            datapath.send_msg(mod)
            log.info(f"[IPS] Unblocked {src_ip} on switch {dpid:#x}")

        del self.blocked_ips[src_ip]
        return {"status": "unblocked", "src_ip": src_ip}

    def get_blocked_list(self):
        return [{"ip": ip, **info} for ip, info in self.blocked_ips.items()]


class IPSRestController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data[IPS_INSTANCE_NAME]

    @route("ips", "/ips/block", methods=["POST"])
    def block_ip(self, req, **kwargs):
        try:
            body = req.json if req.body else {}
        except Exception:
            return self._json({"status": "error", "message": "Invalid JSON"}, 400)

        src_ip = body.get("src_ip", "")
        reason = body.get("reason", "Snort alert")
        idle   = int(body.get("idle_timeout", IDLE_TIMEOUT_DEFAULT))
        hard   = int(body.get("hard_timeout", HARD_TIMEOUT_DEFAULT))

        if not src_ip:
            return self._json({"status": "error", "message": "src_ip required"}, 400)

        result = self.app.block_ip(src_ip, reason, idle, hard)
        code   = 200 if result["status"] == "blocked" else 500
        return self._json(result, code)

    @route("ips", "/ips/block/{src_ip}", methods=["DELETE"])
    def unblock_ip(self, req, src_ip, **kwargs):
        return self._json(self.app.unblock_ip(src_ip))

    @route("ips", "/ips/blocked", methods=["GET"])
    def list_blocked(self, req, **kwargs):
        return self._json({"blocked": self.app.get_blocked_list()})

    @route("ips", "/ips/switches", methods=["GET"])
    def list_switches(self, req, **kwargs):
        switches = [{"dpid": f"{dpid:#x}"} for dpid in self.app.datapaths]
        return self._json({"switches": switches, "count": len(switches)})

    @route("ips", "/ips/status", methods=["GET"])
    def status(self, req, **kwargs):
        return self._json({
            "status":        "running",
            "switches":      len(self.app.datapaths),
            "blocked_count": len(self.app.blocked_ips),
        })

    def _json(self, data, status=200):
        return Response(
            content_type="application/json",
            body=json.dumps(data).encode("utf-8"),
            status=status
        )
