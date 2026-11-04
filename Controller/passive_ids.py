"""Passive APF sensor using the existing collector, models and dashboard."""

import argparse
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import os
from pathlib import Path
import signal
import socket
import struct
import threading
import time
from urllib.parse import urlsplit

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapReader

from ae_inference import AEInferenceEngine
from ml_inference import MLInferenceEngine
from traffic_capture import TrafficCapture


ROOT = Path(__file__).resolve().parent
LOGGER = logging.getLogger("apf.passive")


def packet_info(frame):
    ethernet = frame.getlayer(Ether)
    if ethernet is None:
        return None
    info = {
        "eth_src": ethernet.src, "eth_dst": ethernet.dst,
        "packet_size": len(frame), "tcp_flags": {},
    }
    arp = frame.getlayer(ARP)
    ip = frame.getlayer(IP)
    if arp is not None:
        return dict(info, protocol="ARP", src_ip=arp.psrc, dst_ip=arp.pdst,
                    arp_op=arp.op, arp_spa=arp.psrc, arp_tpa=arp.pdst)
    if ip is None:
        return None
    info.update(src_ip=ip.src, dst_ip=ip.dst, protocol="OTHER")
    transport = ip.payload
    if isinstance(transport, (TCP, UDP)):
        info.update(protocol=transport.name, src_port=transport.sport,
                    dst_port=transport.dport)
        if isinstance(transport, TCP):
            info["tcp_flags"] = {
                name: bool(int(transport.flags) & bit)
                for name, bit in (("FIN", 1), ("SYN", 2), ("RST", 4),
                                  ("PSH", 8), ("ACK", 16))
            }
    elif isinstance(transport, ICMP):
        info.update(protocol="ICMP", icmp_type=transport.type,
                    icmp_code=transport.code)
    return info


class PassiveSensor:
    def __init__(self, dataset, model_dir, capture_only=False):
        self._ml_mode = "OFF" if capture_only else "OBSERVE"
        self._ml_engine = None if capture_only else MLInferenceEngine(str(model_dir), LOGGER)
        self._ae_engine = None if capture_only else AEInferenceEngine(str(model_dir), LOGGER)
        self._ae_defer_to_rf = False
        self.events = deque(maxlen=200)
        self.totals = Counter()
        self.lock = threading.Lock()
        self.capture_state = "starting"
        self.capture = TrafficCapture(str(dataset), controller=self, logger=LOGGER)
        self.capture._ml_pcap_enabled = False

    def on_detection_observed(self, tier, src, dst, attack_type, confidence):
        now = datetime.now(timezone.utc)
        event = dict(time=now.isoformat(), tier=tier, src_ip=src, dst_ip=dst,
                     attack_type=attack_type, confidence=float(confidence))
        with self.lock:
            self.events.appendleft(event)
            self.totals[tier] += 1

    def read(self, path):
        status = dict(status="running", deployment_mode="passive",
                      capture_state=self.capture_state, switches=0,
                      detection_enabled=False, ml_mode=self._ml_mode,
                      rest_blocked=0, tier_blocked=0)
        if path == "/ips/status":
            return status
        if path == "/ips/switches":
            return {"switches": [], "count": 0}
        if path == "/ips/blocked":
            return {"blocked": []}
        with self.lock:
            if path == "/ips/alerts":
                return {"alerts": list(self.events)[:50]}
            if path == "/ips/metrics":
                cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
                recent = sum(datetime.fromisoformat(e["time"]) >= cutoff for e in self.events)
                return dict(status, snort_running=False, confirmed_attackers=0,
                            rf_loaded=bool(self._ml_engine and self._ml_engine.is_loaded),
                            ae_loaded=bool(self._ae_engine and self._ae_engine.is_loaded),
                            alerts_total=sum(self.totals.values()), alerts_last_60s=recent,
                            by_attack={}, by_tier={k.lower(): v for k, v in self.totals.items()},
                            cpu_pct=None, ram_pct=None, disk_pct=None)
        return None


class DashboardHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, sensor, **kwargs):
        self.sensor = sensor
        super().__init__(*args, **kwargs)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/docs" or path.startswith("/docs/"):
            from local_docs import document
            status, content_type, data = document(path)
            self.respond(status, content_type, data)
            return
        if path == "/":
            data = (ROOT.parent / "Dashboard" / "index.html").read_bytes()
            self.respond(200, "text/html; charset=utf-8", data)
            return
        payload = self.sensor.read(path)
        self.respond(200 if payload is not None else 404, "application/json",
                     json.dumps(payload if payload is not None else
                                {"status": "not_found"}, allow_nan=False).encode())

    def respond(self, status, content_type, data):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


def capture_packets(args, sensor, stop):
    def record(frame):
        info = packet_info(frame)
        if info is not None:
            sensor.capture.record_packet(info)

    if args.pcap:
        with PcapReader(str(args.pcap)) as reader:
            previous = None
            for frame in reader:
                timestamp = float(frame.time)
                if previous is not None and stop.wait(max(0, timestamp - previous)):
                    break
                if stop.is_set():
                    break
                record(frame)
                previous = timestamp
        return

    if not hasattr(socket, "AF_PACKET"):
        raise RuntimeError("Live capture requires Linux AF_PACKET")
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as source:
        source.bind((args.interface, 0))
        # PACKET_ADD_MEMBERSHIP with PACKET_MR_PROMISC. The socket owns membership.
        membership = struct.pack("=IHH8s", socket.if_nametoindex(args.interface), 1, 0, b"")
        source.setsockopt(263, 1, membership)
        source.settimeout(0.5)
        while not stop.is_set():
            try:
                frame, address = source.recvfrom(65535)
            except socket.timeout:
                continue
            if address[2] != socket.PACKET_OUTGOING:
                record(Ether(frame))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--interface", help="Linux mirror/TAP interface")
    inputs.add_argument("--pcap", type=Path, help="Replay at original packet spacing")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--dataset", type=Path, default=Path("dataset-passive.csv"))
    parser.add_argument("--model-dir", type=Path, default=ROOT / "ml_models")
    parser.add_argument("--capture-only", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    os.environ["IPS_V2_FEATURES"] = "1"
    sensor = PassiveSensor(args.dataset, args.model_dir, args.capture_only)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    handler = partial(DashboardHandler, sensor=sensor)
    with ThreadingHTTPServer(("127.0.0.1", args.port), handler) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        sensor.capture.start()
        try:
            LOGGER.info("Dashboard on http://127.0.0.1:%d", server.server_port)
            sensor.capture_state = "capturing"
            capture_packets(args, sensor, stop)
        except KeyboardInterrupt:
            stop.set()
        finally:
            sensor.capture.stop()
        if args.pcap and not stop.is_set():
            sensor.capture_state = "replay_complete"
            LOGGER.info("Replay complete. Dashboard remains available until stopped.")
            try:
                stop.wait()
            except KeyboardInterrupt:
                pass
        server.shutdown()


if __name__ == "__main__":
    main()
