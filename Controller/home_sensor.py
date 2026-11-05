"""Long-running passive home collection with versioned daily CSVs and health records."""

import argparse
from collections import Counter
import csv
import hashlib
from datetime import datetime, timezone
from functools import partial
from http.server import ThreadingHTTPServer
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import struct
import sys
import threading
import time
import uuid

from scapy.layers.l2 import Ether
from scapy.error import Scapy_Exception
from scapy.utils import PcapReader

from http_dashboard import DashboardHandler
from site_features import DeviceWindow, FeatureHistory, SCHEMA_VERSION, decode
from site_policy import ShadowPolicy, digest, load_json
from collection_io import collection_lease


LOGGER = logging.getLogger("apf.home")
META_COLUMNS = ["schema_version", "run_id", "window_start_utc", "window_end_utc",
                "window_seconds", "device_ip", "vlan", "ground_truth",
                "metadata_enabled", "content_enabled", "history_restarted",
                "cardinality_overflows_total", "window_complete"]


def utc(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def collection_contract(networks, metadata=False, content=False, max_sources=128):
    """Pure construction: preflight and runtime must compare the same contract."""
    feature_names = list(FeatureHistory().features("schema", DeviceWindow(), 0, 5, Counter()))
    return {"schema_version": SCHEMA_VERSION, "columns": META_COLUMNS + feature_names,
            "networks": [str(ipaddress.ip_network(n, strict=True)) for n in networks],
            "metadata": metadata, "content": content, "window_seconds": 5,
            "max_sources": max_sources, "cardinality_limit": 128,
            "ground_truth_default": "UNKNOWN",
            "bytes_unit": "captured Ethernet bytes, normally excluding FCS",
            "profile_semantics": "observed history, unverified",
            "parsers": {"G11_G14": "header summaries, no full TCP session reassembly",
                        "G15": "single-question UDP DNS only",
                        "G16": "complete ClientHello in one TCP packet, custom fingerprint",
                        "G17": "complete HTTP/1 request headers in one TCP packet"}}


def atomic_json(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(data, output, indent=2, allow_nan=False)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


class StorageLimitError(RuntimeError):
    pass


class HomeCollection:
    def __init__(self, directory, networks, metadata=False, content=False,
                 min_free_bytes=1024**3, max_data_bytes=5 * 1024**3, max_sources=128,
                 policy=None, approved_baselines=(), capture_source="unspecified"):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.networks = [ipaddress.ip_network(network, strict=True) for network in networks]
        self.metadata = metadata
        self.content = content
        self.min_free_bytes = min_free_bytes
        self.max_data_bytes = max_data_bytes
        self.max_sources = max_sources
        self.run_id = uuid.uuid4().hex[:12]
        self.lock = threading.RLock()
        self.health = Counter()
        self.capture_source = capture_source
        import scapy
        self.runtime_provenance = {"python": sys.version.split()[0], "scapy": scapy.__version__,
            "system":platform.system(),"kernel":platform.release(),
            "source_sha256":{name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                for name in ("home_sensor.py","site_features.py","site_policy.py","collection_io.py")}}
        self.policy = ShadowPolicy(load_json(policy) if policy else None,
                                   [load_json(path) for path in approved_baselines])
        for device in self.policy.devices.values():
            ip = ipaddress.ip_address(device["ip"])
            if not any(ip.version == network.version and ip in network for network in self.networks):
                raise ValueError("Policy device is outside configured collection networks")
        if self.policy.config:
            atomic_json(self.directory / ("policy-" + self.run_id + ".json"), self.policy.config)
        self.history = FeatureHistory(max_sources)
        self.windows = {}
        self.start = None
        self.latest = None
        self.rows_written = 0
        self.state = "starting"
        self.error = None
        self.last_checkpoint = 0
        self.first_event_time = None
        self.contract = collection_contract(networks, metadata, content, max_sources)
        self.columns = self.contract["columns"]
        self.contract_hash = digest(self.contract)
        if any(profile["collection_schema_sha256"] != self.contract_hash
               for profile in self.policy.approved.values()):
            raise ValueError("Approved profile belongs to different collection settings/schema")
        contract_path = self.directory / "schema.json"
        if contract_path.exists():
            if json.loads(contract_path.read_text(encoding="utf-8")) != self.contract:
                raise ValueError("Collection settings changed. Use a new data directory.")
        else:
            atomic_json(contract_path, self.contract)
        saved = self.directory / "profile-state.json"
        if saved.exists():
            state = json.loads(saved.read_text(encoding="utf-8"))
            if state.get("schema_version") != SCHEMA_VERSION:
                raise ValueError("Incompatible profile snapshot")
            profiles = state["sources"]
            if not isinstance(profiles, list) or len(profiles) > max_sources:
                raise ValueError("Profile snapshot exceeds configured source cap")
            for key, profile in profiles:
                if (not isinstance(key, str) or "@" not in key or key in self.history.sources or
                        not isinstance(profile, dict) or set(profile) != {"peers", "windows", "ttl_mean"} or
                        not isinstance(profile["peers"], list) or len(profile["peers"]) > 1024 or
                        any(not isinstance(peer,str) for peer in profile["peers"]) or
                        len(set(profile["peers"])) != len(profile["peers"]) or
                        type(profile["windows"]) is not int or profile["windows"] < 0 or
                        profile["ttl_mean"] is not None and (type(profile["ttl_mean"]) not in (int,float) or
                            not math.isfinite(profile["ttl_mean"]) or not 0 <= profile["ttl_mean"] <= 255)):
                    raise ValueError("Invalid profile snapshot")
                address = ipaddress.ip_address(key.split("@",1)[0])
                if not any(address.version == network.version and address in network for network in self.networks):
                    raise ValueError("Profile snapshot device outside collection networks")
                for peer in profile["peers"]:
                    ipaddress.ip_address(peer)
                self.history.sources[key] = profile
        self._check_storage()

    def _check_storage(self):
        free = shutil.disk_usage(self.directory).free
        data_bytes = sum(path.stat().st_size for path in self.directory.iterdir() if path.is_file())
        self.health["disk_free_bytes"] = free
        self.health["data_bytes"] = data_bytes
        if free < self.min_free_bytes or data_bytes >= self.max_data_bytes:
            self.state = "storage_limit"
            raise StorageLimitError("Collection stopped at disk budget. Archive files before restarting.")

    def record(self, packet):
        with self.lock:
            timestamp = packet["timestamp"]
            if not math.isfinite(timestamp) or timestamp < 0:
                self.health["invalid_timestamps"] += 1
                return
            if self.first_event_time is None:
                self.first_event_time = timestamp
            self.advance(timestamp)
            if timestamp < self.start:
                self.health["late_packets"] += 1
                return
            self.latest = timestamp
            self.health["parsed_packets"] += 1
            self.health["parsed_bytes"] += packet["size"]
            self.health[packet["protocol"] + "_packets"] += 1
            self.health["truncated_packets"] += bool(packet.get("capture_truncated"))
            self.health["unsupported_jumbograms"] += bool(packet.get("unsupported_jumbogram"))
            for protocol in ("dns", "tls", "http"):
                self.health[protocol + "_parse_errors"] += bool(packet.get(protocol + "_error"))
            for address, outbound in ((packet["src"], True), (packet["dst"], False)):
                try:
                    ip = ipaddress.ip_address(address)
                except ValueError:
                    self.health["invalid_addresses"] += 1
                    continue
                matching = [network for network in self.networks if ip.version == network.version and ip in network]
                if (not matching or ip.is_multicast or ip.is_unspecified or
                        any(network.version == 4 and network.prefixlen < 31 and
                            ip in (network.network_address, network.broadcast_address)
                            for network in matching)):
                    continue
                key = address + "@" + packet["vlan"]
                if key not in self.windows:
                    if len(self.windows) >= self.max_sources:
                        self.health["source_window_omissions"] += 1
                        continue
                    self.windows[key] = DeviceWindow()
                self.windows[key].observe(packet, outbound, self.health)

    def advance(self, timestamp):
        if self.start is None:
            self.start = math.floor(timestamp / 5) * 5
        if timestamp >= self.start + 5:
            self._flush(self.start + 5)
            self.start = math.floor(timestamp / 5) * 5

    def _flush(self, end, complete=True):
        if not self.windows:
            return
        self._check_storage()
        duration = max(0.000001, end - self.start)
        path = self.directory / ("features-" + datetime.fromtimestamp(self.start, timezone.utc).date().isoformat()
                                 + "-" + self.run_id + ".csv")
        evidence_path = path.with_name(path.name.replace("features-", "policy-events-")).with_suffix(".jsonl")
        with path.open("a", newline="", encoding="utf-8") as output, evidence_path.open("a", encoding="utf-8") as evidence:
            writer = csv.DictWriter(output, fieldnames=self.columns)
            if output.tell() == 0:
                writer.writeheader()
            for key, window in self.windows.items():
                ip, vlan = key.split("@", 1)
                row = dict(schema_version=SCHEMA_VERSION, run_id=self.run_id,
                           window_start_utc=utc(self.start), window_end_utc=utc(end),
                           window_seconds=duration, device_ip=ip, vlan=vlan, ground_truth="UNKNOWN",
                           metadata_enabled=int(self.metadata), content_enabled=int(self.content),
                           history_restarted=int(end - self.first_event_time < 3600),
                           cardinality_overflows_total=self.health["cardinality_overflows"],
                           window_complete=int(complete and duration == 5 and self.first_event_time <= self.start))
                row.update(self.history.features(key, window, self.start, duration, self.health))
                writer.writerow(row)
                record = self.policy.evaluate(row, window, self.health, self.capture_source, self.contract_hash)
                evidence.write(json.dumps(record, allow_nan=False, separators=(",", ":")) + "\n")
                self.rows_written += 1
            output.flush()
            os.fsync(output.fileno())
            evidence.flush()
            os.fsync(evidence.fileno())
        self.windows.clear()

    def snapshot(self):
        with self.lock:
            return {"schema_version": SCHEMA_VERSION, "run_id": self.run_id,
                    "collection_schema_sha256": self.contract_hash,
                    "capture_state": self.state, "error": self.error,
                    "rows_written": self.rows_written, "device_profiles": len(self.history.sources),
                    "health": dict(self.health), "updated_at": utc(time.time()),
                    "metadata_enabled": self.metadata, "content_enabled": self.content,
                    "kernel_statistics_available": self.health["kernel_stats_reads"] > 0,
                    "capture_source": self.capture_source,
                    "shadow_policy": self.policy.snapshot(),
                    "model_scoring": False, "ground_truth": "UNKNOWN"}

    def checkpoint(self, force=False):
        with self.lock:
            if not force and time.monotonic() - self.last_checkpoint < 60:
                return
            atomic_json(self.directory / "profile-state.json", {
                "schema_version": SCHEMA_VERSION, "sources": list(self.history.sources.items()),
                "note": "TTL and destination history restored. Rolling hourly buckets restart."})
            atomic_json(self.directory / ("run-" + self.run_id + ".json"),
                        dict(self.snapshot(), runtime_provenance=self.runtime_provenance))
            self.last_checkpoint = time.monotonic()

    def read(self, path):
        status = dict(status="running", deployment_mode="collection", switches=0,
                      detection_enabled=False, ml_mode="OFF", rest_blocked=0, tier_blocked=0,
                      capture_state=self.state)
        if path == "/ips/status":
            return status
        if path == "/ips/collection":
            return self.snapshot()
        if path == "/ips/schema":
            return self.contract
        if path == "/ips/policy":
            with self.lock:
                return self.policy.snapshot()
        if path == "/ips/blocked":
            return {"blocked": []}
        if path == "/ips/alerts":
            return {"alerts": []}
        if path == "/ips/switches":
            return {"switches": [], "count": 0}
        if path == "/ips/metrics":
            metrics = dict(status, snort_running=False, rf_loaded=False, ae_loaded=False,
                           confirmed_attackers=0, alerts_total=0, alerts_last_60s=0,
                           by_attack={}, by_tier={}, cpu_pct=None, ram_pct=None, disk_pct=None)
            try:
                import psutil
                metrics.update(cpu_pct=psutil.cpu_percent(interval=None),
                               ram_pct=psutil.virtual_memory().percent,
                               disk_pct=psutil.disk_usage(self.directory).percent)
            except ImportError:
                pass
            return metrics
        return None


def collect(args, collector, stop):
    def ingest(frame):
        collector.health["received_frames"] += 1
        packet = decode(frame, collector.metadata, collector.content)
        if packet is None:
            collector.health["unsupported_frames"] += 1
        else:
            collector.record(packet)

    if args.pcap:
        with PcapReader(str(args.pcap)) as packets:
            for frame in packets:
                if stop.is_set():
                    break
                ingest(frame)
                collector.checkpoint()
        return

    if not hasattr(socket, "AF_PACKET"):
        raise RuntimeError("Live capture requires Linux")
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as capture:
        capture.bind((args.interface, 0))
        capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024**2)
        collector.health["socket_rcvbuf_bytes"] = capture.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        timestamp_option = getattr(socket, "SO_TIMESTAMPNS", 35)
        capture.setsockopt(socket.SOL_SOCKET, timestamp_option, 1)
        capture.setsockopt(263, 1, struct.pack("=IHH8s", socket.if_nametoindex(args.interface), 1, 0, b""))
        capture.settimeout(.5)
        def sample_kernel_statistics():
            received, drops = struct.unpack("II", capture.getsockopt(263, 6, 8))
            collector.health["kernel_packets"] += received
            collector.health["kernel_drops"] += drops
            collector.health["kernel_stats_reads"] += 1
            collector.health["kernel_stats_at"] = time.time()

        next_health = time.monotonic() + 5
        while not stop.is_set():
            try:
                payload, ancillary, flags, address = capture.recvmsg(262144, 128)
                collector.health["socket_truncated_frames"] += bool(flags & socket.MSG_TRUNC)
                if address[2] == socket.PACKET_OUTGOING:
                    collector.health["outgoing_copies_skipped"] += 1
                else:
                    try:
                        frame = Ether(payload)
                        for level, kind, value in ancillary:
                            if level == socket.SOL_SOCKET and kind == timestamp_option:
                                seconds, nanoseconds = struct.unpack("@ll", value[:struct.calcsize("@ll")])
                                frame.time = seconds + nanoseconds / 1_000_000_000
                                collector.health["kernel_timestamped_frames"] += 1
                                break
                        else:
                            collector.health["missing_kernel_timestamps"] += 1
                        ingest(frame)
                    except (ValueError, struct.error, IndexError, AttributeError, Scapy_Exception) as error:
                        collector.health["decoder_failures"] += 1
                        LOGGER.debug("Decoder rejected frame: %s", error)
            except socket.timeout:
                pass
            if time.monotonic() >= next_health:
                sample_kernel_statistics()
                with collector.lock:
                    collector.advance(time.time())
                    collector._check_storage()
                collector.checkpoint()
                next_health = time.monotonic() + 5
        # Include losses since the last periodic sample in the closed-run review gate.
        sample_kernel_statistics()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--interface")
    inputs.add_argument("--pcap", type=Path)
    parser.add_argument("--lan", action="append", required=True, help="Local IPv4 or IPv6 CIDR. Repeat for multiple subnets.")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--metadata", action="store_true", help="Measure DNS and complete TLS ClientHello metadata")
    parser.add_argument("--http", action="store_true", help="Measure complete HTTP/1 request header lexical features")
    parser.add_argument("--policy", type=Path, help="Operator-approved inventory and TCP initiation rules (shadow only)")
    parser.add_argument("--approved-baseline", type=Path, action="append", default=[],
                        help="Offline-reviewed profile matching the policy hash. Repeat per device.")
    parser.add_argument("--min-free-gib", type=float, default=1)
    parser.add_argument("--max-data-gib", type=float, default=5)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or args.min_free_gib <= 0 or args.max_data_gib <= 0:
        parser.error("Port and storage budgets must be positive and finite")
    if not math.isfinite(args.min_free_gib + args.max_data_gib):
        parser.error("Storage budgets must be finite")
    if args.approved_baseline and not args.policy:
        parser.error("--approved-baseline requires --policy")
    logging.basicConfig(level=logging.INFO)
    args.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    # OS-managed lock releases even when the process crashes.
    with collection_lease(args.data_dir):
        try:
            collector = HomeCollection(args.data_dir, args.lan, args.metadata, args.http,
                int(args.min_free_gib * 1024**3), int(args.max_data_gib * 1024**3),
                policy=args.policy, approved_baselines=args.approved_baseline,
                capture_source="pcap_replay" if args.pcap else "live_linux")
        except (ValueError, OSError, StorageLimitError) as error:
            parser.exit(78, str(error) + "\n")
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        handler = partial(DashboardHandler, sensor=collector)
        with ThreadingHTTPServer(("127.0.0.1", args.port), handler) as server:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                collector.state = "collecting"
                collector.checkpoint(force=True)
                LOGGER.info("Collection dashboard http://127.0.0.1:%d", args.port)
                collect(args, collector, stop)
                with collector.lock:
                    if collector.start is not None:
                        end = collector.start + 5 if args.pcap else time.time()
                        collector._flush(min(collector.start + 5, max(collector.start + .000001, end)), complete=False)
                collector.state = "replay_complete" if args.pcap else "stopped"
            except Exception as error:
                collector.state = "failed"
                collector.error = str(error)
                raise
            finally:
                collector.checkpoint(force=True)
                server.shutdown()


if __name__ == "__main__":
    try:
        main()
    except StorageLimitError as error:
        LOGGER.error("%s", error)
        raise SystemExit(78)
    except BlockingIOError:
        LOGGER.error("Another collector or offline reader owns this data directory")
        raise SystemExit(78)
