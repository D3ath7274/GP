import csv
import json
import struct
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Controller"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from home_sensor import HomeCollection, StorageLimitError
from site_features import DeviceWindow, FeatureHistory, client_hello, decode
from audit_home_data import audit
from local_docs import document


def observation(dst="192.0.2.20", timestamp=1, ipv6=False, payload=b""):
    ip = IPv6(src="2001:db8::10", dst="2001:db8::20") if ipv6 else IP(src="192.0.2.10", dst=dst)
    frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / ip / TCP(sport=10000, dport=80, flags="S") / payload
    frame.time = timestamp
    return decode(Ether(bytes(frame))) | {"timestamp": timestamp}


class HomeTests(unittest.TestCase):
    def collector(self, path, **kwargs):
        return HomeCollection(path, ["192.0.2.0/24", "2001:db8::/64"],
                              min_free_bytes=1, **kwargs)

    def test_novelty_is_measured_before_history_update(self):
        history = FeatureHistory()
        health = Counter()
        for peers, expected in [({"one"}, 1), ({"one"}, 0), ({"one", "two"}, .5)]:
            result = history.features("device", DeviceWindow(peers=peers), 0, 5, health)
            self.assertEqual(result["device_new_dst_ratio"], expected)

    def test_window_rate_counts_and_ipv6(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = self.collector(tmp)
            packet = observation()
            collector.record(packet)
            collector.record(observation(timestamp=2, ipv6=True))
            collector.advance(6)
            with next(Path(tmp).glob("features-*.csv")).open() as output:
                rows = list(csv.DictReader(output))
            self.assertEqual(len(rows), 4)  # Each local endpoint has its own directional row.
            self.assertEqual(float(rows[0]["out_pps"]), .2)
            self.assertEqual(int(rows[0]["out_bytes"]), packet["size"])
            self.assertTrue(all(row["ground_truth"] == "UNKNOWN" for row in rows))

    def test_daily_rotation_state_reload_and_schema_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = self.collector(tmp)
            collector.record(observation(timestamp=86399))
            collector.record(observation(timestamp=86401))
            collector.advance(86406)
            collector.checkpoint(force=True)
            self.assertEqual(len(list(Path(tmp).glob("features-*.csv"))), 2)
            restored = self.collector(tmp)
            restored.record(observation(timestamp=86411))
            restored.advance(86416)
            with next(Path(tmp).glob("*" + restored.run_id + ".csv")).open() as output:
                rows = list(csv.DictReader(output))
            self.assertEqual(float(rows[0]["device_new_dst_ratio"]), 0)
            with self.assertRaises(ValueError):
                self.collector(tmp, metadata=True)

    def test_late_and_capacity_loss_are_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = self.collector(tmp, max_sources=1)
            collector.record(observation(timestamp=10))
            collector.record(observation(timestamp=1))
            self.assertEqual(collector.health["late_packets"], 1)
            self.assertGreater(collector.health["source_window_omissions"], 0)
            self.assertEqual(len(collector.windows), 1)

    def test_storage_limit_stops_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(StorageLimitError):
                self.collector(tmp, max_data_bytes=1)

    def test_rolling_buckets_expire(self):
        history = FeatureHistory()
        history.features("device", DeviceWindow(peers={"old"}, ports={80}), 0, 5, Counter())
        result = history.features("device", DeviceWindow(peers={"new"}, ports={443}), 3601, 5, Counter())
        self.assertEqual(result["g13_dst_ips_hour_bucketed"], 1)
        self.assertEqual(result["g13_dst_ports_10m_bucketed"], 1)

    def test_dns_is_opt_in_and_names_are_reduced(self):
        frame = Ether()/IP(src="192.0.2.10", dst="192.0.2.1")/UDP(dport=53)/DNS(qd=DNSQR(qname="private.example"))
        self.assertIsNone(decode(frame)["dns"])
        parsed = decode(frame, metadata=True)["dns"]
        self.assertTrue(parsed["query"])
        self.assertNotIn("private.example", json.dumps(parsed))

    def test_http_is_opt_in_and_fragmented_inputs_do_not_get_full_parse(self):
        payload = b"GET /private?a=%41 HTTP/1.1\r\nHost: example\r\n\r\n"
        frame = Ether()/IP()/TCP()/payload
        self.assertIsNone(decode(frame)["http"])
        self.assertEqual(decode(frame, content=True)["http"]["length"], len(b"/private?a=%41"))
        partial = Ether()/IP()/TCP()/b"GET /private HTTP/1.1\r\n"
        self.assertTrue(decode(partial, content=True)["http_error"])

    def test_complete_tls_and_incomplete_tls(self):
        name = b"example.test"
        names = b"\0" + len(name).to_bytes(2, "big") + name
        sni = len(names).to_bytes(2, "big") + names
        extensions = struct.pack("!HH", 0, len(sni)) + sni
        hello = b"\3\3" + bytes(32) + b"\0\0\2\x13\x01\1\0" + len(extensions).to_bytes(2, "big") + extensions
        handshake = b"\1" + len(hello).to_bytes(3, "big") + hello
        record = b"\x16\3\1" + len(handshake).to_bytes(2, "big") + handshake
        parsed = client_hello(record)
        self.assertTrue(parsed["sni_present"])
        self.assertNotIn("example.test", json.dumps(parsed))
        with self.assertRaises(ValueError):
            client_hello(record[:-1])

    def test_capped_cardinality_is_recorded(self):
        window = DeviceWindow()
        health = Counter()
        for i in range(150):
            window.observe(observation(dst="198.51.100." + str(i)), True, health)
        self.assertEqual(len(window.peers), 128)
        self.assertGreater(health["cardinality_overflows"], 0)

    def test_audit_detects_corrupted_rates(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = self.collector(tmp)
            collector.record(observation())
            collector.advance(6)
            collector.checkpoint(force=True)
            self.assertFalse(audit(tmp)["integrity_issues"])
            path = next(Path(tmp).glob("features-*.csv"))
            with path.open(newline="") as source:
                rows = list(csv.DictReader(source))
            rows[0]["out_pps"] = "999999"
            with path.open("w", newline="") as output:
                writer = csv.DictWriter(output, fieldnames=collector.columns)
                writer.writeheader()
                writer.writerows(rows)
            self.assertEqual(audit(tmp)["integrity_issues"]["rate_mismatch"], 1)

    def test_local_docs_route_and_traversal(self):
        status, content_type, page = document("/docs/deployment/home-collection")
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn(b"site-v3.0", page)
        self.assertEqual(document("/docs/../../Controller/ips_config.json")[0], 404)

    def test_pair_periodicity_has_sample_support(self):
        history = FeatureHistory()
        for timestamp in (0, 60, 120):
            row = history.features("source", DeviceWindow(peers={"destination"}), timestamp, 5, Counter())
        self.assertIsNone(row["g13_pair_interval_cv_mean"])
        row = history.features("source", DeviceWindow(peers={"destination"}), 180, 5, Counter())
        self.assertEqual(row["g13_pair_interval_cv_mean"], 0)
        self.assertEqual(row["g13_pair_interval_supported_pairs"], 1)

    def test_broadcast_does_not_create_a_device_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = self.collector(tmp)
            collector.record(observation(dst="192.0.2.255"))
            self.assertEqual(len(collector.windows), 1)

    def test_ethernet_padding_is_not_application_payload(self):
        frame = Ether()/IP(src="192.0.2.10", dst="198.51.100.20")/TCP(flags="S")
        padded = Ether(bytes(frame) + bytes(20))
        result = decode(padded)
        self.assertEqual(result["payload_length"], 0)
        self.assertEqual(result["size"], len(bytes(frame)) + 20)
