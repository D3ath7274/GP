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
from site_policy import QUALITY_FAILURES
from audit_home_data import audit
from local_docs import document


def tls_client_hello(name=b"example.test", padding=0):
    """One TLS ClientHello record; padding uses the padding extension (21)."""
    names = b"\0" + len(name).to_bytes(2, "big") + name
    sni = len(names).to_bytes(2, "big") + names
    extensions = struct.pack("!HH", 0, len(sni)) + sni
    if padding:
        extensions += struct.pack("!HH", 21, padding) + bytes(padding)
    hello = b"\3\3" + bytes(32) + b"\0\0\2\x13\x01\1\0" + len(extensions).to_bytes(2, "big") + extensions
    handshake = b"\1" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\3\1" + len(handshake).to_bytes(2, "big") + handshake


def offload_frame(payload, ip_length=0):
    """An outbound IPv4 frame as a host capture sees large-send offload: total length 0."""
    return bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                 / IP(src="192.0.2.10", dst="198.51.100.20", len=ip_length)
                 / TCP(sport=50000, dport=443, flags="PA") / payload)


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
        record = tls_client_hello()
        parsed = client_hello(record)
        self.assertTrue(parsed["sni_present"])
        self.assertNotIn("example.test", json.dumps(parsed))
        with self.assertRaises(ValueError):
            client_hello(record[:-1])

    def test_encrypted_bytes_resembling_tls_are_not_parse_errors(self):
        # Observed in a pilot capture: mid-stream server data starting 0x16 with 0x01 at offset 5.
        lookalike = bytes([0x16, 0xEF, 0xD1, 0x30, 0xCE, 0x01]) + bytes(range(256)) * 5
        self.assertIsNone(client_hello(lookalike))

        def segment(payload):
            frame = (Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
                     / IP(src="198.51.100.20", dst="192.0.2.10")
                     / TCP(sport=443, dport=50000, flags="PA") / payload)
            return decode(Ether(bytes(frame)), metadata=True)

        result = segment(lookalike)
        self.assertIsNone(result["tls"])
        self.assertFalse(result.get("tls_error"))
        self.assertTrue(segment(tls_client_hello()[:-1])["tls_error"])

    def test_only_plausible_unterminated_requests_are_http_errors(self):
        def request(payload):
            frame = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                     / IP(src="192.0.2.10", dst="198.51.100.20")
                     / TCP(sport=50000, dport=80, flags="PA") / payload)
            return decode(Ether(bytes(frame)), content=True)

        # Starts of server segments from a pilot capture: encrypted bytes, not requests.
        for lookalike in (b"QXZ \x93\x11\xfe\x00 binary data", b"YLG *V\xb6^&$q\x10\x1d\xf8\xfc\x17"):
            self.assertFalse(request(lookalike)["http_error"], lookalike)
        for start in (b"GET /very/long/path", b"OPTIONS * HTTP/1.1\r\nHost", b"GET http://example.test/",
                      b"CONNECT example.test:443", b"GET index.html HTTP/1.1\r\nHost: example"):
            self.assertTrue(request(start)["http_error"], start)
        complete = request(b"GET index.html HTTP/1.1\r\nHost: example\r\n\r\n")
        self.assertEqual(complete["http"]["length"], len(b"index.html"))

    def test_one_compatibility_ccs_before_retried_clienthello(self):
        ccs = b"\x14\x03\x03\x00\x01\x01"
        record = tls_client_hello()
        self.assertEqual(client_hello(ccs + record), client_hello(record))
        self.assertIsNone(client_hello(ccs))
        self.assertIsNone(client_hello(ccs + ccs + record))
        self.assertIsNone(client_hello(b"\x14\x03\x03\x00\x02\x01\x01" + record))

    def test_ipv4_zero_length_offload_frame_uses_captured_datagram(self):
        record = tls_client_hello(padding=1600)
        result = decode(Ether(offload_frame(record)), metadata=True)
        self.assertTrue(result["ipv4_zero_length"])
        self.assertFalse(result["capture_truncated"])
        self.assertEqual(result["payload_length"], len(record))
        self.assertTrue(result["tls"]["sni_present"])
        normal = decode(Ether(offload_frame(record, ip_length=None)), metadata=True)
        self.assertNotIn("ipv4_zero_length", normal)
        self.assertEqual(normal["payload_length"], result["payload_length"])
        self.assertEqual(normal["tls"], result["tls"])

    def test_ipv4_zero_length_never_counts_padding_or_snap_cut_bytes(self):
        syn = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                    / IP(src="192.0.2.10", dst="198.51.100.20", len=0) / TCP(flags="S"))
        padded = decode(Ether(syn + bytes(60 - len(syn))))
        self.assertTrue(padded["ipv4_zero_length"])
        self.assertEqual(padded["payload_length"], 0)
        raw = offload_frame(tls_client_hello(padding=1600))
        cut = Ether(raw[:200])
        cut.wirelen = len(raw)
        result = decode(cut, metadata=True)
        self.assertTrue(result["capture_truncated"])
        self.assertEqual(result["payload_length"], 0)
        self.assertIsNone(result["tls"])

    def test_ipv4_zero_length_frames_are_counted_and_hold_learning(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = self.collector(tmp, metadata=True)
            frame = Ether(offload_frame(tls_client_hello(padding=1600)))
            collector.record(decode(frame, metadata=True) | {"timestamp": 1})
            collector.advance(6)
            collector.checkpoint(force=True)
            result = audit(tmp)
            self.assertEqual(result["quality_counters"]["ipv4_zero_length_frames"], 1)
            self.assertEqual(result["counts"]["g16_complete_clienthello_count"], 1)
        self.assertIn("ipv4_zero_length_frames", QUALITY_FAILURES)

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
