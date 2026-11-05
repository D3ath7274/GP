"""Protect active collection isolation and the retained thesis extraction lane."""

import csv
from functools import partial
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Controller"))

from http_dashboard import DashboardHandler
from traffic_capture import ALL_COLUMNS, TrafficCapture


class ReferencePreservationTests(unittest.TestCase):
    def test_home_import_needs_no_legacy_runner_or_inference(self):
        # A fresh interpreter prevents earlier suite imports from masking coupling.
        program = """
import importlib.abc
import sys
class RejectLegacy(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {'passive_ids', 'ml_inference', 'ae_inference', 'traffic_capture'}:
            raise AssertionError('unexpected legacy dependency: ' + fullname)
sys.meta_path.insert(0, RejectLegacy())
import home_sensor
assert home_sensor.DashboardHandler.__module__ == 'http_dashboard'
"""
        result = subprocess.run([sys.executable, "-c", program],
                                cwd=ROOT / "Controller", capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_shared_read_transport_serves_ui_docs_json_and_rejects_writes(self):
        class Sensor:
            def read(self, path):
                return {"mode": "read_only"} if path == "/ips/status" else None

        handler = partial(DashboardHandler, sensor=Sensor())
        with ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            base = "http://127.0.0.1:" + str(server.server_port)
            try:
                with urlopen(base + "/ips/status", timeout=5) as response:
                    self.assertEqual(json.load(response), {"mode": "read_only"})
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                for path in ("/", "/docs", "/docs/architecture/feature-rationale"):
                    with urlopen(base + path, timeout=5) as response:
                        self.assertIn("text/html", response.headers["Content-Type"])
                        self.assertGreater(len(response.read()), 100)
                with self.assertRaises(HTTPError) as missing:
                    urlopen(base + "/missing", timeout=5)
                self.assertEqual(missing.exception.code, 404)
                missing.exception.close()
                for method in ("POST", "DELETE", "PUT"):
                    with self.assertRaises(HTTPError) as mutation:
                        urlopen(Request(base + "/ips/block", method=method), timeout=5)
                    self.assertEqual(mutation.exception.code, 501)
                    mutation.exception.close()
            finally:
                server.shutdown()
                worker.join(timeout=5)

    def test_original_packets_still_produce_full_legacy_schema_and_known_math(self):
        # Two equal 60-byte SYNs one second apart; independent expected counts,
        # bytes, timing, size and flags. No model loading or background thread.
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"IPS_V2_FEATURES": "1"}):
            path = Path(temporary) / "legacy.csv"
            capture = TrafficCapture(str(path))
            capture._running = True
            packet = dict(src_ip="192.0.2.10", dst_ip="198.51.100.20",
                          src_port=40000, dst_port=80, protocol="TCP",
                          packet_size=60, eth_src="02:00:00:00:00:01",
                          eth_dst="02:00:00:00:00:02", tcp_flags={"SYN": True})
            with patch("traffic_capture.time.time", return_value=100):
                capture.record_packet(packet)
            with patch("traffic_capture.time.time", return_value=101):
                capture.record_packet(packet)
            with patch("traffic_capture.time.time", return_value=105):
                capture._flush_flows()
            capture._running = False
            with path.open(newline="", encoding="utf-8") as source:
                reader = csv.DictReader(source)
                self.assertEqual(reader.fieldnames, ALL_COLUMNS)
                rows = list(reader)
            self.assertEqual(len(ALL_COLUMNS), 102)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            for name, expected in {"total_packets": 2, "total_bytes": 120,
                                   "syn_count": 2, "ack_count": 0,
                                   "inter_arrival_mean": 1, "inter_arrival_std": 0,
                                   "avg_packet_size": 60, "pkt_size_std": 0,
                                   "small_pkt_ratio": 1, "flows_per_window": 1}.items():
                self.assertEqual(float(row[name]), expected, name)
            # Default legacy labels are intentionally not borrowed as site truth.
            self.assertEqual(row["label"], "0")


if __name__ == "__main__":
    unittest.main()
