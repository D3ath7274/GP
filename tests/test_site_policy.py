"""Policy behavior under identity changes, measurement faults and attempted promotion."""

from copy import deepcopy
import csv
import json
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path
import subprocess
import socket
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Controller"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap
from home_sensor import HomeCollection, atomic_json
from passive_ids import DashboardHandler
from site_features import DeviceWindow, decode
from site_policy import ShadowPolicy, digest, quality_for, validate_policy
from review_site_baseline import approve, stopped_collection


ROOT = Path(__file__).resolve().parents[1]


def policy():
    config = json.loads((ROOT / "Controller/site_policy.example.json").read_text())
    config["observation"].update(bidirectional_verified=True, reference="test-ledger-1",
        valid_from="1970-01-01T00:00:00Z", valid_until="1971-01-01T00:00:00Z")
    config["devices"][0].update(valid_from="1970-01-01T00:00:00Z", valid_until="1971-01-01T00:00:00Z")
    return config


def packet(at=0, port=443, flags="S", mac="02:00:00:00:00:01", udp=False):
    transport = UDP(dport=port) if udp else TCP(dport=port, flags=flags)
    frame = Ether(src=mac) / IP(src="192.0.2.10", dst="192.0.2.20") / transport
    return decode(Ether(bytes(frame))) | {"timestamp": at}


class PolicyTests(unittest.TestCase):
    def create(self, directory, **kwargs):
        path = Path(directory) / "input-policy.json"
        atomic_json(path, policy())
        collector = HomeCollection(directory, ["192.0.2.0/24"], policy=path,
            min_free_bytes=1, capture_source="live_linux", **kwargs)
        # Synthetic live health permits deterministic gate tests; it is not a Linux capture test.
        collector.health.update(kernel_stats_reads=1, kernel_stats_at=10)
        return collector, path

    def closed_run(self, directory):
        collector, path = self.create(directory)
        collector.record(packet(0))
        collector.record(packet(5))
        collector.advance(10)
        collector.state = "stopped"
        collector.checkpoint(force=True)
        return collector, path

    def review(self, directory, path):
        return approve(directory, path, "camera-1", "1970-01-01T00:00:00Z",
                       "1970-01-01T00:00:10Z", "test-reviewer", "independent test activity ledger")

    def test_policy_rejects_typo_duplicate_and_invalid_binding(self):
        config = policy()
        config["roles"]["camera"]["tcp_initiation_allow"][0]["prot"] = "tcp"
        with self.assertRaises(ValueError):
            validate_policy(config)
        for field, value in (("mac", "ff:ff:ff:ff:ff:ff"), ("vlan", "4095"),
                             ("valid_until", "1969-01-01T00:00:00Z")):
            config = policy()
            config["devices"][0][field] = value
            with self.assertRaises(ValueError):
                validate_policy(config)
        config = policy()
        config["devices"].append(deepcopy(config["devices"][0]))
        with self.assertRaises(ValueError):
            validate_policy(config)

    def test_role_violation_is_shadow_and_cannot_enter_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector, _ = self.create(tmp)
            collector.record(packet(port=22))
            collector.advance(5)
            snapshot = collector.read("/ips/policy")
            finding = snapshot["recent_findings"][0]
            self.assertEqual(finding["findings"][0]["type"], "ROLE_SERVICE_VIOLATION")
            self.assertEqual(finding["learning"], "HOLD")
            self.assertEqual(finding["action"], "SHADOW_ONLY")
            self.assertEqual(snapshot["candidates"], {})
            self.assertEqual(collector.read("/ips/blocked"), {"blocked": []})
            collector.record(packet(at=5, port=443))
            collector.advance(10)
            # Returning to permitted traffic cannot clear an incident hold during this run.
            self.assertEqual(collector.policy.candidates, {})
            self.assertEqual(collector.read("/ips/policy")["incident_held_subjects"], 1)

    def test_tcp_reply_and_udp_are_unassessed_by_initiation_policy(self):
        window = DeviceWindow()
        from collections import Counter
        for item in (packet(port=49152, flags="SA"), packet(port=49152, flags="A"), packet(udp=True)):
            window.observe(item, True, Counter())
        self.assertEqual(window.tcp_initiations, set())

    def test_quality_failure_freezes_later_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector, _ = self.create(tmp)
            collector.record(packet())
            collector.advance(5)
            before = deepcopy(collector.policy.candidates)
            collector.health["kernel_drops"] += 1
            collector.record(packet(5))
            collector.advance(10)
            self.assertEqual(before, collector.policy.candidates)
            row = collector.snapshot()["shadow_policy"]["counts"]
            self.assertGreater(row["quality_degraded"], 0)
            collector.record(packet(10))
            collector.advance(15)
            self.assertEqual(before, collector.policy.candidates)

    def test_identity_change_and_expiry_are_not_approved(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector, _ = self.create(tmp)
            collector.record(packet(mac="02:00:00:00:00:02"))
            collector.advance(5)
            row = collector.policy.snapshot()["recent_findings"][0]
            self.assertEqual(row["identity"], "CONFLICTING_SOURCE_MAC")
            self.assertEqual(row["learning"], "HOLD")
            self.assertEqual(collector.policy.candidates, {})
        with tempfile.TemporaryDirectory() as tmp:
            collector, _ = self.create(tmp)
            collector.record(packet(40_000_000))
            collector.advance(40_000_005)
            self.assertEqual(collector.policy.snapshot()["recent_findings"][0]["identity"], "EXPIRED_BINDING")

    def test_partial_replay_unverified_and_stale_windows_are_held(self):
        row = {"window_complete": 1, "window_start_utc": "1970-01-01T00:00:00Z",
               "window_end_utc": "1970-01-01T00:00:05Z"}
        health = {"kernel_stats_reads": 1, "kernel_stats_at": 5}
        self.assertEqual(quality_for(policy(), row, health, "pcap_replay")[0], "UNAVAILABLE")
        config = policy()
        config["observation"].update(bidirectional_verified=False, valid_from=None, valid_until=None)
        self.assertEqual(quality_for(config, row, health, "live_linux")[0], "UNAVAILABLE")
        self.assertEqual(quality_for(policy(), row, health | {"kernel_stats_at": 100}, "live_linux")[0], "UNAVAILABLE")
        self.assertEqual(quality_for(policy(), row | {"window_complete": 0}, health, "live_linux")[0], "DEGRADED")

    def test_approved_baseline_is_frozen_and_bound_to_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector, path = self.closed_run(tmp)
            profile = self.review(tmp, path)
            original = deepcopy(profile)
            observer = ShadowPolicy(policy(), [profile])
            # A future high-rate window changes only the candidate and diagnostic residual.
            window = DeviceWindow(macs={"02:00:00:00:00:01"}, out_packets=500)
            with next(Path(tmp).glob("features-*.csv")).open() as source:
                row = next(csv.DictReader(source))
            row.update(window_complete=1, out_pps=100, out_bytes_per_second=10000,
                       g14_new_syn_rate=100, packet_size_mean=100)
            record = observer.evaluate(row, window, {"kernel_stats_reads": 1, "kernel_stats_at": 5}, "live_linux")
            self.assertEqual(profile, original)
            self.assertGreater(record["baseline_residuals"]["out_pps"], 0)
            self.assertEqual(record["findings"], [])  # Residuals have no calibrated threshold yet.
            revised = policy()
            revised["revision"] = "different-policy"
            with self.assertRaises(ValueError):
                ShadowPolicy(revised, [profile])
            approved_path = Path(tmp) / "approved.json"
            atomic_json(approved_path, profile)
            with self.assertRaisesRegex(ValueError, "different collection settings"):
                self.create(tmp, metadata=True, approved_baselines=[approved_path])

    def test_review_rejects_replay_even_if_early_windows_look_eligible(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector, path = self.closed_run(tmp)
            collector.capture_source = "pcap_replay"
            collector.checkpoint(force=True)
            with self.assertRaisesRegex(ValueError, "unmeasured"):
                self.review(tmp, path)

    def test_policy_snapshot_does_not_expose_mutable_candidate_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector, _ = self.closed_run(tmp)
            snapshot = collector.policy.snapshot()
            snapshot["candidates"].clear()
            self.assertIn("camera-1", collector.policy.candidates)

    def test_review_rejects_post_window_loss_and_missing_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector, path = self.closed_run(tmp)
            collector.health["kernel_drops"] = 1
            collector.checkpoint(force=True)
            with self.assertRaisesRegex(ValueError, "quality-degraded"):
                self.review(tmp, path)
        with tempfile.TemporaryDirectory() as tmp:
            _, path = self.closed_run(tmp)
            events = next(Path(tmp).glob("policy-events-*.jsonl"))
            events.write_text(events.read_text().split("\n", 1)[1])
            with self.assertRaises(ValueError):
                self.review(tmp, path)

    def test_review_rejects_hidden_device_id_and_feature_tampering(self):
        for field, value in (("device_id", "other-device"), ("features", {"out_pps": 999})):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                _, path = self.closed_run(tmp)
                events = next(Path(tmp).glob("policy-events-*.jsonl"))
                records = [json.loads(line) for line in events.read_text().splitlines()]
                records[0][field] = value
                records[0]["evidence_id"] = digest({k: v for k, v in records[0].items() if k != "evidence_id"})
                events.write_text("".join(json.dumps(record) + "\n" for record in records))
                with self.assertRaises((ValueError, KeyError)):
                    self.review(tmp, path)

    def test_review_rejects_an_active_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, path = self.closed_run(tmp)
            with stopped_collection(Path(tmp)):
                with self.assertRaisesRegex(ValueError, "Stop the collector"):
                    self.review(tmp, path)

    def test_csv_contract_and_unconfigured_collection_remain_compatible(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = HomeCollection(tmp, ["192.0.2.0/24"], min_free_bytes=1)
            self.assertEqual(len(collector.columns), 71)
            collector.record(packet())
            collector.advance(5)
            self.assertFalse(collector.read("/ips/policy")["configured"])
            self.assertEqual(collector.read("/ips/policy")["candidates"], {})
            self.assertEqual(len(list(Path(tmp).glob("policy-events-*.jsonl"))), 1)

    def test_review_cli_creates_loadable_profile_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector, path = self.closed_run(tmp)
            output = Path(tmp) / "reviewed.json"
            command = [sys.executable, str(ROOT / "scripts/review_site_baseline.py"), "approve",
                       "--data-dir", tmp, "--policy", str(path), "--device-id", "camera-1",
                       "--start", "1970-01-01T00:00:00Z", "--end", "1970-01-01T00:00:10Z",
                       "--reviewer", "test-operator", "--reason", "Reviewed synthetic ledger",
                       "--output", str(output)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            restored, _ = self.create(tmp, approved_baselines=[output])
            self.assertEqual(restored.policy.snapshot()["approved_device_ids"], ["camera-1"])
            original = output.read_bytes()
            duplicate = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertEqual(output.read_bytes(), original)

    def test_policy_http_dashboard_docs_and_rejected_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector, _ = self.create(tmp)
            collector.record(packet(port=22))
            collector.advance(5)
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(DashboardHandler, sensor=collector))
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            origin = "http://127.0.0.1:" + str(server.server_port)
            try:
                with urlopen(origin + "/ips/policy") as response:
                    payload = json.load(response)
                self.assertEqual(payload["counts"]["finding_windows"], 1)
                self.assertFalse(payload["enforcement_enabled"])
                with urlopen(origin + "/") as response:
                    self.assertIn(b'policy-findings', response.read())
                with urlopen(origin + "/docs/security/shadow-policy") as response:
                    self.assertIn(b'Shadow policy', response.read())
                with self.assertRaises(HTTPError) as error:
                    urlopen(Request(origin + "/ips/policy", data=b"{}", method="POST"))
                self.assertEqual(error.exception.code, 501)
                error.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                worker.join()

    def test_home_cli_replay_emits_shadow_evidence_and_unknown_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config = directory / "policy.json"
            atomic_json(config, policy())
            frames = []
            for at, port in ((0, 22), (5, 443), (10, 443)):
                frame = Ether(src="02:00:00:00:00:01") / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(dport=port, flags="S")
                frame.time = at
                frames.append(frame)
            capture = directory / "fixture.pcap"
            wrpcap(str(capture), frames)
            with socket.socket() as available:
                available.bind(("127.0.0.1", 0))
                port = available.getsockname()[1]
            destination = directory / "collection"
            result = subprocess.run([sys.executable, str(ROOT / "Controller/home_sensor.py"),
                "--pcap", str(capture), "--lan", "192.0.2.0/24", "--policy", str(config),
                "--data-dir", str(destination), "--port", str(port), "--min-free-gib", "0.000001"],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads(next(destination.glob("run-*.json")).read_text())
            self.assertEqual(manifest["capture_state"], "replay_complete")
            self.assertEqual(manifest["capture_source"], "pcap_replay")
            self.assertEqual(manifest["shadow_policy"]["counts"]["finding_windows"], 1)
            with next(destination.glob("features-*.csv")).open() as source:
                self.assertTrue(all(row["ground_truth"] == "UNKNOWN" for row in csv.DictReader(source)))
            self.assertTrue(list(destination.glob("policy-events-*.jsonl")))


if __name__ == "__main__":
    unittest.main()
