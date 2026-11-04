"""Golden extraction, failure recovery, lease, report and preflight qualification."""

from argparse import Namespace
from copy import deepcopy
import csv
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Controller"))
sys.path.insert(0, str(ROOT / "scripts"))
from collection_io import collection_lease
from home_sensor import HomeCollection, StorageLimitError, atomic_json, collection_contract
from collection_report import report
from home_preflight import preflight, visibility
from qualify_home_collection import qualify
from qualify_home_runtime import exercise
from test_home_collection import observation


class ReadinessTests(unittest.TestCase):
    def sample(self, directory):
        collector = HomeCollection(directory, ["192.0.2.0/24"], min_free_bytes=1, capture_source="pcap_replay")
        collector.record(observation(timestamp=0))
        collector.advance(5)
        collector.state = "replay_complete"
        collector.checkpoint(force=True)
        return collector

    def test_all_feature_columns_match_independent_wire_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = qualify(Path(tmp) / "golden")
            self.assertEqual(result["status"], "PASS", result)
            self.assertGreaterEqual(result["checks"], 142)

    def test_restart_soak_keeps_rates_counts_novelty_and_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = exercise(Path(tmp) / "runtime", 20, 2)
            self.assertEqual(result["status"], "PASS", result)
            self.assertEqual(result["rows_checked"], 40)
            self.assertNotEqual(*result["run_ids"])

    def test_atomic_replace_failure_preserves_previous_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            atomic_json(path, {"generation":1})
            with patch("home_sensor.os.replace", side_effect=OSError("interrupted")):
                with self.assertRaises(OSError):
                    atomic_json(path, {"generation":2})
            self.assertEqual(json.loads(path.read_text())["generation"], 1)
            atomic_json(path, {"generation":3})
            self.assertEqual(json.loads(path.read_text())["generation"], 3)

    def test_corrupt_restart_profile_is_rejected_without_replacing_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.sample(tmp)
            path=Path(tmp)/"profile-state.json"
            data=json.loads(path.read_text());data["sources"][0][1]["windows"]=True
            path.write_text(json.dumps(data))
            raw=path.read_bytes()
            with self.assertRaises(ValueError):
                HomeCollection(tmp,["192.0.2.0/24"],min_free_bytes=1)
            self.assertEqual(path.read_bytes(),raw)

    def test_invalid_packet_timestamp_is_counted_without_an_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector=HomeCollection(tmp,["192.0.2.0/24"],min_free_bytes=1)
            packet=observation(timestamp=0);packet["timestamp"]=float("nan")
            collector.record(packet)
            self.assertEqual(collector.health["invalid_timestamps"],1)
            self.assertFalse(collector.windows)

    def test_process_lease_conflict_and_crash_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            program = "import sys,os;sys.path.insert(0,sys.argv[1]);from collection_io import collection_lease\nwith collection_lease(sys.argv[2]): os._exit(9)"
            with collection_lease(tmp):
                child = subprocess.run([sys.executable,"-c",program,str(ROOT/"Controller"),tmp],capture_output=True,timeout=10)
                self.assertNotEqual(child.returncode, 9)
            child = subprocess.run([sys.executable,"-c",program,str(ROOT/"Controller"),tmp],capture_output=True,timeout=10)
            self.assertEqual(child.returncode, 9)
            with collection_lease(tmp):
                pass

    def test_offline_report_refuses_active_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.sample(tmp)
            with collection_lease(tmp):
                with self.assertRaises(OSError):
                    report(tmp)

    def test_report_catches_interrupted_two_file_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.sample(tmp)
            path = next(Path(tmp).glob("policy-events-*.jsonl"))
            path.write_text("", encoding="utf-8")
            result = report(tmp)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("evidence_csv_length_mismatch", result["integrity_issues"])

    def test_report_verifies_evidence_digest_and_all_numeric_features(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.sample(tmp)
            path = next(Path(tmp).glob("policy-events-*.jsonl"))
            lines = path.read_text().splitlines()
            event = json.loads(lines[0]); event["identity"] = "forged"
            lines[0] = json.dumps(event)
            path.write_text("\n".join(lines)+"\n", encoding="utf-8")
            self.assertIn("evidence_hash_mismatch", report(tmp)["integrity_issues"])
            path = next(Path(tmp).glob("features-*.csv"))
            with path.open(newline="") as source:
                reader = csv.DictReader(source); columns = reader.fieldnames; rows = list(reader)
            rows[0]["packet_size_mean"] = "NaN"
            with path.open("w",newline="") as output:
                writer = csv.DictWriter(output,fieldnames=columns); writer.writeheader(); writer.writerows(rows)
            self.assertIn("nonfinite_feature", report(tmp)["integrity_issues"])

    def test_storage_failure_does_not_flush_pending_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = HomeCollection(tmp,["192.0.2.0/24"],min_free_bytes=1)
            collector.record(observation(timestamp=0))
            with patch("home_sensor.shutil.disk_usage",return_value=Namespace(free=0)):
                with self.assertRaises(StorageLimitError):
                    collector.advance(5)
            self.assertFalse(list(Path(tmp).glob("features-*.csv")))
            self.assertTrue(collector.windows)

    def test_report_does_not_infer_idle_gaps_or_parser_counts_are_attacks(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = self.sample(tmp)
            collector.record(observation(timestamp=60)); collector.advance(65); collector.checkpoint(force=True)
            result = report(tmp)
            self.assertFalse(result["integrity_issues"])
            self.assertEqual(result["status"], "REVIEW")
            device = result["devices"]["192.0.2.10@untagged"]
            self.assertEqual(device["unobserved_gap_seconds"],55)

    def test_visibility_requires_bound_dated_bidirectional_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"visibility.json"
            value = {"version":"visibility-v1","interface":"example0","networks":["192.0.2.0/24"],
                "valid_from":"2026-01-01T00:00:00+00:00","valid_until":"2027-01-01T00:00:00+00:00",
                "reviewer":"lab-operator","limitations":["Only tested local path"],
                "tested_paths":[{"alias":"phone-pc","family":"IPv4","request_seen":True,"response_seen":True,"reference":"private test ledger"}]}
            path.write_text(json.dumps(value))
            self.assertEqual(visibility(None,"example0",value["networks"],1780000000)[0],"REVIEW")
            self.assertEqual(visibility(path,"example0",value["networks"],1780000000)[0],"PASS")
            self.assertEqual(visibility(path,"example0",value["networks"],1800000000)[0],"REVIEW")
            with self.assertRaises(ValueError):
                visibility(path,"other0",value["networks"],1780000000)
            value["tested_paths"][0]["response_seen"] = False
            path.write_text(json.dumps(value))
            self.assertEqual(visibility(path,"example0",value["networks"],1780000000)[0],"REVIEW")

    def test_preflight_is_noncreating_and_rejects_changed_contract(self):
        with tempfile.TemporaryDirectory() as tmp, socket.socket() as listener:
            listener.bind(("127.0.0.1",0))
            data = Path(tmp)/"new"
            args = Namespace(interface="example0",pcap=None,lan=["192.0.2.0/24"],data_dir=data,
                port=listener.getsockname()[1],min_free_gib=.000001,max_data_gib=1,metadata=False,http=False,
                policy=None,approved_baseline=[],visibility_evidence=None)
            result = preflight(args)
            self.assertFalse(data.exists())
            self.assertIn("FAIL",[c["status"] for c in result["checks"] if c["check"]=="dashboard_port"])
            self.sample(data)
            args.metadata = True
            result = preflight(args)
            self.assertEqual(next(c for c in result["checks"] if c["check"]=="schema")["status"],"FAIL")
