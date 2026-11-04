"""Evidence boundaries, ordered semantics and durable/read-only policy operations."""

from copy import deepcopy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Controller"))
from firewall_policy import (AddressResolver, PolicyEvaluator, canonical_bytes, diff_policies,
                             normalize, parse_json, port_intervals, query, read_input, sha256)
from policy_http import make_server
from policy_store import PolicyStore

REFERENCE = ROOT / "examples/policies/reference-v1.json"


def model():
    return read_input(REFERENCE)[1]


def point(port=443, source="192.0.2.10", destination="198.51.100.20", source_port=None):
    return query(source, destination, "tcp", port, source_port)


class PolicyModelTests(unittest.TestCase):
    def test_normalization_is_stable_and_rejects_duplicate_json_keys(self):
        policy = model()
        self.assertEqual(canonical_bytes(policy), canonical_bytes(normalize(policy)))
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            parse_json(b'{"format":"one","format":"two"}')

    def test_native_vendor_or_unknown_fields_are_never_silently_normalized(self):
        for field, value in (("source_kind", "vendor_api"), ("native_rulebase", [])):
            with self.subTest(field=field):
                policy = model()
                policy[field] = value
                with self.assertRaises(ValueError):
                    normalize(policy)
        with self.assertRaises(ValueError):
            normalize({"nftables": []})

    def test_groups_cycles_missing_objects_and_unresolved_selectors(self):
        policy = model()
        resolved = AddressResolver(policy["objects"]).resolve(["@trusted_clients"])
        self.assertEqual(len(resolved.networks), 2)
        self.assertFalse(resolved.unresolved)
        for members in (["@trusted_clients"], ["@missing"]):
            changed = deepcopy(policy)
            changed["objects"]["workstation"] = {"kind": "address_group", "members": members}
            with self.assertRaises(ValueError):
                normalize(changed)
        self.assertTrue(AddressResolver(policy["objects"]).resolve(["@application_clients"]).unresolved)

    def test_strict_networks_port_ranges_and_bool_rejection(self):
        self.assertEqual(port_intervals([443, "80-90", 91, 80]), ((80, 91), (443, 443)))
        for ports in ([True], [65536], ["90-80"], ["any"], []):
            with self.assertRaises(ValueError):
                port_intervals(ports)
        policy = model()
        policy["rules"][0]["sources"] = ["192.0.2.10/24"]
        with self.assertRaises(ValueError):
            normalize(policy)

    def test_duplicate_rule_id_or_position_rejected(self):
        for field in ("id", "position"):
            policy = model()
            policy["rules"][1][field] = policy["rules"][0][field]
            with self.assertRaises(ValueError):
                normalize(policy)

    def test_resource_limits_nonfinite_and_unknown_rule_fields(self):
        with self.assertRaises(ValueError):
            parse_json(b'{"bad":NaN}')
        policy = model()
        policy["rules"][0]["source_zone"] = "unspecified-native-semantics"
        with self.assertRaises(ValueError):
            normalize(policy)
        with patch("firewall_policy.MAX_EXPANSION_WORK", 2), self.assertRaisesRegex(ValueError, "expansion work"):
            normalize(model())

    def test_allow_deny_default_and_disabled_search_are_distinct(self):
        evaluator = PolicyEvaluator(model())
        self.assertEqual(evaluator.search(point())["model_verdict"], "ALLOW")
        self.assertEqual(evaluator.search(point(22))["decisive_rule"], "deny-ssh")
        denied = evaluator.search(point(source="203.0.113.10"))
        self.assertEqual(denied["model_verdict"], "DENY")
        self.assertTrue(denied["used_default"])
        disabled = evaluator.search(point(2222), include_disabled=True)
        self.assertEqual(disabled["matches"][0]["id"], "disabled-2222")
        self.assertEqual(disabled["model_verdict"], "DENY")
        self.assertEqual(disabled["reachability"], "NOT_EVALUATED")

    def test_unknown_earlier_rule_cannot_be_overridden_by_later_deny(self):
        result = PolicyEvaluator(model()).search(point(8443))
        self.assertEqual(result["model_verdict"], "INDETERMINATE")
        self.assertIsNone(result["decisive_rule"])
        self.assertEqual(result["preceding_uncertain_rules"], ["application-8443"])

    def test_unknown_after_decisive_match_does_not_override_model_order(self):
        policy = model()
        policy["rules"][2]["destination_ports"] = [443]
        self.assertEqual(PolicyEvaluator(normalize(policy)).search(point())["model_verdict"], "ALLOW")

    def test_global_context_unknown_and_missing_source_port(self):
        policy = model()
        policy["unmodeled_context"] = ["Native NAT lookup stage unresolved"]
        self.assertEqual(PolicyEvaluator(normalize(policy)).search(point())["model_verdict"], "INDETERMINATE")
        policy = model()
        policy["rules"][0]["source_ports"] = ["40000-50000"]
        evaluator = PolicyEvaluator(normalize(policy))
        self.assertEqual(evaluator.search(point())["model_verdict"], "INDETERMINATE")
        self.assertEqual(evaluator.search(point(source_port=45000))["model_verdict"], "ALLOW")
        self.assertEqual(evaluator.search(point(source_port=1000))["model_verdict"], "DENY")

    def test_ipv6_udp_and_invalid_query_contracts(self):
        evaluator = PolicyEvaluator(model())
        self.assertEqual(evaluator.search(query("2001:db8::10", "2001:db8:1::20", "tcp", 443))["model_verdict"], "ALLOW")
        self.assertEqual(evaluator.search(query("192.0.2.10", "198.51.100.53", "udp", 53))["model_verdict"], "ALLOW")
        for args in (("192.0.2.10", "2001:db8::10", "tcp", 443),
                     ("192.0.2.10", "198.51.100.20", "tcp", None),
                     ("192.0.2.10", "198.51.100.20", "icmp", 443)):
            with self.assertRaises(ValueError):
                query(*args)

    def test_search_limit_does_not_skip_effective_rules(self):
        result = PolicyEvaluator(model()).search(point(8443), limit=1)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["total_matches"], 2)
        self.assertEqual(result["model_verdict"], "INDETERMINATE")

    def test_diff_has_explicit_context_and_no_actor_guess(self):
        before = model()
        after = read_input(ROOT / "examples/policies/reference-v2.json")[1]
        changes = diff_policies(before, after)
        self.assertEqual(changes["rules"]["modified"][0]["id"], "allow-web")
        self.assertIn("destination_ports", changes["rules"]["modified"][0]["fields"])
        self.assertEqual(changes["rules"]["modified"][0]["field_changes"]["destination_ports"]["after"], ["443", "8443"])
        self.assertEqual(changes["actor_attribution"], "UNAVAILABLE")
        after["tenant"] = "another-tenant"
        with self.assertRaises(ValueError):
            diff_policies(before, after)


class PolicyStoreTests(unittest.TestCase):
    def create(self, path):
        raw, policy = read_input(REFERENCE)
        with PolicyStore(path, writable=True) as store:
            result = store.import_snapshot(raw, policy)
        return result["snapshot_id"]

    def test_duplicate_import_and_raw_history_preserve_one_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.sqlite3"
            identifier = self.create(path)
            with PolicyStore(path, writable=True) as store:
                raw, policy = read_input(REFERENCE)
                second = store.import_snapshot(raw, policy)
                self.assertFalse(second["created"])
                self.assertEqual(store.list_snapshots()["total"], 1)
                self.assertEqual(store.provenance(identifier)["total_imports"], 2)
            before = path.read_bytes()
            with PolicyStore(path) as store:
                self.assertEqual(store.get_snapshot(identifier), model())
                with self.assertRaises(ValueError):
                    store.import_snapshot(raw, policy)
                with self.assertRaises(sqlite3.OperationalError):
                    store.connection.execute("DELETE FROM snapshots")
            self.assertEqual(path.read_bytes(), before)

    def test_wrong_raw_model_pair_and_transaction_failure_leave_no_partial_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.sqlite3"
            raw, policy = read_input(REFERENCE)
            with PolicyStore(path, writable=True) as store:
                changed = deepcopy(policy)
                changed["policy_revision"] = "unrelated"
                with self.assertRaises(ValueError):
                    store.import_snapshot(raw, changed)
                store.connection.execute("CREATE TRIGGER abort_import BEFORE INSERT ON imports BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
                with self.assertRaises(sqlite3.IntegrityError):
                    store.import_snapshot(raw, policy)
                self.assertEqual(store.list_snapshots()["total"], 0)
                self.assertEqual(store.connection.execute("SELECT count(*) FROM raw_exports").fetchone()[0], 0)

    def test_missing_read_store_and_unrelated_database_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "absent.sqlite3"
            with self.assertRaises(sqlite3.OperationalError):
                PolicyStore(path)
            self.assertFalse(path.exists())
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.execute("CREATE TABLE private_data(value TEXT)")
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                PolicyStore(path, writable=True)
            self.assertEqual(path.read_bytes(), before)

    def test_snapshot_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.sqlite3"
            identifier = self.create(path)
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.execute("UPDATE snapshots SET normalized=? WHERE id=?", (b'{}', identifier))
            with PolicyStore(path) as store:
                with self.assertRaisesRegex(ValueError, "integrity"):
                    store.get_snapshot(identifier)

    def test_raw_export_tampering_is_detected_during_read_and_reimport(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.sqlite3"
            identifier = self.create(path)
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.execute("UPDATE raw_exports SET content=?", (b'corrupt',))
            with PolicyStore(path, writable=True) as store:
                with self.assertRaisesRegex(ValueError, "integrity"):
                    store.provenance(identifier)
                raw, policy = read_input(REFERENCE)
                with self.assertRaisesRegex(ValueError, "integrity"):
                    store.import_snapshot(raw, policy)

    def test_cli_validate_import_list_search_and_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "policy.sqlite3")
            def run(*args):
                result = subprocess.run([sys.executable, str(ROOT / "scripts/policy_inventory.py"), *args],
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout)
            self.assertTrue(run("validate", "--input", str(REFERENCE))["valid"])
            first = run("import", "--input", str(REFERENCE), "--store", path)["snapshot_id"]
            second = run("import", "--input", str(ROOT / "examples/policies/reference-v2.json"), "--store", path)["snapshot_id"]
            self.assertEqual(run("list", "--store", path)["total"], 2)
            result = run("search", "--store", path, "--snapshot", first, "--source", "192.0.2.10",
                         "--destination", "198.51.100.20", "--protocol", "tcp", "--destination-port", "8443")
            self.assertEqual(result["model_verdict"], "INDETERMINATE")
            self.assertTrue(run("diff", "--store", path, "--before", first, "--after", second)["rules"]["modified"])

    def test_http_read_only_dashboard_queries_and_invalid_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.sqlite3"
            identifier = self.create(path)
            original = path.read_bytes()
            server = make_server(path, 0)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            origin = "http://127.0.0.1:" + str(server.server_port)
            try:
                with urlopen(origin + "/") as response:
                    self.assertIn(b'Read-only policy workbench', response.read())
                    self.assertIn("nosniff", response.headers.get("X-Content-Type-Options"))
                for route in ("/policy/status", "/policy/snapshots", "/policy/snapshots/" + identifier):
                    with urlopen(origin + route) as response:
                        self.assertIsInstance(json.load(response), dict)
                parameters = dict(snapshot=identifier, **point())
                parameters = {name: value for name, value in parameters.items() if value is not None}
                with urlopen(origin + "/policy/search?" + urlencode(parameters)) as response:
                    self.assertEqual(json.load(response)["model_verdict"], "ALLOW")
                for request, status in ((Request(origin + "/policy/snapshots", data=b'{}'), 501),
                                        (origin + "/policy/search?source=x&source=y", 400),
                                        (origin + "/policy/snapshots/" + "0" * 64, 404),
                                        (origin + "/policy/status?unexpected=true", 400)):
                    with self.assertRaises(HTTPError) as error:
                        urlopen(request)
                    self.assertEqual(error.exception.code, status)
                    error.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                worker.join()
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
