"""Independent finite-space oracle and authority boundaries for model-change analysis."""

from copy import deepcopy
from itertools import product
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Controller"))
from firewall_policy import canonical_bytes, normalize, read_input, sha256
from policy_change import impact, proposal, verify_proposal
from policy_audit import AuditBudgetError
from policy_store import PolicyStore
from policy_http import make_server
from test_policy_audit import oracle_matches, policy, rule


def base():
    return read_input(ROOT / "examples/policies/change-reference-v1.json")[1]


def request(value, operations):
    return {"version":"policy-proposal-v1","base_snapshot":sha256(canonical_bytes(normalize(value))),
            "reason":"Independent offline test","operations":operations}


class ChangeTests(unittest.TestCase):
    def test_duplicate_disable_is_access_equivalent_but_default_logging_is_unqualified(self):
        value = base(); original = canonical_bytes(value)
        result = proposal(value, request(value, [{"operation":"disable_rule","rule":"duplicate-web"}]))
        self.assertEqual(result["impact"]["access_equivalence"], "EQUIVALENT_FOR_SUPPORTED_SUBSET")
        self.assertEqual(result["impact"]["logging_equivalence"], "INDETERMINATE")
        self.assertFalse(result["candidate_is_observed"])
        self.assertFalse(result["automatic_apply"])
        self.assertEqual(canonical_bytes(value), original)
        self.assertTrue(verify_proposal(value,result)["verified"])

    def test_reorder_has_concrete_restriction_and_remove_has_attribution_change(self):
        value = base()
        moved = proposal(value, request(value,[{"operation":"move_rule_before","rule":"deny-8080","before_rule":"allow-half-8080"}]))
        examples = [x for x in moved["impact"]["examples"] if "ACCESS_RESTRICTED" in x["kinds"]]
        self.assertTrue(examples)
        self.assertEqual(examples[0]["witness"]["destination_port"],8080)
        removed = proposal(value,request(value,[{"operation":"remove_rule","rule":"allow-web"}]))
        self.assertEqual(removed["impact"]["access_equivalence"],"EQUIVALENT_FOR_SUPPORTED_SUBSET")
        self.assertGreater(removed["impact"]["counts"]["attribution_changes"],0)

    def test_broadening_and_default_or_deny_reject_changes(self):
        before = base(); after = deepcopy(before)
        after["rules"][0]["destination_ports"].append("8443")
        result = impact(before,after)
        self.assertTrue(result["known_access_change_present"])
        self.assertTrue(any(x["witness"]["destination_port"]==8443 and "ACCESS_EXPANDED" in x["kinds"] for x in result["examples"]))
        before = policy([]); after = deepcopy(before); after["default_action"]="allow"
        self.assertGreater(impact(before,after)["counts"]["access_expansions"],0)
        after["default_action"]="reject"
        self.assertGreater(impact(before,after)["counts"]["denial_behavior_changes"],0)

    def test_logging_change_is_not_access_change(self):
        before=base();after=deepcopy(before);after["rules"][0]["logging"]=False
        result=impact(before,after)
        self.assertEqual(result["access_equivalence"],"EQUIVALENT_FOR_SUPPORTED_SUBSET")
        self.assertEqual(result["logging_equivalence"],"DIFFERENT")

    def test_unknown_envelope_does_not_hide_known_changes_elsewhere(self):
        before=base();before["rules"].insert(0,dict(rule("unknown",0,ports=[8443]),constraints=["Unmodeled application"]))
        after=deepcopy(before);after["rules"][1]["destination_ports"].append("444")
        result=impact(before,after)
        self.assertEqual(result["access_equivalence"],"DIFFERENT")
        self.assertEqual(result["coverage_status"],"PARTIAL_UNKNOWN")
        self.assertTrue(result["known_access_change_present"])
        self.assertTrue(any("INDETERMINATE" in x["kinds"] for x in result["examples"]))
        before["unmodeled_context"]=["Unmodeled global zone"]
        result=impact(before,before)
        self.assertEqual(result["access_equivalence"],"INDETERMINATE")

    def test_unresolved_address_and_disabled_unknown_are_not_fabricated_matches(self):
        before=policy([rule("dynamic",0)])
        before["objects"]={"dynamic":{"kind":"unresolved","reason":"Unknown inventory"}}
        before["rules"][0]["sources"]=["@dynamic"]
        self.assertEqual(impact(before,before)["access_equivalence"],"INDETERMINATE")
        before["rules"][0]["enabled"]=False
        self.assertEqual(impact(before,before)["access_equivalence"],"EQUIVALENT_FOR_SUPPORTED_SUBSET")

    def test_ipv6_source_port_change_and_display_cap_do_not_skip_analysis(self):
        before=base();after=deepcopy(before)
        after["rules"][-1]["source_ports"]=[12345]
        full=impact(before,after,200);limited=impact(before,after,1)
        self.assertEqual(full["counts"],limited["counts"])
        self.assertTrue(limited["truncated"])
        self.assertIn("ACCESS_RESTRICTED",limited["witnesses_by_kind"])
        self.assertTrue(any(":" in e["witness"]["source"] and "ACCESS_RESTRICTED" in e["kinds"] for e in full["examples"]))

    def test_context_limits_stale_target_and_operation_validation(self):
        value=base(); other=deepcopy(value);other["site"]="elsewhere"
        with self.assertRaises(ValueError): impact(value,other)
        with self.assertRaises(AuditBudgetError): impact(value,value,max_work=1)
        large = policy([rule(str(n),n) for n in range(201)])
        with self.assertRaises(AuditBudgetError): impact(large,large)
        for operations in ([{"operation":"apply","rule":"allow-web"}],
                [{"operation":"disable_rule","rule":"missing"}],
                [{"operation":"move_rule_before","rule":"allow-web","before_rule":"allow-web"}],
                [{"operation":"disable_rule","rule":"allow-web"}]*2):
            with self.subTest(operations=operations),self.assertRaises(ValueError): proposal(value,request(value,operations))
        bad=request(value,[{"operation":"remove_rule","rule":"allow-web"}]);bad["base_snapshot"]="0"*64
        with self.assertRaises(ValueError): proposal(value,bad)

    def test_receipt_tampering_and_even_rehashed_false_state_are_rejected(self):
        value=base();receipt=proposal(value,request(value,[{"operation":"disable_rule","rule":"duplicate-web"}]))
        receipt["automatic_apply"]=True
        with self.assertRaises(ValueError): verify_proposal(value,receipt)
        receipt["receipt_sha256"]=sha256(canonical_bytes({k:v for k,v in receipt.items() if k!="receipt_sha256"}))
        with self.assertRaises(ValueError): verify_proposal(value,receipt)

    def test_independent_exhaustive_oracle_for_access_changes(self):
        rng=random.Random(9941)
        points=list(product([f"192.0.2.{n}" for n in range(4)], [f"198.51.100.{n}" for n in range(4)], [0,1,65535],range(4)))
        def verdict(rules,point):
            return next((r["action"] for r in rules if r["enabled"] and oracle_matches(r,*point)),"deny")
        for _ in range(35):
            rules=[rule(f"r{n}",n,rng.choice([["192.0.2.0/30"],["192.0.2.0/31"],["192.0.2.2/31"]]),
                    rng.choice([[0],[1,2],[0,1,2,3]]),rng.choice(["allow","deny","reject"])) for n in range(6)]
            before=policy(rules);after=deepcopy(before)
            chosen=rng.randrange(6)
            after["rules"][chosen]["action"]=rng.choice(["allow","deny","reject"])
            differs=any(verdict(before["rules"],p)!=verdict(after["rules"],p) for p in points)
            result=impact(before,after)
            self.assertEqual(result["access_equivalence"]=="DIFFERENT",differs)
            for example in result["examples"]:
                if any(kind.startswith("ACCESS_") or kind=="DENIAL_BEHAVIOR_CHANGED" for kind in example["kinds"]):
                    w=example["witness"];p=(w["source"],w["destination"],w["source_port"],w["destination_port"])
                    self.assertNotEqual(verdict(before["rules"],p),verdict(after["rules"],p))

    def test_cli_receipt_and_http_preview_are_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/"policies.sqlite3";value=base()
            with PolicyStore(db,writable=True) as store:
                identifier=store.import_snapshot(canonical_bytes(value),value)["snapshot_id"]
            original=db.read_bytes();receipt_path=Path(tmp)/"receipt.json"
            command=[sys.executable,str(ROOT/"scripts/policy_inventory.py"),"propose","--store",str(db),"--snapshot",identifier,
                     "--request",str(ROOT/"examples/policies/disable-duplicate.request.json"),"--output",str(receipt_path)]
            result=subprocess.run(command,capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([sys.executable,str(ROOT/"scripts/policy_inventory.py"),"verify-proposal","--store",str(db),"--input",str(receipt_path)],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue(json.loads(result.stdout)["verified"])
            refused=subprocess.run(command,capture_output=True,text=True,timeout=15)
            self.assertNotEqual(refused.returncode,0)
            with make_server(db,0) as server:
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                try:
                    origin=f"http://127.0.0.1:{server.server_port}"
                    for route,params in (("impact",dict(before=identifier,after=identifier)),
                        ("preview",dict(snapshot=identifier,operation="disable_rule",rule="duplicate-web"))):
                        with urlopen(origin+"/policy/"+route+"?"+urlencode(params),timeout=10) as response:
                            self.assertEqual(json.load(response)["enforcement"],"NOT_ATTEMPTED")
                    with self.assertRaises(HTTPError) as denied:
                        urlopen(origin+"/policy/preview?"+urlencode(dict(snapshot=identifier,operation="apply",rule="allow-web")),timeout=5)
                    denied.exception.close()
                finally:
                    server.shutdown();thread.join(5)
            self.assertEqual(db.read_bytes(),original)
