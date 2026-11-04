"""Compare symbolic audit claims with independent exhaustive packet-space enumeration."""

from copy import deepcopy
import ipaddress
from itertools import product
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.parse import urlencode
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"Controller"))
from firewall_policy import read_input, canonical_bytes, normalize
from policy_audit import audit_policy, AuditBudgetError
from policy_store import PolicyStore
from policy_http import make_server


def rule(identifier, position, sources=None, ports=None, action="allow", logging=True):
    return dict(id=identifier,position=position,enabled=True,sources=sources or ["192.0.2.0/30"],
        destinations=["198.51.100.0/30"],protocol="tcp",source_ports="any",
        destination_ports=ports or [0,1,2,3],action=action,logging=logging,owner="lab",comment="Test",constraints=[])


def policy(rules):
    value = read_input(ROOT/"examples/policies/reference-v1.json")[1]
    value["objects"]={};value["rules"]=rules
    return value


def findings(result,kind,identifier):
    return [f for f in result["findings"] if f["type"]==kind and f.get("rule")==identifier]


def oracle_matches(rule, source, destination, sport, dport):
    def ports(values, port):
        if values=="any": return True
        for value in values:
            bounds = [int(x) for x in str(value).split("-")]
            if bounds[0]<=port<=bounds[-1]: return True
        return False
    return (any(ipaddress.ip_address(source) in ipaddress.ip_network(n) for n in rule["sources"])
        and any(ipaddress.ip_address(destination) in ipaddress.ip_network(n) for n in rule["destinations"])
        and ports(rule["source_ports"],sport) and ports(rule["destination_ports"],dport))


class AuditTests(unittest.TestCase):
    def test_union_of_prior_rules_shadows_without_pairwise_containment(self):
        rules=[rule("left",1,["192.0.2.0/31"]),rule("right",2,["192.0.2.2/31"]),rule("whole",3)]
        result=audit_policy(policy(rules))
        self.assertTrue(findings(result,"FULLY_SHADOWED","whole"))
        self.assertTrue(findings(result,"REDUNDANT_BEHAVIOR","whole"))
        self.assertFalse(findings(result,"DUPLICATE_RULE","whole"))

    def test_prior_action_and_logging_differences_prevent_behavior_equivalence(self):
        for kwargs in ({"action":"deny"},{"logging":False},{"logging":None}):
            result=audit_policy(policy([rule("first",1,**kwargs),rule("later",2)]))
            self.assertTrue(findings(result,"FULLY_SHADOWED","later"))
            self.assertFalse(findings(result,"REDUNDANT_BEHAVIOR","later"))
            self.assertFalse(findings(result,"DUPLICATE_RULE","later"))

    def test_shadowing_uses_effective_first_match_not_all_prior_actions(self):
        rules=[rule("first",1),rule("unreachable-deny",2,action="deny"),rule("later",3)]
        self.assertTrue(findings(audit_policy(policy(rules)),"REDUNDANT_BEHAVIOR","later"))

    def test_partial_overlap_has_covered_and_uncovered_witnesses(self):
        rules=[rule("earlier",1,ports=[0]),rule("later",2)]
        item=findings(audit_policy(policy(rules)),"PARTIAL_OVERLAP","later")[0]
        self.assertEqual(item["covered_witness"]["destination_port"],0)
        self.assertNotEqual(item["residual_witness"]["destination_port"],0)

    def test_unresolved_predecessor_global_context_and_disabled_are_conservative(self):
        rules=[rule("unknown",1),rule("current",2)]
        rules[0]["constraints"]=["unmodeled application"]
        result=audit_policy(policy(rules))
        self.assertEqual(result["status"],"INDETERMINATE")
        self.assertFalse(findings(result,"FULLY_SHADOWED","current"))
        rules[0]["enabled"]=False
        result=audit_policy(policy(rules))
        self.assertFalse(result["indeterminate_rules"])
        value=policy(rules);value["unmodeled_context"]=["global schedule"]
        self.assertFalse(findings(audit_policy(value),"FULLY_SHADOWED","current"))

    def test_ipv6_and_source_port_dimensions(self):
        rules=[rule("first",1),rule("second",2)]
        for item in rules:
            item["sources"]=["2001:db8::/126"];item["destinations"]=["2001:db8:1::/126"]
        rules[0]["source_ports"]=[100]
        result=audit_policy(policy(rules))
        item=findings(result,"PARTIAL_OVERLAP","second")[0]
        self.assertEqual(item["covered_witness"]["source_port"],100)
        self.assertIn(":",item["covered_witness"]["source"])
        self.assertNotEqual(item["residual_witness"]["source_port"],100)

    def test_object_findings_are_explicitly_model_scoped(self):
        value=policy([rule("one",1)])
        value["objects"]={"a":{"kind":"address","values":["192.0.2.0/30"]},
            "b":{"kind":"address_group","members":["@a"]}}
        result=audit_policy(value)
        self.assertTrue(any(f["type"]=="DUPLICATE_ADDRESS_SET" for f in result["findings"]))
        self.assertTrue(any(f["type"]=="UNREFERENCED_OBJECT_IN_MODEL" for f in result["findings"]))
        self.assertFalse(result["automatic_cleanup"])

    def test_caps_fail_without_publishing_a_partial_proof(self):
        with self.assertRaises(AuditBudgetError):
            audit_policy(policy([rule("one",1),rule("two",2)]),max_work=1)
        with self.assertRaises(AuditBudgetError):
            audit_policy(policy([rule(str(n),n) for n in range(201)]))

    def test_whitespace_comment_is_missing_documentation(self):
        item=rule("blank",1);item["comment"]="   "
        result=audit_policy(policy([item]))
        self.assertEqual(findings(result,"MISSING_DOCUMENTATION","blank")[0]["fields"],["comment"])

    def test_exhaustive_oracle_checks_shadow_redundancy_and_witnesses(self):
        rng=random.Random(1138)
        universe=list(product([f"192.0.2.{n}" for n in range(4)], [f"198.51.100.{n}" for n in range(4)], [0], range(4)))
        for campaign in range(40):
            rules=[]
            for index in range(8):
                sources=rng.choice([["192.0.2.0/30"],["192.0.2.0/31"],["192.0.2.2/31"]])
                ports=rng.choice([[0],[1,2],[0,1,2,3]])
                rules.append(rule(f"r{index}",index,sources,ports,rng.choice(["allow","deny"]),rng.choice([True,False])))
            result=audit_policy(policy(rules))
            prior=[]
            for current in rules:
                own=[p for p in universe if oracle_matches(current,*p)]
                first=[next((r for r in prior if oracle_matches(r,*p)),None) for p in own]
                shadow=all(r is not None for r in first)
                redundant=shadow and all((r["action"],r["logging"])==(current["action"],current["logging"]) for r in first)
                self.assertEqual(bool(findings(result,"FULLY_SHADOWED",current["id"])),shadow,(campaign,current))
                self.assertEqual(bool(findings(result,"REDUNDANT_BEHAVIOR",current["id"])),redundant)
                for item in findings(result,"PARTIAL_OVERLAP",current["id"]):
                    witness=item["residual_witness"]
                    point=(witness["source"],witness["destination"],witness["source_port"],witness["destination_port"])
                    self.assertTrue(oracle_matches(current,*point))
                    self.assertFalse(any(oracle_matches(r,*point) for r in prior))
                prior.append(current)

    def test_cli_and_http_audit_remain_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"policies.sqlite3"
            value=normalize(policy([rule("one",1),rule("two",2)]))
            with PolicyStore(path,writable=True) as store:
                identifier=store.import_snapshot(canonical_bytes(value),value)["snapshot_id"]
            before=path.read_bytes()
            result=subprocess.run([sys.executable,str(ROOT/"scripts/policy_inventory.py"),"audit","--store",str(path),"--snapshot",identifier],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue(findings(json.loads(result.stdout),"DUPLICATE_RULE","two"))
            with make_server(path,0) as server:
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                try:
                    with urlopen(f"http://127.0.0.1:{server.server_port}/policy/audit?"+urlencode({"snapshot":identifier}),timeout=5) as response:
                        self.assertEqual(json.load(response)["enforcement"],"NOT_ATTEMPTED")
                finally:
                    server.shutdown();thread.join(5)
            self.assertEqual(path.read_bytes(),before)
