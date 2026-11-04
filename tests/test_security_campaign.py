"""Measurement denominators, abstentions and independent outcome boundaries."""

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from evaluate_security_campaign import score


def record(identifier,truth="malicious",verdict="clear"):
    value=json.loads((ROOT/"examples/testing/campaign-results.example.json").read_text())["records"][0]
    value.update(id=identifier,subject=identifier,truth=truth,verdict=verdict,arrival_verified=True,coverage_qualified=True,quality_ok=True)
    if verdict=="alert": value["detected_at"]="2026-11-04T10:00:02+00:00"
    return value


class CampaignTests(unittest.TestCase):
    def test_counts_abstention_and_window_denominators(self):
        values=[record("tp",verdict="alert"),record("fn"),record("abstain",verdict="abstain"),
                record("fp","benign","alert"),record("tn","benign"),record("unknown-benign","benign","abstain")]
        result=score({"version":"campaign-results-v1","records":values})
        self.assertEqual(result["counts"]["FN"],2)
        self.assertEqual(result["metrics"]["recall"],1/3)
        self.assertEqual(result["metrics"]["precision"],.5)
        self.assertEqual(result["metrics"]["false_alerts_per_qualified_benign_window"],1/3)

    def test_unknown_and_unseen_traffic_are_excluded_not_true_negative(self):
        item=record("unknown",truth="unknown");item["arrival_verified"]=False
        result=score({"version":"campaign-results-v1","records":[item]})
        self.assertEqual(result["status"],"NO_QUALIFIED_EVIDENCE")
        self.assertIsNone(result["metrics"]["recall"])
        self.assertNotIn("TN",result["counts"])

    def test_readback_is_separate_from_verified_traffic_containment(self):
        item=record("readback",verdict="alert")
        item.update(block_requested_at="2026-11-04T10:00:03+00:00",rule_readback_at="2026-11-04T10:00:04+00:00")
        result=score({"version":"campaign-results-v1","records":[item]})
        self.assertEqual(result["counts"]["unverified_block_requests"],1)
        self.assertEqual(result["latencies"]["request_to_readback"]["n"],1)
        self.assertEqual(result["latencies"]["request_to_verified_containment"]["n"],0)
        item.update(traffic_block_verified_at="2026-11-04T10:00:06+00:00",benign_continuity_verified=True)
        result=score({"version":"campaign-results-v1","records":[item]})
        self.assertEqual(result["counts"]["independently_verified_containments"],1)
        self.assertEqual(result["counts"]["continuity_pass"],1)

    def test_duplicate_mixed_revision_invalid_times_and_inconsistent_verdict_fail(self):
        item=record("one")
        for records in ([item,deepcopy(item)], [item,dict(record("two"),detector_revision="different")],
                        [dict(item,detected_at="2026-11-04T09:00:00+00:00",verdict="alert")],
                        [dict(item,verdict="alert")], [dict(item,rule_readback_at="2026-11-04T10:00:03+00:00")]):
            with self.subTest(records=records),self.assertRaises(ValueError):
                score({"version":"campaign-results-v1","records":records})
