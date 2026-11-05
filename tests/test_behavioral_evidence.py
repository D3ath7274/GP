"""Independent arithmetic, split/missingness boundaries and real CLI regressions."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Controller"))
from behavioral_evidence import (catalog_groups, digest, fit_reference, read_rows,
    score_row, strict_json, tail_rank, validate_reference)
from home_sensor import collection_contract


def rows(start, count=64):
    """Synthetic feature vectors, not packet captures or labeled attack evidence."""
    fields = collection_contract(["192.0.2.0/24"])["columns"]
    result = []
    for index in range(count):
        timestamp = datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(seconds=(start+index)*5)
        row = dict.fromkeys(fields, "")
        row.update(schema_version="site-v3.0", run_id="synthetic", device_ip="192.0.2.10", vlan="untagged",
            ground_truth="UNKNOWN", window_start_utc=timestamp.isoformat(),
            window_end_utc=(timestamp+timedelta(seconds=5)).isoformat(),
            window_seconds="5", metadata_enabled="0", content_enabled="0",
            history_restarted="0", cardinality_overflows_total="0", window_complete="1",
            out_packets="20", in_packets="20", out_bytes="1200", in_bytes="1200",
            out_pps="4", out_bytes_per_second="240", packet_size_mean="60", packet_size_std="0",
            inter_arrival_mean="0.1", inter_arrival_std="0", inter_arrival_cv="0",
            g11_null_flag_count="0", g11_xmas_flag_count="0", g11_fin_no_ack_count="0", g11_syn_count="2",
            g11_rst_in_count="0", g11_icmp_port_unreachable_in="0", g11_dst_ip_count="1",
            g11_dst_port_count="2", g11_service_edge_count="2")
        result.append(row)
    return result


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        catalog=json.loads((ROOT/"docs-site/reference/feature-groups.json").read_text())
        self.groups,self.columns=catalog_groups(catalog)
        self.fit,self.calibration=rows(1000),rows(1064)

    def model(self, **kwargs):
        return fit_reference(self.fit,self.calibration,self.groups,
                             selected=["G1","G11"],reviewed=True,**kwargs)

    def later(self):
        return rows(1128,1)[0]

    def test_inclusive_rank_arithmetic_and_ties(self):
        self.assertEqual(tail_rank(0,[0,0,1]),1)
        self.assertEqual(tail_rank(1,[0,0,1]),.5)
        self.assertEqual(tail_rank(2,[0,0,1]),.25)

    def test_zero_mad_change_is_unusual_instead_of_fabricated_zero_z(self):
        model=self.model(); row=self.later()
        self.assertEqual(score_row(model,row)["verdict"],"WITHIN_REFERENCE")
        row["g11_dst_port_count"]="99"
        result=score_row(model,row)
        self.assertEqual(result["verdict"],"REVIEW_ANOMALY")
        self.assertEqual(result["overall_tail_rank"],1/65)
        explanation=result["groups"]["G11"]["leading_features"][0]
        self.assertTrue(explanation["zero_mad"])
        self.assertIsNone(explanation["modified_z"])
        self.assertIsNone(result["malicious_probability"])
        self.assertFalse(result["automatic_apply"])

    def test_duplicate_correlated_features_do_not_sum_votes(self):
        base=self.model()
        small=deepcopy(self.groups); small["G11"]=["g11_dst_port_count"]
        single=fit_reference(self.fit,self.calibration,small,["G1","G11"],reviewed=True)
        row=self.later(); row["g11_dst_port_count"]="99"
        self.assertEqual(score_row(base,row)["overall_tail_rank"],score_row(single,row)["overall_tail_rank"])

    def test_median_mad_and_rank_are_independently_expected(self):
        for index,row in enumerate(self.fit): row["g11_dst_port_count"]=str(1+index%4)
        model=self.model()
        feature=model["devices"]["192.0.2.10@untagged"]["qualified"]["G11"]["features"]["g11_dst_port_count"]
        self.assertEqual(feature["median"],2.5)
        self.assertEqual(feature["mad"],1)
        self.assertEqual(tail_rank(1.5,feature["distances"]),33/65)

    def test_review_split_overlap_and_resolution_are_required(self):
        with self.assertRaisesRegex(ValueError,"review"):
            fit_reference(self.fit,self.calibration,self.groups)
        with self.assertRaisesRegex(ValueError,"resolution"):
            self.model(alpha=.01)
        with self.assertRaisesRegex(ValueError,"Fit must"):
            fit_reference(self.fit,rows(1030),self.groups,["G11"],reviewed=True)
        duplicate=self.fit+[deepcopy(self.fit[0])]
        with self.assertRaisesRegex(ValueError,"duplicate"):
            fit_reference(duplicate,self.calibration,self.groups,["G11"],reviewed=True)
        known_attack=deepcopy(self.fit);known_attack[0]["ground_truth"]="MALICIOUS"
        with self.assertRaisesRegex(ValueError,"non-benign"):
            fit_reference(known_attack,self.calibration,self.groups,["G11"],reviewed=True)

    def test_missing_sparse_and_nonfinite_measurements_abstain(self):
        model=self.model()
        for field,value in (("inter_arrival_cv",""),("inter_arrival_mean","nan"),("out_packets","1")):
            row=self.later(); row[field]=value
            self.assertEqual(score_row(model,row)["verdict"],"INSUFFICIENT_EVIDENCE")

    def test_context_change_warmup_capped_unknown_and_past_rows_abstain(self):
        model=self.model()
        for field,value in (("device_ip","192.0.2.11"),("metadata_enabled","1"),
                            ("window_complete","0"),
                            ("cardinality_overflows_total","1"),("schema_version","legacy")):
            row=self.later(); row[field]=value
            self.assertEqual(score_row(model,row)["verdict"],"INSUFFICIENT_EVIDENCE")
        self.assertEqual(score_row(model,self.fit[0])["verdict"],"INSUFFICIENT_EVIDENCE")

    def test_inconsistent_rates_or_fractional_counters_are_not_attack_findings(self):
        model=self.model()
        for name,value in (("out_pps","999"),("out_bytes_per_second","1"),("out_packets","2.5")):
            row=self.later();row[name]=value
            result=score_row(model,row)
            self.assertEqual(result["verdict"],"INSUFFICIENT_EVIDENCE")
            self.assertTrue(result["reasons"])

    def test_warmup_is_feature_specific_instead_of_discarding_all_rhythm(self):
        model=self.model();row=self.later();row["history_restarted"]="1"
        self.assertEqual(score_row(model,row)["verdict"],"WITHIN_REFERENCE")
        from behavioral_evidence import supported_value
        row.update(g13_dst_ips_hour_bucketed="2",device_new_dst_ratio="1",g12_ttl_residual="10")
        for field in ("g13_dst_ips_hour_bucketed","device_new_dst_ratio","g12_ttl_residual"):
            self.assertIsNone(supported_value(row,field))

    def test_scoring_is_frozen_and_audit_support_fields_are_excluded(self):
        model=self.model(); original=deepcopy(model)
        for value in (2,100,2):
            row=self.later();row["g11_dst_port_count"]=str(value);score_row(model,row)
        self.assertEqual(model,original)
        self.assertNotIn("profile_windows_before",self.groups["DEVICE"])
        self.assertFalse(set(self.groups["G11"]) & {"ground_truth","run_id","device_ip"})

    def test_optional_parsers_are_unqualified_when_inspection_is_disabled(self):
        model=fit_reference(self.fit,self.calibration,self.groups,["G11","G15","G16","G17"],reviewed=True)
        device=model["devices"]["192.0.2.10@untagged"]
        self.assertEqual(set(device["qualified"]),{"G11"})
        self.assertEqual(set(device["excluded"]),{"G15","G16","G17"})

    def test_reference_validation_rejects_hash_sorting_and_authority_tampering(self):
        original=self.model(); validate_reference(original,self.groups)
        for kind in ("hash","sort","authority"):
            model=deepcopy(original)
            if kind=="hash":model["alpha"]=.04
            elif kind=="sort":
                feature=model["devices"]["192.0.2.10@untagged"]["qualified"]["G11"]["features"]["g11_dst_port_count"]
                feature["distances"][0]=10
            else:model["automatic_apply"]=True
            if kind!="hash":model["sha256"]=digest({k:v for k,v in model.items() if k!="sha256"})
            with self.assertRaises(ValueError):validate_reference(model,self.groups)

    def test_strict_json_and_csv_reject_ambiguous_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"bad.json"
            for text in ('{"a":1,"a":2}', '{"a":NaN}'):
                path.write_text(text)
                with self.assertRaises(ValueError):strict_json(path)
            path=Path(directory)/"bad.csv";path.write_text("ground_truth,label\nUNKNOWN,0\n")
            with self.assertRaises(ValueError):read_rows(path,self.columns)

    def test_real_cli_roundtrip_does_not_overwrite_or_update_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory)
            def write(name, values):
                path=directory/name
                with path.open("w",newline="") as output:
                    writer=csv.DictWriter(output,fieldnames=list(values[0]));writer.writeheader();writer.writerows(values)
                return path
            fit,calibration=write("fit.csv",self.fit),write("cal.csv",self.calibration)
            row=self.later();row["g11_dst_port_count"]="99"
            incoming=write("later.csv",[row]);reference=directory/"reference.json";report=directory/"report.json"
            command=[sys.executable,str(ROOT/"scripts/score_feature_groups.py")]
            result=subprocess.run(command+["fit","--fit-csv",str(fit),"--calibration-csv",str(calibration),
                "--output",str(reference),"--groups","G1","G11","--reviewed-reference"],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            original=reference.read_bytes()
            result=subprocess.run(command+["score","--reference",str(reference),"--csv",str(incoming),
                "--output",str(report)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(report.read_text())["verdict_counts"]["REVIEW_ANOMALY"],1)
            result=subprocess.run(command+["score","--reference",str(reference),"--csv",str(incoming),
                "--output",str(report)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(reference.read_bytes(),original)

    def test_prepare_preserves_chronology_reports_omissions_and_refuses_existing_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory);path=directory/"input.csv";output=directory/"slices"
            data=rows(1000,193);data[0]["window_complete"]="0"
            with path.open("w",newline="") as source:
                writer=csv.DictWriter(source,fieldnames=list(data[0]));writer.writeheader();writer.writerows(data)
            command=[sys.executable,str(ROOT/"scripts/score_feature_groups.py"),"prepare","--csv",str(path),
                     "--output-dir",str(output),"--calibration-windows","64"]
            result=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            receipt=json.loads((output/"selection.json").read_text())
            self.assertEqual(receipt["omitted_reason_counts"],{"window_complete":1})
            self.assertEqual(receipt["slice_rows"],{"fit":64,"calibration":64,"later":64})
            first=read_rows(output/"fit.csv",self.columns);second=read_rows(output/"calibration.csv",self.columns)
            self.assertLess(first[-1]["window_start_utc"],second[0]["window_start_utc"])
            self.assertTrue(all(r["ground_truth"]=="UNKNOWN" for r in first+second))
            result=subprocess.run(command,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)


if __name__ == "__main__":unittest.main()
