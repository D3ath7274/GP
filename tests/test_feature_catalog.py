"""Source-to-rationale coverage, planned status, leakage and staged-index checks."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from check_feature_catalog import CATALOG,RATIONALE,source_columns,validate


def read(name):
    return (ROOT/name).read_text(encoding="utf-8")


class CatalogTests(unittest.TestCase):
    def test_all_columns_and_numbered_groups_are_covered(self):
        result=validate(json.loads(read(CATALOG)),read(RATIONALE),source_columns(read))
        self.assertEqual(result["columns"],{"legacy":102,"site_v3":71})
        self.assertEqual(result["groups"],30)

    def test_missing_invented_duplicate_columns_and_groups_fail(self):
        initial=json.loads(read(CATALOG))
        for kind in ("missing","invented","duplicate","group"):
            catalog=deepcopy(initial)
            if kind=="group": catalog["groups"].append(deepcopy(catalog["groups"][0]))
            else:
                group=next(g for g in catalog["groups"] if g["id"]=="BASE")
                if kind=="missing": group["site_columns"].pop()
                elif kind=="invented": group["site_columns"].append("invented")
                else: group["site_columns"].append(group["site_columns"][0])
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                validate(catalog,read(RATIONALE),source_columns(read))

    def test_planned_group_cannot_claim_implemented_measurements(self):
        catalog=json.loads(read(CATALOG))
        next(g for g in catalog["groups"] if g["id"]=="G18")["site_columns"]=["out_packets"]
        with self.assertRaisesRegex(ValueError,"Planned"):
            validate(catalog,read(RATIONALE),source_columns(read))

    def test_missing_empty_rationale_and_label_predictors_fail(self):
        catalog=json.loads(read(CATALOG));page=read(RATIONALE)
        for subject in (page.replace("## G1:","## Changed G1:"),page.split("## G1:")[0]+"## G1: Timing and burst rhythm\nToo short.\n"+"## G2:"+page.split("## G2:",1)[1]):
            with self.assertRaises(ValueError): validate(catalog,subject,source_columns(read))
        next(g for g in catalog["groups"] if g["id"]=="LABELS")["model_use"]="requires_qualification"
        with self.assertRaisesRegex(ValueError,"Labels"):
            validate(catalog,page,source_columns(read))

    def test_dynamic_feature_definition_requires_an_explicit_checker_update(self):
        def altered(name):
            text=read(name)
            return text.replace("result = dict(out_packets=", "result = dict(**{'extra': 1}, out_packets=") if name.endswith("site_features.py") else text
        with self.assertRaisesRegex(ValueError,"Dynamic"):
            source_columns(altered)

    def test_staged_check_uses_git_index_instead_of_unstaged_rationale_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            files=[CATALOG,RATIONALE,"Controller/traffic_capture.py","Controller/home_sensor.py","Controller/site_features.py","scripts/check_feature_catalog.py"]
            for name in files:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,path)
            subprocess.run(["git","init","-q"],cwd=root,check=True,capture_output=True)
            subprocess.run(["git","add","."],cwd=root,check=True,capture_output=True)
            catalog=json.loads((root/CATALOG).read_text());catalog["groups"].pop()
            (root/CATALOG).write_text(json.dumps(catalog))
            command=[sys.executable,str(root/"scripts/check_feature_catalog.py")]
            self.assertEqual(subprocess.run(command+["--staged"],cwd=root,capture_output=True,timeout=15).returncode,0)
            self.assertNotEqual(subprocess.run(command,cwd=root,capture_output=True,timeout=15).returncode,0)
            subprocess.run(["git","add",CATALOG],cwd=root,check=True,capture_output=True)
            self.assertNotEqual(subprocess.run(command+["--staged"],cwd=root,capture_output=True,timeout=15).returncode,0)
