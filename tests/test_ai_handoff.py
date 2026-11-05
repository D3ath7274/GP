"""Coverage, line-ending portability and non-executing handoff generation."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import build_ai_handoff as builder

class HandoffTests(unittest.TestCase):
    def catalog(self):
        return {"version":"file-purposes-v1","files":{
            "sample.py":"Example source module used for independent symbol extraction checks.",
            "Controller/ml_models/example.joblib":"Opaque trusted fixture fingerprinted without attempting model deserialization."},
            "local_only":{"private/":"Excluded private input must never be opened by the builder."}}

    def test_conditional_class_nested_symbols_and_imports(self):
        source="import os\nif True:\n class P:\n  def method(self):\n   def inside(): pass\n"
        symbols,imports=builder.symbols(source)
        self.assertEqual([x["name"] for x in symbols],["P","P.method","P.method.inside"])
        self.assertEqual(imports,["os"])

    def test_exact_path_purpose_coverage_and_no_private_reads(self):
        catalog=self.catalog()
        raw={"sample.py":b"def one(): pass\n","Controller/ml_models/example.joblib":b"\x80binary-not-a-model"}
        snapshot,text=builder.build(sorted(raw),catalog,raw.__getitem__,"base")
        self.assertEqual(len(snapshot["files"]),2)
        self.assertIn("P",builder.symbols("class P: pass")[0][0]["name"])
        self.assertIn("sample.py",text)
        bad=deepcopy(catalog);bad["files"].pop("sample.py")
        with self.assertRaises(ValueError):builder.build(sorted(raw),bad,raw.__getitem__,"base")
        bad=deepcopy(catalog);bad["files"]["sample.py"]="short"
        with self.assertRaises(ValueError):builder.build(sorted(raw),bad,raw.__getitem__,"base")

    def test_lf_normalization_and_raw_artifact_fingerprints(self):
        catalog=self.catalog()
        a={"sample.py":b"def f():\n pass\n","Controller/ml_models/example.joblib":b"raw\r\nbytes"}
        catalog["files"]["sample.js"]="JavaScript source is fingerprinted through shared implementation classification."
        a["sample.js"]=b"console.log(1);\n"
        b=dict(a);b["sample.py"]=a["sample.py"].replace(b"\n",b"\r\n")
        first,_=builder.build(sorted(a),catalog,a.__getitem__,"base")
        second,_=builder.build(sorted(b),catalog,b.__getitem__,"base")
        self.assertEqual(first,second)
        self.assertIn("sha256",next(r for r in first["files"] if r["path"]=="sample.js"))
        b["Controller/ml_models/example.joblib"]=b"raw\nbytes"
        third,_=builder.build(sorted(b),catalog,b.__getitem__,"base")
        self.assertNotEqual(first["files"][0]["sha256"],third["files"][0]["sha256"])

    def test_staged_reader_does_not_substitute_unstaged_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            subprocess.run(["git","init","-q",str(root)],check=True)
            (root/"sample.py").write_text("pass\n")
            subprocess.run(["git","-C",str(root),"add","sample.py"],check=True)
            (root/"sample.py").write_text("raise Exception('unstaged')\n")
            with patch.object(builder,"ROOT",root):
                self.assertEqual(builder.tracked(),["sample.py"])
                self.assertEqual(builder.read("sample.py",True),b"pass\n")
                self.assertIn(b"unstaged",builder.read("sample.py"))

if __name__=="__main__":
    unittest.main()
