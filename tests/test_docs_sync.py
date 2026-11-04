"""Exercise the guard against the Git index and committed changes, including bypass attempts."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_docs_sync import is_implementation


GUARD = Path(__file__).resolve().parents[1] / "scripts/check_docs_sync.py"
PAGE = "docs-site/deployment/home-collection.mdx"
MAINTENANCE = "docs-site/developers/maintenance.mdx"
CHANGE_LOG = "docs-site/reference/change-log.mdx"


class DocsSyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Documentation tests")
        self.git("config", "user.email", "tests@example.invalid")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "core.hooksPath", ".disabled-hooks")
        self.write("Controller/home_sensor.py", "original\n")
        self.write(PAGE, "Original collection guide\n")
        self.write(MAINTENANCE, "Original maintenance guide\n")
        self.write(CHANGE_LOG, "# Changelog\n")
        self.write("docs-site/documentation-map.json", json.dumps({
            "version": 1, "fallback_pages": [MAINTENANCE],
            "rules": [{"sources": ["Controller/home_sensor.py"], "pages": [PAGE]}]}))
        self.git("add", ".")
        self.git("commit", "-qm", "baseline")
        self.base = self.git("rev-parse", "HEAD").strip()

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True)

    def write(self, name, content, stage=False):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        if stage:
            self.git("add", "--", name)

    def record(self):
        self.write(CHANGE_LOG, "# Changelog\n\n## 2026-11-04 Test change\nBehavior and verification.\n", True)

    def guard(self, *mode):
        return subprocess.run([sys.executable, str(GUARD), *(mode or ("--staged",))],
                              cwd=self.root, capture_output=True, text=True)

    def test_requires_changelog_and_affected_page(self):
        self.write("Controller/home_sensor.py", "modified\n", True)
        self.assertEqual(self.guard().returncode, 1)
        self.record()
        self.assertEqual(self.guard().returncode, 1)  # A changelog alone is insufficient.
        self.write(MAINTENANCE, "Unrelated maintenance edit\n", True)
        self.assertEqual(self.guard().returncode, 1)
        self.write(PAGE, "Affected operator behavior and verification\n", True)
        self.assertEqual(self.guard().returncode, 0)

    def test_unstaged_page_does_not_satisfy_commit(self):
        self.write("Controller/home_sensor.py", "modified\n", True)
        self.record()
        self.write(PAGE, "Unstaged explanation\n")
        self.assertEqual(self.guard().returncode, 1)
        self.git("add", "--", PAGE)
        self.assertEqual(self.guard().returncode, 0)

    def test_deleted_documentation_cannot_satisfy_guard(self):
        self.write("Controller/home_sensor.py", "modified\n", True)
        self.record()
        self.git("rm", "--", PAGE)
        self.assertEqual(self.guard().returncode, 1)

    def test_unmapped_code_requires_developer_page(self):
        self.write("new_runtime.py", "print('example')\n", True)
        self.record()
        self.assertEqual(self.guard().returncode, 1)
        self.write(MAINTENANCE, "New extension described\n", True)
        self.assertEqual(self.guard().returncode, 0)

    def test_missing_map_blocks_implementation(self):
        self.write("Controller/home_sensor.py", "modified\n", True)
        self.record()
        self.write(PAGE, "Updated behavior\n", True)
        self.git("rm", "--", "docs-site/documentation-map.json")
        self.assertEqual(self.guard().returncode, 1)

    def test_pr_and_push_diff_modes(self):
        self.write("Controller/home_sensor.py", "modified\n", True)
        self.record()
        self.write(PAGE, "Updated behavior\n", True)
        self.git("commit", "-qm", "documented change")
        self.assertEqual(self.guard("--base", self.base).returncode, 0)
        self.assertEqual(self.guard("--from", self.base).returncode, 0)
        self.write("Controller/home_sensor.py", "undocumented next change\n", True)
        self.git("commit", "-qm", "missing documentation")
        self.assertEqual(self.guard("--from", "HEAD^").returncode, 1)

    def test_docs_only_and_runtime_dependency_classification(self):
        self.write(PAGE, "Documentation-only correction\n", True)
        self.assertEqual(self.guard().returncode, 0)
        for name in ("Controller/requirements-home.txt", "requirements.txt", "Controller/model.onnx",
                     "Controller/scripts/policy.nft", "scripts/start_docs.ps1",
                     ".github/workflows/documentation.yml", ".githooks/pre-commit"):
            self.assertTrue(is_implementation(name), name)
        self.assertFalse(is_implementation("docs-site/DOCUMENTATION_VALIDATION.md"))


if __name__ == "__main__":
    unittest.main()
