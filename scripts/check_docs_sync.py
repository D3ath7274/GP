"""Require a documentation record for implementation changes."""

import argparse
import re
import subprocess
import sys
from pathlib import PurePosixPath

CHANGE_LOG = "docs-site/reference/change-log.mdx"
NON_CODE = {".md", ".mdx", ".rst", ".txt", ".pdf", ".docx", ".csv", ".log", ".pyc"}
CODE_SUFFIXES = {
    ".py", ".sh", ".ps1", ".js", ".mjs", ".ts", ".tsx", ".html", ".css",
    ".lua", ".rules", ".json", ".yaml", ".yml", ".toml", ".ini",
    ".conf", ".service", ".joblib", ".h5", ".keras", ".ipynb",
}


def is_implementation(name):
    path = PurePosixPath(name)
    if path.parts[0] in {"docs-site", "docs", ".github", ".githooks"}:
        return False
    if path.suffix.lower() in NON_CODE:
        return False
    return path.parts[0] in {"Controller", "Dashboard", "QoS", "SDN Topology"} or (
        path.suffix.lower() in CODE_SUFFIXES or path.name in {"Dockerfile", "Makefile"}
    )


def git_diff(*args):
    return subprocess.check_output(["git", "diff", *args])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--base", help="Compare the PR merge base with HEAD")
    args = parser.parse_args()
    diff = ["--cached"] if args.staged else [f"{args.base}...HEAD"]
    changed = git_diff("--name-only", "--no-renames", "-z", *diff, "--")
    implementation = [name for name in changed.decode("utf-8").split("\0")
                      if name and is_implementation(name)]
    if not implementation:
        print("Documentation sync: no implementation changes.")
        return 0

    patch = git_diff("--unified=0", *diff, "--", CHANGE_LOG).decode("utf-8")
    added_lines = [
        line[1:] for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    added_entry = any(
        re.fullmatch(r"## \d{4}-\d{2}-\d{2} .+", line)
        for line in added_lines
    ) and any(line.strip() and not line.startswith("#") for line in added_lines)
    if added_entry:
        print("Documentation sync: changelog entry present.")
        return 0

    print("Add a new dated heading and change notes to " + CHANGE_LOG, file=sys.stderr)
    for name in implementation:
        print(f"  {name}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
