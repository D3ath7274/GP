"""Require a dated change record and an affected content page for implementation changes."""

import argparse
from fnmatch import fnmatchcase
import json
import re
import subprocess
import sys
from pathlib import PurePosixPath

CHANGE_LOG = "docs-site/reference/change-log.mdx"
DOCUMENTATION_MAP = "docs-site/documentation-map.json"
NON_CODE = {".md", ".mdx", ".rst", ".txt", ".pdf", ".docx", ".csv", ".log", ".pyc"}
CODE_SUFFIXES = {
    ".py", ".sh", ".ps1", ".js", ".cjs", ".mjs", ".ts", ".tsx", ".html", ".css",
    ".lua", ".rules", ".json", ".yaml", ".yml", ".toml", ".ini",
    ".conf", ".service", ".joblib", ".h5", ".keras", ".ipynb",
    ".nft", ".pkl", ".onnx", ".pt", ".bat", ".cmd",
}


def is_implementation(name):
    path = PurePosixPath(name)
    if path.parts[0] in {"docs-site", "docs"}:
        return False
    if path.parts[0] == ".githooks":
        return True
    if fnmatchcase(path.name, "requirements*.txt"):
        return True
    if path.suffix.lower() in NON_CODE:
        return False
    return path.parts[0] in {"Controller", "Dashboard", "QoS", "SDN Topology"} or (
        path.suffix.lower() in CODE_SUFFIXES or path.name in {"Dockerfile", "Makefile"}
    )


def git_diff(*args):
    return subprocess.check_output(["git", "diff", *args])


def snapshot_file(name, staged):
    target = ":" + name if staged else "HEAD:" + name
    result = subprocess.run(["git", "show", target], capture_output=True)
    return result.stdout if result.returncode == 0 else None


def load_map(staged):
    content = snapshot_file(DOCUMENTATION_MAP, staged)
    if content is None:
        raise ValueError("Missing " + DOCUMENTATION_MAP + " in the checked snapshot")
    mapping = json.loads(content)
    if not isinstance(mapping, dict) or mapping.get("version") != 1 or not isinstance(mapping.get("rules"), list):
        raise ValueError("Invalid documentation map")
    groups = [(mapping.get("fallback_pages"), None)]
    for rule in mapping["rules"]:
        if not isinstance(rule, dict):
            raise ValueError("Invalid documentation rule")
        sources = rule.get("sources")
        if not isinstance(sources, list) or not sources or any(not isinstance(s, str) or not s for s in sources):
            raise ValueError("Each documentation rule needs source patterns")
        groups.append((rule.get("pages"), sources))
    for pages, _ in groups:
        if not isinstance(pages, list) or not pages:
            raise ValueError("Each documentation rule needs content pages")
        for page in pages:
            if (not isinstance(page, str) or not page.startswith("docs-site/") or
                    not page.endswith(".mdx") or page == CHANGE_LOG or ".." in PurePosixPath(page).parts or
                    snapshot_file(page, staged) is None):
                raise ValueError("Missing/invalid mapped documentation page: " + str(page))
    return mapping


def related_pages(name, mapping):
    # First matching rule wins: specific sources precede broad scripts/test patterns.
    for rule in mapping["rules"]:
        if any(fnmatchcase(name, pattern) for pattern in rule["sources"]):
            return rule["pages"]
    return mapping["fallback_pages"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--base", help="Compare the PR merge base with HEAD")
    mode.add_argument("--from", dest="from_ref", help="Compare an exact previous commit/tree with HEAD for push checks")
    args = parser.parse_args()
    if args.staged:
        diff = ["--cached"]
    elif args.from_ref:
        diff = [args.from_ref, "HEAD"]
    else:
        diff = [f"{args.base}...HEAD"]
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
    try:
        mapping = load_map(args.staged)
    except (ValueError, TypeError, KeyError) as error:
        print(str(error), file=sys.stderr)
        return 1
    changed_names = set(changed.decode("utf-8").split("\0"))
    missing = [(name, related_pages(name, mapping)) for name in implementation
               if not changed_names.intersection(related_pages(name, mapping))]
    if added_entry and not missing:
        print("Documentation sync: dated changelog and affected content pages present.")
        return 0
    if not added_entry:
        print("Add a new dated heading and change notes to " + CHANGE_LOG, file=sys.stderr)
    for name, pages in missing:
        print(f"Update documentation for {name}: " + " or ".join(pages), file=sys.stderr)
    print("Checks use staged/committed files. Documentation accuracy and API changes still require review.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
