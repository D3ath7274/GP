"""Audit stopped site-v3 data, with daily/device and evidence-integrity summaries."""

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Controller"))
from collection_report import report


def audit(directory):
    return report(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_dir", type=Path)
    parser.add_argument("--output", type=Path, help="New private JSON report outside the collection directory")
    args = parser.parse_args()
    try:
        if args.output and args.output.resolve().is_relative_to(args.data_dir.resolve()):
            raise ValueError("Report output must be outside the collection directory")
        result = audit(args.data_dir)
        text = json.dumps(result, indent=2, allow_nan=False)
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                output.write(text + "\n")
        print(text)
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, f"Audit failed: {error}\n")
    return {"PASS": 0, "FAIL": 1, "REVIEW": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
