"""Fit frozen, reviewed reference intervals and inspect later site-v3 feature groups."""

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Controller"))
from behavioral_evidence import (ALLOWED_GROUPS, DEFAULT_GROUPS, catalog_groups, digest,
    fit_reference, read_dataset, row_identity, row_issues, score_row, strict_json, timestamp, validate_reference)


def source_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_new(path, value):
    encoded = json.dumps(value, indent=2, allow_nan=False)
    if len(encoded.encode()) > 64 * 1024 * 1024:
        raise ValueError("Output exceeds 64 MiB; use a smaller research slice")
    # Never overwrite a previous experiment/reference. Parent creation is explicit.
    with Path(path).open("x", encoding="utf-8") as output:
        output.write(encoded + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="Select bounded chronological research slices from a closed CSV")
    prepare.add_argument("--csv", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--fit-windows", type=int, default=64)
    prepare.add_argument("--calibration-windows", type=int, default=128)
    fit = commands.add_parser("fit", help="Build a frozen research reference, not a deployed model")
    fit.add_argument("--fit-csv", type=Path, required=True)
    fit.add_argument("--calibration-csv", type=Path, required=True)
    fit.add_argument("--output", type=Path, required=True)
    fit.add_argument("--groups", nargs="+", choices=sorted(ALLOWED_GROUPS), default=list(DEFAULT_GROUPS))
    fit.add_argument("--alpha", type=float, default=.05)
    fit.add_argument("--min-samples", type=int, default=64)
    fit.add_argument("--reviewed-reference", action="store_true",
                     help="Acknowledge operator review of both reference intervals; not proof of clean traffic")
    score = commands.add_parser("score", help="Inspect a later closed CSV without updating the reference")
    score.add_argument("--reference", type=Path, required=True)
    score.add_argument("--csv", type=Path, required=True)
    score.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command != "prepare" and args.output.exists():
            raise ValueError("Output exists; choose a new experiment filename")
        catalog_path = ROOT / "docs-site/reference/feature-groups.json"
        groups, columns = catalog_groups(strict_json(catalog_path))
        if args.command == "prepare":
            if not 20 <= args.fit_windows <= 4096 or not 20 <= args.calibration_windows <= 4096:
                raise ValueError("Slice sizes must each be in [20,4096]")
            rows, input_hash = read_dataset(args.csv, columns)
            devices, omitted = defaultdict(list), Counter()
            for row in rows:
                issues = row_issues(row)
                if issues:
                    omitted.update(issues)
                else:
                    devices[row_identity(row)].append(row)
            if not devices or len(devices) > 16:
                raise ValueError("Need 1–16 eligible device/VLAN identities")
            slices = {name:[] for name in ("fit", "calibration", "later")}
            for values in devices.values():
                values.sort(key=lambda r:timestamp(r["window_start_utc"]))
                if len(values) <= args.fit_windows + args.calibration_windows:
                    raise ValueError("Each device needs fit + calibration + at least one later eligible window")
                for first,second in zip(values,values[1:]):
                    if timestamp(second["window_start_utc"]) < timestamp(first["window_end_utc"]):
                        raise ValueError("Overlapping or duplicate windows")
                slices["fit"].extend(values[:args.fit_windows])
                slices["calibration"].extend(values[args.fit_windows:args.fit_windows+args.calibration_windows])
                slices["later"].extend(values[args.fit_windows+args.calibration_windows:])
            args.output_dir.mkdir(mode=0o700)  # No parents/overwrite; operator owns the location.
            for name,values in slices.items():
                with (args.output_dir/(name+".csv")).open("x",newline="",encoding="utf-8") as output:
                    writer=csv.DictWriter(output,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(values)
            write_new(args.output_dir/"selection.json",dict(version="feature-evidence-selection-v1",
                input_sha256=input_hash,omitted_reason_counts=dict(omitted),
                eligible_rows=sum(len(v) for v in slices.values()),
                slice_rows={k:len(v) for k,v in slices.items()},ground_truth_modified=False,
                reference_review="REQUIRED_SEPARATELY",meaning="Chronological research split, not independent attack validation"))
            print(json.dumps({"status":"PREPARED","output_dir":str(args.output_dir),"automatic_apply":False}))
            return
        if args.command == "fit":
            fit_rows,fit_hash=read_dataset(args.fit_csv,columns)
            calibration_rows,calibration_hash=read_dataset(args.calibration_csv,columns)
            result = fit_reference(fit_rows, calibration_rows,
                                   groups, args.groups, args.alpha, args.min_samples, args.reviewed_reference)
            result["provenance"] = dict(fit_csv_sha256=fit_hash,
                calibration_csv_sha256=calibration_hash,
                feature_catalog_sha256=source_hash(catalog_path),
                method_sha256=hashlib.sha256((ROOT/"Controller/behavioral_evidence.py").read_bytes().replace(b"\r\n",b"\n")).hexdigest())
            result["sha256"] = digest({k:v for k,v in result.items() if k != "sha256"})
            validate_reference(result, groups)
        else:
            reference = validate_reference(strict_json(args.reference), groups)
            current = hashlib.sha256((ROOT/"Controller/behavioral_evidence.py").read_bytes().replace(b"\r\n",b"\n")).hexdigest()
            if reference["provenance"].get("method_sha256") != current:
                raise ValueError("Method source changed; review and rebuild the research reference")
            rows,input_hash = read_dataset(args.csv, columns)
            results = [score_row(reference, row) for row in rows]
            result = dict(version="feature-group-report-v1", reference_sha256=reference["sha256"],
                          input_sha256=input_hash, automatic_apply=False,
                          verdict_counts={label:sum(r["verdict"]==label for r in results)
                              for label in ("REVIEW_ANOMALY","WITHIN_REFERENCE","INSUFFICIENT_EVIDENCE")}, rows=results)
        write_new(args.output, result)
        print(json.dumps({"status":"WRITTEN", "output":str(args.output), "automatic_apply":False,
                          "meaning":"Research evidence only; separate capture/identity and attack evaluation required"}))
    except (OSError, ValueError, KeyError, TypeError, OverflowError, csv.Error) as error:
        parser.exit(1, "Feature evidence: " + str(error) + "\n")


if __name__ == "__main__":
    main()
