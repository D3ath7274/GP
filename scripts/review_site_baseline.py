"""Validate a shadow policy or explicitly approve reviewed windows from a stopped collector."""

import argparse
from contextlib import contextmanager
import csv
from datetime import datetime, timezone
import hashlib
from itertools import zip_longest
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Controller"))
from site_policy import (BASELINE_VERSION, POLICY_VERSION, PROFILE_FIELDS, QUALITY_FAILURES,
                         ShadowPolicy, digest, load_json, timestamp, update_summary, validate_policy)


@contextmanager
def stopped_collection(directory):
    """Use the collector's OS-managed lock, rather than assuming files are closed."""
    with (directory / ".collection.lock").open("a+b") as lock:
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt
                lock.seek(0)
                lock.write(b"0")
                lock.flush()
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise ValueError("Stop the collector before reviewing its files") from error
        yield


def file_hash(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def approve(directory, policy_path, device_id, start, end, reviewer, reason):
    """Caller supplies independent review; this validates provenance, not benignness."""
    directory = Path(directory)
    config = validate_policy(load_json(policy_path))
    policy_hash = digest(config)
    device = next((d for d in config["devices"] if d["id"] == device_id), None)
    if device is None:
        raise ValueError("Undeclared device ID")
    if not reviewer.strip() or not reason.strip() or len(reviewer) > 128 or len(reason) > 2048:
        raise ValueError("A reviewer and an independent review/ledger reason are required")
    begin, finish = timestamp(start), timestamp(end)
    if begin >= finish:
        raise ValueError("Review start must precede end")
    stats, intervals, provenance = {}, [], []
    with stopped_collection(directory):
        schema = load_json(directory / "schema.json")
        schema_hash = digest(schema)
        for path in sorted(directory.glob("policy-events-*.jsonl")):
            features_path = path.with_name(path.name.replace("policy-events-", "features-")).with_suffix(".csv")
            used_runs = set()
            with path.open(encoding="utf-8") as events, features_path.open(newline="", encoding="utf-8") as features:
                reader = csv.DictReader(features)
                if reader.fieldnames != schema["columns"]:
                    raise ValueError("CSV header differs from collection schema")
                for line, row in zip_longest(events, reader):
                    if not line or row is None or not line.endswith("\n"):
                        raise ValueError("Evidence and CSV are incomplete or have different row counts")
                    record = json.loads(line)
                    for field in ("run_id", "schema_version", "device_ip", "vlan", "window_start_utc", "window_end_utc"):
                        if record[field] != row[field]:
                            raise ValueError("Evidence does not match feature CSV")
                    left, right = timestamp(row["window_start_utc"]), timestamp(row["window_end_utc"])
                    if (row["device_ip"] != device["ip"] or row["vlan"] != device["vlan"] or
                            left < begin or right > finish):
                        continue
                    if record.get("evidence_id") != digest({k: v for k, v in record.items() if k != "evidence_id"}):
                        raise ValueError("Evidence digest mismatch")
                    if (record.get("version") != POLICY_VERSION or record.get("policy_sha256") != policy_hash or
                            record.get("collection_schema_sha256") != schema_hash or
                            record.get("device_id") != device_id or record.get("quality") != "SUFFICIENT" or
                            record.get("quality_reasons") or record.get("identity") != "MATCHED_INVENTORY" or
                            record.get("findings") or record.get("learning") != "ELIGIBLE_FOR_REVIEW" or
                            record.get("ground_truth") != "UNKNOWN"):
                        raise ValueError("Selected interval includes held, suspicious or incompatible evidence")
                    if (row["window_complete"] != "1" or right - left != 5 or float(row["window_seconds"]) != 5 or
                            row["schema_version"] != schema["schema_version"] or row["ground_truth"] != "UNKNOWN" or
                            row["device_ip"] != device["ip"] or row["vlan"] != device["vlan"]):
                        raise ValueError("Selected CSV has incompatible identity or incomplete windows")
                    for name in PROFILE_FIELDS:
                        if record["features"][name] != (float(row[name]) if row[name] else None):
                            raise ValueError("Evidence feature differs from CSV")
                    if len(intervals) >= 1_000_000:
                        raise ValueError("Review exceeds one million windows; use a shorter interval")
                    update_summary(stats, record["features"])
                    intervals.append((left, right))
                    used_runs.add(record["run_id"])
            for run_id in sorted(used_runs):
                # Run IDs are created by the collector, but validate before constructing paths.
                if len(run_id) != 12 or any(c not in "0123456789abcdef" for c in run_id):
                    raise ValueError("Invalid run ID")
                run = load_json(directory / ("run-" + run_id + ".json"))
                if (run["run_id"] != run_id or run["capture_state"] != "stopped" or
                        run.get("collection_schema_sha256") != schema_hash or
                        run.get("error") or run.get("capture_source") != "live_linux" or
                        not run.get("kernel_statistics_available") or
                        run.get("shadow_policy", {}).get("policy_sha256") != policy_hash or
                        any(run["health"].get(name, 0) for name in QUALITY_FAILURES)):
                    raise ValueError("Selected run is unfinished, unmeasured, failed or quality-degraded")
                if digest(load_json(directory / ("policy-" + run_id + ".json"))) != policy_hash:
                    raise ValueError("Saved policy differs from review policy")
                provenance.append({"run_id": run_id, "events_file": path.name,
                                   "events_sha256": file_hash(path), "features_file": features_path.name,
                                   "features_sha256": file_hash(features_path),
                                   "run_sha256": file_hash(directory / ("run-" + run_id + ".json"))})
        intervals.sort()
        if len(intervals) < 2:
            raise ValueError("At least two complete eligible windows are required for a descriptive profile")
        if any(b[0] < a[1] for a, b in zip(intervals, intervals[1:])):
            raise ValueError("Overlapping or duplicated device windows")
    profile = {"version": BASELINE_VERSION, "policy_sha256": policy_hash, "device_id": device_id,
               "collection_schema_sha256": schema_hash,
               "review_start": start, "review_end": end, "reviewer": reviewer.strip(), "reason": reason.strip(),
               "approved_at": datetime.now(timezone.utc).isoformat(), "window_count": len(intervals),
               "observed_seconds": sum(b - a for a, b in intervals),
               "features": stats, "provenance": provenance,
               "semantics": "Operator-reviewed descriptive profile; no calibrated attack threshold or model promotion"}
    ShadowPolicy(config, [profile])
    return profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("validate")
    check.add_argument("--policy", type=Path, required=True)
    review = commands.add_parser("approve")
    review.add_argument("--data-dir", type=Path, required=True)
    review.add_argument("--policy", type=Path, required=True)
    review.add_argument("--device-id", required=True)
    review.add_argument("--start", required=True)
    review.add_argument("--end", required=True)
    review.add_argument("--reviewer", required=True)
    review.add_argument("--reason", required=True)
    review.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate":
            policy = validate_policy(load_json(args.policy))
            print(json.dumps({"valid": True, "policy_sha256": digest(policy), "mode": "shadow"}))
        else:
            profile = approve(args.data_dir, args.policy, args.device_id, args.start, args.end, args.reviewer, args.reason)
            # Never replace an existing approval; preserve each review as an explicit artifact.
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                json.dump(profile, output, indent=2, allow_nan=False)
                output.flush()
                os.fsync(output.fileno())
            print(json.dumps({"written": str(args.output), "window_count": profile["window_count"],
                              "profile_sha256": digest(profile)}))
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
