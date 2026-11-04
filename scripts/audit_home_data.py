"""Check closed site-v3 collection files without assigning benign/malicious labels."""

import argparse
from collections import Counter
from datetime import datetime
import csv
import ipaddress
import json
import math
from pathlib import Path


def audit(directory):
    directory = Path(directory)
    schema = json.loads((directory / "schema.json").read_text(encoding="utf-8"))
    issues = Counter()
    counts = Counter()
    earliest = latest = None
    for path in sorted(directory.glob("features-*.csv")):
        counts["files"] += 1
        previous = {}
        with path.open(newline="", encoding="utf-8") as source:
            reader = csv.DictReader(source)
            if reader.fieldnames != schema["columns"]:
                issues["schema_mismatch"] += 1
                continue
            for row in reader:
                counts["rows"] += 1
                try:
                    if None in row or any(value is None for value in row.values()):
                        raise ValueError("broken row")
                    if row["schema_version"] != schema["schema_version"] or row["ground_truth"] != "UNKNOWN":
                        raise ValueError("unexpected provenance")
                    ipaddress.ip_address(row["device_ip"])
                    start = datetime.fromisoformat(row["window_start_utc"]).timestamp()
                    end = datetime.fromisoformat(row["window_end_utc"]).timestamp()
                    duration = float(row["window_seconds"])
                    if not 0 < duration <= 5 or abs(end - start - duration) > .001:
                        raise ValueError("window bounds")
                    earliest = start if earliest is None else min(earliest, start)
                    latest = end if latest is None else max(latest, end)
                    key = (row["device_ip"], row["vlan"])
                    if key in previous and start < previous[key]:
                        issues["out_of_order_or_duplicate_windows"] += 1
                    previous[key] = end
                    if float(row["out_packets"]) < 0 or float(row["in_packets"]) < 0:
                        raise ValueError("negative counts")
                    for field, numerator in (("out_pps", "out_packets"), ("out_bytes_per_second", "out_bytes")):
                        if not math.isclose(float(row[field]), float(row[numerator]) / duration, rel_tol=1e-6, abs_tol=1e-6):
                            issues["rate_mismatch"] += 1
                    if row["device_new_dst_ratio"] and not 0 <= float(row["device_new_dst_ratio"]) <= 1:
                        issues["invalid_novelty"] += 1
                    for field in schema["columns"]:
                        if field.startswith("g") or field in ("out_pps", "out_bytes_per_second"):
                            if field != "ground_truth" and row[field] and not math.isfinite(float(row[field])):
                                issues["nonfinite_feature"] += 1
                    counts["partial_windows"] += row["window_complete"] == "0"
                except (ValueError, TypeError, KeyError):
                    issues["invalid_row"] += 1
    quality = Counter()
    for path in directory.glob("run-*.json"):
        run = json.loads(path.read_text(encoding="utf-8"))
        for name in ("kernel_drops", "late_packets", "source_window_omissions", "cardinality_overflows",
                     "decoder_failures", "history_evictions", "destination_history_evictions", "pair_history_evictions",
                     "timestamp_reorders", "truncated_packets", "unsupported_jumbograms",
                     "socket_truncated_frames", "missing_kernel_timestamps", "invalid_timestamps",
                     "dns_parse_errors", "tls_parse_errors", "http_parse_errors"):
            quality[name] += run["health"].get(name, 0)
        quality["failed_runs"] += run["capture_state"] in ("failed", "storage_limit")
        quality["unmeasured_kernel_loss_runs"] += not run.get("kernel_statistics_available", False)
    if not counts["rows"]:
        issues["no_feature_rows"] += 1
    return {"schema_version": schema["schema_version"], "counts": dict(counts),
            "integrity_issues": dict(issues), "quality_counters": dict(quality),
            "observed_span_days": (latest - earliest) / 86400 if earliest is not None else 0,
            "interpretation": "File invariants only. Review coverage, activity ledger, quality and labels independently."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_dir", type=Path)
    args = parser.parse_args()
    try:
        result = audit(args.data_dir)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f"Audit failed: {error}\n")
    print(json.dumps(result, indent=2))
    return 1 if result["integrity_issues"] else 2 if any(result["quality_counters"].values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
