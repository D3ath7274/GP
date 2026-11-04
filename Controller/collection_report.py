"""Streaming closed-run integrity/daily quality report. Never assigns labels."""

from collections import Counter
import csv
from datetime import datetime, timezone
import ipaddress
from itertools import zip_longest
import json
import math
from pathlib import Path
import sqlite3
import tempfile

from collection_io import collection_lease
from site_policy import digest, PROFILE_FIELDS

QUALITY_COUNTERS = ("kernel_drops", "late_packets", "source_window_omissions", "cardinality_overflows",
    "decoder_failures", "history_evictions", "destination_history_evictions", "pair_history_evictions",
    "timestamp_reorders", "truncated_packets", "unsupported_jumbograms", "socket_truncated_frames",
    "missing_kernel_timestamps", "invalid_timestamps", "dns_parse_errors", "tls_parse_errors", "http_parse_errors")
TEXT_FIELDS = {"schema_version", "run_id", "window_start_utc", "window_end_utc", "device_ip", "vlan", "ground_truth"}


def instant(value):
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError("Window timestamp lacks timezone")
    return result.timestamp()


def report(directory):
    directory = Path(directory)
    with collection_lease(directory):
        return _report(directory)


def _report(directory):
    schema = json.loads((directory / "schema.json").read_text(encoding="utf-8"))
    schema_hash = digest(schema)
    issues, counts, quality, capture_totals = Counter(), Counter(), Counter(), Counter()
    devices, days, used_runs, run_rows = {}, {}, set(), Counter()
    earliest = latest = None
    # A temporary disk index bounds RAM and detects overlaps across run/daily files.
    with tempfile.TemporaryDirectory(prefix="apf-report-") as temporary:
        db = sqlite3.connect(str(Path(temporary) / "intervals.sqlite3"))
        try:
            db.execute("CREATE TABLE windows (device TEXT, start REAL, end REAL, PRIMARY KEY(device,start))")
            for path in sorted(directory.glob("features-*.csv")):
                counts["files"] += 1
                sidecar = path.with_name(path.name.replace("features-", "policy-events-")).with_suffix(".jsonl")
                if not sidecar.exists():
                    issues["missing_evidence_file"] += 1
                    continue
                with path.open(newline="", encoding="utf-8") as source, sidecar.open(encoding="utf-8") as evidence:
                    reader = csv.DictReader(source)
                    if reader.fieldnames != schema["columns"]:
                        issues["schema_mismatch"] += 1
                        continue
                    for row, line in zip_longest(reader, evidence):
                        counts["rows"] += 1
                        if counts["rows"] > 2_000_000:
                            raise ValueError("Report exceeds two million rows; use a smaller closed collection")
                        if row is None or not line or not line.endswith("\n"):
                            issues["evidence_csv_length_mismatch"] += 1
                            continue
                        try:
                            if None in row or any(v is None for v in row.values()):
                                raise ValueError("Broken CSV row")
                            if row["schema_version"] != schema["schema_version"] or row["ground_truth"] != "UNKNOWN":
                                raise ValueError("Unexpected provenance")
                            ipaddress.ip_address(row["device_ip"])
                            numeric = {k: float(v) if v else None for k, v in row.items() if k not in TEXT_FIELDS}
                            if any(v is not None and not math.isfinite(v) for v in numeric.values()):
                                issues["nonfinite_feature"] += 1
                                continue
                            start, end = instant(row["window_start_utc"]), instant(row["window_end_utc"])
                            date = datetime.fromtimestamp(start, timezone.utc).date().isoformat()
                            if path.name != "features-" + date + "-" + row["run_id"] + ".csv":
                                raise ValueError("Row date/run and filename differ")
                            duration = numeric["window_seconds"]
                            if not 0 < duration <= 5 or abs(end - start - duration) > .001:
                                raise ValueError("Window bounds")
                            for name in ("metadata_enabled", "content_enabled", "history_restarted", "window_complete"):
                                if row[name] not in ("0", "1"):
                                    raise ValueError("Invalid binary metadata")
                            if bool(numeric["metadata_enabled"]) != schema["metadata"] or bool(numeric["content_enabled"]) != schema["content"]:
                                raise ValueError("Parser settings differ from contract")
                            if row["window_complete"] == "1" and (duration != 5 or start % 5):
                                raise ValueError("Complete window must follow five-second grid")
                            for name in ("out_packets", "in_packets", "out_bytes", "in_bytes"):
                                if numeric[name] is None or numeric[name] < 0 or not numeric[name].is_integer():
                                    raise ValueError("Invalid nonnegative integer counter")
                            for field, numerator in (("out_pps", "out_packets"), ("out_bytes_per_second", "out_bytes"), ("g14_new_syn_rate", "g11_syn_count")):
                                if not math.isclose(numeric[field], numeric[numerator] / duration, rel_tol=1e-6, abs_tol=1e-6):
                                    issues["rate_mismatch"] += 1
                            if numeric["device_new_dst_ratio"] is not None and not 0 <= numeric["device_new_dst_ratio"] <= 1:
                                issues["invalid_novelty"] += 1
                            record = json.loads(line)
                            if record.get("evidence_id") != digest({k: v for k, v in record.items() if k != "evidence_id"}):
                                issues["evidence_hash_mismatch"] += 1
                            for field in ("run_id", "schema_version", "device_ip", "vlan", "window_start_utc", "window_end_utc"):
                                if record[field] != row[field]:
                                    raise ValueError("Evidence/CSV identity or time mismatch")
                            if record["collection_schema_sha256"] != schema_hash:
                                raise ValueError("Evidence schema hash differs")
                            if any(record["features"][k] != numeric[k] for k in PROFILE_FIELDS):
                                raise ValueError("Evidence/CSV feature mismatch")
                            key = row["device_ip"] + "@" + row["vlan"]
                            if key not in devices:
                                if len(devices) >= 4096:
                                    raise ValueError("Report exceeds 4096 device bindings")
                                devices[key] = Counter()
                            prior = db.execute("SELECT end FROM windows WHERE device=? AND start<=? ORDER BY start DESC LIMIT 1", (key, start)).fetchone()
                            following = db.execute("SELECT start FROM windows WHERE device=? AND start>? ORDER BY start LIMIT 1", (key, start)).fetchone()
                            if prior and prior[0] > start or following and following[0] < end:
                                issues["out_of_order_or_duplicate_windows"] += 1
                            try:
                                db.execute("INSERT INTO windows VALUES (?,?,?)", (key, start, end))
                            except sqlite3.IntegrityError:
                                issues["duplicate_window_key"] += 1
                            device = devices[key]
                            device["rows"] += 1
                            device["observed_window_seconds"] += duration
                            device["out_packets"] += numeric["out_packets"]
                            device["in_packets"] += numeric["in_packets"]
                            device["first_seen_epoch"] = min(device.get("first_seen_epoch", start), start)
                            device["last_seen_epoch"] = max(device.get("last_seen_epoch", end), end)
                            day = datetime.fromtimestamp(start, timezone.utc).date().isoformat()
                            daily = days.setdefault(day, Counter())
                            for target in (daily, counts, device):
                                target["partial_windows"] += row["window_complete"] == "0"
                                target["review_eligible_windows"] += record["learning"] == "ELIGIBLE_FOR_REVIEW"
                                target["held_windows"] += record["learning"] != "ELIGIBLE_FOR_REVIEW"
                                target["finding_windows"] += bool(record["findings"])
                                for name in ("g15_query_count", "g15_response_count", "g16_complete_clienthello_count", "g17_complete_http_requests"):
                                    target[name] += numeric[name]
                            daily["rows"] += 1
                            earliest = start if earliest is None else min(earliest, start)
                            latest = end if latest is None else max(latest, end)
                            used_runs.add(row["run_id"])
                            run_rows[row["run_id"]] += 1
                        except (ValueError, TypeError, KeyError, OverflowError):
                            issues["invalid_row"] += 1
            for key, device in devices.items():
                previous_end = None
                for start, end in db.execute("SELECT start,end FROM windows WHERE device=? ORDER BY start", (key,)):
                    if previous_end is not None:
                        gap = max(0, start - previous_end)
                        device["unobserved_gap_seconds"] += gap
                        device["longest_unobserved_gap_seconds"] = max(device["longest_unobserved_gap_seconds"], gap)
                    previous_end = max(previous_end or end, end)
        finally:
            db.close()
    runs = {}
    expected_sidecars = {p.name.replace("features-","policy-events-").replace(".csv",".jsonl") for p in directory.glob("features-*.csv")}
    issues["orphan_evidence_files"] += len({p.name for p in directory.glob("policy-events-*.jsonl")} - expected_sidecars)
    for path in directory.glob("run-*.json"):
        run = json.loads(path.read_text(encoding="utf-8"))
        identifier = run["run_id"]
        if path.name != "run-" + identifier + ".json" or run.get("collection_schema_sha256") != schema_hash:
            issues["run_provenance_mismatch"] += 1
        if run["rows_written"] != run_rows[identifier]:
            issues["run_row_count_mismatch"] += 1
        runs[identifier] = {"capture_state": run["capture_state"], "capture_source": run.get("capture_source"), "rows_written": run["rows_written"], "updated_at": run["updated_at"]}
        runs[identifier]["runtime_provenance"] = run.get("runtime_provenance")
        quality["unversioned_runs"] += not bool(run.get("runtime_provenance"))
        for name in ("received_frames", "parsed_packets", "parsed_bytes", "unsupported_frames", "kernel_packets", "kernel_drops", "outgoing_copies_skipped"):
            capture_totals[name] += run["health"].get(name,0)
        for name in QUALITY_COUNTERS:
            value = run["health"].get(name, 0)
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                issues["invalid_quality_counter"] += 1
            else:
                quality[name] += value
        quality["failed_runs"] += run["capture_state"] in ("failed", "storage_limit")
        quality["unclosed_runs"] += run["capture_state"] not in ("stopped", "replay_complete", "failed", "storage_limit")
        quality["replay_runs"] += run.get("capture_source") != "live_linux"
        quality["unmeasured_kernel_loss_runs"] += not run.get("kernel_statistics_available", False)
    issues["missing_run_records"] += len(used_runs - set(runs))
    if not counts["rows"]:
        issues["no_feature_rows"] += 1
    issues += Counter()
    quality["partial_windows"] = counts["partial_windows"]
    status = "FAIL" if issues else "REVIEW" if any(quality.values()) or counts["held_windows"] else "PASS"
    return {"version": "collection-quality-v1", "status": status, "schema_version": schema["schema_version"],
        "collection_schema_sha256": schema_hash, "counts": dict(counts), "integrity_issues": dict(issues),
        "quality_counters": dict(quality), "observed_span_days": (latest - earliest) / 86400 if earliest is not None else 0,
        "capture_totals":dict(capture_totals),
        "days_utc": days, "devices": devices, "runs": runs,
        "parser_settings": {"metadata": schema["metadata"], "http": schema["content"]},
        "interpretation": "Closed-file checks; gaps may mean idle/offline/bypass/loss. Parser counts are not application coverage or detection accuracy. Labels remain UNKNOWN."}
