"""Frozen, offline feature-group evidence; never imports an enforcement adapter.

Empirical ranks are diagnostics conditional on a reviewed reference distribution,
not probabilities of compromise or guaranteed time-series false-alarm rates.
"""

from bisect import bisect_left
from collections import defaultdict
from copy import deepcopy
import csv
from datetime import datetime, timezone
import hashlib
import ipaddress
import io
import json
import math
from pathlib import Path
import re
import statistics


VERSION = "feature-group-evidence-v1"
MAX_ROWS = 4096
MAX_BYTES = 32 * 1024 * 1024
MAX_DEVICES = 16
DEFAULT_GROUPS = ("BASE", "G1", "G6", "G11", "G12", "G13", "G14")
ALLOWED_GROUPS = set(DEFAULT_GROUPS) | {"DEVICE", "G15", "G16", "G17"}
META = ("schema_version", "run_id", "window_start_utc", "window_end_utc",
        "window_seconds", "device_ip", "vlan", "ground_truth", "metadata_enabled",
        "content_enabled", "history_restarted", "cardinality_overflows_total", "window_complete")
EXCLUDE = {"profile_windows_before"}  # Age/support is not evidence of an attacker.


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


def strict_json(path):
    if Path(path).stat().st_size > MAX_BYTES:
        raise ValueError("JSON exceeds the 32 MiB research limit")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    def constant(_value):
        raise ValueError("Nonfinite JSON constant")
    with Path(path).open("rb") as source:
        raw=source.read(MAX_BYTES+1)
    if len(raw)>MAX_BYTES:
        raise ValueError("JSON grew beyond the research limit")
    return json.loads(raw.decode("utf-8-sig"),
                      object_pairs_hook=pairs, parse_constant=constant)


def catalog_groups(catalog):
    """Use the source-mapped catalog, without importing capture or model modules."""
    output = {}
    for group in catalog["groups"]:
        if group["id"] in ALLOWED_GROUPS:
            output[group["id"]] = [f for f in group["site_columns"] if f not in EXCLUDE]
    columns = [f for g in catalog["groups"] for f in g["site_columns"]]
    if len(columns) != 71 or len(set(columns)) != 71 or set(META) - set(columns):
        raise ValueError("Unsupported site column contract")
    return output, set(columns)


def number(value):
    if isinstance(value, bool) or value is None or value == "":
        return None
    try:
        result = float(value)
    except (ValueError, TypeError):
        return None
    return result if math.isfinite(result) and abs(result) <= 1e18 else None


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        raise ValueError("Invalid event timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("Event timestamps must explicitly use UTC")
    return parsed.timestamp()


def row_identity(row):
    address = str(ipaddress.ip_address(row["device_ip"]))
    vlan = row["vlan"]
    if not isinstance(vlan, str) or len(vlan) > 32 or "@" in vlan:
        raise ValueError("Invalid VLAN identity")
    return address + "@" + vlan


def row_issues(row):
    """CSV-local eligibility only; capture loss/identity need separate evidence."""
    issues = []
    if row.get("schema_version") != "site-v3.0":
        issues.append("unsupported_schema")
    start, end = timestamp(row["window_start_utc"]), timestamp(row["window_end_utc"])
    if end - start != 5 or number(row.get("window_seconds")) != 5:
        issues.append("not_complete_five_second_window")
    for name, expected in (("window_complete", 1),
                           ("cardinality_overflows_total", 0)):
        if number(row.get(name)) != expected:
            issues.append(name)
    for name in ("metadata_enabled", "content_enabled", "history_restarted"):
        if str(row.get(name)) not in ("0", "1"):
            issues.append(name)
    for name in ("out_packets", "in_packets", "out_bytes", "in_bytes"):
        value=number(row.get(name))
        if value is None or value < 0 or not value.is_integer():
            issues.append("invalid_"+name)
    for rate,total in (("out_pps","out_packets"),("out_bytes_per_second","out_bytes")):
        value,count=number(row.get(rate)),number(row.get(total))
        if value is None or count is None or not math.isclose(value,count/5,rel_tol=1e-9,abs_tol=1e-9):
            issues.append("inconsistent_"+rate)
    return issues


def supported_value(row, field):
    """State a denominator/support condition; missing never becomes zero."""
    value = number(row.get(field))
    if value is None:
        return None
    if (field.startswith("g13_") or field in ("device_new_dst_ratio", "g12_ttl_residual")) and str(row.get("history_restarted")) != "0":
        return None
    if field != "g12_ttl_residual" and value < 0:
        return None
    if ((field.endswith(("_count", "_packets", "_bytes", "_pairs", "_bucketed"))
            or field in ("device_macs_observed", "profile_windows_before")) and not value.is_integer()):
        return None
    if field == "g12_ttl_mean" and value > 255 or field == "g12_ttl_residual" and abs(value) > 255:
        return None
    if field == "g12_tcp_window_mean" and value > 65535:
        return None
    if field.endswith("ratio") or field.endswith("ratio_mean"):
        if field not in ("g14_out_in_bytes_ratio",) and value > 1:
            return None
    if field in ("inter_arrival_mean", "inter_arrival_std", "inter_arrival_cv"):
        minimum = 2 if field == "inter_arrival_mean" else 3
        if (number(row.get("out_packets")) or 0) < minimum:
            return None
        if field == "inter_arrival_cv" and not (number(row.get("inter_arrival_mean")) or 0) > 0:
            return None
    if field == "packet_size_std" and (number(row.get("out_packets")) or 0) < 2:
        return None
    if field.startswith(("g15_", "g16_")) and str(row.get("metadata_enabled")) != "1":
        return None
    if field.startswith("g17_") and str(row.get("content_enabled")) != "1":
        return None
    # Ten is a conservative engineering default for parser-derived means/ratios,
    # not a theorem or a declaration of detector accuracy.
    support = None
    if field == "g15_nxdomain_response_ratio":
        support = "g15_response_count"
    elif field in ("g15_qname_length_mean", "g15_qname_entropy_mean"):
        support = "g15_query_count"
    elif field.startswith("g17_uri_"):
        support = "g17_complete_http_requests"
    if support and (number(row.get(support)) or 0) < 10:
        return None
    if field == "g13_pair_interval_cv_mean" and (number(row.get("g13_pair_interval_supported_pairs")) or 0) < 1:
        return None
    return value


def read_dataset(path, columns):
    path = Path(path)
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("CSV exceeds the 32 MiB research limit; select a closed bounded interval")
    with path.open("rb") as source:
        raw = source.read(MAX_BYTES+1)
    if len(raw) > MAX_BYTES:
        raise ValueError("CSV grew beyond the research limit")
    rows = []
    with io.StringIO(raw.decode("utf-8-sig"), newline="") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or len(reader.fieldnames) != len(columns) or set(reader.fieldnames) != columns:
            raise ValueError("CSV must have exactly the current 71 site columns")
        for row in reader:
            if len(rows) >= MAX_ROWS or None in row or any(v is None for v in row.values()):
                raise ValueError("CSV row cap exceeded or malformed row")
            row_identity(row)
            row_issues(row)
            rows.append(row)
    if not rows:
        raise ValueError("Empty CSV")
    return rows, hashlib.sha256(raw).hexdigest()


def read_rows(path, columns):
    return read_dataset(path, columns)[0]


def tail_rank(score, sorted_reference):
    """Inclusive >= tie handling with the finite-sample +1 correction."""
    return (1 + len(sorted_reference) - bisect_left(sorted_reference, score)) / (len(sorted_reference) + 1)


def feature_score(value, feature):
    return -math.log2(tail_rank(abs(value - feature["median"]), feature["distances"]))


def group_score(row, features):
    scores = []
    for name, feature in features.items():
        value = supported_value(row, name)
        if value is None:
            return None
        scores.append(feature_score(value, feature))
    return max(scores) if scores else None


def chronological(rows):
    if not rows or len(rows) > MAX_ROWS:
        raise ValueError("Reference row count must be in [1,4096]")
    grouped = defaultdict(list)
    for row in rows:
        identity = row_identity(row)
        if len(grouped) >= MAX_DEVICES and identity not in grouped:
            raise ValueError("More than 16 device/VLAN identities; use a smaller research slice")
        if row_issues(row):
            raise ValueError("Reference contains ineligible rows: " + ",".join(row_issues(row)))
        grouped[identity].append(row)
    for values in grouped.values():
        values.sort(key=lambda r: timestamp(r["window_start_utc"]))
        for first, second in zip(values, values[1:]):
            if timestamp(second["window_start_utc"]) < timestamp(first["window_end_utc"]):
                raise ValueError("Overlapping or duplicate reference windows")
    return grouped


def fit_reference(fit_rows, calibration_rows, groups, selected=DEFAULT_GROUPS,
                  alpha=.05, min_samples=64, reviewed=False):
    if not reviewed:
        raise ValueError("Explicit operator review of both reference intervals is required")
    if not isinstance(alpha, (float, int)) or isinstance(alpha, bool) or not .001 <= alpha <= .1:
        raise ValueError("alpha must be in [0.001, 0.1]")
    if type(min_samples) is not int or not 20 <= min_samples <= MAX_ROWS:
        raise ValueError("min_samples must be an integer in [20,4096]")
    if not selected or len(set(selected)) != len(selected) or set(selected) - ALLOWED_GROUPS:
        raise ValueError("Select unique supported site measurement groups")
    fit, calibration = chronological(fit_rows), chronological(calibration_rows)
    if any(r.get("ground_truth") not in ("UNKNOWN", "REVIEWED_BENIGN") for r in fit_rows + calibration_rows):
        raise ValueError("Known non-benign reference labels are not eligible")
    if set(fit) != set(calibration):
        raise ValueError("Fit/calibration device identities must match exactly")
    required_calibration = max(min_samples, math.ceil(1 / alpha) - 1)
    model = dict(version=VERSION, schema="site-v3.0", alpha=float(alpha), min_samples=min_samples,
                 selected=list(selected), groups={g:list(groups[g]) for g in selected}, devices={},
                 provenance={},
                 automatic_apply=False, model_promotion=False,
                 interpretation="Empirical reference-tail evidence, not malicious probability; time-series validity unqualified")
    for identity in sorted(fit):
        fitted, calibrated = fit[identity], calibration[identity]
        if len(fitted) < min_samples or len(calibrated) < required_calibration:
            raise ValueError("Insufficient reference windows or alpha resolution")
        fit_end = max(timestamp(r["window_end_utc"]) for r in fitted)
        if min(timestamp(r["window_start_utc"]) for r in calibrated) < fit_end:
            raise ValueError("Fit must end before calibration begins")
        settings = {(str(r["metadata_enabled"]), str(r["content_enabled"])) for r in fitted + calibrated}
        if len(settings) != 1:
            raise ValueError("Inspection settings must not change between reference intervals")
        device = dict(settings=list(next(iter(settings))), fit_windows=len(fitted),
                      calibration_windows=len(calibrated), fit_end=fit_end,
                      calibration_end=max(timestamp(r["window_end_utc"]) for r in calibrated),
                      qualified={}, excluded={}, overall_scores=[])
        for group in selected:
            features, unavailable = {}, []
            for name in groups[group]:
                values = [supported_value(r, name) for r in fitted]
                values = [v for v in values if v is not None]
                if len(values) < min_samples:
                    unavailable.append(name)
                    continue
                median = statistics.median(values)
                distances = sorted(abs(v - median) for v in values)
                features[name] = dict(median=median, mad=statistics.median(distances), distances=distances)
            scores = [group_score(r, features) for r in calibrated] if features else []
            scores = sorted(s for s in scores if s is not None)
            if len(scores) < required_calibration:
                device["excluded"][group] = dict(reason="insufficient_supported_calibration", unavailable=unavailable)
            else:
                device["qualified"][group] = dict(features=features, scores=scores, unavailable=unavailable)
        if not device["qualified"]:
            raise ValueError("No group has enough supported fit/calibration measurements")
        for row in calibrated:
            scores = [group_score(row, g["features"]) for g in device["qualified"].values()]
            if scores and all(s is not None for s in scores):
                device["overall_scores"].append(max(scores))
        device["overall_scores"].sort()
        if len(device["overall_scores"]) < required_calibration:
            device["overall_scores"] = []
        model["devices"][identity] = device
    model["sha256"] = digest(model)
    return model


def validate_reference(model, groups):
    """Validate untrusted JSON shape/ranges; a matching hash is not authentication."""
    expected = {"version", "schema", "alpha", "min_samples", "selected", "groups", "devices",
                "automatic_apply", "model_promotion", "interpretation", "sha256", "provenance"}
    if not isinstance(model, dict) or set(model) != expected or model.get("version") != VERSION or model.get("schema") != "site-v3.0":
        raise ValueError("Unsupported evidence reference")
    copy = {k:v for k,v in model.items() if k != "sha256"}
    if digest(copy) != model["sha256"] or model["automatic_apply"] is not False or model["model_promotion"] is not False:
        raise ValueError("Reference hash/authority mismatch")
    provenance=model["provenance"]
    if (not isinstance(provenance,dict) or provenance and (set(provenance)!={"fit_csv_sha256",
            "calibration_csv_sha256","feature_catalog_sha256","method_sha256"}
            or any(not isinstance(v,str) or re.fullmatch("[0-9a-f]{64}",v) is None for v in provenance.values()))):
        raise ValueError("Invalid reference provenance")
    selected = model["selected"]
    if (not isinstance(selected, list) or not selected or any(not isinstance(g,str) for g in selected)
            or len(set(selected)) != len(selected) or set(selected) - ALLOWED_GROUPS
            or model["groups"] != {g:groups[g] for g in selected}):
        raise ValueError("Reference group contract mismatch")
    alpha, minimum = model["alpha"], model["min_samples"]
    if type(alpha) not in (int,float) or not .001 <= alpha <= .1 or type(minimum) is not int or not 20 <= minimum <= MAX_ROWS:
        raise ValueError("Invalid reference threshold/support")
    required = max(minimum, math.ceil(1 / alpha) - 1)
    if not isinstance(model["devices"], dict) or not 1 <= len(model["devices"]) <= MAX_DEVICES:
        raise ValueError("Invalid reference device cap")
    def vector(values, minimum_count, nonnegative=True):
        if (not isinstance(values,list) or not minimum_count <= len(values) <= MAX_ROWS
                or any(type(x) not in (int,float) or number(x) is None or nonnegative and x < 0 for x in values)
                or values != sorted(values)):
            raise ValueError("Invalid sorted reference vector")
    for identity, device in model["devices"].items():
        if "@" not in identity:
            raise ValueError("Invalid reference identity")
        address, vlan = identity.split("@",1)
        if row_identity({"device_ip":address,"vlan":vlan}) != identity:
            raise ValueError("Noncanonical reference identity")
        if not isinstance(device,dict) or set(device) != {"settings","fit_windows","calibration_windows","fit_end","calibration_end","qualified","excluded","overall_scores"}:
            raise ValueError("Invalid device reference")
        if (device["settings"] not in (["0","0"],["0","1"],["1","0"],["1","1"])
                or any(type(device[k]) is not int or not required_count <= device[k] <= MAX_ROWS
                       for k,required_count in (("fit_windows",minimum),("calibration_windows",required)))
                or any(type(device[k]) not in (int,float) or number(device[k]) is None for k in ("fit_end","calibration_end"))
                or device["fit_end"] >= device["calibration_end"]):
            raise ValueError("Invalid reference settings/time/support")
        if (not isinstance(device["qualified"],dict) or not device["qualified"] or not isinstance(device["excluded"],dict)
                or set(device["qualified"]) & set(device["excluded"])
                or set(device["qualified"]) | set(device["excluded"]) != set(selected)):
            raise ValueError("Invalid qualified/excluded group partition")
        for group, data in device["qualified"].items():
            if not isinstance(data,dict) or set(data) != {"features","scores","unavailable"} or not isinstance(data["features"],dict) or not data["features"] or set(data["features"]) - set(groups[group]):
                raise ValueError("Invalid group features")
            if (not isinstance(data["unavailable"],list) or any(not isinstance(f,str) for f in data["unavailable"])
                    or len(set(data["unavailable"]))!=len(data["unavailable"])
                    or set(data["unavailable"]) & set(data["features"])
                    or set(data["unavailable"]) | set(data["features"]) != set(groups[group])):
                raise ValueError("Invalid supported/unavailable feature partition")
            vector(data["scores"], required)
            if len(data["scores"])>device["calibration_windows"]:
                raise ValueError("Calibration vector exceeds observed windows")
            for name, feature in data["features"].items():
                if (not isinstance(feature,dict) or set(feature) != {"median","mad","distances"}
                        or number(feature["median"]) is None or number(feature["mad"]) is None or feature["mad"] < 0):
                    raise ValueError("Invalid feature reference")
                vector(feature["distances"], minimum)
                if len(feature["distances"])>device["fit_windows"]:
                    raise ValueError("Feature vector exceeds observed fit windows")
                if feature["mad"] != statistics.median(feature["distances"]):
                    raise ValueError("Inconsistent reference MAD")
        if device["overall_scores"]:
            vector(device["overall_scores"], required)
    return model


def score_row(model, row):
    result = dict(device_key=row_identity(row), run_id=row.get("run_id"),
                  window_start_utc=row.get("window_start_utc"), verdict="INSUFFICIENT_EVIDENCE",
                  automatic_apply=False, malicious_probability=None, overall_tail_rank=None,
                  observation_qualification="REQUIRES_SEPARATE_CAPTURE_AND_IDENTITY_EVIDENCE", groups={})
    issues = row_issues(row)
    device = model["devices"].get(result["device_key"])
    if issues or device is None:
        result["reasons"] = issues or ["unknown_device_identity"]
        return result
    if ([str(row["metadata_enabled"]),str(row["content_enabled"])] != device["settings"]
            or timestamp(row["window_start_utc"]) < device["calibration_end"]):
        result["reasons"] = ["settings_mismatch_or_not_later_than_calibration"]
        return result
    scores = []
    for group, data in device["qualified"].items():
        score = group_score(row, data["features"])
        if score is None:
            result["groups"][group] = dict(status="INSUFFICIENT_EVIDENCE", reason="missing_or_unsupported_feature")
            continue
        scores.append(score)
        tail = tail_rank(score, data["scores"])
        explanations = []
        for name, feature in data["features"].items():
            value = supported_value(row, name)
            modified_z = .6744897501960817 * ((value-feature["median"]) / feature["mad"]) if feature["mad"] else None
            z_status = "ZERO_MAD" if feature["mad"] == 0 else "AVAILABLE"
            if modified_z is not None and not math.isfinite(modified_z):
                modified_z = None
                z_status = "NUMERIC_RANGE"
            explanations.append(dict(feature=name, value=value, reference_median=feature["median"],
                reference_mad=feature["mad"], fit_tail_rank=tail_rank(abs(value-feature["median"]), feature["distances"]),
                modified_z=modified_z,
                modified_z_status=z_status,
                zero_mad=feature["mad"] == 0))
        explanations.sort(key=lambda e:e["fit_tail_rank"])
        result["groups"][group] = dict(status="UNUSUAL" if tail <= model["alpha"] else "WITHIN_REFERENCE",
            empirical_tail_rank=tail, calibration_windows=len(data["scores"]), leading_features=explanations[:5])
    result["excluded_groups"] = deepcopy(device["excluded"])
    if len(scores) == len(device["qualified"]) and device["overall_scores"]:
        tail = tail_rank(max(scores), device["overall_scores"])
        result["overall_tail_rank"] = tail
        result["verdict"] = "REVIEW_ANOMALY" if tail <= model["alpha"] else "WITHIN_REFERENCE"
        result["scope"] = "qualified groups only; excluded/unobserved attacks are not assessed"
    else:
        result["reasons"] = ["incomplete_group_evidence_or_global_calibration"]
    return result
