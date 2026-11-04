"""Shadow policy and learning eligibility. This module never changes firewall rules."""

from collections import Counter, deque
from copy import deepcopy
from datetime import datetime
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re


POLICY_VERSION = "shadow-policy-v1"
BASELINE_VERSION = "reviewed-profile-v1"
PROFILE_FIELDS = ("out_pps", "out_bytes_per_second", "g14_new_syn_rate", "packet_size_mean")
# These are run-latched: a clean later window cannot hide an earlier measurement failure.
QUALITY_FAILURES = (
    "kernel_drops", "late_packets", "invalid_timestamps", "truncated_packets",
    "socket_truncated_frames", "missing_kernel_timestamps", "decoder_failures",
    "unsupported_jumbograms", "source_window_omissions", "cardinality_overflows",
    "timestamp_reorders", "history_evictions", "pair_history_evictions",
    "destination_history_evictions", "dns_parse_errors", "tls_parse_errors", "http_parse_errors",
)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


def load_json(path):
    path = Path(path)
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Policy/profile document exceeds 1 MiB")
    return json.loads(path.read_text(encoding="utf-8"))


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Expected a timezone-aware ISO timestamp")
    instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if instant.tzinfo is None:
        raise ValueError("Timestamps must include a timezone")
    return instant.timestamp()


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise ValueError("Identifiers must contain 1..64 letters, digits, underscores or hyphens")
    return value


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("Expected exactly these policy fields: " + ", ".join(expected))


def validate_policy(config):
    keys(config, ("version", "revision", "observation", "roles", "devices"))
    if config["version"] != POLICY_VERSION:
        raise ValueError("Unsupported policy version")
    identifier(config["revision"])
    observation = config["observation"]
    keys(observation, ("id", "bidirectional_verified", "reference", "valid_from", "valid_until"))
    identifier(observation["id"])
    if type(observation["bidirectional_verified"]) is not bool:
        raise ValueError("bidirectional_verified must be true or false")
    if not isinstance(observation["reference"], str) or len(observation["reference"]) > 512:
        raise ValueError("Observation reference must be a short local ledger reference")
    if observation["bidirectional_verified"]:
        if (not observation["reference"].strip() or
                timestamp(observation["valid_from"]) >= timestamp(observation["valid_until"])):
            raise ValueError("Verified observation needs a reference and a valid time interval")
    elif observation["valid_from"] is not None or observation["valid_until"] is not None:
        raise ValueError("Unverified observations must have null validity timestamps")
    roles = config["roles"]
    if not isinstance(roles, dict) or not 1 <= len(roles) <= 32:
        raise ValueError("Declare 1..32 roles")
    for name, role in roles.items():
        identifier(name)
        keys(role, ("tcp_initiation_allow",))
        rules = role["tcp_initiation_allow"]
        if not isinstance(rules, list) or len(rules) > 64:
            raise ValueError("A role supports at most 64 TCP initiation rules")
        for rule in rules:
            keys(rule, ("destination", "ports"))
            if not isinstance(rule["destination"], str):
                raise ValueError("Rule destination must be a CIDR string")
            ipaddress.ip_network(rule["destination"], strict=True)
            if not isinstance(rule["ports"], list) or not 1 <= len(rule["ports"]) <= 128:
                raise ValueError("Each rule needs 1..128 destination ports")
            if any(type(port) is not int or not 1 <= port <= 65535 for port in rule["ports"]):
                raise ValueError("TCP ports must be integers in 1..65535")
    devices = config["devices"]
    if not isinstance(devices, list) or not 1 <= len(devices) <= 128:
        raise ValueError("Declare 1..128 device bindings")
    seen_ids, seen_bindings = set(), set()
    for device in devices:
        keys(device, ("id", "ip", "vlan", "mac", "role", "valid_from", "valid_until"))
        identifier(device["id"])
        ip = ipaddress.ip_address(device["ip"])
        if ip.is_multicast or ip.is_unspecified or str(ip) != device["ip"]:
            raise ValueError("Inventory addresses must be canonical unicast IPs")
        vlan = device["vlan"]
        if not isinstance(vlan, str) or (vlan != "untagged" and
                not re.fullmatch(r"(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){0,3}", vlan)):
            raise ValueError("VLAN must be 'untagged' or a decimal VLAN ID")
        if vlan != "untagged" and any(int(tag) > 4094 for tag in vlan.split(".")):
            raise ValueError("VLAN is outside 0..4094")
        if (not isinstance(device["mac"], str) or
                not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", device["mac"]) or
                int(device["mac"][:2], 16) & 1 or device["mac"] == "00:00:00:00:00:00"):
            raise ValueError("Expected a lowercase unicast MAC")
        identifier(device["role"])
        if device["role"] not in roles:
            raise ValueError("Device references an undeclared role")
        if timestamp(device["valid_from"]) >= timestamp(device["valid_until"]):
            raise ValueError("Device binding has an invalid time interval")
        binding = device["ip"] + "@" + vlan
        if device["id"] in seen_ids or binding in seen_bindings:
            raise ValueError("Duplicate device ID or IP/VLAN binding")
        seen_ids.add(device["id"])
        seen_bindings.add(binding)
    return config


def in_interval(document, start, end):
    return timestamp(document["valid_from"]) <= start and end <= timestamp(document["valid_until"])


def quality_for(config, row, health, source):
    reasons = [name for name in QUALITY_FAILURES if health.get(name, 0)]
    if not row["window_complete"]:
        reasons.append("incomplete_window")
    if reasons:
        return "DEGRADED", reasons
    if config is None:
        return "UNAVAILABLE", ["observation_not_configured"]
    observation = config["observation"]
    start, end = timestamp(row["window_start_utc"]), timestamp(row["window_end_utc"])
    if not observation["bidirectional_verified"] or not in_interval(observation, start, end):
        reasons.append("observation_unverified_or_expired")
    if source != "live_linux":
        reasons.append("live_capture_not_measured")
    if not health.get("kernel_stats_reads", 0):
        reasons.append("kernel_statistics_unavailable")
    last_read = health.get("kernel_stats_at", 0)
    if not start - 10 <= last_read <= end + 10:
        reasons.append("kernel_statistics_stale")
    return ("UNAVAILABLE", reasons) if reasons else ("SUFFICIENT", [])


def update_summary(summary, values):
    for name in PROFILE_FIELDS:
        value = values.get(name)
        if value is None:
            continue
        if type(value) not in (float, int) or not math.isfinite(value) or value < 0:
            raise ValueError("Invalid profile feature: " + name)
        item = summary.setdefault(name, {"count": 0, "mean": 0.0, "m2": 0.0,
                                         "min": value, "max": value})
        item["count"] += 1
        delta = value - item["mean"]
        item["mean"] += delta / item["count"]
        item["m2"] += delta * (value - item["mean"])
        item["min"], item["max"] = min(item["min"], value), max(item["max"], value)


class ShadowPolicy:
    def __init__(self, config=None, approved=None):
        self.config = validate_policy(config) if config is not None else None
        self.policy_hash = digest(config) if config is not None else None
        self.devices = {d["ip"] + "@" + d["vlan"]: d for d in config["devices"]} if config else {}
        self.rules = {name: [(ipaddress.ip_network(r["destination"]), set(r["ports"]))
                            for r in role["tcp_initiation_allow"]]
                      for name, role in config["roles"].items()} if config else {}
        self.counts = Counter()
        self.recent = deque(maxlen=50)
        self.candidates = {}
        self.incident_holds = set()
        self.approved = {}
        for profile in approved or []:
            self._validate_approved(profile)
            if profile["device_id"] in self.approved:
                raise ValueError("Duplicate approved profile for a device")
            self.approved[profile["device_id"]] = profile
        self.approved_hashes = {key: digest(profile) for key, profile in self.approved.items()}

    def _validate_approved(self, approved):
        if not isinstance(approved, dict):
            raise ValueError("Approved profile must be an object")
        if (approved.get("version") != BASELINE_VERSION or not self.config or
                approved.get("policy_sha256") != self.policy_hash or
                approved.get("device_id") not in {d["id"] for d in self.devices.values()} or
                type(approved.get("window_count")) is not int or
                not 2 <= approved["window_count"] <= 1_000_000 or
                not isinstance(approved.get("reviewer"), str) or not approved["reviewer"].strip() or
                not isinstance(approved.get("reason"), str) or not approved["reason"].strip() or
                not approved.get("provenance") or not isinstance(approved.get("features"), dict) or
                not re.fullmatch(r"[0-9a-f]{64}", str(approved.get("collection_schema_sha256", ""))) or
                set(approved["features"]) != set(PROFILE_FIELDS)):
            raise ValueError("Approved profile does not match this policy or lacks review provenance")
        if timestamp(approved.get("review_start")) >= timestamp(approved.get("review_end")):
            raise ValueError("Invalid approved review interval")
        for name, stats in approved["features"].items():
            if (name not in PROFILE_FIELDS or not isinstance(stats, dict) or
                    set(stats) != {"count", "mean", "m2", "min", "max"} or
                    any(type(v) not in (float, int) or not math.isfinite(v) or v < 0
                        for v in stats.values()) or
                    type(stats["count"]) is not int or stats["count"] != approved["window_count"] or
                    not stats["min"] <= stats["mean"] <= stats["max"]):
                raise ValueError("Invalid approved profile statistics")

    def evaluate(self, row, window, health, source, contract_hash=None):
        self.counts["windows_evaluated"] += 1
        quality, reasons = quality_for(self.config, row, health, source)
        self.counts["quality_" + quality.lower()] += 1
        key = row["device_ip"] + "@" + row["vlan"]
        device = self.devices.get(key)
        identity = "UNREGISTERED"
        if device:
            start, end = timestamp(row["window_start_utc"]), timestamp(row["window_end_utc"])
            if not in_interval(device, start, end):
                identity = "EXPIRED_BINDING"
            elif not window.macs:
                identity = "UNOBSERVED_SOURCE_MAC"
            elif window.macs != {device["mac"]}:
                identity = "CONFLICTING_SOURCE_MAC"
            else:
                identity = "MATCHED_INVENTORY"
        self.counts["identity_" + identity.lower()] += 1
        violations = []
        if device:
            for peer, port, protocol in sorted(window.tcp_initiations):
                if not any(ipaddress.ip_address(peer) in network and port in ports
                           for network, ports in self.rules[device["role"]]):
                    violations.append({"destination": peer, "port": port, "protocol": protocol})
        findings = []
        if identity in ("CONFLICTING_SOURCE_MAC", "EXPIRED_BINDING"):
            findings.append({"type": "IDENTITY_REVIEW_REQUIRED", "severity": "suspicious"})
        if violations:
            findings.append({"type": "ROLE_SERVICE_VIOLATION", "severity": "suspicious",
                             "retained_edge_count": len(violations), "samples": violations[:8]})
        if findings:
            self.incident_holds.add(key)
        # Eligible means eligible for independent review, never approved benign traffic.
        eligible = quality == "SUFFICIENT" and identity == "MATCHED_INVENTORY" and key not in self.incident_holds
        values = {name: row.get(name) for name in PROFILE_FIELDS}
        if eligible:
            candidate = self.candidates.setdefault(device["id"], {"windows": 0, "features": {}})
            candidate["windows"] += 1
            update_summary(candidate["features"], values)
            self.counts["review_eligible_windows"] += 1
        else:
            self.counts["held_windows"] += 1
        record = {"version": POLICY_VERSION, "policy_sha256": self.policy_hash,
                  "collection_schema_sha256": contract_hash,
                  "run_id": row["run_id"], "schema_version": row["schema_version"],
                  "window_start_utc": row["window_start_utc"], "window_end_utc": row["window_end_utc"],
                  "device_ip": row["device_ip"], "vlan": row["vlan"],
                  "device_id": device["id"] if device else None,
                  "role": device["role"] if device else None, "identity": identity,
                  "quality": quality, "quality_reasons": reasons,
                  "learning": "ELIGIBLE_FOR_REVIEW" if eligible else "HOLD",
                  "incident_hold": key in self.incident_holds,
                  "ground_truth": "UNKNOWN", "action": "SHADOW_ONLY",
                  "findings": findings, "features": values,
                  "approved_profile_sha256": self.approved_hashes.get(device["id"]) if device else None,
                  "baseline_residuals": self._residuals(device, values)}
        record["evidence_id"] = digest(record)
        if findings:
            self.counts["finding_windows"] += 1
            self.recent.append(record)
        return record

    def _residuals(self, device, values):
        if not device or device["id"] not in self.approved:
            return {}
        approved = self.approved[device["id"]]
        # Residuals are diagnostics, without a calibrated anomaly threshold or probability.
        return {name: value - approved["features"][name]["mean"]
                for name, value in values.items()
                if value is not None and name in approved["features"]}

    def snapshot(self):
        return deepcopy({"version": POLICY_VERSION, "mode": "shadow", "configured": self.config is not None,
                "policy_sha256": self.policy_hash, "enforcement_enabled": False,
                "counts": dict(self.counts), "candidates": self.candidates,
                "incident_held_subjects": len(self.incident_holds),
                "approved_profile_sha256": self.approved_hashes,
                "approved_device_ids": sorted(self.approved),
                "recent_findings": list(reversed(self.recent)), "ground_truth": "UNKNOWN"})
