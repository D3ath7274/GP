"""Read-only readiness checks; a network interface is not proof of a traffic mirror."""

import argparse
from datetime import datetime, timezone
import importlib
import ipaddress
import json
import math
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Controller"))
from collection_io import collection_lease


def visibility(path, interface, networks, now):
    if path is None:
        return "REVIEW", "No observation attestation: perform the guide's request/response tests."
    evidence = json.loads(path.read_text(encoding="utf-8"))
    required = {"version", "interface", "networks", "valid_from", "valid_until", "reviewer", "tested_paths", "limitations"}
    if set(evidence) != required or evidence["version"] != "visibility-v1":
        raise ValueError("Invalid visibility-v1 fields")
    def instant(value):
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("Visibility times require UTC offsets")
        return stamp.timestamp()
    if evidence["interface"] != interface or evidence["networks"] != networks:
        raise ValueError("Visibility evidence does not match interface/ordered networks")
    if not instant(evidence["valid_from"]) <= now < instant(evidence["valid_until"]):
        return "REVIEW", "Observation attestation is not currently valid."
    if not isinstance(evidence["reviewer"], str) or not evidence["reviewer"].strip():
        raise ValueError("Visibility evidence needs a reviewer")
    paths = evidence["tested_paths"]
    if not isinstance(paths, list) or not 1 <= len(paths) <= 256:
        raise ValueError("Visibility evidence needs 1..256 tested paths")
    if not isinstance(evidence["limitations"], list) or any(not isinstance(x, str) for x in evidence["limitations"]):
        raise ValueError("Record observation limitations as text entries")
    for item in paths:
        if (not isinstance(item, dict) or set(item) != {"alias", "family", "request_seen", "response_seen", "reference"}
                or item["family"] not in ("IPv4", "IPv6")
                or any(not isinstance(item[k], str) or not item[k].strip() for k in ("alias", "reference"))
                or type(item["request_seen"]) is not bool or type(item["response_seen"]) is not bool):
            raise ValueError("Invalid tested path")
        if not item["request_seen"] or not item["response_seen"]:
            return "REVIEW", "At least one tested path lacks both directions."
    families = {"IPv4" if ipaddress.ip_network(n).version == 4 else "IPv6" for n in networks}
    if not families <= {p["family"] for p in paths}:
        return "REVIEW", "At least one configured IP family has no bidirectional test."
    return "PASS", f"Operator attested {len(paths)} paths; untested paths remain outside this evidence."


def preflight(args):
    checks = []
    def add(name, status, detail):
        checks.append(dict(check=name, status=status, detail=detail))
    add("python", "PASS" if sys.version_info >= (3, 10) else "FAIL", sys.version.split()[0])
    modules = {}
    for name in ("scapy", "markdown", "psutil"):
        try:
            modules[name] = importlib.import_module(name)
            add("dependency_" + name, "PASS", "Import succeeded")
        except ImportError:
            add("dependency_" + name, "FAIL" if name == "scapy" else "REVIEW", "Import unavailable")
    networks = [str(ipaddress.ip_network(n, strict=True)) for n in args.lan]
    for value in (args.min_free_gib, args.max_data_gib):
        if not math.isfinite(value) or value <= 0:
            raise ValueError("Storage budgets must be positive and finite")
    if not 1 <= args.port <= 65535:
        raise ValueError("Port must be 1..65535")
    ancestor = args.data_dir.resolve()
    while not ancestor.exists():
        ancestor = ancestor.parent
    free = shutil.disk_usage(ancestor).free
    used = sum(p.stat().st_size for p in args.data_dir.iterdir() if p.is_file()) if args.data_dir.exists() else 0
    add("disk", "PASS" if free >= args.min_free_gib * 1024**3 and used < args.max_data_gib * 1024**3 else "FAIL",
        f"free_bytes={free}; collection_bytes={used}; directory is not created")
    add("directory_access", "PASS" if os.access(ancestor, os.W_OK) else "FAIL", "Access check only; no write probe")
    try:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", args.port))
        add("dashboard_port", "PASS", "Loopback bind probe succeeded; socket closed")
    except OSError:
        add("dashboard_port", "FAIL", "Loopback port unavailable")
    if args.pcap:
        from scapy.utils import PcapReader
        with PcapReader(str(args.pcap)) as packets:
            first = next(packets, None)
        add("pcap", "PASS" if first is not None else "FAIL", "First record checked; full replay qualification is separate")
        add("live_capture", "REVIEW", "Replay does not qualify live visibility, packet loss or clock")
    else:
        linux = sys.platform.startswith("linux") and hasattr(socket, "AF_PACKET")
        add("platform", "PASS" if linux else "FAIL", "Live capture requires Linux AF_PACKET")
        if linux:
            try:
                socket.if_nametoindex(args.interface)
                state = (Path("/sys/class/net") / args.interface / "operstate").read_text().strip()
                add("interface", "PASS" if state == "up" else "REVIEW", "Operational state: " + state)
                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)):
                    pass
                add("capture_permission", "PASS", "Raw socket opened and closed without receiving traffic")
            except OSError:
                add("capture_permission_or_interface", "FAIL", "Interface or CAP_NET_RAW/root access unavailable")
            try:
                result = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                                        capture_output=True, text=True, timeout=4, check=False)
                add("clock", "PASS" if result.returncode == 0 and result.stdout.strip() == "yes" else "REVIEW",
                    "timedatectl synchronization assertion; independent clock accuracy is not measured")
            except (OSError, subprocess.TimeoutExpired):
                add("clock", "REVIEW", "Clock synchronization could not be queried")
        status, detail = visibility(args.visibility_evidence, args.interface, networks, datetime.now(timezone.utc).timestamp())
        add("visibility", status, detail)
    if "scapy" in modules:
        from home_sensor import collection_contract
        from site_policy import ShadowPolicy, digest, load_json
        contract = collection_contract(networks, args.metadata, args.http)
        import hashlib
        source_hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in
                        ("Controller/home_sensor.py", "Controller/site_features.py", "Controller/site_policy.py", "Controller/collection_io.py")}
        add("source_fingerprints", "PASS", json.dumps(source_hashes, sort_keys=True))
        policy = ShadowPolicy(load_json(args.policy) if args.policy else None,
                              [load_json(path) for path in args.approved_baseline])
        if any(p["collection_schema_sha256"] != digest(contract) for p in policy.approved.values()):
            raise ValueError("Approved baseline and requested schema differ")
        if any(not any(ipaddress.ip_address(d["ip"]) in ipaddress.ip_network(n) for n in networks)
               for d in policy.devices.values()):
            raise ValueError("Policy device outside configured networks")
        try:
            with collection_lease(args.data_dir, create=False):
                schema = args.data_dir / "schema.json"
                if schema.exists() and json.loads(schema.read_text(encoding="utf-8")) != contract:
                    add("schema", "FAIL", "Existing settings differ: use a new collection directory")
                else:
                    add("schema", "PASS", "Requested contract matches or directory is new: " + digest(contract))
                saved = args.data_dir / "profile-state.json"
                if saved.exists():
                    state = json.loads(saved.read_text(encoding="utf-8"))
                    add("profile_checkpoint", "REVIEW", "Checkpoint exists; runtime and recovery suite validate restored contents")
            add("collection_lease", "PASS", "No competing owner observed; this is a point-in-time check")
        except OSError:
            add("collection_lease", "FAIL", "Existing lease unavailable; stop collection before this check")
    return {"version": "preflight-v1", "checks": checks,
            "status": "FAIL" if any(c["status"] == "FAIL" for c in checks) else
                      "REVIEW" if any(c["status"] == "REVIEW" for c in checks) else "PASS",
            "model_scoring": False, "enforcement": "NOT_ATTEMPTED",
            "meaning": "Point-in-time prerequisites, not detection accuracy or whole-network coverage."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface")
    source.add_argument("--pcap", type=Path)
    parser.add_argument("--lan", action="append", required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--metadata", action="store_true")
    parser.add_argument("--http", action="store_true")
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--approved-baseline", type=Path, action="append", default=[])
    parser.add_argument("--visibility-evidence", type=Path)
    parser.add_argument("--min-free-gib", type=float, default=1)
    parser.add_argument("--max-data-gib", type=float, default=5)
    args = parser.parse_args()
    try:
        result = preflight(args)
    except (OSError, ValueError, TypeError, KeyError, ImportError) as error:
        result = {"version": "preflight-v1", "status": "FAIL", "error": str(error)}
    print(json.dumps(result, indent=2, allow_nan=False))
    return {"PASS": 0, "FAIL": 1, "REVIEW": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
