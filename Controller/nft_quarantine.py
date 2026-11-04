"""Manage temporary IPv4 quarantines in a dedicated, operator-provisioned nft set."""

import argparse
import ipaddress
import json
import subprocess


TABLE = "apf_quarantine"
SET = "blocked_v4"
CHAIN = "forward_guard"


def nft(*args):
    result = subprocess.run(["nft", *args], check=True, capture_output=True,
                            text=True, timeout=10)
    return result.stdout


def read_set():
    objects = json.loads(nft("-j", "list", "table", "inet", TABLE))["nftables"]
    sets = [obj["set"] for obj in objects if "set" in obj]
    selected = next((item for item in sets if item["name"] == SET), None)
    if selected is None or selected.get("type") != "ipv4_addr":
        raise ValueError("Expected the dedicated IPv4 quarantine set")
    if "timeout" not in selected.get("flags", []):
        raise ValueError("Quarantine set must support native expiry")
    chain = next((obj["chain"] for obj in objects
                  if obj.get("chain", {}).get("name") == CHAIN), {})
    if chain.get("hook") != "forward" or chain.get("policy") != "accept":
        raise ValueError("Expected an accepting forward guard chain")
    match = {"match": {"op": "==", "left": {"payload": {
        "protocol": "ip", "field": "saddr"}}, "right": "@" + SET}}
    if not any(obj.get("rule", {}).get("chain") == CHAIN
               and obj["rule"].get("expr") == [match, {"drop": None}]
               for obj in objects):
        raise ValueError("Expected an exact source-set drop rule in the forward guard")
    return selected


def members(selected):
    for element in selected.get("elem", []):
        yield element["elem"]["val"] if isinstance(element, dict) else element


def change(action, address, scope=None, protected=(), ttl=300):
    ip = ipaddress.IPv4Address(address)
    if action == "add":
        if not 1 <= ttl <= 300:
            raise ValueError("TTL must be between 1 and 300 seconds")
        if ip not in scope or any(ip in network for network in protected):
            raise ValueError("Source is outside scope or protected")
        if ip.is_multicast or ip.is_loopback or ip.is_unspecified or (
                scope.prefixlen < 31 and ip in (scope.network_address, scope.broadcast_address)):
            raise ValueError("Source must be a unicast host")
    present = str(ip) in set(members(read_set()))
    if action == "add" and not present:
        nft("add", "element", "inet", TABLE, SET, "{", str(ip), "timeout", f"{ttl}s", "}")
    elif action == "remove" and present:
        nft("delete", "element", "inet", TABLE, SET, "{", str(ip), "}")
    active = str(ip) in set(members(read_set()))
    if active != (action == "add"):
        raise ValueError("Read-back did not confirm the requested set state")
    return {"source": str(ip), "set_member": active,
            "changed": present != active, "verification": "nftables read-back"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    add = sub.add_parser("add")
    add.add_argument("address")
    add.add_argument("--scope", required=True, type=ipaddress.IPv4Network)
    add.add_argument("--protect", required=True, action="append", type=ipaddress.IPv4Network)
    add.add_argument("--ttl", type=int, default=300)
    sub.add_parser("remove").add_argument("address")
    sub.add_parser("status")
    args = parser.parse_args()
    try:
        if args.action == "status":
            result = {"members": sorted(members(read_set()))}
        else:
            result = change(args.action, args.address, getattr(args, "scope", None),
                            getattr(args, "protect", ()), getattr(args, "ttl", 300))
        print(json.dumps(result))
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Quarantine state unconfirmed: {error}\n")


if __name__ == "__main__":
    main()
