"""Versioned operator-described policy model; no native vendor parser or firewall writes.

The evaluator answers a concrete header-policy question. It never claims that a
route exists, NAT was resolved, an application is authorized, or a device blocked traffic.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re


FORMAT = "apf-policy-v1"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_RULES = 10_000
MAX_OBJECTS = 2_048
MAX_EXPANSION = 4_096
MAX_EXPANSION_WORK = 100_000
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")


def canonical_bytes(value):
    """Deterministic bytes let a snapshot's ID identify its exact normalized content."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field: " + key)
        result[key] = value
    return result


def parse_json(raw):
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("Policy input exceeds 8 MiB")
    def invalid_number(value):
        raise ValueError("Non-finite JSON number: " + value)
    try:
        return json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=invalid_number)
    except (RecursionError, UnicodeError) as error:
        raise ValueError("Invalid or excessively nested policy JSON") from error


def read_input(path):
    with Path(path).open("rb") as source:
        raw = source.read(MAX_INPUT_BYTES + 1)
    return raw, normalize(parse_json(raw))


def _fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError("Expected exactly these fields: " + ", ".join(names))


def _text(value, limit=512, empty=False):
    if not isinstance(value, str) or len(value) > limit or (not empty and not value.strip()):
        raise ValueError("Expected bounded text")
    if any(ord(char) < 32 for char in value):
        raise ValueError("Control characters are not allowed in policy text")
    return value


def _id(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("Invalid policy identifier")
    return value


def _conditions(value):
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError("At most 32 explicit unmodeled conditions are allowed")
    return sorted(set(_text(item) for item in value))


def _addresses(values):
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_EXPANSION:
        raise ValueError("Address selectors need 1..4096 entries")
    result = set()
    for value in values:
        if not isinstance(value, str):
            raise ValueError("Address selector must be text")
        if value == "any":
            result.add(value)
        elif value.startswith("@"):
            result.add("@" + _id(value[1:]))
        else:
            # strict=True rejects accidental network broadening, such as .10/24.
            result.add(str(ipaddress.ip_network(value, strict=True)))
    return sorted(result)


def port_intervals(value):
    if value == "any":
        return ((0, 65535),)
    if not isinstance(value, list) or not 1 <= len(value) <= 128:
        raise ValueError("Ports must be 'any' or 1..128 integers/ranges")
    intervals = []
    for item in value:
        if type(item) is int:
            low = high = item
        elif isinstance(item, str) and re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", item):
            bounds = [int(n) for n in item.split("-")]
            low, high = bounds[0], bounds[-1]
        else:
            raise ValueError("Invalid port or port range")
        if not 0 <= low <= high <= 65535:
            raise ValueError("Port range must stay within 0..65535")
        intervals.append((low, high))
    merged = []
    for low, high in sorted(intervals):
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(high, merged[-1][1]))
        else:
            merged.append((low, high))
    return tuple(merged)


def _ports(value):
    ranges = port_intervals(value)
    if ranges == ((0, 65535),):
        return "any"
    return [str(a) if a == b else f"{a}-{b}" for a, b in ranges]


@dataclass(frozen=True)
class ResolvedAddresses:
    networks: tuple
    unresolved: bool = False


class AddressResolver:
    """Bounded recursive expansion, retaining unknown objects instead of making them ANY."""
    def __init__(self, objects):
        self.objects = objects
        self.cache = {}
        self.work = 0

    def _consume(self, amount):
        self.work += amount
        if self.work > MAX_EXPANSION_WORK:
            raise ValueError("Total address expansion work exceeds 100000 entries")

    def resolve(self, selectors, stack=()):
        networks, unresolved = set(), False
        for selector in selectors:
            if selector == "any":
                self._consume(2)
                networks.update((ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")))
            elif not selector.startswith("@"):
                self._consume(1)
                networks.add(ipaddress.ip_network(selector))
            else:
                name = selector[1:]
                if name in stack:
                    raise ValueError("Address-group cycle: " + " -> ".join((*stack, name)))
                if len(stack) >= 16:
                    raise ValueError("Address-group depth exceeds 16")
                if name not in self.objects:
                    raise ValueError("Unknown address object: " + name)
                if name not in self.cache:
                    item = self.objects[name]
                    if item["kind"] == "unresolved":
                        self.cache[name] = ResolvedAddresses((), True)
                    else:
                        members = item["values"] if item["kind"] == "address" else item["members"]
                        self.cache[name] = self.resolve(members, (*stack, name))
                expanded = self.cache[name]
                self._consume(len(expanded.networks))
                networks.update(expanded.networks)
                unresolved = unresolved or expanded.unresolved
            if len(networks) > MAX_EXPANSION:
                raise ValueError("Address expansion exceeds 4096 networks")
        return ResolvedAddresses(tuple(sorted(networks, key=lambda n: (n.version, int(n.network_address), n.prefixlen))), unresolved)


def normalize(value):
    """Reject unknown fields so an unsupported selector cannot silently disappear."""
    _fields(value, ("format", "source_kind", "tenant", "site", "device", "context", "vendor",
                    "policy_revision", "collected_at", "default_action", "unmodeled_context", "objects", "rules"))
    if value["format"] != FORMAT or value["source_kind"] != "operator_description":
        raise ValueError("Only apf-policy-v1 operator descriptions are supported")
    result = {name: _id(value[name]) for name in ("tenant", "site", "device", "context", "vendor")}
    result.update(format=FORMAT, source_kind="operator_description",
                  policy_revision=_text(value["policy_revision"], 128))
    instant = datetime.fromisoformat(_text(value["collected_at"]).replace("Z", "+00:00"))
    if instant.tzinfo is None:
        raise ValueError("collected_at must include a timezone")
    result["collected_at"] = instant.astimezone(timezone.utc).isoformat()
    if value["default_action"] not in ("allow", "deny", "reject"):
        raise ValueError("Explicit default action must be allow, deny or reject")
    result["default_action"] = value["default_action"]
    result["unmodeled_context"] = _conditions(value["unmodeled_context"])
    objects = value["objects"]
    if not isinstance(objects, dict) or len(objects) > MAX_OBJECTS:
        raise ValueError("At most 2048 address objects are supported")
    result["objects"] = {}
    for name, item in sorted(objects.items()):
        _id(name)
        if not isinstance(item, dict):
            raise ValueError("Invalid object definition")
        kind = item.get("kind")
        if kind in ("address", "address_group"):
            field = "values" if kind == "address" else "members"
            _fields(item, ("kind", field))
            result["objects"][name] = {"kind": kind, field: _addresses(item[field])}
        elif kind == "unresolved":
            _fields(item, ("kind", "reason"))
            result["objects"][name] = {"kind": kind, "reason": _text(item["reason"])}
        else:
            raise ValueError("Unsupported address-object kind")
    resolver = AddressResolver(result["objects"])
    for name in result["objects"]:
        resolver.resolve(["@" + name])  # Validate even currently unused objects.
    rules = value["rules"]
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise ValueError("At most 10000 rules are supported")
    result["rules"], ids, positions = [], set(), set()
    for rule in rules:
        _fields(rule, ("id", "position", "enabled", "sources", "destinations", "protocol",
                       "source_ports", "destination_ports", "action", "logging", "owner", "comment", "constraints"))
        identifier, position = _id(rule["id"]), rule["position"]
        if type(position) is not int or position < 0 or position in positions or identifier in ids:
            raise ValueError("Rule IDs and nonnegative integer positions must be unique")
        if type(rule["enabled"]) is not bool or (rule["logging"] is not None and type(rule["logging"]) is not bool):
            raise ValueError("enabled must be boolean; logging must be boolean or null")
        if rule["protocol"] not in ("any", "tcp", "udp", "icmp", "icmpv6"):
            raise ValueError("Unsupported protocol")
        if rule["action"] not in ("allow", "deny", "reject"):
            raise ValueError("Unsupported rule action")
        item = dict(rule, sources=_addresses(rule["sources"]), destinations=_addresses(rule["destinations"]),
                    source_ports=_ports(rule["source_ports"]), destination_ports=_ports(rule["destination_ports"]),
                    constraints=_conditions(rule["constraints"]), comment=_text(rule["comment"], 1024, empty=True),
                    owner=None if rule["owner"] is None else _text(rule["owner"], 128))
        if item["protocol"] not in ("tcp", "udp") and (item["source_ports"] != "any" or item["destination_ports"] != "any"):
            raise ValueError("Only TCP/UDP rules can constrain ports")
        resolver.resolve(item["sources"])
        resolver.resolve(item["destinations"])
        result["rules"].append(item)
        ids.add(identifier)
        positions.add(position)
    result["rules"].sort(key=lambda rule: rule["position"])
    return result


def query(source, destination, protocol, destination_port=None, source_port=None):
    src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    if src.version != dst.version:
        raise ValueError("Mixed-family queries require NAT64 modeling, which is unsupported")
    if protocol not in ("tcp", "udp", "icmp", "icmpv6"):
        raise ValueError("Query needs a concrete supported protocol")
    if (protocol == "icmp" and src.version != 4) or (protocol == "icmpv6" and src.version != 6):
        raise ValueError("ICMP protocol and address family disagree")
    for port in (destination_port, source_port):
        if port is not None and (type(port) is not int or not 0 <= port <= 65535):
            raise ValueError("Query ports must be integers in 0..65535")
    if protocol in ("tcp", "udp") and destination_port is None:
        raise ValueError("TCP/UDP query requires destination_port")
    if protocol not in ("tcp", "udp") and (destination_port is not None or source_port is not None):
        raise ValueError("ICMP queries do not use transport ports")
    return dict(source=str(src), destination=str(dst), protocol=protocol,
                destination_port=destination_port, source_port=source_port)


def _address_match(resolved, address):
    if any(address.version == network.version and address in network for network in resolved.networks):
        return True
    return None if resolved.unresolved else False


def _port_match(selector, port):
    if selector == "any":
        return True
    if port is None:
        return None
    return any(low <= port <= high for low, high in port_intervals(selector))


class PolicyEvaluator:
    def __init__(self, snapshot):
        self.policy = snapshot
        self.resolver = AddressResolver(snapshot["objects"])

    def match(self, rule, point):
        tests = [rule["protocol"] in ("any", point["protocol"]),
                 _address_match(self.resolver.resolve(rule["sources"]), ipaddress.ip_address(point["source"])),
                 _address_match(self.resolver.resolve(rule["destinations"]), ipaddress.ip_address(point["destination"])),
                 _port_match(rule["source_ports"], point["source_port"]),
                 _port_match(rule["destination_ports"], point["destination_port"])]
        if False in tests:
            return "NO_MATCH"
        if None in tests or rule["constraints"]:
            return "POSSIBLE"
        return "MATCH"

    def search(self, point, limit=100, include_disabled=False):
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("Result limit must be 1..200")
        # Validate callers too, rather than relying only on the CLI or HTTP boundary.
        point = query(**point)
        self.resolver = AddressResolver(self.policy["objects"])  # Per-query work budget.
        matches, total, decisive, preceding_unknown = [], 0, None, []
        for rule in self.policy["rules"]:
            if not rule["enabled"] and not include_disabled:
                continue
            match = self.match(rule, point)
            if match == "NO_MATCH":
                continue
            total += 1
            if len(matches) < limit:
                matches.append(dict(rule, match=match))
            if rule["enabled"] and decisive is None:
                if match == "POSSIBLE":
                    if len(preceding_unknown) < 20:
                        preceding_unknown.append(rule["id"])
                else:
                    decisive = rule
        unresolved = bool(preceding_unknown or self.policy["unmodeled_context"])
        verdict = "INDETERMINATE" if unresolved else (decisive["action"] if decisive else self.policy["default_action"]).upper()
        return {"query": point, "matches": matches, "total_matches": total, "truncated": total > limit,
                "model_verdict": verdict, "decisive_rule": decisive["id"] if decisive and not unresolved else None,
                "used_default": decisive is None and not unresolved,
                "preceding_uncertain_rules": preceding_unknown,
                "unmodeled_context": self.policy["unmodeled_context"],
                "assessment_scope": "operator-described ordered header policy",
                "reachability": "NOT_EVALUATED", "enforcement": "NOT_ATTEMPTED"}


def diff_policies(before, after):
    scope = ("tenant", "site", "device", "context", "vendor", "source_kind")
    if any(before[name] != after[name] for name in scope):
        raise ValueError("Diff requires the same policy identity/context")
    def changed(left, right):
        return {"added": sorted(right.keys() - left.keys()), "removed": sorted(left.keys() - right.keys()),
                "modified": [{"id": key, "fields": sorted(name for name in set(left[key]) | set(right[key])
                              if left[key].get(name) != right[key].get(name)),
                              "field_changes": {name: {"before": left[key].get(name), "after": right[key].get(name)}
                                                for name in sorted(set(left[key]) | set(right[key]))
                                                if left[key].get(name) != right[key].get(name)}}
                             for key in sorted(left.keys() & right.keys()) if left[key] != right[key]]}
    return {"rules": changed({r["id"]: r for r in before["rules"]}, {r["id"]: r for r in after["rules"]}),
            "objects": changed(before["objects"], after["objects"]),
            "default_action_changed": before["default_action"] != after["default_action"],
            "default_action": {"before": before["default_action"], "after": after["default_action"]},
            "unmodeled_context_changed": before["unmodeled_context"] != after["unmodeled_context"],
            "before_revision": before["policy_revision"], "after_revision": after["policy_revision"],
            "actor_attribution": "UNAVAILABLE", "enforcement": "NOT_ATTEMPTED"}
