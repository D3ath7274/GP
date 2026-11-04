"""Bounded deterministic set analysis for the operator header-model subset."""

from dataclasses import dataclass
import ipaddress
from itertools import product

from firewall_policy import AddressResolver, normalize, port_intervals


class AuditBudgetError(ValueError):
    pass


class Budget:
    def __init__(self, maximum=250000):
        self.work = 0
        self.maximum = maximum

    def tick(self, amount=1):
        self.work += amount
        if self.work > self.maximum:
            raise AuditBudgetError("Audit work budget exceeded; no complete audit result is available")


@dataclass(frozen=True, order=True)
class Box:
    family: int
    protocol: str
    dimensions: tuple  # source address, destination address, source port, destination port

    def witness(self):
        address = ipaddress.IPv4Address if self.family == 4 else ipaddress.IPv6Address
        return {"source":str(address(self.dimensions[0][0])), "destination":str(address(self.dimensions[1][0])),
                "protocol":self.protocol, "source_port":self.dimensions[2][0] if self.protocol in ("tcp","udp") else None,
                "destination_port":self.dimensions[3][0] if self.protocol in ("tcp","udp") else None}


def intersection(left, right, budget):
    budget.tick()
    if (left.family, left.protocol) != (right.family, right.protocol):
        return None
    dimensions = tuple((max(a,c),min(b,d)) for (a,b),(c,d) in zip(left.dimensions,right.dimensions))
    return None if any(a>b for a,b in dimensions) else Box(left.family,left.protocol,dimensions)


def subtract(left, right, budget):
    overlap = intersection(left,right,budget)
    if overlap is None:
        return [left]
    core = list(left.dimensions)
    pieces = []
    for index, (low, high) in enumerate(overlap.dimensions):
        a,b = core[index]
        if a < low:
            part = list(core); part[index]=(a,low-1)
            pieces.append(Box(left.family,left.protocol,tuple(part)))
        if high < b:
            part = list(core); part[index]=(high+1,b)
            pieces.append(Box(left.family,left.protocol,tuple(part)))
        core[index]=(low,high)
    return pieces


def difference(region, cuts, budget):
    result = region
    for cut in cuts:
        result = [piece for box in result for piece in subtract(box,cut,budget)]
        if len(result)>4096:
            raise AuditBudgetError("Audit residual exceeds 4096 regions")
        if not result:
            break
    return result


def regions(rule, resolver, budget):
    sources, destinations = resolver.resolve(rule["sources"]), resolver.resolve(rule["destinations"])
    if sources.unresolved or destinations.unresolved or rule["constraints"]:
        return None
    result = []
    for family in (4,6):
        src = list(ipaddress.collapse_addresses(n for n in sources.networks if n.version==family))
        dst = list(ipaddress.collapse_addresses(n for n in destinations.networks if n.version==family))
        for protocol in ("tcp","udp","icmp" if family==4 else "icmpv6"):
            if rule["protocol"] not in ("any",protocol):
                continue
            sports = port_intervals(rule["source_ports"]) if protocol in ("tcp","udp") else ((0,0),)
            dports = port_intervals(rule["destination_ports"]) if protocol in ("tcp","udp") else ((0,0),)
            for source,destination,sport,dport in product(src,dst,sports,dports):
                budget.tick()
                result.append(Box(family,protocol,((int(source.network_address),int(source.broadcast_address)),
                    (int(destination.network_address),int(destination.broadcast_address)),sport,dport)))
                if len(result)>4096:
                    raise AuditBudgetError("A rule exceeds 4096 regions")
    return sorted(set(result))


def audit_policy(snapshot, max_work=250000):
    policy = normalize(snapshot)
    if len(policy["rules"])>200:
        raise AuditBudgetError("Prototype audit admits at most 200 rules; search/import have separate limits")
    budget = Budget(max_work)
    resolver = AddressResolver(policy["objects"])
    findings, uncertain, previous = [], [], []
    def finding(kind, **evidence):
        if len(findings)>=4096:
            raise AuditBudgetError("Audit exceeds 4096 findings")
        findings.append(dict(type=kind, **evidence))
    for rule in policy["rules"]:
        identifier = rule["id"]
        if not rule["enabled"]:
            finding("DISABLED_RULE",rule=identifier)
        if rule["logging"] is False:
            finding("EXPLICIT_LOGGING_DISABLED",rule=identifier,meaning="Metadata review; no logging policy/compliance verdict")
        missing = [name for name in ("owner","comment") if not rule[name] or not rule[name].strip()]
        if missing:
            finding("MISSING_DOCUMENTATION",rule=identifier,fields=missing)
        if not rule["enabled"]:
            continue
        area = regions(rule,resolver,budget)
        if area is None or policy["unmodeled_context"]:
            uncertain.append(identifier)
            previous.append((rule,None))
            continue
        if not area:
            finding("EMPTY_SUPPORTED_REGION",rule=identifier)
            previous.append((rule,area))
            continue
        remaining = area
        covered_by, covered_witness = [], None
        equivalent = rule["logging"] is not None
        unknown_predecessors = []
        for before, prior in previous:
            if prior is None:
                unknown_predecessors.append(before["id"])
                equivalent = False
                continue
            overlaps = [common for box in remaining for cut in prior
                        if (common:=intersection(box,cut,budget)) is not None]
            if overlaps:
                covered_by.append(before["id"])
                covered_witness = covered_witness or overlaps[0].witness()
                equivalent = equivalent and before["logging"] is not None and (before["action"],before["logging"])==(rule["action"],rule["logging"])
            if prior == area and (before["action"],before["logging"])==(rule["action"],rule["logging"]) and rule["logging"] is not None:
                finding("DUPLICATE_RULE",rule=identifier,duplicate_of=before["id"],witness=area[0].witness())
            remaining = difference(remaining,prior,budget)
        if not remaining:
            finding("FULLY_SHADOWED",rule=identifier,covered_by=covered_by,covered_witness=covered_witness)
            if equivalent:
                finding("REDUNDANT_BEHAVIOR",rule=identifier,covered_by=covered_by,action=rule["action"],logging=rule["logging"])
        elif covered_by:
            finding("PARTIAL_OVERLAP",rule=identifier,covered_by=covered_by,covered_witness=covered_witness,
                    residual_witness=remaining[0].witness(),residual_regions=len(remaining),
                    residual_reachability="INDETERMINATE" if unknown_predecessors else "REACHES_RULE_IN_MODEL")
        if unknown_predecessors:
            uncertain.append(identifier)
        previous.append((rule,area))
    # Reachability of object references is scoped to this model, including disabled rules.
    referenced = set()
    pending = [v[1:] for r in policy["rules"] for field in ("sources","destinations") for v in r[field] if v.startswith("@")]
    while pending:
        name = pending.pop()
        if name in referenced:
            continue
        budget.tick()
        referenced.add(name)
        item = policy["objects"][name]
        pending.extend(v[1:] for v in item.get("members",item.get("values",[])) if v.startswith("@"))
    equivalents = {}
    for name in policy["objects"]:
        if name not in referenced:
            finding("UNREFERENCED_OBJECT_IN_MODEL",object=name,meaning="NAT/VPN/application/native references are outside this model")
        addresses = resolver.resolve(["@"+name])
        if addresses.unresolved:
            continue
        key = tuple(str(n) for family in (4,6) for n in ipaddress.collapse_addresses(n for n in addresses.networks if n.version==family))
        if key in equivalents:
            finding("DUPLICATE_ADDRESS_SET",object=name,duplicate_of=equivalents[key])
        else:
            equivalents[key]=name
    return {"version":"policy-audit-v1", "status":"INDETERMINATE" if uncertain or policy["unmodeled_context"] else "COMPLETE_FOR_SUPPORTED_SUBSET",
        "source_kind":"operator_description", "scope":"First-match IPv4/IPv6 TCP/UDP/ICMP/ICMPv6 address/port model only; ANY is restricted to those protocols. No native profiles, schedules, routes, NAT, usage or deletion proof.",
        "findings":findings,"finding_count":len(findings),"indeterminate_rules":sorted(set(uncertain)),
        "unmodeled_context":policy["unmodeled_context"],"work_units":budget.work,
        "automatic_cleanup":False,"reachability":"NOT_EVALUATED","enforcement":"NOT_ATTEMPTED"}
