"""Offline, bounded change-impact proofs for operator-described header policies."""

from copy import deepcopy
from dataclasses import dataclass
import hashlib
from pathlib import Path
import sys

from firewall_policy import AddressResolver, canonical_bytes, diff_policies, normalize, sha256
from policy_audit import AuditBudgetError, Box, Budget, difference, intersection, regions

MAX_REGIONS = 4096
ENGINE_MANIFEST = {"python": sys.version.split()[0], "source_sha256": {
    name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
    for name in ("policy_change.py", "policy_audit.py", "firewall_policy.py")}}
ENGINE_SHA256 = sha256(canonical_bytes(ENGINE_MANIFEST))
SCOPE = ("Operator-described IPv4/IPv6 TCP/UDP/ICMP/ICMPv6 first-match header subset. "
         "ANY covers only those protocols. No native profiles, routes, NAT, stateful sessions or live reachability proof.")


@dataclass(frozen=True)
class EffectiveRegion:
    box: Box
    action: str | None
    logging: bool | None
    decisive_rule: str | None
    uncertain_rule: str | None = None


def universe():
    result = []
    for family, bits in ((4, 32), (6, 128)):
        for protocol in ("tcp", "udp", "icmp" if family == 4 else "icmpv6"):
            ports = (0, 65535) if protocol in ("tcp", "udp") else (0, 0)
            addresses = (0, 2**bits - 1)
            result.append(Box(family, protocol, (addresses, addresses, ports, ports)))
    return result


def overlaps(left, right, budget):
    result = []
    for a in left:
        for b in right:
            common = intersection(a, b, budget)
            if common is not None:
                result.append(common)
                if len(result) > MAX_REGIONS:
                    raise AuditBudgetError("Impact intersections exceed 4096 regions")
    return result


def possible_envelope(rule, resolver, budget):
    """Over-approximate unknown matches solely to mark uncertainty, never to prove a permit."""
    upper = dict(rule, constraints=[])
    for field in ("sources", "destinations"):
        if resolver.resolve(rule[field]).unresolved:
            upper[field] = ["any"]
    return regions(upper, resolver, budget)


def effective_regions(policy, budget):
    if len(policy["rules"]) > 200:
        raise AuditBudgetError("Change analysis admits at most 200 rules per snapshot")
    remaining = universe()
    if policy["unmodeled_context"]:
        return [EffectiveRegion(box, None, None, None, "GLOBAL_CONTEXT") for box in remaining]
    resolver = AddressResolver(policy["objects"])
    result = []
    for rule in policy["rules"]:
        if not rule["enabled"]:
            continue
        area = regions(rule, resolver, budget)
        unknown = area is None
        if unknown:
            area = possible_envelope(rule, resolver, budget)
        selected = overlaps(remaining, area, budget)
        for box in selected:
            result.append(EffectiveRegion(box, None if unknown else rule["action"],
                None if unknown else rule["logging"], None if unknown else rule["id"],
                rule["id"] if unknown else None))
        if len(result) > MAX_REGIONS:
            raise AuditBudgetError("Effective policy exceeds 4096 regions")
        # Later rules cannot produce a definite verdict inside a possible earlier match.
        remaining = difference(remaining, area, budget)
        if not remaining:
            break
    result.extend(EffectiveRegion(box, policy["default_action"], None, None) for box in remaining)
    if len(result) > MAX_REGIONS:
        raise AuditBudgetError("Effective policy exceeds 4096 regions")
    return result


def outcome(region):
    return {"action": region.action.upper() if region.action else "INDETERMINATE",
            "logging": region.logging, "decisive_rule": region.decisive_rule,
            "used_default": region.action is not None and region.decisive_rule is None,
            "uncertain_rule": region.uncertain_rule}


def impact(before, after, limit=100, max_work=250000):
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("Impact display limit must be 1..200")
    before, after = normalize(before), normalize(after)
    structural = diff_policies(before, after)  # Also requires identical tenant/site/device/context/vendor.
    budget = Budget(max_work)
    left, right = effective_regions(before, budget), effective_regions(after, budget)
    counts = {name: 0 for name in ("compared_regions", "access_expansions", "access_restrictions",
        "denial_behavior_changes", "explicit_logging_changes", "logging_unqualified_regions",
        "attribution_changes", "indeterminate_access_regions")}
    examples, total_examples, witnesses_by_kind = [], 0, {}
    for old in left:
        for new in right:
            common = intersection(old.box, new.box, budget)
            if common is None:
                continue
            counts["compared_regions"] += 1
            kinds = []
            if old.action is None or new.action is None:
                counts["indeterminate_access_regions"] += 1
                kinds.append("INDETERMINATE")
            elif old.action != new.action:
                if new.action == "allow":
                    counts["access_expansions"] += 1
                    kinds.append("ACCESS_EXPANDED")
                elif old.action == "allow":
                    counts["access_restrictions"] += 1
                    kinds.append("ACCESS_RESTRICTED")
                else:
                    counts["denial_behavior_changes"] += 1
                    kinds.append("DENIAL_BEHAVIOR_CHANGED")
            if old.logging is None or new.logging is None:
                counts["logging_unqualified_regions"] += 1
            elif old.logging != new.logging:
                counts["explicit_logging_changes"] += 1
                kinds.append("LOGGING_CHANGED")
            if old.action is not None and new.action is not None and old.decisive_rule != new.decisive_rule:
                counts["attribution_changes"] += 1
                kinds.append("RULE_ATTRIBUTION_CHANGED")
            if kinds:
                total_examples += 1
                example = {"kinds": kinds, "witness": common.witness(),
                           "before": outcome(old), "after": outcome(new)}
                for kind in kinds:
                    witnesses_by_kind.setdefault(kind, example)
                if len(examples) < limit:
                    examples.append(example)
    access_changed = any(counts[name] for name in ("access_expansions", "access_restrictions", "denial_behavior_changes"))
    # A known counterexample disproves equivalence even if other regions are unknown.
    access = "DIFFERENT" if access_changed else "INDETERMINATE" if counts["indeterminate_access_regions"] else "EQUIVALENT_FOR_SUPPORTED_SUBSET"
    logging = ("DIFFERENT" if counts["explicit_logging_changes"] else "INDETERMINATE"
               if counts["logging_unqualified_regions"] else "EQUIVALENT_FOR_SUPPORTED_SUBSET")
    return {"version": "policy-impact-v1", "source_kind": "operator_description", "scope": SCOPE,
        "before_snapshot": sha256(canonical_bytes(before)), "after_snapshot": sha256(canonical_bytes(after)),
        "access_equivalence": access, "logging_equivalence": logging,
        "coverage_status": "PARTIAL_UNKNOWN" if counts["indeterminate_access_regions"] else "COMPLETE_FOR_SUPPORTED_SUBSET",
        "known_access_change_present": access_changed, "counts": counts,
        "display_limit": limit,
        "examples": examples, "total_example_regions": total_examples, "truncated": total_examples > limit,
        "witnesses_by_kind": witnesses_by_kind,
        "structural_changes": structural, "work_units": budget.work,
        "native_equivalence": "NOT_EVALUATED", "reachability": "NOT_EVALUATED", "enforcement": "NOT_ATTEMPTED",
        "engine_sha256": ENGINE_SHA256, "engine_manifest": deepcopy(ENGINE_MANIFEST),
        "interpretation": "Regions are symbolic header-space partitions, not traffic counts or risk probabilities. Display truncation does not limit analysis. Missing/default logging remains unqualified."}


def proposal(base, request, limit=100):
    """Build a hypothetical model and receipt without mutating a snapshot or firewall."""
    if not isinstance(request, dict) or set(request) != {"version", "base_snapshot", "reason", "operations"}:
        raise ValueError("Expected exact policy-proposal-v1 fields")
    if request["version"] != "policy-proposal-v1":
        raise ValueError("Unsupported proposal version")
    base = normalize(base)
    base_id = sha256(canonical_bytes(base))
    if request["base_snapshot"] != base_id:
        raise ValueError("Stale/mismatched proposal base snapshot")
    reason = request["reason"]
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 1024 or any(ord(c) < 32 for c in reason):
        raise ValueError("Proposal needs bounded nonempty review rationale")
    operations = request["operations"]
    if not isinstance(operations, list) or not 1 <= len(operations) <= 16:
        raise ValueError("Proposal needs 1..16 explicit operations")
    candidate, touched = deepcopy(base), set()
    for operation in operations:
        if not isinstance(operation, dict):
            raise ValueError("Operation must be an object")
        kind = operation.get("operation")
        required = {"operation", "rule", "before_rule"} if kind == "move_rule_before" else {"operation", "rule"}
        if set(operation) != required or kind not in ("disable_rule", "remove_rule", "move_rule_before"):
            raise ValueError("Unsupported operation or fields")
        identifier = operation["rule"]
        if not isinstance(identifier, str) or identifier in touched:
            raise ValueError("One operation per target rule; rule ID must be text")
        matches = [r for r in candidate["rules"] if r["id"] == identifier]
        if not matches:
            raise ValueError("Unknown proposal rule")
        rule = matches[0]
        touched.add(identifier)
        if kind == "disable_rule":
            if not rule["enabled"]:
                raise ValueError("Target rule is already disabled")
            rule["enabled"] = False
        elif kind == "remove_rule":
            candidate["rules"].remove(rule)
        else:
            anchor = operation["before_rule"]
            if not isinstance(anchor, str) or anchor == identifier:
                raise ValueError("Move requires a different existing before_rule")
            anchors = [r for r in candidate["rules"] if r["id"] == anchor]
            if not anchors:
                raise ValueError("Unknown move anchor")
            candidate["rules"].remove(rule)
            candidate["rules"].insert(candidate["rules"].index(anchors[0]), rule)
            for index, item in enumerate(candidate["rules"]):
                item["position"] = (index + 1) * 10
    request_id = sha256(canonical_bytes(request))
    candidate["policy_revision"] = "offline-proposal-" + request_id[:16]
    candidate = normalize(candidate)
    assessment = impact(base, candidate, limit)
    result = {"version": "policy-proposal-receipt-v1", "base_snapshot": base_id,
        "request_sha256": request_id, "request": deepcopy(request), "candidate_sha256": sha256(canonical_bytes(candidate)),
        "candidate_is_observed": False, "candidate_policy": candidate, "impact": assessment,
        "state": "OFFLINE_REVIEW_REQUIRED", "automatic_apply": False, "enforcement": "NOT_ATTEMPTED"}
    result["receipt_sha256"] = sha256(canonical_bytes(result))
    return result


def verify_proposal(base, receipt):
    fields = {"version", "base_snapshot", "request_sha256", "request", "candidate_sha256",
              "candidate_is_observed", "candidate_policy", "impact", "state", "automatic_apply",
              "enforcement", "receipt_sha256"}
    if not isinstance(receipt, dict) or set(receipt) != fields:
        raise ValueError("Invalid proposal receipt fields")
    if receipt["receipt_sha256"] != sha256(canonical_bytes({k: v for k, v in receipt.items() if k != "receipt_sha256"})):
        raise ValueError("Proposal receipt hash mismatch")
    if not isinstance(receipt["impact"], dict) or "display_limit" not in receipt["impact"]:
        raise ValueError("Proposal receipt has no impact display contract")
    expected = proposal(base, receipt["request"], receipt["impact"]["display_limit"])
    if canonical_bytes(expected) != canonical_bytes(receipt):
        raise ValueError("Proposal does not reproduce against this snapshot/engine; regenerate and review")
    return {"version": "proposal-verification-v1", "verified": True,
            "receipt_sha256": receipt["receipt_sha256"], "base_snapshot": expected["base_snapshot"],
            "scope": "Integrity and deterministic replay only; not source authentication or approval",
            "enforcement": "NOT_ATTEMPTED"}
