"""Score independently reviewed campaign windows; never treats absent evidence as a pass."""

import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
import math
import os
import statistics
from pathlib import Path
import sys


FIELDS = {"id", "campaign", "scenario", "subject", "truth", "truth_reference", "detector_revision", "verdict",
          "arrival_verified", "coverage_qualified", "quality_ok", "activity_started_at", "observation_ended_at", "detected_at",
          "block_requested_at", "rule_readback_at", "traffic_block_verified_at", "benign_continuity_verified", "outcome_reference"}
SCENARIOS = {"recon", "syn-load", "udp-load", "icmp-load", "arp-conflict", "auth-attempts", "http-canary", "dns-tls-metadata", "benign-control"}


def timestamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Campaign times need timezone offsets")
    return result.timestamp()


def score(document):
    if not isinstance(document,dict) or set(document)!={"version","records"} or document["version"]!="campaign-results-v1":
        raise ValueError("Expected campaign-results-v1 with records")
    if not isinstance(document["records"],list) or not 1<=len(document["records"])<=100000:
        raise ValueError("Supply 1..100000 independently reviewed windows")
    ids, revisions, scenarios, campaigns, intervals = set(),set(),{},{},{}
    counts, exclusions = Counter(),Counter()
    latency = {"detection_from_activity":[],"request_to_readback":[],"request_to_verified_containment":[]}
    for record in document["records"]:
        if not isinstance(record,dict) or set(record)!=FIELDS:
            raise ValueError("Record fields differ from the explicit campaign contract")
        for name in ("id","campaign","scenario","subject","truth_reference","detector_revision","outcome_reference"):
            if not isinstance(record[name],str) or not 1<=len(record[name])<=512 or any(ord(c)<32 for c in record[name]):
                raise ValueError("Campaign identifiers/references must be bounded nonempty text")
        if record["id"] in ids:
            raise ValueError("Duplicate evaluation window ID")
        ids.add(record["id"])
        if record["scenario"] not in SCENARIOS or record["truth"] not in ("malicious","benign","unknown") or record["verdict"] not in ("alert","clear","abstain"):
            raise ValueError("Unsupported scenario/truth/verdict")
        for name in ("arrival_verified","coverage_qualified","quality_ok"):
            if type(record[name]) is not bool:
                raise ValueError("Qualification fields must be boolean")
        if record["benign_continuity_verified"] is not None and type(record["benign_continuity_verified"]) is not bool:
            raise ValueError("Continuity is boolean or null (unmeasured)")
        times={name:timestamp(record[name]) if record[name] is not None else None for name in
               ("activity_started_at","observation_ended_at","detected_at","block_requested_at","rule_readback_at","traffic_block_verified_at")}
        start,end = times["activity_started_at"],times["observation_ended_at"]
        if start is None or end is None or not 0 < end-start <= 3600:
            raise ValueError("A bounded observation interval of up to one hour is mandatory")
        if any(value is not None and not start<=value<=end for value in times.values()):
            raise ValueError("Event timestamp is outside its observation interval")
        intervals.setdefault((record["campaign"],record["subject"]),[]).append((start,end))
        if record["verdict"]=="alert" and times["detected_at"] is None or record["verdict"]!="alert" and times["detected_at"] is not None:
            raise ValueError("Alert verdict and detection timestamp disagree")
        sequence=[times[name] for name in ("activity_started_at","detected_at","block_requested_at","rule_readback_at","traffic_block_verified_at") if times[name] is not None]
        if any(b<a for a,b in zip(sequence,sequence[1:])):
            raise ValueError("Campaign timestamps are not ordered; inspect clocks/evidence")
        if (times["rule_readback_at"] is not None or times["traffic_block_verified_at"] is not None) and times["block_requested_at"] is None:
            raise ValueError("Verification requires a corresponding block request")
        revisions.add(record["detector_revision"])
        if len(revisions)>1:
            raise ValueError("Score one frozen detector/configuration revision per report")
        reasons=[name for name in ("arrival_verified","coverage_qualified","quality_ok") if not record[name]]
        if record["truth"]=="unknown": reasons.append("unknown_truth")
        if reasons:
            counts["excluded_windows"]+=1
            exclusions.update(reasons)
            continue
        counts["qualified_windows"]+=1
        label=("TP" if record["verdict"]=="alert" else "FN") if record["truth"]=="malicious" else (
               "FP" if record["verdict"]=="alert" else "TN" if record["verdict"]=="clear" else "BENIGN_ABSTAIN")
        if record["verdict"]=="abstain": counts["abstentions"]+=1
        counts[label]+=1
        scenarios.setdefault(record["scenario"],Counter())[label]+=1
        campaigns.setdefault(record["campaign"],Counter())[label]+=1
        if times["detected_at"] is not None:
            latency["detection_from_activity"].append(times["detected_at"]-times["activity_started_at"])
        requested=times["block_requested_at"]
        if requested is not None:
            counts["block_requests"]+=1
            for field,key in (("rule_readback_at","request_to_readback"),("traffic_block_verified_at","request_to_verified_containment")):
                if times[field] is not None: latency[key].append(times[field]-requested)
            if times["traffic_block_verified_at"] is not None:
                counts["independently_verified_containments"]+=1
            else:
                counts["unverified_block_requests"]+=1
            if record["truth"]=="benign": counts["benign_block_requests"]+=1
            continuity=record["benign_continuity_verified"]
            counts["continuity_unmeasured" if continuity is None else "continuity_pass" if continuity else "continuity_failed"]+=1
    for windows in intervals.values():
        ordered = sorted(windows)
        if any(right[0] < left[1] for left,right in zip(ordered,ordered[1:])):
            raise ValueError("Overlapping windows for one campaign/subject would inflate evidence")
    def ratio(n,d): return n/d if d else None
    def summary(values):
        ordered=sorted(values)
        return {"n":len(values),"median_seconds":statistics.median(ordered) if ordered else None,
                "p95_nearest_rank_seconds":ordered[math.ceil(.95*len(ordered))-1] if ordered else None,
                "maximum_seconds":max(ordered) if ordered else None}
    benign=counts["FP"]+counts["TN"]+counts["BENIGN_ABSTAIN"]
    return {"version":"campaign-scorecard-v1","status":"NO_QUALIFIED_EVIDENCE" if not counts["qualified_windows"] else "MEASURED_CAMPAIGN_WINDOWS",
        "detector_revision":next(iter(revisions)),"counts":dict(counts),"exclusion_reasons":dict(exclusions),
        "by_scenario":scenarios,"by_campaign":campaigns,
        "metrics":{"recall":ratio(counts["TP"],counts["TP"]+counts["FN"]),"precision":ratio(counts["TP"],counts["TP"]+counts["FP"]),
                   "false_alerts_per_qualified_benign_window":ratio(counts["FP"],benign),"abstention_rate":ratio(counts["abstentions"],counts["qualified_windows"])},
        "latencies":{k:summary(v) for k,v in latency.items()},
        "interpretation":"Window-level campaign measurements, not independent statistical trials, calibrated probabilities or production certification. Malicious abstentions count as misses; benign abstentions are separate from true negatives. Rule readback alone does not prove containment."}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",type=Path,required=True)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    try:
        if args.input.stat().st_size>32*1024**2:
            raise ValueError("Campaign input exceeds 32 MiB")
        raw=args.input.read_bytes()
        result=score(json.loads(raw))
        result["input_sha256"]=hashlib.sha256(raw).hexdigest()
        text=json.dumps(result,indent=2,allow_nan=False)
        if args.output:
            fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,"w",encoding="utf-8") as output: output.write(text+"\n")
        print(text)
    except (OSError,ValueError,TypeError,KeyError) as error:
        parser.exit(1,f"Campaign evaluation failed: {error}\n")
    return 2 if result["status"]=="NO_QUALIFIED_EVIDENCE" else 0


if __name__=="__main__":
    raise SystemExit(main())
