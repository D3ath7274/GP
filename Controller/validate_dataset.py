#!/usr/bin/env python3
"""
Dataset validation utility (stdlib only — runs anywhere, no pandas needed).
Validates a single captured session CSV, or the merged master, BEFORE training.

Usage:
    python3 validate_dataset.py dataset_session2_icmp.csv "ICMP Flood"
    python3 validate_dataset.py dataset_v2_master.csv          # merged: no expected type

Exit code 0 = PASS, 1 = problems found (printed).
"""
import sys
import csv
import math
from collections import Counter

CANONICAL = {'ICMP Flood', 'SYN Flood', 'UDP Flood', 'Port Scan',
             'ARP Spoofing', 'Control Plane Saturation'}

# Features that were structurally dead in v1 and must carry signal in v2.
# If reply_rate AND bwd_packet_count are BOTH all-zero, the capture was run in
# v1 mode (IPS_V2_FEATURES not set) and must be redone.
V2_LIVE = ['bwd_packet_count', 'reply_rate', 'dst_port_std',
           'sequential_port_score', 'is_broadcast_dst', 'is_registered_iot']


def _f(v):
    try:
        x = float(v)
        return 0.0 if (math.isnan(x) or math.isinf(x)) else x
    except (TypeError, ValueError):
        return 0.0


def main():
    if len(sys.argv) < 2:
        sys.exit('usage: validate_dataset.py <file.csv> [ExpectedAttackType]')
    path = sys.argv[1]
    expect = sys.argv[2] if len(sys.argv) > 2 else None

    with open(path, 'r', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    if not rows:
        sys.exit(f'FAIL: {path} is empty')
    cols = list(rows[0].keys())
    n = len(rows)
    issues = []
    warnings = []

    print(f'\n=== validate {path} ===')
    print(f'rows={n}  cols={len(cols)}')

    # --- label / attack_type distribution ---
    at = Counter(r.get('attack_type', '?') for r in rows)
    print('attack_type counts:')
    for k, c in at.most_common():
        print(f'   {k:28s} {c}')

    # --- only canonical labels (+ normal) ---
    bad = [k for k in at if k not in CANONICAL and k != 'normal']
    if bad:
        issues.append(f'non-canonical attack_type values present: {bad} '
                      f'(label pollution — should be impossible with the canonical guard)')

    # --- expected attack present with enough rows + source diversity ---
    if expect:
        cnt = at.get(expect, 0)
        if cnt < 50:
            issues.append(f'{expect}: only {cnt} rows (<50 CRITICALLY LOW)')
        elif cnt < 200:
            print(f'   NOTE: {expect} has {cnt} rows (<200 — consider an extra round)')
        srcs = sorted({r.get('src_ip') for r in rows if r.get('attack_type') == expect})
        print(f'   {expect} launched from {len(srcs)} source IPs: {srcs}')
        if len(srcs) < 2:
            issues.append(f'{expect} from <2 source IPs — low profile diversity')

    # --- v2 feature liveness ---
    print('v2 feature liveness (nonzero %):')
    live_any = False
    for feat in V2_LIVE:
        if feat in cols:
            nz = sum(1 for r in rows if _f(r.get(feat)) != 0)
            pct = 100 * nz / n
            print(f'   {feat:22s} {nz:6d} nonzero ({pct:5.1f}%)')
            if feat in ('bwd_packet_count', 'reply_rate') and nz > 0:
                live_any = True
    if not live_any:
        issues.append('reply_rate AND bwd_packet_count are all-zero — this CSV was '
                      'captured in v1 mode. Re-capture with IPS_V2_FEATURES=1.')

    # --- is_registered_iot should be set for the IoT hosts (10.0.0.5/.6) ---
    if 'is_registered_iot' in cols and 'src_ip' in cols:
        iot_rows = [r for r in rows if r.get('src_ip') in ('10.0.0.5', '10.0.0.6')]
        iot_flagged = sum(1 for r in iot_rows if _f(r.get('is_registered_iot')) == 1)
        if iot_rows:
            print(f'   is_registered_iot on IoT hosts: {iot_flagged}/{len(iot_rows)} flagged')
            if iot_flagged == 0:
                issues.append('no IoT rows have is_registered_iot=1 — register TempSensor/Cam '
                              'before collecting (and confirm REGISTER:IOT reached the controller)')

    # --- BLEED CHECK: attack rows whose protocol/rate contradicts the label ---
    # Catches the three labeling bugs (sticky _confirmed_attackers, throttle reset,
    # protocol-blind inheritance): an attack label landing on benign or wrong-protocol
    # traffic. A real volumetric flood has matching protocol AND a flood-rate signal;
    # a port scan fans out across many dst ports. Rows that wear an attack label
    # without those signals are mislabeled (bleed).
    ATTACK_PROTO = {
        'SYN Flood': 'TCP', 'Port Scan': 'TCP',
        'ICMP Flood': 'ICMP',
        'UDP Flood': 'UDP', 'Control Plane Saturation': 'UDP',
        'ARP Spoofing': 'ARP',
    }
    has_proto = 'protocol' in cols
    proto_mismatch = Counter()
    rate_bleed = Counter()
    for r in rows:
        a = r.get('attack_type', 'normal')
        if a not in ATTACK_PROTO:
            continue
        # 1. protocol contradiction — definite mislabel (e.g. an ICMP/ARP flow
        #    wearing a "SYN Flood" label from per-host inheritance)
        if has_proto and r.get('protocol') and r['protocol'] != ATTACK_PROTO[a]:
            proto_mismatch[a] += 1
            continue
        # 2. rate contradiction — benign traffic wearing a flood/scan label
        if a == 'SYN Flood':
            if _f(r.get('syn_count')) < 50:
                rate_bleed[a] += 1
        elif a in ('ICMP Flood', 'UDP Flood', 'Control Plane Saturation'):
            if _f(r.get('packets_per_second')) < 50:
                rate_bleed[a] += 1
        elif a == 'Port Scan':
            if _f(r.get('unique_dst_ports')) < 20:
                rate_bleed[a] += 1
        # ARP Spoofing: rate is not meaningful (DAI/binding-based) — protocol check only

    print('label-integrity (bleed) check:')
    if not proto_mismatch and not rate_bleed:
        print('   no protocol/rate contradictions in attack rows')
    for a, c in proto_mismatch.most_common():
        print(f'   PROTO MISMATCH: {c} {a!r} rows are not {ATTACK_PROTO[a]} (label inheritance bleed)')
    for a, c in rate_bleed.most_common():
        tot = at.get(a, 0)
        pct = 100 * c / tot if tot else 0
        print(f'   RATE BLEED: {c}/{tot} ({pct:.1f}%) {a!r} rows have no flood/scan-rate signal')
    # Distinguish catastrophic corruption (FAIL) from a small/structural residual
    # (WARN). The protocol-blind inheritance bug produces dozens+ of mismatches; a
    # stray row or two is noise. Rate bleed from sticky-confirm / victim back-scatter
    # is huge (>50% of the class); the unavoidable residual — the attacker's OWN
    # benign same-protocol traffic during its attack window — runs ~15-25% and is
    # FP-safe (it biases the model toward false positives, not false negatives, and
    # scrubbing it at label-time would risk under-labeling real attacks).
    PROTO_FAIL_FLOOR = 5
    RATE_BLEED_FAIL = 0.40
    proto_total = sum(proto_mismatch.values())
    if proto_total > PROTO_FAIL_FLOOR:
        issues.append(f'{proto_total} attack rows have a protocol that contradicts their label '
                      f'(inheritance bleed) — recapture on the patched controller')
    elif proto_total:
        warnings.append(f'{proto_total} stray protocol-mismatched attack row(s) — negligible')
    for a, c in rate_bleed.items():
        tot = at.get(a, 0)
        if not tot:
            continue
        frac = c / tot
        if frac > RATE_BLEED_FAIL:
            issues.append(f'{a}: {c}/{tot} ({100*frac:.0f}%) rows lack a flood/scan-rate signal '
                          f'(major mislabel — sticky-confirm/back-scatter) — recapture')
        elif frac > 0.10:
            warnings.append(f'{a}: {c}/{tot} ({100*frac:.0f}%) low-rate rows labeled as attack — '
                            f"likely the attacker's own benign same-protocol traffic during the "
                            f'attack window (FP-safe residual, acceptable)')

    # --- NaN / inf in numeric columns ---
    string_cols = {'timestamp', 'src_ip', 'dst_ip', 'protocol', 'attack_type', 'snort_sid',
                   'meta_src_mac_oui', 'meta_device_name', 'meta_attack_tool',
                   'meta_mininet_event', 'meta_session_name'}
    nan_inf = 0
    for r in rows:
        for c in cols:
            if c in string_cols:
                continue
            v = r.get(c, '')
            if v not in ('', None):
                try:
                    x = float(v)
                    if math.isnan(x) or math.isinf(x):
                        nan_inf += 1
                except (TypeError, ValueError):
                    pass
    if nan_inf:
        issues.append(f'{nan_inf} NaN/inf values in numeric columns')
    else:
        print('   no NaN/inf in numeric columns')

    # --- normal:attack balance ---
    attack_rows = sum(c for k, c in at.items() if k != 'normal')
    normal_rows = at.get('normal', 0)
    print(f'normal/attack: {normal_rows}/{attack_rows}')

    if warnings:
        print('warnings (non-fatal):')
        for w in warnings:
            print('  -', w)
    print('\nRESULT:', 'PASS ✅' if not issues else 'ISSUES ❌')
    for i in issues:
        print('  -', i)
    sys.exit(0 if not issues else 1)


if __name__ == '__main__':
    main()
