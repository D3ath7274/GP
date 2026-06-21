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

    print('\nRESULT:', 'PASS ✅' if not issues else 'ISSUES ❌')
    for i in issues:
        print('  -', i)
    sys.exit(0 if not issues else 1)


if __name__ == '__main__':
    main()
