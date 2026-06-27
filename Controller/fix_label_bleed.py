#!/usr/bin/env python3
"""
Label-bleed salvage — relabel mislabeled attack rows back to normal (no recapture).

Fixes the "sticky-confirm / protocol-blind inheritance" artifact that
validate_dataset.py flags as RATE BLEED / PROTO MISMATCH: rows wearing an attack
label without the matching protocol or rate signature. These are benign background
flows (or wrong-protocol flows) that inherited a confirmed attacker's label across
a session boundary (e.g. session 3's SYN-Flood confirmation bleeding into the UDP/
PortScan/ARP sessions). Relabeling them to normal is the CORRECT label and clears
the ISSUES verdict without re-running collection.

Conservative by design — it ONLY relabels:
  (a) protocol-mismatched attack rows (always a definite mislabel), and
  (b) CROSS-TYPE rate-bleed rows: an attack label that is NOT the session's own
      attack type AND lacks that class's rate signal (e.g. 'SYN Flood' rows in a
      UDP/PortScan/ARP session).
It deliberately LEAVES the session's own-type low-rate residual alone — the validator
accepts that as FP-safe, and scrubbing it would risk under-labeling real attacks.

Usage:
  python3 fix_label_bleed.py dataset_session4_udp.csv dataset_session5_portscan.csv ...
  python3 fix_label_bleed.py --own "UDP Flood" dataset_session4_udp.csv   # force own-type
Writes <file>.bak, rewrites <file> in place, prints counts. Re-run validate_dataset.py
afterwards to confirm PASS.
"""
import sys
import os
import csv
import shutil

# Must match validate_dataset.py
ATTACK_PROTO = {
    'SYN Flood': 'TCP', 'Port Scan': 'TCP',
    'ICMP Flood': 'ICMP',
    'UDP Flood': 'UDP', 'Control Plane Saturation': 'UDP',
    'ARP Spoofing': 'ARP',
}
# Infer the session's intended attack type from a token in the filename.
FNAME_OWN = [
    ('portscan', 'Port Scan'), ('arpspoof', 'ARP Spoofing'),
    ('icmp', 'ICMP Flood'), ('syn', 'SYN Flood'), ('udp', 'UDP Flood'),
    ('scan', 'Port Scan'), ('arp', 'ARP Spoofing'),
    ('cps', 'Control Plane Saturation'), ('normal', None),
]


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def fails_rate_signal(a, row):
    """Mirror validate_dataset.py's per-class rate test (True == no flood/scan signal)."""
    if a == 'SYN Flood':
        return _f(row.get('syn_count')) < 50
    if a in ('ICMP Flood', 'UDP Flood'):
        return _f(row.get('packets_per_second')) < 50
    if a == 'Control Plane Saturation':
        return _f(row.get('unique_dst_ports')) < 100
    if a == 'Port Scan':
        return _f(row.get('unique_dst_ports')) < 20
    return False  # ARP Spoofing: rate not meaningful (protocol check only)


def infer_own(path):
    name = os.path.basename(path).lower()
    for tok, own in FNAME_OWN:
        if tok in name:
            return own
    return None


def fix_file(path, own):
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        cols = reader.fieldnames
        rows = list(reader)

    proto_fixed = rate_fixed = 0
    for r in rows:
        a = r.get('attack_type', 'normal')
        if a not in ATTACK_PROTO:
            continue
        proto = r.get('protocol')
        if proto and proto != ATTACK_PROTO[a]:
            kind = 'proto'                         # definite mislabel
        elif a != own and fails_rate_signal(a, r):
            kind = 'rate'                          # cross-type bleed, benign
        else:
            continue                               # own-type / legit -> keep
        r['attack_type'] = 'normal'
        r['label'] = '0'
        if 'snort_sid' in r:
            r['snort_sid'] = ''
        if kind == 'proto':
            proto_fixed += 1
        else:
            rate_fixed += 1

    changed = proto_fixed + rate_fixed
    if changed:
        shutil.copyfile(path, path + '.bak')
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
    print("%-34s own=%-26s relabeled->normal: %d proto-mismatch + %d cross-type "
          "rate-bleed  (%s)"
          % (os.path.basename(path), repr(own), proto_fixed, rate_fixed,
             '.bak written' if changed else 'no change'))


def main():
    args = sys.argv[1:]
    own_override = None
    if args and args[0] == '--own':
        own_override = args[1]
        args = args[2:]
    if not args:
        print("usage: python3 fix_label_bleed.py [--own '<Attack Type>'] file.csv ...")
        sys.exit(1)
    for p in args:
        if not os.path.exists(p):
            print("skip (not found): %s" % p)
            continue
        fix_file(p, own_override or infer_own(p))


if __name__ == '__main__':
    main()
