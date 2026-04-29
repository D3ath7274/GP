import csv

with open(r'd:\4th Year\Graduation Project\data\GP\dataset11.csv', 'r', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))

print("=== DETAILED VIEW: ROWS 2095-2165 (attack onset) ===")
header = f"{'Row':>5} {'Time':>12} {'Src':>12} {'Proto':>5} {'Lbl':>3} {'Attack':>12} {'Tool':>6} {'PPS':>12} {'Pkts':>6} {'SID':>8}"
print(header)
print("-" * len(header))
for i in range(2095, min(2165, len(rows))):
    r = rows[i]
    ts = r["timestamp"][-12:]
    src = r["src_ip"]
    proto = r["protocol"]
    label = r["label"]
    attack = r["attack_type"]
    tool = r["meta_attack_tool"]
    pps = r["packets_per_second"]
    pkts = r["total_packets"]
    sid = r.get("snort_sid", "?")
    print(f"{i:>5} {ts:>12} {src:>12} {proto:>5} {label:>3} {attack:>12} {tool:>6} {pps:>12} {pkts:>6} {sid:>8}")

print()
print("=== FIRST 10 ROWS WITH tool=hping3 ===")
count = 0
for i, r in enumerate(rows):
    if r.get("meta_attack_tool") == "hping3" and count < 10:
        ts = r["timestamp"]
        src = r["src_ip"]
        proto = r["protocol"]
        label = r["label"]
        attack = r["attack_type"]
        pps = r["packets_per_second"]
        pkts = r["total_packets"]
        print(f"  Row {i}: {ts}  src={src}  proto={proto}  label={label}  attack={attack}  pkts={pkts}  pps={pps}")
        count += 1

print()
# Count how many attack-tool rows have label=0 vs label=1 vs label=2
l0 = sum(1 for r in rows if r.get("meta_attack_tool") == "hping3" and r["label"] == "0")
l1 = sum(1 for r in rows if r.get("meta_attack_tool") == "hping3" and r["label"] == "1")
l2 = sum(1 for r in rows if r.get("meta_attack_tool") == "hping3" and r["label"] == "2")
print(f"Rows with tool=hping3: label=0: {l0}, label=1: {l1}, label=2: {l2}")
print(f"  => {l0} rows during attack are labeled NORMAL (misses)")
print(f"  => {l1} rows during attack labeled by Snort (all SID 469 = Port Scan misclass)")
print(f"  => {l2} rows during attack labeled by behavioral detection")
