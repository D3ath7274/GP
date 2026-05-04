# Data Collection Walkthrough v5 (Clean Labels)

This walkthrough is the corrected procedure after the dataset audit findings.
It is designed to avoid label spread, victim mislabeling, and missing-session output.

## What Changed (vs v4)

- Confirmed attackers are now protocol-gated (no cross-protocol label spread).
- Snort response SIDs are filtered (`524, 1418, 1420, 1421, 503, 504`).
- ICMP flood counters track only ICMP Echo Request (type 8), not replies.
- Behavioral attack labels are protocol-gated per flow.
- CPS confirmation key uses `(src_ip, attack_type)` (not destination-dependent).

## Session Targets

| Session | File | Expected Attack Type |
|---|---|---|
| 1 | `dataset_session1_normal.csv` | none |
| 2 | `dataset_session2_icmp.csv` | ICMP Flood |
| 3 | `dataset_session3_syn.csv` | SYN Flood |
| 4 | `dataset_session4_udp.csv` | UDP Flood |
| 5 | `dataset_session5_portscan.csv` | Port Scan |
| 6 | `dataset_session6_arpspoof.csv` | ARP Spoofing |
| 7 | `dataset_session7_cps.csv` | Control Plane Saturation |

## Pre-Run (Do Once Per Day)

```bash
cd ~/final\ testing/GP/Controller
sudo rm -rf __pycache__
rm -f dataset.csv dataset_session*.csv
python3 -m py_compile traffic_capture.py
```

## Golden Sequence (After Every Attack Round)

```text
1) Ctrl+C attack process
2) Wait 10 seconds
3) echo "ATTACK_STOP" | nc -u -w1 <controller_ip> 9999
4) echo "CONTROL:UNBLOCK:<attacker_ip>" | nc -u -w1 <controller_ip> 9999
5) Wait 30 seconds cooldown
6) Confirm no new "SUSPECTED" logs for attacker
7) Start next round
```

## Base Session Template

### A) Start controller

```bash
cd ~/final\ testing/GP/Controller
sudo rm -rf __pycache__
rm -f dataset.csv
sudo ryu-manager Controller.py
```

### B) Start topology and baseline connectivity

```bash
sudo python3 "SDN Topology/topology .py"
pingall
pingall
```

### C) Register IoT nodes

```bash
py net.register_iot_device(net, 'TempSensor', '10.0.0.5/24', '00:00:00:00:00:05', 's1', 'IOT:TemperatureSensor')
py net.register_iot_device(net, 'Cam', '10.0.0.6/24', '00:00:00:00:00:06', 's1', 'IOT:SecurityCamera')
pingall
```

### D) Start background traffic

```bash
echo "MININET_EVENT:normal" | nc -u -w1 <controller_ip> 9999
h1 ping -i 0.5 10.0.0.4 &
h2 ping -i 0.5 10.0.0.3 &
sta1 ping -i 0.5 10.0.0.2 &
sta2 ping -i 0.5 10.0.0.1 &
TempSensor bash -c 'while true; do echo "TEMP:22.5" | nc -u -w0 10.0.0.4 8883; sleep 2; done' &
Cam bash -c 'while true; do dd if=/dev/urandom bs=1024 count=1 2>/dev/null | nc -u -w0 10.0.0.4 8883; sleep 5; done' &
h2 iperf -s &
sta1 iperf -c 10.0.0.4 -t 5400 &
```

### E) Baseline wait + detection on

```bash
# wait 5 minutes
echo "CONTROL:DETECT:ON" | nc -u -w1 <controller_ip> 9999
```

Verify in controller logs:
- DAI baseline frozen message appears.
- No immediate repeated suspect spam from a normal host.

### F) Run 3 attack rounds for session type

Use the same attack commands from `walkthrough.md` for each session.
After each round, apply the Golden Sequence strictly.

### G) Recovery and save

```bash
echo "CONTROL:DETECT:OFF" | nc -u -w1 <controller_ip> 9999
echo "MININET_EVENT:recovery" | nc -u -w1 <controller_ip> 9999
# wait 5 minutes
echo "MININET_EVENT:normal" | nc -u -w1 <controller_ip> 9999
```

Stop controller with `Ctrl+C`, then:

```bash
cp dataset.csv dataset_sessionN_<type>.csv
wc -l dataset_sessionN_<type>.csv
```

## Mandatory QA After Each Session

Run this QA check immediately after saving each session:

```bash
python3 - <<'PY'
import csv,sys,collections
f=sys.argv[1] if len(sys.argv)>1 else 'dataset.csv'
rows=0; atk=0
mix=collections.Counter()
with open(f,newline='',encoding='utf-8') as fh:
    r=csv.DictReader(fh)
    for row in r:
        rows += 1
        if row.get('label') == '2':
            atk += 1
            mix[(row.get('attack_type',''), row.get('protocol',''))] += 1
print('file:', f, 'rows:', rows, 'attack_rows:', atk)
for (a,p),n in mix.most_common(8):
    print(f'  {a:28s} | {p:5s} | {n}')
PY dataset_sessionN_<type>.csv
```

### QA Acceptance Rules

- Session 1: `attack_rows == 0`.
- Sessions 2-7: `attack_rows > 0` (if zero, session invalid and must be rerun).
- Attack protocol must match attack type:
  - ICMP Flood -> ICMP only
  - SYN Flood, Port Scan -> TCP only
  - UDP Flood, Control Plane Saturation -> UDP only
  - ARP Spoofing -> ARP only

If protocol mismatch appears, do not merge; rerun affected session after confirming latest code is deployed.

## Common Failure Modes To Watch

- Missing file for session 7: always run the save step explicitly.
- Attack rows = 0 (seen previously in ICMP/ARP sessions): detection was not active, command failed, or attack duration too short.
- Unexpected Snort victim labels: verify filtered response SIDs and latest `traffic_capture.py` deployed.

## Merge Only After All QA Passes

```bash
python3 dataset_merge.py \
  dataset_session1_normal.csv \
  dataset_session2_icmp.csv \
  dataset_session3_syn.csv \
  dataset_session4_udp.csv \
  dataset_session5_portscan.csv \
  dataset_session6_arpspoof.csv \
  dataset_session7_cps.csv \
  -o training_dataset.csv
```

