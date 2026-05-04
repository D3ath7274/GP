# Data Collection Walkthrough v4 — Per-Attack-Type Sessions

> Deprecated: use `walkthrough_v5_clean.md` for corrected anti-corruption logic and mandatory QA checks.

## Architecture

One session = one attack type, multiple attackers. Merge at the end.

| Session | Attack Type | Attackers |
|---|---|---|
| 1 | Normal only (extended baseline) | — |
| 2 | ICMP Flood | h1, Cam, TempSensor |
| 3 | SYN Flood | h1, Cam, sta1 |
| 4 | UDP Flood | h1, sta1, Cam |
| 5 | Port Scan | h1, Cam, TempSensor |
| 6 | ARP Spoofing | Cam, h1, TempSensor |
| 7 | Control Plane Saturation | h1, Cam, TempSensor |

## Detection Logic (Current)

```
ICMP Flood           → icmp_cnt > 500
Port Scan            → ports > 100 AND syn_cnt > 100 AND ack_cnt < 50
SYN Flood            → syn_cnt > 300 AND ack_cnt < 50 AND ports <= 10
Control Plane Sat.   → udp_cnt > 500 AND ports > 100
UDP Flood            → udp_cnt > 500 (AND ports <= 100, implicitly)
ARP Spoofing         → DAI baseline MAC mismatch
```

---

## Deploy Updated Code (Do Once)

```bash
# Copy to VM
scp traffic_capture.py ryu@192.168.1.24:~/final\ testing/GP/Controller/
scp Controller.py ryu@192.168.1.24:~/final\ testing/GP/Controller/

# On VM
cd ~/final\ testing/GP/Controller
sudo rm -rf __pycache__
rm -f dataset.csv
python3 -c "from traffic_capture import ALL_COLUMNS; print(len(ALL_COLUMNS))"
# → Must print 102
```

---

## Anti-Corruption: The Golden Sequence

> [!CAUTION]
> Follow this EXACTLY after every attack round. Skip = corrupted labels.

```
1. Ctrl+C the attack
2. Wait 10 seconds                                ← residual traffic drain
3. echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
4. echo "CONTROL:UNBLOCK:<attacker_ip>" | nc ...   ← 30s cooldown auto-starts
5. Wait 30 seconds                                ← cooldown expires
6. Check controller log: NO new "SUSPECTED"
7. Start next attack round
```

---

## Session Template (Repeat for Every Session)

### A. Start Controller

```bash
cd ~/final\ testing/GP/Controller
sudo rm -rf __pycache__
rm -f dataset.csv
sudo ryu-manager Controller.py
```

### B. Start Topology

```bash
sudo python3 topology\ .py
pingall
pingall

# Register IoT
py net.register_iot_device(net, 'TempSensor', '10.0.0.5/24', '00:00:00:00:00:05', 's1', 'IOT:TemperatureSensor')
py net.register_iot_device(net, 'Cam', '10.0.0.6/24', '00:00:00:00:00:06', 's1', 'IOT:SecurityCamera')
pingall
```

### C. Start Background Traffic

```bash
echo "MININET_EVENT:normal" | nc -u -w1 192.168.1.24 9999
                                                              # wait 2s
h1 ping -i 0.5 10.0.0.4 &                                    # wait 1s
h2 ping -i 0.5 10.0.0.3 &                                    # wait 1s
sta1 ping -i 0.5 10.0.0.2 &                                  # wait 1s
sta2 ping -i 0.5 10.0.0.1 &                                  # wait 1s
h1 ping -i 1 10.0.0.1 &                                      # wait 1s
h2 ping -i 1 10.0.0.2 &                                      # wait 1s

TempSensor bash -c 'while true; do echo "TEMP:22.5" | nc -u -w0 10.0.0.4 8883; sleep 2; done' &
                                                              # wait 2s
Cam bash -c 'while true; do dd if=/dev/urandom bs=1024 count=1 2>/dev/null | nc -u -w0 10.0.0.4 8883; sleep 5; done' &
                                                              # wait 2s
h2 iperf -s &                                                 # wait 2s
sta1 iperf -c 10.0.0.4 -t 5400 &                             # wait 2s
```

### D. Baseline Wait

```
Wait 5 minutes minimum (idle). Background runs automatically.
```

### E. Enable Detection

```bash
echo "CONTROL:DETECT:ON" | nc -u -w1 192.168.1.24 9999
```
> Verify: `DAI baseline: 6 bindings frozen`

### F. Run Attacks (see per-session section below)

### G. Recovery

```bash
echo "CONTROL:DETECT:OFF" | nc -u -w1 192.168.1.24 9999
echo "MININET_EVENT:recovery" | nc -u -w1 192.168.1.24 9999

# Wait 5 minutes for clean normal traffic
echo "MININET_EVENT:normal" | nc -u -w1 192.168.1.24 9999
```

### H. Save

```bash
# Controller VM: Ctrl+C, then:
cp dataset.csv dataset_sessionN.csv
wc -l dataset_sessionN.csv
```

---

## Session 1: Normal Only (15-20 min)

**No attacks.** Just background traffic to build a large normal baseline.

Steps A → B → C → wait 15-20 minutes → G → H

Save as `dataset_session1_normal.csv`

Expected: ~3,000-5,000 rows of pure normal traffic.

---

## Session 2: ICMP Flood (3 attacker rotations)

Steps A → B → C → D → E, then:

### Round 1: h1 → h2
```bash
echo "ATTACK_START:hping3:flood" | nc -u -w1 192.168.1.24 9999
h1 hping3 --icmp --flood 10.0.0.4
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.3" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s, verify log clean ────
```

### Round 2: Cam → h1
```bash
echo "ATTACK_START:hping3:flood" | nc -u -w1 192.168.1.24 9999
Cam hping3 --icmp --flood 10.0.0.3
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.6" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

### Round 3: TempSensor → sta2
```bash
echo "ATTACK_START:hping3:flood" | nc -u -w1 192.168.1.24 9999
TempSensor hping3 --icmp --flood 10.0.0.2
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.5" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

Then: G → H. Save as `dataset_session2_icmp.csv`

---

## Session 3: SYN Flood (3 attacker rotations)

Steps A → B → C → D → E, then:

### Round 1: h1 → h2 (port 80)
```bash
echo "ATTACK_START:hping3:flood" | nc -u -w1 192.168.1.24 9999
h1 hping3 -S --flood -p 80 10.0.0.4
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.3" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

### Round 2: Cam → TempSensor (port 1883 / MQTT)
```bash
echo "ATTACK_START:hping3:iot-flood" | nc -u -w1 192.168.1.24 9999
Cam hping3 -S --flood -p 1883 10.0.0.5
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.6" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

### Round 3: sta1 → h2 (port 443)
```bash
echo "ATTACK_START:hping3:flood" | nc -u -w1 192.168.1.24 9999
sta1 hping3 -S --flood -p 443 10.0.0.4
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.1" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

Then: G → H. Save as `dataset_session3_syn.csv`

---

## Session 4: UDP Flood (3 attacker rotations)

Steps A → B → C → D → E, then:

### Round 1: h1 → TempSensor (port 8883 / MQTT-S)
```bash
echo "ATTACK_START:hping3:flood" | nc -u -w1 192.168.1.24 9999
h1 hping3 --udp --flood -p 8883 10.0.0.5
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.3" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

### Round 2: sta1 → h2 (port 53 / DNS)
```bash
echo "ATTACK_START:hping3:flood" | nc -u -w1 192.168.1.24 9999
sta1 hping3 --udp --flood -p 53 10.0.0.4
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.1" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

### Round 3: Cam → h1 (port 5000)
```bash
echo "ATTACK_START:hping3:flood" | nc -u -w1 192.168.1.24 9999
Cam hping3 --udp --flood -p 5000 10.0.0.3
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.6" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

Then: G → H. Save as `dataset_session4_udp.csv`

---

## Session 5: Port Scan (3 attacker rotations)

Steps A → B → C → D → E, then:

### Round 1: h1 → TempSensor
```bash
echo "ATTACK_START:nmap:scan" | nc -u -w1 192.168.1.24 9999
h1 nmap -Pn -sS -T4 -p 1-65535 10.0.0.5
# ──── Wait for completion or Ctrl+C after 5 min ────
# ──── Wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.3" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

### Round 2: Cam → h2
```bash
echo "ATTACK_START:nmap:scan" | nc -u -w1 192.168.1.24 9999
Cam nmap -Pn -sS -T4 -p 1-65535 10.0.0.4
# ──── 5 min or completion, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.6" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

### Round 3: TempSensor → h1
```bash
echo "ATTACK_START:nmap:scan" | nc -u -w1 192.168.1.24 9999
TempSensor nmap -Pn -sS -T4 -p 1-65535 10.0.0.3
# ──── 5 min or completion, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.5" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

Then: G → H. Save as `dataset_session5_portscan.csv`

---

## Session 6: ARP Spoofing (3 attacker rotations)

Steps A → B → C → D → E, then:

### Round 1: Cam impersonates sta1 to sta2
```bash
echo "ATTACK_START:arpspoof:spoof" | nc -u -w1 192.168.1.24 9999
Cam arpspoof -i Cam-eth0 -t 10.0.0.2 10.0.0.1
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.6" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

### Round 2: h1 impersonates h2 to sta2
```bash
echo "ATTACK_START:arpspoof:spoof" | nc -u -w1 192.168.1.24 9999
h1 arpspoof -i h1-eth0 -t 10.0.0.2 10.0.0.4
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.3" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

### Round 3: TempSensor impersonates h2 to h1
```bash
echo "ATTACK_START:arpspoof:spoof" | nc -u -w1 192.168.1.24 9999
TempSensor arpspoof -i TempSensor-eth0 -t 10.0.0.3 10.0.0.4
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.5" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

Then: G → H. Save as `dataset_session6_arpspoof.csv`

---

## Session 7: Control Plane Saturation (3 attacker rotations)

**What it is:** Flood the controller with Packet-In messages by sending tiny UDP packets to thousands of incrementing ports. Each new (src, dst, port) = new flow = new Packet-In to controller.

Steps A → B → C → D → E, then:

### Round 1: h1 → h2
```bash
echo "ATTACK_START:hping3:saturation" | nc -u -w1 192.168.1.24 9999
h1 hping3 --udp --flood -d 0 --destport ++1 10.0.0.4
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.3" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

### Round 2: Cam → TempSensor
```bash
echo "ATTACK_START:hping3:saturation" | nc -u -w1 192.168.1.24 9999
Cam hping3 --udp --flood -d 0 --destport ++1 10.0.0.5
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.6" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

### Round 3: TempSensor → h1
```bash
echo "ATTACK_START:hping3:saturation" | nc -u -w1 192.168.1.24 9999
TempSensor hping3 --udp --flood -d 0 --destport ++1 10.0.0.3
# ──── 5 min, Ctrl+C, wait 10s ────
echo "ATTACK_STOP" | nc -u -w1 192.168.1.24 9999
echo "CONTROL:UNBLOCK:10.0.0.5" | nc -u -w1 192.168.1.24 9999
# ──── Wait 30s ────
```

Then: G → H. Save as `dataset_session7_cps.csv`

---

## Final Merge

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

wc -l training_dataset.csv
```

## Expected Dataset Composition

| Session | Attack Type | Rounds | Est. Rows |
|---|---|---|---|
| 1 | Normal only | — | 3,000-5,000 |
| 2 | ICMP Flood | 3 | 2,000-4,000 |
| 3 | SYN Flood | 3 | 2,000-4,000 |
| 4 | UDP Flood | 3 | 2,000-4,000 |
| 5 | Port Scan | 3 | 2,000-4,000 |
| 6 | ARP Spoofing | 3 | 2,000-3,000 |
| 7 | Control Plane Sat. | 3 | 2,000-4,000 |
| **Total** | | | **~15,000-28,000** |

> [!NOTE]
> Row counts are now MUCH lower because victim responses are correctly labeled normal.
> For more rows, see the [For More Rows Plan](file:///C:/Users/moody/.gemini/antigravity/brain/d7599b8f-2a62-4049-a0cc-c86da6286ef4/for_more_rows_plan.md).

## Time Estimate Per Session

```
Setup (topology + register + background + baseline)  = ~8 min
3 attack rounds × (5 min + 10s + 30s)                = ~17 min
Recovery                                              = ~5 min
                                                      ─────────
                                                       ~30 min
× 7 sessions                                         = ~3.5 hours total
```

## IP Reference

| Device | IP | MAC | Type |
|---|---|---|---|
| sta1 | 10.0.0.1 | 42:00:00:00:00:00 | WiFi Station |
| sta2 | 10.0.0.2 | 42:00:00:00:00:01 | WiFi Station |
| h1 | 10.0.0.3 | 00:00:00:00:00:03 | Wired Host |
| h2 | 10.0.0.4 | 00:00:00:00:00:04 | Wired Host |
| TempSensor | 10.0.0.5 | 00:00:00:00:00:05 | IoT (Temp) |
| Cam | 10.0.0.6 | 00:00:00:00:00:06 | IoT (Camera) |
