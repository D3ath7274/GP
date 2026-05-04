# Session Dataset Audit Report

## Overview

| Session | File | Rows | Attack Rows | Verdict |
|---|---|---|---|---|
| 1 | `session1_normal.csv` | 2,617 | 0 | ✅ Clean |
| 2 | `session2_icmp.csv` | 2,216 | 710 | 🔴 Corrupted |
| 3 | `session3_syn.csv` | 11,781 | 4,592 | 🔴 Corrupted |
| 4 | `session4_udp.csv` | 2,055 | 368 | 🟡 Partially corrupted |
| 5 | `session5_portscan.csv` | 2,204 | 423 | 🟡 Partially corrupted |
| 6 | `session6_arpspoof.csv` | 3,262 | 272 | 🟡 Minor issues |
| 7 | (missing — no dataset) | — | — | — |

---

## Root Cause #1: `_confirmed_attackers` Label Spread (Still Active)

**Affects:** Sessions 2, 3, 4, 5

When a host is confirmed as an attacker (e.g., `_confirmed_attackers["10.0.0.3"] = "SYN Flood"`), **ALL flows from that IP** get that attack label — including background pings, ARP, IoT heartbeats.

### Evidence from Session 3 (SYN Flood):

| Attack Type | Source | Rows | What's really happening |
|---|---|---|---|
| `SYN Flood` | h1 (10.0.0.3) | 167 | ✅ Real SYN flood traffic |
| `SYN Flood` | h1 (10.0.0.3) | **ARP=24, ICMP=84, UDP=10** | ❌ Background pings/ARP from h1 inheriting "SYN Flood" label |

h1's background `ping -i 0.5 10.0.0.4` produces ICMP flows. Since h1 is a confirmed attacker, those ICMP flows get `label=2, attack_type="SYN Flood"`. **The model would learn that ICMP traffic = SYN Flood.**

### Evidence from Session 4 (UDP Flood):

```
UDP Flood + ARP = 30 rows    ← h1's ARP traffic mislabeled
UDP Flood + ICMP = 71 rows   ← h1's ping traffic mislabeled
UDP Flood + TCP = 55 rows    ← h1's iperf traffic mislabeled
ICMP Flood from h1 = 3 rows  ← residual from previous detection
```

### Fix needed:
In `_compute_label`, when a confirmed attacker is found, only label the flow if the flow's protocol matches the confirmed attack type:

```python
if src_ip in self._confirmed_attackers:
    confirmed_type = self._confirmed_attackers[src_ip]
    # Only label if protocol matches attack type
    if confirmed_type == 'SYN Flood' and protocol == 'TCP':
        return 2, confirmed_type, "none"
    elif confirmed_type == 'ICMP Flood' and protocol == 'ICMP':
        return 2, confirmed_type, "none"
    elif confirmed_type in ('UDP Flood', 'Control Plane Saturation') and protocol == 'UDP':
        return 2, confirmed_type, "none"
    elif confirmed_type == 'Port Scan' and protocol == 'TCP':
        return 2, confirmed_type, "none"
    elif confirmed_type == 'ARP Spoofing' and protocol == 'ARP':
        return 2, confirmed_type, "none"
    # else: non-matching protocol → normal (background traffic)
```

---

## Root Cause #2: Snort Alert Victim-Matching (Still Active)

**Affects:** Sessions 3, 4, 5

Even after the Snort fix (changed to `a['src_ip'] == src_ip`), victims are STILL being labeled because **Snort fires alerts where the victim IS the src_ip**:

```
Snort alert: SNMP request tcp FROM 10.0.0.4:80 TO 10.0.0.3:161
                                    ^^^^^^^^
                                    victim (h2) is the src_ip!
```

h2 responds to SYN flood from port 80 → some responses hit well-known ports (161, 162, 705). Snort fires with h2 as src_ip. The fix `a['src_ip'] == src_ip` still matches because h2 IS the Snort alert's src_ip.

### Evidence from Session 3:

| Snort Attack Type | Source (victim) | Rows |
|---|---|---|
| SNMP trap tcp | h2 (10.0.0.4) | 1,032 |
| SNMP AgentX/tcp request | h2 (10.0.0.4) | 1,152 |
| BAD-TRAFFIC tcp port 0 | h2 (10.0.0.4) | 767 |
| SNMP trap tcp | TempSensor (10.0.0.5) | 767 |
| SNMP AgentX/tcp request | TempSensor (10.0.0.5) | 563 |

**4,281 rows** of victim-blaming from Snort — 36% of the entire session!

### Fix needed:
Filter out Snort alerts on well-known response ports. If the alert's dst_port is a well-known port (0, 161, 162, 705) AND the alert's src_port is a common service port (80, 443, 1883, 8883), it's a victim response — skip it:

```python
# Skip Snort alerts that are clearly victim responses
RESPONSE_SIDS = {524, 1418, 1420, 1421, 503, 504}  # BAD-TRAFFIC, SNMP, MISC
matching_alerts = [
    a for a in alerts
    if a['src_ip'] == src_ip and a.get('sid') not in RESPONSE_SIDS
]
```

---

## Root Cause #3: ICMP Flood Labels ALL Hosts (Not Just Attacker)

**Affects:** Session 2

### Evidence:

| Source | ICMP Flood rows | Role | Should be labeled? |
|---|---|---|---|
| h1 (10.0.0.3) | 202 | Attacker (Round 1) | ✅ Yes |
| Cam (10.0.0.6) | 71 | Attacker (Round 2) | ✅ Yes |
| TempSensor (10.0.0.5) | 70 | Attacker (Round 3) | ✅ Yes |
| h2 (10.0.0.4) | 190 | **Victim** | ❌ No |
| sta1 (10.0.0.1) | 155 | **Bystander** | ❌ No |
| sta2 (10.0.0.2) | 22 | **Bystander** | ❌ No |

h2 responds with ICMP echo replies → same flow key `(10.0.0.4, 10.0.0.3, 0, ICMP)`. But ICMP responses are normal! The issue: `_host_icmp_count` counts ALL ICMP from a host, including echo replies. The ICMP Flood detector `icmp_cnt > 500` fires on the victim because it receives and responds to 500+ ICMPs.

And sta1/sta2 have ICMP Flood labels from `_confirmed_attackers` label spread — they weren't even involved.

### Fix needed:
ICMP Flood detection should only count ICMP **echo requests** (type=8), not echo replies (type=0):

```python
# In process_packet(), when counting ICMP:
if protocol == 'ICMP':
    icmp_type = pkt_info.get('icmp_type', 0)
    if icmp_type == 8:  # Echo Request only
        self._host_icmp_count[src_ip] += 1
```

---

## Root Cause #4: Cam Never Confirmed in CPS Session (Detection Bug)

**Affects:** Session 7 (Control Plane Saturation)

### From the CPS log:

```
Round 2: Cam → TempSensor
  Window 1: SUSPECTED (1/3)
  ... (many windows)
  Window N: SUSPECTED (1/3)   ← counter keeps resetting!
  Window N+1: SUSPECTED (1/3)
  ... eventually ...
  Window M: 2/3
  Window M+1: Still never reaches 3/3 in many windows
```

Cam shows `1/3` repeatedly, never consecutively reaching 3/3. The `_attack_confirmations` counter requires 3 consecutive windows, but Cam's detection keeps resetting to `1/3`.

**Root cause:** The consecutive-window tracker checks `detected_this_window` keys. If the attack type or target IP changes between windows (Cam floods TempSensor but the detection reports different target IPs in different windows), the key doesn't match and the counter resets.

Looking at the log: Cam was first suspected targeting `10.0.0.4` (line 368), then `10.0.0.5` (lines 403, 422, 496...). The target keeps alternating, breaking the consecutive count.

### Fix needed:
The confirmation key should use `(src_ip, attack_type)` only — drop `dst_ip` from the tracking key. An attacker flooding multiple targets is still an attacker.

---

## Volume Analysis

### Session 3 (SYN Flood): 11,781 rows — Larger than expected

With MAX_FLOWS_PER_PAIR = 50, each window should have ~52 rows during attack. The cap IS working (max rows/window = 62 vs 17,929 before). But 11,781 is still high because:
- 3 rounds × ~60 windows × ~52 rows/window = ~9,360 attack rows
- Plus ~1,400 baseline/recovery rows
- Total ~10,760 — close to observed 11,781 ✅

**Volume is now correct.** The cap is working.

### Session 7 (CPS): No dataset file saved

The user forgot to save `dataset_session7_cps.csv`, or the session was terminated before saving.

---

## Summary: All 4 Fixes Needed

| # | Bug | Root Cause | Impact | Fix |
|---|---|---|---|---|
| 1 | Label spread | `_confirmed_attackers` labels ALL protocols | All sessions | Protocol-match gate |
| 2 | Snort victim-matching | Victim response ports trigger Snort rules | Sessions 3, 5 | Filter response SIDs |
| 3 | ICMP victim counting | Echo replies counted as flood | Session 2 | Count only type=8 |
| 4 | CPS target alternation | Confirmation key includes dst_ip | Session 7 | Key on (src, type) only |
