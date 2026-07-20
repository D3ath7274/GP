# Red-Team Test Runbook — validating all 4 tiers as *blockers* against real attacks

**Scope & authorization.** This exercises the IPS against real attack tools in your **own
isolated lab** (the t530 + Mininet VM + a Kali attacker you control). Only attack the testbed
assets described here. This is defensive validation of your own system — do not point these
tools at anything you are not authorized to test.

**Goal.** Prove that each tier — **Tier 1 Snort (as a blocker)**, Tier 2 rate/DAI, Tier 3
Random Forest, Tier 4 Autoencoder — actually **stops** a live attack, then that the full stack
blocks every attack class and an outsider. "Blocked" here means the attack traffic is
*enforced-dropped* (verified at the switch / firewall), not merely logged.

Legend: **[t530]** controller host · **[mn]** Mininet CLI · **[kali]** external attacker box ·
**[vm]** Mininet VM shell.

---

## 1. Roles & topology
| Role | Machine | Plays |
|---|---|---|
| Defender | t530 (`Controller_main_Claude.py`) + Mininet VM (`topology.py`) | the IPS + the protected network |
| Insider attacker | a Mininet host (`sta1`/`sta2`/`h1`) | a **compromised IoT device** attacking from inside the SDN |
| Outsider attacker | **Kali** on the LAN (192.168.1.x) | a real hacker hitting the controller and any exposed service |

Targets: internal server `h2` = `10.0.0.4`; the controller host = `<t530-ip>`.

## 2. Defender setup — arm ALL tiers as blockers
**[t530]** launch with the NIC watched + outsider auto-block on:
```bash
cd ~/GP/Controller
sudo IPS_EXTERNAL_BLOCK=1 IPS_MGMT_WHITELIST=<your-admin/ssh-ip> \
  SNORT_PHYS_IFACE=enp1s0 SNORT_IFACES=enp1s0,snort_tap IPS_V2_FEATURES=1 \
  python3 -c "import collections,collections.abc; collections.MutableMapping=collections.abc.MutableMapping; from ryu.cmd.manager import main; main()" \
  Controller_main_Claude.py --wsapi-port 8081 2>&1 | tee redteam_run.log
```
**[mn]** bring the network up (PART 3 of `t530_full_system_runbook.md`): register IoT, `pingall`,
`py net.start_background_traffic(net)`, and confirm `curl -s :8081/ips/switches` = `1` and
`dataset.csv` growing. Then arm the full stack:
```bash
python3 ipsctl.py CONTROL:DETECT:ON            # Tier 1 (Snort) + Tier 2 (rate/DAI) BLOCK
python3 ipsctl.py CONTROL:ML:AUTHORIZE:0.80    # Tier 3 (RF) + Tier 4 (AE) BLOCK
```

## 3. Attacker toolkit (Kali)
`hping3` (floods), `nmap`/`nping` (scan, crafted floods), `arpspoof`/`dsniff` (MITM), `scapy`
(custom/zero-day-ish packets), `slowhttptest` (low-and-slow). Internal attacks reuse the same
tools *inside* a Mininet host (`sta1 hping3 …`).

## 4. Universal verification (use after every attack)
```bash
# on [t530]:
curl -s http://127.0.0.1:8081/ips/blocked | python3 -m json.tool   # attacker IP listed, valid JSON
grep -E "BLOCKED|EXT-BLOCK|reason=" redteam_run.log | tail          # which tier decided (reason=…)
# on [vm]  — GROUND TRUTH that the DROP enforces:
sudo ovs-ofctl dump-flows s1 | grep -i drop                         # priority=65000 dl_src=… actions=drop, n_packets climbing
# from the attacker — the proof it's cut:
<attacker> ping -c4 10.0.0.4     # 100% loss     |   another host: 0% loss (surgical)
# outsider only:
sudo iptables -S INPUT | grep <kali-ip>                             # -A INPUT -s <kali> -j DROP
```
The `reason=` field names the deciding tier: `snort-<sid>` · `rate-counter-<N>w` · `ml-<conf>` ·
`ae-<conf>`. **Reset between tests:** `python3 ipsctl.py CONTROL:UNBLOCK:<ip>` (blocks are
permanent; `CLEAR` alone will not restore connectivity), then `CONTROL:CLEAR`.

---

## 5. Per-tier blocking tests (isolate each tier, prove it blocks)

### 5.1 Tier 1 — **Snort as a blocker** (the focus)
Snort fires **sub-second**; the rate tier needs 2–3 windows (10–15 s). So a **short** flood is
blocked by Snort *before* the rate tier can confirm — clean isolation. Keep `ML:OFF` so RF/AE
stay out.
```bash
[t530] python3 ipsctl.py CONTROL:DETECT:ON ; python3 ipsctl.py CONTROL:ML:OFF
```
Run each for **~6 seconds** (Ctrl-C early), from a Mininet host (insider):
```python
[mn] sta1 timeout 6 hping3 --icmp --flood 10.0.0.4      # ICMP -> SID 1000001 / builtin 434
[mn] sta1 timeout 6 hping3 -S --flood -p 80 10.0.0.4    # SYN  -> SID 1000002
[mn] sta1 timeout 6 hping3 --udp --flood -p 53 10.0.0.4 # UDP  -> SID 1000003
[mn] sta1 nmap -sS -p 1-1000 10.0.0.4                   # scan -> port_scan inspector (GID 122)
```
**PASS:** log shows `[SNORT] BLOCKED 10.0.0.1 (…) — instant signature match` and the BLOCK box
with `Detection: snort-<sid>`; `dump-flows` shows the DROP; attacker ping = 100% loss. The
sub-0.2 s `Latency` line is your Snort-tier evidence.

### 5.2 Tier 2 — rate counters + DAI
Snort's sub-second block preempts the rate tier on floods, so to see the **rate counter** block
you must take Snort out of the race for this test — relaunch the controller **without Snort**
(omit `SNORT_IFACES`) *or* stop it, then:
```bash
[t530] python3 ipsctl.py CONTROL:DETECT:ON ; python3 ipsctl.py CONTROL:ML:OFF
[mn]   sta1 hping3 --icmp --flood 10.0.0.4        # sustain >= 15 s (3 windows)
```
**PASS (rate):** `[⚠] SUSPECTED …` for N windows → `[⛔] ATTACK CONFIRMED` → BLOCK box with
`reason=rate-counter-<N>w`; DROP enforces.
**DAI (detection):** `[mn] sta1 arpspoof -i sta1-wlan0 -t 10.0.0.4 10.0.0.3 &` → the
`⚠ ARP SPOOFING DETECTED (DAI)` box (attacker MAC vs real owner). *Note:* DAI currently
**detects/flags** but does not auto-block — treat this as a detection PASS (or ask to wire DAI
blocking under DETECT:ON). Stop with `sta1 pkill arpspoof`; restore Snort afterwards.

### 5.3 Tier 3 — Random Forest (isolated)
`DETECT:OFF` removes Snort/rate; disable the AE so only the RF can decide.
```bash
[t530] python3 ipsctl.py CONTROL:DETECT:OFF
       python3 ipsctl.py CONTROL:ML:AE:OFF
       python3 ipsctl.py CONTROL:ML:AUTHORIZE:0.80
[mn]   sta1 hping3 -S --flood -p 80 10.0.0.4       # >= 20 s (several windows)
```
**PASS:** `[ML] ATTACK (block) 10.0.0.1 … type=SYN Flood conf=0.8x` → BLOCK box `reason=ml-0.8x`.
Re-enable: `CONTROL:ML:AE:ON`. If the RF names it but never blocks, it's under-confident on live
traffic → retrain (`ml_models/retrain_rf_v4.py`) or lower the bar (`CONTROL:ML:BLOCK:0.70`).

### 5.4 Tier 4 — Autoencoder / **zero-day** (isolated)
Disable the RF so only the AE can decide, and attack with something **held out of training**
(the real zero-day proof) — e.g. a scapy-crafted flood or an unusual protocol/port mix.
```bash
[t530] python3 ipsctl.py CONTROL:DETECT:OFF
       python3 ipsctl.py CONTROL:ML:RF:OFF
       python3 ipsctl.py CONTROL:ML:AUTHORIZE:0.80
[mn]   sta1 hping3 --udp --flood -p ++1 10.0.0.4    # or a scapy zero-day-style stream
```
**PASS:** `[AE] ANOMALY (block) 10.0.0.1 conf=0.7x (zero-day net)` → BLOCK box `reason=ae-0.7x`.
Re-enable: `CONTROL:ML:RF:ON`. Tune with `CONTROL:ML:AE:BLOCK:<x>` if it over/under-fires.

---

## 6. Full-stack layered test (all tiers armed)
```bash
[t530] python3 ipsctl.py CONTROL:DETECT:ON ; python3 ipsctl.py CONTROL:ML:AUTHORIZE:0.80
```
Fire the whole catalogue (≥20 s each; `UNBLOCK` + `CLEAR` between):
```python
[mn] sta1 hping3 --icmp --flood 10.0.0.4          # ICMP
[mn] sta1 hping3 -S --flood -p 80 10.0.0.4        # SYN
[mn] sta1 hping3 --udp --flood -p 53 10.0.0.4     # UDP
[mn] sta1 hping3 --udp --flood -p ++1 10.0.0.4    # Control-Plane Saturation
[mn] sta1 nmap -sS -p 1-1000 10.0.0.4             # Port Scan
[mn] sta1 arpspoof -i sta1-wlan0 -t 10.0.0.4 10.0.0.3 &   # ARP (DAI detect)
```
**PASS:** every class blocked by ≥1 tier (`reason=` shows which fired first), `/ips/blocked` +
dashboard reflect it, per-window compute < 5000 ms, RAM has headroom.

## 7. Outsider tests (real Kali hacker)
### 7.1 Direct hit on the controller (management plane)
```bash
[kali] nmap -sS -p 1-1000 <t530-ip>                # recon scan of the controller itself
[kali] hping3 -S --flood -p 8081 <t530-ip>         # flood the REST/dashboard port
```
**PASS:** Snort on `enp1s0` fires → `[EXT-BLOCK] host-firewall DROP for external attacker <kali-ip>`
→ `iptables -S INPUT | grep <kali-ip>` shows the DROP; re-running the scan from Kali times out.
(OpenFlow can't touch this — it's the host firewall doing the block, by design.)

### 7.2 Outsider **through the SDN** (all 4 tiers, real external IP)
Expose an internal service so external traffic transits `s1` → `packet_in` → all tiers:
```python
[mn]  py net.expose_service(net)                   # h2:80 as <vm-ip>:8080
```
```bash
[kali] nping --tcp --flags syn -p 8080 --rate 3000 -c 30000 <vm-ip>   # SYN flood through the SDN
[kali] nmap -sS -p 1-1000 <vm-ip>                                     # (after: py net.expose_service(net, ports='1-1000'))
```
**PASS:** a BLOCK box with `reason=snort-/ml-/ae-…` showing the **real `192.168.1.x` external
source IP** — the honest "detects & blocks outsiders with the full stack" result. Tear down:
`py net.unexpose_service(net)`.

## 8. Robustness / evasion probes (red-team realism)
Try to *beat* the IPS; each should still be caught by *some* tier (that's the point of layering):
- **Low-and-slow flood:** `hping3 -S -p 80 -i u10000 10.0.0.4` (below the flood rate) — signatures/rate
  may miss; the AE's timing regularity should still flag. Record which tier saves it.
- **Randomised source ports:** `hping3 --udp --flood -p 53 --rand-source 10.0.0.4` — tests entropy
  features and the per-source assumptions.
- **Slow HTTP:** `slowhttptest -c 1000 -H -u http://10.0.0.4` — connection-exhaustion vs volumetric.
- **MAC/IP spoofing:** an attacker changing MAC to dodge a `dl_src` DROP — note whether re-detection
  and re-block happen, and how fast.
Document each: *did it evade? which tier caught it? how long until block?* Gaps here are legitimate
Chapter-5 "Limitations" findings, not failures.

## 9. Scorecard (fill during the run)
| Test | Expected tier / `reason=` | Blocked? | Enforced (dump-flows/iptables)? | Latency | Notes |
|---|---|---|---|---|---|
| 5.1 Snort ICMP/SYN/UDP/scan | `snort-<sid>` | | | | |
| 5.2 rate flood / DAI ARP | `rate-counter-Nw` / DAI box | | | | |
| 5.3 RF (SYN) | `ml-0.8x` | | | | |
| 5.4 AE (zero-day) | `ae-0.7x` | | | | |
| 6 full stack ×6 | any tier | | | | |
| 7.1 Kali → controller | `EXT-BLOCK` + iptables | | | | |
| 7.2 Kali → SDN service | `snort/ml/ae` + real ext IP | | | | |
| 8 evasion ×4 | any tier / (miss) | | | | |

## 10. Evidence to capture
`redteam_run.log` (master), each BLOCK box, `/ips/blocked` JSON, `dump-flows` before/after,
`iptables -S` for the outsider, the attacker's 100%-loss ping vs an innocent host's 0%-loss, and a
dashboard screenshot mid-attack. Reset the lab fully at the end: `CONTROL:CLEAR`, `UNBLOCK` every IP,
`sudo iptables -F INPUT` (if you added external blocks), `mn -c`.

## 11. Gotchas specific to this test
- **Snort preempts the rate tier** on floods (it's faster) — that's why §5.2 takes Snort out to
  show the rate counter. In §6 the `reason=` will usually read `snort-…` for floods; that's correct.
- **Blocks are permanent** — always `UNBLOCK` between tests or a "failed" next test is just the prior
  DROP still in place.
- **Don't whitelist the attacker** and **do whitelist your admin IP** (`IPS_MGMT_WHITELIST`) — or
  §7.1 either won't block Kali, or will block *you*.
- **`dump-flows` is truth.** If the box prints BLOCKED but `n_packets` on the DROP rule stays 0, the
  `dl_src` didn't match the real frames (check the attacker's actual MAC) — a real finding, not a UI glitch.
