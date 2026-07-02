# Chapter 5 — Figure Capture Runbook

Quick, do-this-get-that guide for the Chapter-5 figures in scope: **5.1, 5.2, 5.4,
5.5, 5.6, 5.10, 5.15, 5.16, 5.19**. Assumes the current system: controller on the
**t530**, Mininet-WiFi on the **VM**, dashboard at `http://<t530-ip>:8081/`, control via
`Controller/ipsctl.py`.

Legend for where a command runs: **[t530]** controller host · **[VM]** Mininet host ·
**[mn]** inside the `mininet-wifi>` CLI.

---

## 0. One-time setup

**Controller (t530)** — launch and leave it running in a terminal you can screenshot:
```bash
sudo SNORT_PHYS_IFACE=enp1s0 SNORT_IFACES=enp1s0,snort_tap IPS_V2_FEATURES=1 \
  python3 -c "import collections,collections.abc; collections.MutableMapping=collections.abc.MutableMapping; from ryu.cmd.manager import main; main()" \
  Controller_main_Claude.py --wsapi-port 8081 2>&1 | tee controller_run.log
```
**Topology (VM)** — `sudo python3 topology.py` (targets the t530 IP), then register hosts.

Set the terminal to a dark theme + big font (and browser zoom ~125% for 5.19) so the
figures are legible in the thesis.

---

## Group A — Terminal / log screenshots (controller running)

Arm once, then trigger the matching attack from **[VM]**. Attacks: either the helper
`py net.run_attack_session(net,'<kind>')` **[mn]** or `hping3/nmap/arpspoof` by hand.

Arming commands (run on **[t530]**, `cd ~/GP/Controller`):
```bash
python3 ipsctl.py CONTROL:DETECT:ON            # or OFF
python3 ipsctl.py CONTROL:ML:OBSERVE           # or OFF / AUTHORIZE:0.80
```

| Fig | Mode to set (on **[t530]** via ipsctl) | Trigger | What to frame in the screenshot |
|-----|----------------------------------------|---------|---------------------------------|
| **5.2** | *(none — just startup)* | — | The startup banner: `AE engine loaded … 60 features, threshold=0.48213, 4 layers`, `ML engine loaded … rf_pipeline.joblib (7 classes)`, `Snort on … started (PID …)`, `Feature schema mode: v2 (corrected)`, `Forced n_jobs=1`. |
| **5.4** | `CONTROL:DETECT:ON` | any known attack (e.g. SYN) | One `🚨 IDS ALERT` box: `Rule : SID 1000002`, From/To IPs, attack type, timestamp. |
| **5.5** | `CONTROL:DETECT:ON` + `CONTROL:ML:OFF` | sustained flood (ICMP/UDP) | The rate-tier progression → the `🚫 ATTACKER BLOCKED` box with `Detection : rate-…` and the DROP line. (Hysteresis = it only confirms after N windows.) |
| **5.6** | `CONTROL:DETECT:ON` | `arpspoof` **[mn]** | The `⚠ ARP SPOOFING DETECTED (DAI)` box: Attacker MAC, Claims IP, Real Owner. |
| **5.10** | `CONTROL:DETECT:OFF` + `CONTROL:ML:OBSERVE` | any attack | `[ML-OBSERVE] … verdict=<class> conf=… band=…` lines + the `window: N flows scored — <class>:k, normal:m` summary. |

### 5.15 — flow table before/after a block  **[VM/mn]**
```bash
# BEFORE (no active block): screenshot 1
sh ovs-ofctl dump-flows s1        # inside mininet-wifi>   (or: [VM] sudo ovs-ofctl dump-flows s1)
# ... arm CONTROL:ML:AUTHORIZE:0.80 and run one attack so a block lands ...
# AFTER: screenshot 2 — look for the priority=65000, dl_src=<attacker MAC>, actions=drop entry
sh ovs-ofctl dump-flows s1
```

### 5.16 — detection-to-block latency  **[t530]**
The `🚫 ATTACKER BLOCKED` box already prints `Latency : 0.150s (detection → response)`.
Run 8–10 attacks, then pull every latency line for a table:
```bash
grep -E "Latency" controller_run.log
```
Screenshot the box for one event + paste the grep output as the N-event table.

---

## Group B — Dashboard screenshot (live attack)  **[win browser → http://<t530>:8081/]**

Arm the full stack first: `CONTROL:DETECT:ON` + `CONTROL:ML:AUTHORIZE:0.80`.

### 5.19 — full dashboard under active attack
Run a mixed session (`py net.run_full_attack_demo(net)` **[mn]**, or fire each
`run_attack_session` in turn) so counts and blocks accumulate. Capture the **whole browser
view**: elevated threat level, tier tiles lit (rf/ae/snort dots), populated blocked-host
table (IP·MAC·tier·type·time), and the scrolling event timeline.
> Note: blocks are now **permanent** — `CONTROL:UNBLOCK:<ip>` when done, not just CLEAR.

---

## Group C — Diagram

**5.1** — already drawn in Excalidraw. Ensure it shows: t530 controller ↔ Mininet VM over
**OpenFlow TCP 6633** and **UDP 9999**; OVS **s1** bridging wired/wireless; the mirror to
Snort 3 via the **br-snort VXLAN** bridge. Export PNG at high res.

---

## Suggested capture order (one controller session)
1. Screenshot **5.2** at startup.
2. `DETECT:ON, ML:OFF` → **5.5, 5.6** (rate + DAI), **5.4** (Snort).
3. `DETECT:OFF, ML:OBSERVE` → **5.10** (RF observe lines).
4. `DETECT:ON, ML:AUTHORIZE:0.80` → **5.15** (flow before/after), **5.16** (latencies),
   **5.19** (dashboard). `UNBLOCK` between hosts.
5. Export **5.1**.

Remember to `CONTROL:UNBLOCK:<ip>` (permanent blocks) before re-testing the same host.
