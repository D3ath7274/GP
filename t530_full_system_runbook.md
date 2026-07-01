# HP t530 — Full System Runbook (the single source: install → run → test every tier → dashboard → figures)

*Open **this one file** and you can stand up, exercise, and record the entire project on the t530.
It folds in the Snort 3 install/rules (from `SDN_IPS_Snort_Installation_Runbook.pdf`), the
standalone `snort_alert_reader.py` signature path, the merged-controller REST/block tests (was
`Controller_main_test_guide.md`), the dashboard, and the figure-capture map (Ch.4 + Ch.5).*

**Roles:** **t530 = controller** (Ryu + Snort 3 + RF + AE + REST/dashboard). A separate
**Mininet-WiFi VM = the SDN topology** (traffic + attacks). They connect over **OpenFlow 6633** +
**UDP 9999**; REST + dashboard on **:8081** (nginx holds :8080 on the t530).

> ⚠️ **The t530's IP is DHCP and keeps changing** (seen .65 → .69 → .4). The topology's
> `CONTROLLER_IP` must equal the t530's *current* IP or the switch never connects — and then
> **`pingall` still works** (OVS forwards on its own) while the controller sees **nothing**
> (no `packet_in` → no features → ML/AE silent). Fix permanently with a **router DHCP reservation**
> for the t530's MAC; until then read `ip -br addr` every launch and pass that IP.

## Quick index
| Part | What | When you need it |
|---|---|---|
| 0 | What you can test & how the pieces fit | read once |
| 1 | One-time install & verify (Snort 3, config, rules, mirror, deps, models) | fresh/repaved t530 |
| 2 | Launch the merged controller | every session |
| 3 | Topology + **background (normal) traffic** + **data-flow GATES** (the #1 failure) | every session |
| 4 | Pre-attack checklist (arm ML/AE in OBSERVE) | before any attack |
| 5 | Test **Random Forest** (Tier 3) | ML evidence |
| 6 | Test **Autoencoder** (Tier 4 / zero-day) | AE evidence |
| 7A | **ML-only blocking** (DETECT OFF + AUTHORIZE → RF/AE are the only deciders) | prove the models block hosts |
| 7B | **Full-stack** layered blocking (Snort + rate/DAI + RF + AE) | end-to-end proof |
| 8 | **REST API** block test (`/ips/block`) | REST/block evidence |
| 9 | **Standalone Snort reader** path (`snort_alert_reader.py`) | explicit IDS boxes + external-IP iptables block |
| 10 | **Dashboard** — connect, verify, operate | visibility + screenshots |
| 11 | **Capture the thesis figures** (Ch.4 + Ch.5 map) | writing the thesis |
| 12 | **Outsider (external) attack** — from a Windows/LAN host at the controller | prove defence vs. external threats |

---

## PART 0 — What you can test, and how the pieces fit
The **merged controller `Controller_main_Claude.py`** is ONE `ryu-manager`-style process that already
contains: the OF1.0 learning switch + packet mirror, its **own Snort 3** (`SnortManager`), Tier-2
rate/DAI, Tier-3 RF, Tier-4 AE, the UDP-9999 control channel, OpenFlow-DROP blocking, and the REST
API + dashboard on :8081. **For tiers 1–4 you only run this one process** (Parts 2–8, 10).

The **standalone reader path** (Part 9: `snort_alert_reader.py` + `snort_ryu_bridge.py`, from the
install-runbook PDF) is an *alternative/corroborating* signature pipeline that prints IDS-ALERT
boxes and can block **external** (non-`10.0.0.0/8`) IPs via `iptables`. You don't need it for tiers
1–4, but it's documented because the thesis/install runbook uses it. Don't run a *second* Snort for
it — point the reader at the merged controller's own `alert_json` (Part 9).

> Run **only** `Controller_main_Claude.py` — never also `Controller.py` or `ryu_ips_app.py`
> (they fight over UDP 9999 / OpenFlow / the REST port).

---

## PART 1 — One-time install & verify (skip if already done; just run the CHECKs)

### 1.1 System deps + Snort 3 from source (NOT `apt install snort` — that's v2)
```bash
sudo apt update
sudo apt install -y git curl build-essential cmake flex bison pkg-config autoconf \
  automake libtool libpcap-dev libpcre3-dev libpcre2-dev libdumbnet-dev zlib1g-dev \
  libluajit-5.1-dev libhwloc-dev openssl libssl-dev liblzma-dev libunwind-dev uuid-dev \
  libhyperscan-dev libsafec-dev python3 python3-pip openvswitch-switch tcpdump iproute2 \
  net-tools hping3
sudo systemctl enable --now openvswitch-switch

# DAQ + Snort 3 (only if `/usr/local/bin/snort -V` is missing or shows 2.x)
sudo apt remove -y snort || true ; hash -r
cd ~/Downloads && git clone https://github.com/snort3/libdaq.git && cd libdaq \
  && ./bootstrap && ./configure && make -j"$(nproc)" && sudo make install && sudo ldconfig
cd ~/Downloads && git clone https://github.com/snort3/snort3.git && cd snort3 \
  && ./configure_cmake.sh --prefix=/usr/local && cd build && make -j"$(nproc)" \
  && sudo make install && sudo ldconfig
```
- **CHECK:** `/usr/local/bin/snort -V` → **`Snort++ 3.x`**. (If it says 2.x, the apt binary is on
  PATH — always call `/usr/local/bin/snort` explicitly.)

### 1.2 Install the project's Snort config + the canonical 6-attack rules
```bash
cd ~/GP
sudo mkdir -p /etc/snort/rules /var/log/snort
sudo cp Controller/snort3/sdn_ips.lua            /etc/snort/sdn_ips.lua
sudo cp Controller/snort3/sdn_ips_local.rules    /etc/snort/rules/sdn_ips_local.rules
ls -l /etc/snort/sdn_ips.lua /etc/snort/rules/sdn_ips_local.rules
```
> Use the **repo** `sdn_ips_local.rules` (canonical project schema: ICMP 1000001, SYN 1000002,
> UDP 1000003, CPS 1000004; Port Scan = `port_scan` inspector GID 122; ARP = `arp_spoof` GID 112).
> It is what `snort_monitor.classify_attack()` maps to the ML labels. (The PDF's teaching set with
> SSH-bruteforce/Ryu-flood SIDs is a different file — don't install it for project tests.)

- **CHECK (config loads):** `sudo /usr/local/bin/snort -T -c /etc/snort/sdn_ips.lua -i enp1s0`
  → must end with the config validating and loading the local rules.

### 1.3 Mirror path — choose ONE
- **Simple (default, single-machine):** none needed — the merged controller mirrors to TAP
  `snort_tap` itself (launch uses `SNORT_IFACES=snort_tap`).
- **VXLAN `br-snort` (two-VM, matches the install runbook):** replicate the bridge per
  `t530_bridge_setup.md` (creates `br-snort` + VXLAN ports keys 100/101 + tc mirror; systemd
  `br-snort.service` on the t530 and `mininet-snort-mirror.service` on the Mininet VM). Then launch
  the controller with `SNORT_IFACES=ens33,br-snort IPS_NO_TAP=1` and verify
  `sudo /usr/local/bin/snort -T -c /etc/snort/sdn_ips.lua -i br-snort` passes.

### 1.4 Python deps + models + control tool
```bash
python3 -c "import sklearn,numpy,pandas,joblib,ryu; print('ML deps ok')"   # RF needs sklearn 1.6.1
sudo pip3 install psutil                                                     # dashboard health panel
ls -l Controller/ml_models/rf_pipeline.joblib Controller/ml_models/ae_bundle.joblib
ls -l Controller/ipsctl.py                                                   # UDP-9999 sender (nc is unreliable)
```
- Ryu 4.34 on Python 3.10 needs the `collections.MutableMapping` shim (already in the launch line),
  `dnspython>=2.6`, `eventlet 0.41`, and the patched `ryu/app/wsgi.py` (`ALREADY_HANDLED = []`).
- **Graceful degradation:** a missing model/dep disables only that tier; the rest still run.

---

## PART 2 — Launch the merged controller (t530, Terminal A)
```bash
cd ~/GP/Controller
sudo SNORT_PHYS_IFACE=enp1s0 SNORT_IFACES=snort_tap IPS_V2_FEATURES=1 \
  python3 -c "import collections,collections.abc; collections.MutableMapping=collections.abc.MutableMapping; from ryu.cmd.manager import main; main()" \
  Controller_main_Claude.py --wsapi-port 8081 2>&1 | tee controller_run.log
```
- **GATE (the startup banner must show all tiers up):**
  `Feature schema mode: v2 (corrected)` · `ML engine loaded … (7 classes)` ·
  `AE engine loaded …/ae_bundle.joblib (60 features, threshold=0.482…, … layers)` ·
  `Snort … started` · `wsgi starting up on http://0.0.0.0:8081` · `UDP command listener … 9999`.
  **Leave this terminal running.** (`controller_run.log` is your master recording — **Figure 5.2**.)
- If `:8081` is "Address already in use": `sudo fuser -k 8081/tcp` (nginx/stale controller), relaunch.
- If the AE threshold prints `0.03750`, the **old** bundle is loaded — `git pull` (the current
  bundle is `threshold=0.48213`, bottleneck-16) or rebuild it (PART 6) and relaunch.
- **To also watch the physical NIC** (needed for the outsider test, PART 12): add `enp1s0` to the
  interface list — `SNORT_IFACES=enp1s0,snort_tap`. The banner then reads
  `Snort alert monitor started — watching 2 interface(s): enp1s0, snort_tap`. Keep `snort_tap` for
  the internal SDN and add `enp1s0` for external traffic.

---

## PART 3 — Topology + the data-flow GATES (the critical part)

**3.1 — t530's current IP** (Terminal B): `ip -br addr | grep enp1s0`  → note it (e.g. 192.168.1.4).

**3.2 — Start the topology (Mininet VM), pointing at that exact IP:**
```bash
cd ~/GP/"SDN Topology"
sudo mn -c && sudo CONTROLLER_IP=<that-IP> python3 topology.py
```
Then in `mininet-wifi>`:
```python
py net.register_iot_device(net,'TempSensor','10.0.0.5/24','00:00:00:00:00:05','s1','IOT:TempSensor')
py net.register_iot_device(net,'Cam','10.0.0.6/24','00:00:00:00:00:06','s1','IOT:Camera')
pingall
py net.start_background_traffic(net)
```
The last line starts the **normal-traffic simulator** — an HTTP server + iperf server on `h2`, web
browsing from `sta1/sta2`, periodic iperf, low-rate pings, and realistic IoT telemetry (TempSensor
HTTP/MQTT-UDP publishes, Cam video-style iperf bursts + heartbeats). It serves three purposes:
1. keeps `dataset.csv` growing so the GATEs below pass without you hand-pinging,
2. lets **device baselines mature** — leave it running **≥ 180 s** before judging the AE
   (`is_baseline_mature`); a cold baseline makes normal traffic look anomalous,
3. it's the **legitimate traffic that must keep flowing while an attacker is blocked** — your proof
   (PART 7) that blocking is surgical, not a global outage.

> Leave background traffic running for the **whole** session (all ML/AE/blocking tests). Start every
> attack *on top of* it.

**3.3 — GATE 1 (switch connected).** On the t530: `curl -s http://127.0.0.1:8081/ips/switches`
- **Must show `"count": 1`.** If `0`, `CONTROLLER_IP` is wrong (stale t530 IP) → `mn -c` and relaunch
  3.2 with the IP from 3.1. **`pingall` succeeding does NOT prove the switch connected.**

**3.4 — GATE 2 (features being written).** On the t530:
```bash
ls -l ~/GP/Controller/dataset.csv
sleep 8 && wc -l ~/GP/Controller/dataset.csv     # must be GROWING after pingall
```
- If missing/empty → no `packet_in`. Causes in order: GATE 1 failed · controller restarted after
  traffic (it rotates `dataset.csv`→`.bak` on launch) · no traffic yet. Fix before any ML test.

Only with **GATE 1 = 1 and `dataset.csv` growing** do RF/AE have anything to score.

---

## PART 4 — PRE-ATTACK CHECKLIST (run all of these, in order, before any attack)
On the **t530, Terminal B** (A is the running controller):
```bash
cd ~/GP/Controller
# 1) data is flowing (from PART 3)
curl -s http://127.0.0.1:8081/ips/switches            # -> "count": 1
wc -l dataset.csv ; sleep 6 ; wc -l dataset.csv        # -> GROWING
# 2) arm ML + AE in OBSERVE (no blocking; log every window)
python3 ipsctl.py CONTROL:DETECT:OFF                   # isolate ML: no Snort/rate labels interfere
python3 ipsctl.py CONTROL:ML:OBSERVE                   # RF + AE score + LOG every window
# 3) confirm it took effect
curl -s http://127.0.0.1:8081/ips/status               # -> "ml_mode":"OBSERVE"
python3 ipsctl.py CONTROL:ML:STATS                     # engines respond (note scored count)
# 4) watch live output (3rd terminal; leave running during the attack)
tail -f controller_run.log | grep -E "ML-OBSERVE|AE-OBSERVE"
```
**Every attack must run ≥ 20 s** so several 5-second windows flush. You should see a summary line
per window for **both** engines — including `normal` / low-conf — proving they're alive.

---

## PART 5 — Test the Random Forest (Tier 3)
Do PART 4, then in `mininet-wifi>`:
```python
py net.run_attack_session(net,'syn')      # then icmp, udp, scan, arp, cps  (≥20s each)
```
**GATE / RECORD:** the watch terminal streams `[ML-OBSERVE] window: N flows scored — <verdict>:N`.
```bash
grep "ML-OBSERVE" controller_run.log | tail -30
python3 ipsctl.py CONTROL:ML:STATS        # scored count keeps rising
```
- `verdict=normal` during a real SYN flood ⇒ RF *running but misclassifying* (train/serve skew) →
  retrain per `ml_ae_confidence_boost_plan.md`, **not** "ML didn't activate."
- Scored count stays 0 while `dataset.csv` grows ⇒ RF erroring per-row → paste the next ~40 log lines.
- *Isolate RF from AE (optional):* `mv ml_models/ae_bundle.joblib ml_models/ae_bundle.off` + restart;
  restore afterward.

---

## PART 6 — Test the Autoencoder (Tier 4 / zero-day)
Do PART 4 (same OBSERVE setup). AE logs every window (`max conf`, `err`, `flagged`).
1. Let **normal** traffic run ~60 s (no attack). **GATE:** `[AE-OBSERVE]` with **low err** and
   max conf < 0.60 — AE correctly sees normal as normal.
2. Run each attack `py net.run_attack_session(net,'<kind>')` (≥20 s). **GATE / RECORD:** err jumps,
   conf crosses FLAG (0.60) / BLOCK (0.73).
```bash
grep "AE-OBSERVE" controller_run.log | tail -30
```
- conf = err/(err+threshold): flags at err ≈ 1.5×, blocks at err ≈ 2.7× threshold.
- If err stays low even during attacks ⇒ train/serve skew/threshold → re-fit & rebuild the bundle
  with `ml_models/build_ae_bundle.py` (no controller code change). Confirm the PART-2 banner
  threshold is your new model's p99, not the old `0.03750`.
- *Zero-day experiment (for Ch.5 Fig 5.12/5.13):* hold one attack class out of all training, then
  show the AE still flags it here.

---

## PART 7A — Make the ML models ACTUALLY block (pure-ML blocking)
This proves **the RF/AE themselves block a host**, with Snort and the rate/DAI tier taken out of the
picture so the block can only have come from a model. The trick is the **DETECT gate**: with
`DETECT:OFF` the controller does not rate/Snort-label anything, so RF + AE score **every** flow and
are the **only** tiers that can decide a block.

Background traffic running (PART 3) and both models loaded (PART 2 banner). On the **t530**:
```bash
cd ~/GP/Controller
python3 ipsctl.py CONTROL:DETECT:OFF          # remove rate/DAI/Snort labeling -> ML is the only decider
python3 ipsctl.py CONTROL:ML:AUTHORIZE:0.80   # RF blocks >=0.80, AE blocks >=0.73 (AE band fixed)
curl -s http://127.0.0.1:8081/ips/status      # confirm "ml_mode":"AUTHORIZE"
# optional live watch (Terminal C):
tail -f controller_run.log | grep -E "\[ML\]|\[AE\]|ATTACKER BLOCKED"
```
Now launch an attack from the topology and confirm a model blocks the source:
```python
py net.run_attack_session(net,'syn')          # then icmp / udp / scan / cps  (>=20s each)
```
- **GATE / RECORD:** Terminal A shows a model verdict crossing its band then the block, e.g.
  `[ML] ATTACK (block) 10.0.0.1 verdict=SYN Flood conf=0.9x` **or** `[AE] ANOMALY (block) 10.0.0.1
  conf=0.7x` → `ATTACKER BLOCKED … reason=ml-…/ae-…` (the `reason` names the deciding model).
- **Verify the block actually took effect (two ways):**
  ```bash
  curl -s http://127.0.0.1:8081/ips/blocked | python3 -m json.tool     # attacker IP listed
  ```
  ```python
  # from mininet-wifi>, the attacker can no longer reach the server, but background hosts still can:
  10.0.0.1 ping -c3 10.0.0.4      # the blocked attacker  -> 100% loss
  10.0.0.3 ping -c3 10.0.0.4      # an innocent host      -> 0% loss (surgical block)
  ```
- **Release between rounds:** `python3 ipsctl.py CONTROL:UNBLOCK:10.0.0.1`
  (or `CONTROL:CLEAR:10.0.0.1`), confirm the attacker's ping recovers, then test the next class.
- **Isolate ONE model** (to prove *that* model blocks): rename the other bundle and restart —
  `mv ml_models/ae_bundle.joblib ml_models/ae_bundle.off` (RF-only) **or**
  `mv ml_models/rf_pipeline.joblib ml_models/rf_pipeline.off` (AE-only); restore + restart after.
- **Tune the bar live** without restart: `python3 ipsctl.py CONTROL:ML:BLOCK:0.70` lowers the RF
  block threshold (more aggressive); `CONTROL:ML:FLAG:0.50` lowers the flag bar. Raise them back up
  if you see a legitimate host get blocked.
- This is **Ch.5 Fig 5.16/5.17** evidence (detection→block latency + lateral-movement containment).

> If a model *detects* (you saw it in OBSERVE, PART 5/6) but never blocks here: it's scoring below
> the block band — lower the bar (`CONTROL:ML:BLOCK`) or, for persistent under-confidence on real
> attacks, retrain per `ml_ae_confidence_boost_plan.md`. If nothing scores at all, DETECT is still
> ON or there's no `packet_in` (re-check PART 3 GATEs).

When done, return to the layered configuration for PART 7B:
```bash
python3 ipsctl.py CONTROL:DETECT:ON
```

## PART 7B — Full stack: Snort 3 + Rate/DAI + RF + AE (layered blocking)
Both model files present + controller restarted (or DETECT just turned back ON).
```bash
python3 ipsctl.py CONTROL:DETECT:ON          # Snort labels + Tier-2 rate/DAI block
python3 ipsctl.py CONTROL:ML:AUTHORIZE:0.80  # RF + AE block on high confidence
```
For each `py net.run_attack_session(net,'<kind>')`, capture in Terminal A whichever tiers fire:
- **T1 Snort:** `🚨 IDS ALERT … SID …` · **T2 rate/DAI:** `SUSPECTED … → CONFIRMED → BLOCKED` ·
  **T3 RF:** `[ML] ATTACK (block) … conf=0.xx` · **T4 AE:** `[AE] ANOMALY (block) …` · then
  `ATTACKER BLOCKED`.
```bash
curl -s http://127.0.0.1:8081/ips/blocked | python3 -m json.tool   # attacker listed
sudo ovs-ofctl dump-flows s1 | grep drop                           # (on Mininet VM) the DROP rule
```
- **GATE:** every attack caught by ≥1 tier and blocked; `/ips/blocked` + dashboard reflect it;
  window compute < 5000 ms; RAM has headroom. Release: `python3 ipsctl.py CONTROL:UNBLOCK:<ip>`
  (or `CONTROL:CLEAR:<ip>`).
- Expected coverage: ICMP/SYN/UDP floods → Snort + rate + RF (+AE); Port Scan → Snort port_scan +
  RF; ARP → DAI + Snort arp_spoof (+AE); novel/zero-day → AE.

---

## PART 8 — REST API block test (the merged `/ips/block` path)
Proves the HTTP block channel a SIEM/SOAR (or the Part-9 reader) would drive. Second terminal:
```bash
curl -s -X POST http://127.0.0.1:8081/ips/block \
     -H 'Content-Type: application/json' \
     -d '{"src_ip":"10.0.0.1","reason":"manual REST test"}'
curl -s http://127.0.0.1:8081/ips/blocked
# from mininet-wifi>:  sta1 ping -c3 10.0.0.4   ->  now fails
curl -s -X DELETE http://127.0.0.1:8081/ips/block/10.0.0.1     # unblock -> connectivity returns
```
- **CHECK:** POST → `{"status":"blocked",...}`; controller logs `ATTACKER BLOCKED` (MAC) or
  `[REST-IPS] DROP … (IP-match)`. **RECORD:** POST JSON + `/ips/blocked` + BLOCK log + before/after ping.
- If `curl` is refused, the WSGI server didn't start — re-check the PART-2 banner for the :8081 line.

---

## PART 9 — Standalone Snort reader path (signature-tier corroboration + external-IP blocking)
Use this when you want the explicit **IDS-ALERT boxes** of `snort_alert_reader.py` and/or to block
**external** (non-`10.0.0.0/8`) attackers via `iptables`. The merged controller already runs its own
Snort, so **do not start a second Snort** — point the reader at the controller's `alert_json` and
point the bridge at the merged REST (:8081).

```bash
# Confirm the merged controller's Snort is actually writing alerts. It must EXIST and grow,
# or the reader waits forever ("Waiting for file to appear"). If it's missing, an attack
# hasn't hit a signature yet, or Snort's log dir differs — check controller_run.log.
ls -l /var/log/snort/alert_json.txt

# Terminal C — bridge: forward reader POSTs to the merged controller's REST on :8081.
# ⚠️ sudo STRIPS env vars, so `sudo RYU_API_URL=… python3` is LOST and the bridge falls back
#    to :8080 (you'll see "Forwarding to Ryu: …:8080"). Use `sudo -E` and export the var, OR
#    `sudo env RYU_API_URL=…`. The bridge also needs sudo to create /var/log/snort_ryu_bridge.
cd ~/GP/Controller
sudo -E env RYU_API_URL=http://127.0.0.1:8081/ips/block python3 snort_ryu_bridge.py   # :9000
#   confirm it prints "Forwarding to Ryu: http://127.0.0.1:8081/ips/block"

# Terminal D — reader: tails alert_json, blocks canonical SIDs (internal via bridge→REST,
# external via iptables). PROTECTED_IPS = controller/Mininet/loopback (never blocked).
cd ~/GP/Controller
sudo python3 snort_alert_reader.py
```
- The reader blocks on SIDs `1000001` (ICMP), `1000002` (SYN), `1000003` (UDP), `1000004` (CPS);
  Port Scan/ARP are inspector-based (GID 122/112) and handled by the controller's tiers, not the reader.
- **CHECK:** during an attack the reader prints its `IDS ALERT … [BLOCKING]` box and the controller
  logs a matching REST block for the same source. For an **external** test from a third machine
  (e.g. `hping3 -S -p 8080 <t530-IP>`), confirm `sudo iptables -S INPUT | grep <attacker>` shows a DROP.
- **RECORD (Ch.5 Fig 5.4 / signature evidence):** the reader's IDS box + the controller's block.

> Edit the reader's `PROTECTED_IPS` / `INTERNAL_SDN_NETWORK` at the top of `snort_alert_reader.py`
> if your addressing differs (defaults assume the 192.168.1.200/.201 lab + `10.0.0.0/8` SDN net).

---

## PART 10 — Dashboard: connect, verify, operate
The controller serves the dashboard same-origin at `GET /`, so just open it:
```
http://<t530-current-IP>:8081/
```
- **Verify reachability from the t530 first:** `curl -s http://127.0.0.1:8081/ | head`
  - HTML returned ⇒ working; if a remote browser can't reach it, it's an IP/firewall issue (use the
    **current** enp1s0 IP; the dashboard auto-uses its own origin).
  - `404` ⇒ old code → `git pull` + restart. `Connection refused` ⇒ controller down (Part 2).
- **What you should see** during a Part-7 attack: connection badge **live**, DETECT/ML mode badges,
  threat level **UNDER ATTACK**, the four **tier tiles** with green "loaded" dots, **attacks-by-type**
  bars, **blocked-hosts** table (with **Unblock** buttons → `DELETE /ips/block/<ip>`), the **event
  feed**, and the **system-health** RAM/CPU/disk bars (needs `psutil`).
- The dashboard is **zero-dependency** (no CDN/build) — it renders offline. It polls every 2 s.

---

## PART 11 — Capturing the thesis figures
Full lists live in **`Chapter4_figure_capture_guide.md`** (the 21 Ch.4 figures) and
**`Chapter5_results_outline.md`** (Ch.5 results + the claim→evidence map). The high-value Ch.5
captures map onto this runbook as:

| Ch.5 figure | Capture from | Command / source |
|---|---|---|
| 5.2 tiers loaded | PART 2 banner | screenshot the `ML/AE/Snort … loaded` lines of `controller_run.log` |
| 5.4 Snort signature hit | PART 9 (or PART 7 T1) | reader IDS-ALERT box / `🚨 IDS ALERT` during an attack |
| 5.5–5.6 rate/DAI + ARP | PART 7 | `SUSPECTED→CONFIRMED→BLOCKED` / DAI binding-conflict log |
| 5.10 live RF verdicts | PART 5 | `grep "ML-OBSERVE" controller_run.log` |
| 5.11–5.13 AE / zero-day | PART 6 | AE notebook eval + `grep "AE-OBSERVE"` + the unseen-class block |
| 5.14 attacks-by-type | PART 10 | dashboard panel after a multi-attack session |
| 5.15 flow rule before/after | PART 7A/7B | `sudo ovs-ofctl dump-flows s1` ×2 around a block (Mininet VM) |
| 5.16 detection→block latency | PART 7A | diff detection-log vs flow-install timestamps |
| 5.17 lateral-movement containment | PART 7A | blocked attacker ping fails while an innocent host's ping succeeds |
| 5.18 t530 resource use | PART 10 | dashboard health panel or `curl …/ips/metrics` under load |
| 5.19 dashboard mid-attack | PART 10 | browser at `http://<t530>:8081/` during PART 7 |

---

## PART 12 — Outsider (external) attack test
Everything above is the **insider** model (compromised devices *inside* the SDN, whose packets the
OVS switches mirror to the controller). This part tests an **outsider**: a host on the physical LAN
(e.g. your **Windows** machine) attacking the controller/edge directly.

### 12.0 Data-plane vs management-plane — which tiers see what (read first)
`traffic_capture.py` (→ RF/AE) is fed by OpenFlow `packet_in`: it sees every packet that crosses an
**OVS switch the controller manages** (mirrored via `output:CONTROLLER`). It is an SDN flow monitor,
**not** a raw sniffer on `enp1s0`. So the right split is **not** insider-vs-outsider, it's
**data-plane vs management-plane**:

| Traffic | Path | Inspected by |
|---|---|---|
| Any flow through a managed OVS switch — internal, **or an external attacker in transit to a target** | → `packet_in` | **all 4 tiers** (Snort + rate/DAI + RF + AE), block = OpenFlow DROP |
| Direct hit on the controller's **own** NIC / mgmt port (e.g. flooding `:8081`) | Linux stack, no OVS | **Snort on `enp1s0` + iptables** (no `packet_in`, so RF/AE never see it) |

- **This PART (12.1–12.3)** is the *management-plane* case: Windows floods the controller's own
  `:8081` — that bypasses the SDN, so only Snort + iptables catch it (which is correct; no IPS
  inspects its own mgmt interface via its data plane).
- **For the RF/AE to catch an external attacker (12.5)** the external traffic must *transit the SDN*
  — NAT/expose an internal `10.0.0.x` service to the LAN so Windows attacks *that*; the flow crosses
  `s1` → `packet_in` → all four tiers fire.
- Your Windows box (192.168.1.x) reaches the **t530's IP** directly, but **not** `10.0.0.x` (inside
  the Mininet VM) unless you add NAT/routing (12.5).

### 12.1 Set up (t530)
1. **Launch the controller with Snort watching the NIC** (PART 2, NIC variant):
   ```bash
   sudo SNORT_PHYS_IFACE=enp1s0 SNORT_IFACES=enp1s0,snort_tap IPS_V2_FEATURES=1 \
     python3 -c "import collections,collections.abc; collections.MutableMapping=collections.abc.MutableMapping; from ryu.cmd.manager import main; main()" \
     Controller_main_Claude.py --wsapi-port 8081 > controller_run.log 2>&1 &
   ```
   Banner must read `… watching 2 interface(s): enp1s0, snort_tap`.
2. **Start the external-block pipeline** (PART 9, with the `sudo -E` fix):
   ```bash
   cd ~/GP/Controller
   sudo -E env RYU_API_URL=http://127.0.0.1:8081/ips/block python3 snort_ryu_bridge.py &   # :9000
   sudo python3 snort_alert_reader.py &
   ```
   Confirm your **Windows IP is not** in `PROTECTED_IPS` at the top of `snort_alert_reader.py`
   (that set = controller/Mininet/loopback; edit it to match your real LAN if needed).

### 12.2 Attack from Windows (target = the t530's IP)
Windows has no native `hping3`. Pick one:
- **nmap for Windows** (from nmap.org; bundles `nping`/`ncat`):
  ```powershell
  nmap -sS -p 1-1000 <t530-ip>                                    # port scan  -> port_scan inspector
  nping --tcp --flags syn -p 8081 --rate 2000 -c 20000 <t530-ip>  # SYN flood  -> SYN Flood rule
  ```
- **or WSL2 (Ubuntu on Windows)** for the real tool:
  ```bash
  sudo hping3 -S --flood -p 8081 <t530-ip>       # SYN flood at the REST port
  sudo hping3 --icmp --flood <t530-ip>           # ICMP flood
  ```

### 12.3 Confirm the block (the evidence)
```bash
grep -E "IDS ALERT|BLOCKING|External attacker blocked" controller_run.log   # Snort saw the external src
sudo iptables -S INPUT | grep <windows-ip>                                  # -> "-A INPUT -s <win> -j DROP"
# from Windows: the attack traffic to the t530 now stops (re-run nping -> no responses)
```
- **RECORD:** the reader's `IDS ALERT … [BLOCKING]` box for the external IP + the `iptables … DROP`
  line + the attack dying. This is your outsider-threat figure for Ch.5.

### 12.4 Caveats / tuning
- The repo `sdn_ips_local.rules` is tuned for the 6 internal attacks; the generic **SYN Flood** rule
  (`flags:S`, any→any) and the **port_scan** inspector fire on the external attacker once Snort
  watches `enp1s0`. For a dedicated "flood the controller's REST port" signature, add a rule on
  port 8081 and re-run `sudo /usr/local/bin/snort -T -c /etc/snort/sdn_ips.lua -i enp1s0`.

### 12.5 External attacker through the SDN — the full-4-tier outsider test
To have the **RF/AE (not just Snort/iptables) catch an outsider**, route the external traffic *into*
the data plane so it crosses `s1` → `packet_in` → all four tiers. `topology.py` now automates this
with `expose_service`: it adds a gateway port on `s1` in the root namespace and DNATs the Mininet
VM's LAN traffic to an internal host, **preserving the real external source IP**.

**On the Mininet VM** (in `mininet-wifi>`), first arm the controller (PART 7A/7B: `DETECT:ON`,
`ML:AUTHORIZE:0.80`, background traffic running), then:
```python
py net.expose_service(net)                 # h2:80 reachable as <vm-ip>:8080 (TCP)  — for SYN flood
# for an external PORT SCAN, forward a range instead (dport preserved):
py net.expose_service(net, ports='1-1000')
# for a UDP flood:
py net.expose_service(net, ports='8053', host_port=53, protos=('udp',))
```
It prints the exact `<vm-ip>` and the attack commands. **From Windows** (nmap/nping, or WSL hping3):
```powershell
nping --tcp --flags syn -p 8080 --rate 3000 -c 30000 <vm-ip>   # SYN flood  -> RF/AE/Snort
nmap  -sS -p 1-1000 <vm-ip>                                    # port scan  -> port_scan (needs the range expose)
```
- **Expected:** the attack reaches `h2` **through `s1`**, so the controller scores it with the full
  stack and installs an **OpenFlow DROP** — an `ATTACKER BLOCKED … reason=ml-/ae-/snort-` box
  showing the **real external `192.168.1.x` source IP**. That's the honest "detects attacks from
  outside the environment, with the ML/AE models" proof (contrast PART 12's mgmt-plane hit, which
  only Snort+iptables catch).
- The block is a `dl_src` DROP on the gateway port (the external IP's L2 source on `s1`), so it cuts
  the external ingress at the edge. Tear down with `py net.unexpose_service(net)`.
- **One-by-one testing:** run each attack type at the exposed service separately (SYN flood → scan →
  UDP), and watch which tier fires each time (`reason=` names it) — the external analogue of PART 5/6/7.

---

## Recording checklist (master = `controller_run.log` from PART 2's `tee`)
1. Startup banner — Snort + RF + AE + REST all loaded (Fig 5.2).
2. `/ips/status` + `/ips/switches` (before/after topology connects).
3. `pingall` 0% + REGISTER lines + GATE 2 `dataset.csv` growing.
4. `[ML-OBSERVE]` + `[AE-OBSERVE]` summary lines per attack class (Fig 5.10/5.13).
5. Full-stack BLOCK box per attack + `/ips/blocked` JSON + flow DROP (Fig 5.15).
6. REST block: POST JSON + `/ips/blocked` + BLOCK log + before/after ping (PART 8).
7. (opt) Snort-reader IDS box → REST/iptables block (PART 9, Fig 5.4).
8. Dashboard screenshot mid-attack + health panel (Fig 5.18/5.19).
9. `dataset.csv` labeled rows (or a `CONTROL:ROTATE:test.csv` `PASS ✅`).

## Quick gotchas (t530)
- **ML/AE silent + `dataset.csv` missing** → no `packet_in`; check GATE 1 (`/ips/switches`=1) and
  GATE 2 (growing). Root cause is almost always a **stale `CONTROLLER_IP`** (t530 IP moved).
- **t530 IP keeps changing** → router **DHCP reservation**; else read `ip -br addr` every launch.
- **Control command fails / `nc` missing** → `python3 Controller/ipsctl.py CONTROL:…`.
- **`:8081` in use** → `sudo fuser -k 8081/tcp`. **Snort 2 vs 3** → `/usr/local/bin/snort`.
- **Let attacks run ≥ 20 s** — OBSERVE summaries print only when a 5-s window flushes.
- **Two Snorts** → never run a standalone Snort alongside the merged controller; the reader (PART 9)
  tails the controller's own `alert_json`.

## Related docs
- `AI_Project_Context.md` — current architecture/code reference (absorbs the old `context_claude.md`).
- `PROJECT_EXPLAINER.md` — full A-Z developer + business explanation.
- `t530_bridge_setup.md` — VXLAN `br-snort` mirror on the t530 (PART 1.3 option B).
- `SDN_IPS_Snort_Installation_Runbook.pdf` — original clean-machine/two-VM install (source of PART 1 & 9).
- `Chapter4_figure_capture_guide.md` / `Chapter5_results_outline.md` — the thesis figures + evidence map.
- `ml_ae_confidence_boost_plan.md` — train/serve skew remediation (if RF/AE misclassify live traffic).
