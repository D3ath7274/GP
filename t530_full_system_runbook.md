# HP t530 — Full System Runbook (ML + AE testing, end to end)

*The complete, ordered path to run the IPS on the t530 and **prove RF (Tier 3) and AE (Tier 4)
actually fire** — including the data-flow gate that catches the #1 failure (no `packet_in` →
no features → ML/AE silent). Do each step, pass its **GATE** before moving on.*

**Roles:** t530 = controller (Ryu + Snort 3 + RF + AE + REST/dashboard). Separate Mininet VM =
the SDN topology. They connect over **OpenFlow 6633** + **UDP 9999**; REST/dashboard on **:8081**.

> ⚠️ **The t530's IP keeps changing (DHCP): it's `192.168.1.4` right now (was .65, .69).**
> Every time it changes, the topology's `CONTROLLER_IP` must match the *current* IP or the switch
> never connects — and then **`pingall` still works** (OVS forwards on its own) while the
> controller sees **nothing**. Fix permanently with a **router DHCP reservation** for the t530's
> MAC. Always check `ip -br addr` on the t530 and use that exact IP.

---

## PART 1 — One-time setup (already done on your t530; verify)
- Snort 3 from source: `/usr/local/bin/snort -V` → **Snort++ 3.x**.
- ML deps present (Python 3.10 on this box): `python3 -c "import sklearn,numpy,pandas,joblib,ryu"`.
- Config installed: `/etc/snort/sdn_ips.lua` + `/etc/snort/rules/sdn_ips_local.rules`.
- Models present: `ls -l Controller/ml_models/rf_pipeline.joblib Controller/ml_models/ae_bundle.joblib`.
- Ryu/eventlet patched for py3.10 (the `collections.MutableMapping` shim in the launch line below).
- `Controller/ipsctl.py` present (UDP control sender; `nc` is unreliable here).

---

## PART 2 — Launch the controller (t530, Terminal A)
```bash
cd ~/GP/Controller
sudo SNORT_PHYS_IFACE=enp1s0 SNORT_IFACES=snort_tap IPS_V2_FEATURES=1 python3 -c "import collections,collections.abc; collections.MutableMapping=collections.abc.MutableMapping; from ryu.cmd.manager import main; main()" Controller_main_Claude.py --wsapi-port 8081 2>&1 | tee controller_run.log
```
- `SNORT_IFACES=snort_tap` keeps Snort on the Mininet data-plane only (no physical-LAN noise).
- **GATE:** banner shows `ML engine loaded … (7 classes)`, `AE engine loaded … (60 features,
  threshold=…, 4 layers)`, `Snort … started`, `wsgi starting up on http://0.0.0.0:8081`,
  `UDP command listener … 9999`. **Leave this terminal running.**

> If `:8081` errors "Address already in use", a stale controller/nginx holds it:
> `sudo fuser -k 8081/tcp` then relaunch.

---

## PART 3 — Bring up the topology AND prove data is flowing (the critical part)

**3.1 — Find the t530's current IP** (Terminal B on the t530):
```bash
ip -br addr | grep enp1s0          # note the IP, e.g. 192.168.1.4
```

**3.2 — Start the topology (Mininet VM), pointing at that exact IP:**
```bash
cd ~/GP/"SDN Topology"
sudo mn -c && sudo CONTROLLER_IP=<that-IP> python3 topology.py
```
Then in the Mininet CLI register the IoT devices and ping:
```python
py net.register_iot_device(net,'TempSensor','10.0.0.5/24','00:00:00:00:00:05','s1','IOT:TempSensor')
py net.register_iot_device(net,'Cam','10.0.0.6/24','00:00:00:00:00:06','s1','IOT:Camera')
pingall
```

**3.3 — GATE 1: the switch is actually connected.** On the t530 (Terminal B):
```bash
curl -s http://127.0.0.1:8081/ips/switches
```
- **Must show `"count": 1`.** If `0`, the switch did NOT connect → `CONTROLLER_IP` is wrong
  (stale t530 IP). Re-`mn -c` and relaunch the topology with the IP from 3.1. **Do not continue
  until this is 1** — pingall succeeding does NOT mean the controller is connected.

**3.4 — GATE 2 (the one that just failed for you): features are being written.** On the t530:
```bash
ls -l ~/GP/Controller/dataset.csv      # must EXIST
sleep 8 && wc -l ~/GP/Controller/dataset.csv   # must be GROWING
```
- **`dataset.csv` must exist and grow after `pingall`.** If it's missing/empty, the controller is
  receiving **no `packet_in`** — that's why ML/AE were silent. Causes, in order: GATE 1 failed
  (switch not connected) · the controller was restarted after traffic (it rotates `dataset.csv`
  → `.bak` on launch, so a fresh idle run has none) · no traffic generated yet. Fix and re-check
  before any ML test.

Only when GATE 1 = 1 **and** `dataset.csv` is growing do RF/AE have anything to score.

---

## PART 4 — Test the Random Forest (Tier 3) alone
Goal: RF classifies each attack, nothing else interfering. All control via `ipsctl.py` on the t530.
```bash
cd ~/GP/Controller
python3 ipsctl.py CONTROL:DETECT:OFF      # only ML scores (no Snort/rate labeling/blocking)
python3 ipsctl.py CONTROL:ML:OBSERVE      # RF + AE predict and LOG, never block
```
*(Optional, to isolate RF from AE: `mv ml_models/ae_bundle.joblib ml_models/ae_bundle.off` then
restart the controller — banner shows AE disabled. Restore + restart afterwards.)*

For each attack, in the Mininet CLI — **let each run ≥ 20 s** (so 5-s windows flush):
```python
py net.run_attack_session(net,'syn')      # then icmp, udp, scan, arp, cps
```
**GATE / RECORD:** in Terminal A you see, per window, lines like
`[ML-OBSERVE] 10.0.0.1 → 10.0.0.4  verdict=SYN Flood  conf=0.xx  band=…`.
Verify the verdict matches the attack. Tally:
```bash
grep "ML-OBSERVE" controller_run.log | tail -20
python3 ipsctl.py CONTROL:ML:STATS        # prints how many flows ML scored (should be > 0)
```
- **If `ML:STATS` says 0 scored** while `dataset.csv` grows → RF is erroring per-row; paste the
  next ~40 lines of `controller_run.log` after an attack and I'll pinpoint it.

---

## PART 5 — Test the Autoencoder (Tier 4) alone
Goal: AE silent on normal, flags anomalies on attacks.
```bash
python3 ipsctl.py CONTROL:DETECT:OFF
python3 ipsctl.py CONTROL:ML:OBSERVE
```
*(Optional isolation: `mv ml_models/rf_pipeline.joblib ml_models/rf_pipeline.off` + restart.)*
1. Let **normal** traffic run ~60 s (no attack). **GATE:** few/no `[AE-OBSERVE]` lines (the AE is
   silent below 0.60 confidence on normal).
2. Run each attack `py net.run_attack_session(net,'<kind>')` (≥ 20 s each). **GATE / RECORD:**
   `[AE-OBSERVE] … conf=0.xx err=0.xxxx band=FLAG|BLOCK` appears, conf ≥ 0.60 on attacks.
```bash
grep "AE-OBSERVE" controller_run.log | tail -20
```
- Normal err well below the bundle threshold; attack err well above. (Conf = err/(err+threshold):
  flags at err ≈ 1.5×, blocks at err ≈ 2.7× threshold.)
- Restore any moved model file + restart.

---

## PART 6 — Full stack: Snort 3 + Rate/DAI + RF + AE (blocking ON)
Both model files present + restarted.
```bash
python3 ipsctl.py CONTROL:DETECT:ON          # Snort labels + Tier-2 rate/DAI block
python3 ipsctl.py CONTROL:ML:AUTHORIZE:0.80  # RF + AE block on high confidence
```
For each attack `py net.run_attack_session(net,'<kind>')`, capture in Terminal A whichever tiers fire:
- **T1 Snort:** `🚨 IDS ALERT … SID …`
- **T2 rate/DAI:** `SUSPECTED … 1/N → CONFIRMED → BLOCKED`
- **T3 RF:** `[ML] ATTACK (block) … conf=0.xx`
- **T4 AE:** `[AE] ANOMALY (block) …`
- then `ATTACKER BLOCKED`.

Confirm end-to-end:
```bash
curl -s http://127.0.0.1:8081/ips/blocked | python3 -m json.tool   # attacker listed
```
Dashboard `http://<t530-IP>:8081/` → threat HIGH, blocked table + timeline + health panel.
Release: `python3 ipsctl.py CONTROL:CLEAR:<attacker-ip>` (or `CONTROL:UNBLOCK:<ip>`).
- **GATE:** every attack caught by ≥1 tier and blocked; `/ips/blocked` + dashboard reflect it;
  window compute < 5000 ms, RAM has headroom.

Expected coverage: floods (ICMP/SYN/UDP) → Snort + rate + RF (+AE); Port Scan → Snort port_scan +
RF; ARP spoof → DAI + Snort arp_spoof (+AE); novel/zero-day → AE.

---

## PART 7 — Dashboard + recording
- Dashboard: `http://<t530-IP>:8081/` (served by the controller, same origin). If "can't be
  reached": `curl -s http://127.0.0.1:8081/ | head` on the t530 — HTML ⇒ it's an IP/reach issue
  (use the current enp1s0 IP); 404 ⇒ old code (`git pull` + restart); refused ⇒ controller down.
  `sudo pip3 install psutil` so the health panel shows CPU/RAM/Disk.
- Record: `controller_run.log` (the `tee`), `[ML-OBSERVE]`/`[AE-OBSERVE]` tallies, `/ips/blocked`
  JSON, dashboard screenshots, and an `ls -l dataset.csv` showing rows captured.

---

## Quick gotchas (t530)
- **ML/AE silent + `dataset.csv` missing** → no `packet_in`. Check GATE 1 (`/ips/switches` = 1)
  and GATE 2 (`dataset.csv` growing). Root cause is almost always a **stale `CONTROLLER_IP`**
  (the t530 IP moved) — pingall working does NOT prove the controller is connected.
- **t530 IP keeps changing** → set a router **DHCP reservation** for its MAC; until then, read
  `ip -br addr` every launch and pass that IP as `CONTROLLER_IP`.
- **Control command fails / `nc` missing** → `python3 Controller/ipsctl.py CONTROL:…`.
- **`:8081` in use** → `sudo fuser -k 8081/tcp` (nginx/stale controller).
- **Snort 2 vs 3** → use `/usr/local/bin/snort` (apt installs v2).
- **Let attacks run ≥ 20 s** before judging — `[ML/AE-OBSERVE]` only print when a 5-s window flushes.

## Related docs
- `PROJECT_EXPLAINER.md` — full A-Z developer + business explanation.
- `AI_Project_Context.md` — current architecture/code reference for AI agents.
- `Controller_main_test_guide.md` — the detailed REST/block test steps.
