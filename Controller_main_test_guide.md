# Full System Test & Recording Guide — Controller_main_Claude.py

*Step-by-step to bring up the **merged controller** (everything `Controller.py` does +
the `ryu_ips_app.py` REST API on :8080) and test/record all subsystems operating at the
same time: Snort 3 IDS, the ML tiers (RF + AE), OpenFlow blocking, and the REST block
API. Do each step, confirm its **CHECK**, capture the **RECORD** item for evidence.*

> Run **only** `Controller_main_Claude.py` — do **not** also run `Controller.py` or
> `ryu_ips_app.py` (they would fight over UDP 9999 / OpenFlow / port 8080).

---

## What the merged file gives you (one `ryu-manager` process)
- OpenFlow **1.0** L2 learning switch, traffic mirror → `snort_tap`.
- **Snort 3** via `SnortManager` (alerts → CSV labels + instant block in AUTHORIZE).
- **Tier 3 RF** (`rf_pipeline.joblib`) + **Tier 4 AE** (`ae_bundle.joblib`), per-window.
- DAI/ARP-spoof detection, IoT discovery, UDP **9999** control channel.
- **REST API on :8080** — `POST /ips/block`, `DELETE /ips/block/<ip>`, `GET /ips/blocked`,
  `/ips/switches`, `/ips/status` — re-implemented on OF 1.0 (MAC block via `block_attacker`,
  IP fallback via `nw_src` DROP). Same routes the friend's `snort_ryu_bridge.py` posts to.

---

## STEP 0 — Prerequisites (controller VM)
- Deploy to the VM's `Controller/`: `Controller_main_Claude.py`, `ae_inference.py`,
  `ml_inference.py`, and `ml_models/{rf_pipeline.joblib, ae_bundle.joblib}`.
- Python ≥ 3.9 with `scikit-learn==1.6.1`, `pandas<2.3`, `numpy<2.3`, `joblib` in Ryu's
  interpreter (AE needs none — pure NumPy). `webob` ships with Ryu.
- (Optional, clean 6-attack Snort schema) install Snort 3 + run
  `sudo ./scripts/install_snort3_ips_config.sh`; otherwise the Snort 2.x fallback runs.
- **CHECK:** `python3 -c "import sklearn,numpy,pandas,joblib,webob; print('ok')"` in Ryu's interpreter.

## STEP 1 — Launch the merged controller (record the whole run)
```bash
cd ~/.../GP/Controller
sudo IPS_V2_FEATURES=1 ryu-manager Controller_main_Claude.py 2>&1 | tee controller_run.log
```
- **CHECK** for: `Feature schema mode: v2 (corrected)`; `ML engine loaded … pipeline (7 classes)`;
  `AE engine loaded …/ae_bundle.joblib (60 features, threshold=0.03750, 4 layers)`;
  `Snort on … started`; `REST IPS API on :8080 …`; `UDP command listener started on port 9999`.
- **RECORD #1:** the startup banner showing Snort + RF + AE + REST all up.

## STEP 2 — Confirm the REST API is live (second terminal)
```bash
curl -s http://127.0.0.1:8080/ips/status
curl -s http://127.0.0.1:8080/ips/switches
```
- **CHECK:** `/ips/status` → JSON like `{"status":"running","switches":0,"ml_mode":"OFF",...}`
  (switches becomes ≥1 once the topology connects).
- **RECORD #2:** `/ips/status` JSON before and after the topology connects.

## STEP 3 — Bring up the topology (topology VM)
```bash
cd "~/.../GP/SDN Topology"
sudo mn -c && sudo python3 topology.py
```
Register the two IoT devices in `mininet-wifi>`, then `pingall`.
- **CHECK:** `pingall` = 0% loss; controller logs REGISTER lines; `/ips/switches` now shows 1.
- **RECORD #3:** `pingall` (0% dropped) + the controller's REGISTER lines.

## STEP 4 — Snort IDS test (signature tier)
Detection still OFF; launch one attack:
```python
py net.run_attack_session(net,'icmp')
```
- **CHECK:** controller prints `🚨 IDS ALERT … Attack: ICMP Flood … From 10.0.0.x` boxes
  (deduped ~1/source/30s) — proves Snort sees the mirrored traffic.
- **RECORD #4:** one IDS ALERT box per attack type you run (icmp/syn/udp/scan).

## STEP 5 — ML test: RF + AE with confidence (pure-ML mode)
Send over UDP 9999:
```
CONTROL:DETECT:OFF        # so rate/Snort don't pre-label; RF+AE score every flow
CONTROL:ML:OBSERVE
CONTROL:ML:FLAG:0.60
CONTROL:ML:BLOCK:0.80
```
Run attacks: `py net.run_attack_session(net,'syn')` (repeat udp/icmp/scan/arp/cps).
- **CHECK:** per window you see BOTH:
  `[ML-OBSERVE] 10.0.0.x → 10.0.0.4  verdict=SYN Flood  conf=0.xx  band=…`
  `[AE-OBSERVE] 10.0.0.x → 10.0.0.4  anomaly conf=0.xx  err=0.xxxx  band=…`
  Normal: RF mostly `normal`, AE silent (<0.60). Attacks: high RF/AE confidence.
- **RECORD #5:** the `[ML-OBSERVE]` + `[AE-OBSERVE]` lines per attack class (the confidence
  numbers are your ML evidence). Note per class: RF verdict+conf, AE conf, % over the bars.

## STEP 6 — REST API block test (the merged ryu_ips_app path)
Block a host over HTTP (simulates the Snort→bridge→REST flow):
```bash
curl -s -X POST http://127.0.0.1:8080/ips/block \
     -H 'Content-Type: application/json' \
     -d '{"src_ip":"10.0.0.1","reason":"manual REST test"}'
curl -s http://127.0.0.1:8080/ips/blocked
```
- **CHECK:** response `{"status":"blocked","src_ip":"10.0.0.1",...}`; controller logs an
  `ATTACKER BLOCKED` box (MAC mode) or `[REST-IPS] DROP … (IP-match)`. From topology,
  `mininet-wifi> sta1 ping -c3 10.0.0.4` now fails.
- Unblock: `curl -s -X DELETE http://127.0.0.1:8080/ips/block/10.0.0.1` → connectivity returns.
- **RECORD #6:** POST JSON, `/ips/blocked` list, controller BLOCK log, before/after ping.

## STEP 7 — (Optional) wire the friend's Snort reader to the REST API
Drive the REST API from Snort alerts instead of curl: run the bridge + reader (they post to
`http://127.0.0.1:8080/ips/block`). Do **not** start a second Snort — point the reader at the
controller's own `/var/log/snort/.../alert_json.txt`.
```bash
python3 snort_ryu_bridge.py            # bridge :9000 -> Ryu REST :8080
sudo python3 snort_alert_reader.py     # tails alert_json, posts blocks to the bridge
```
- **CHECK:** during an attack the reader prints its IDS box and the controller logs a REST
  block for the same source — Snort-driven blocking via the merged REST API.
- **RECORD #7 (optional):** reader output + the controller's matching REST block.

## STEP 8 — Live blocking by the ML/Snort tiers (AUTHORIZE)
```
CONTROL:DETECT:ON
CONTROL:ML:AUTHORIZE
```
Run an attack. Tiers block: Snort instant-block on a canonical alert, rate-counter confirm,
RF ≥0.80 (tunable), AE ≥0.73 (`Anomaly (AE)`).
- **CHECK:** `ATTACKER BLOCKED` box with the detecting tier in `reason` (snort-/ml-/ae-);
  attacker flows stop. `CONTROL:UNBLOCK:<ip>` releases it.
- **RECORD #8:** the BLOCK box (note the latency line) + recovery after UNBLOCK.

## STEP 9 — Dataset evidence
Window rows are in `dataset.csv` (label 0 normal / 1 Snort / 2 behavioral-or-AE).
- **RECORD #9:** `head` + a few attack rows of `dataset.csv`, or rotate one
  (`CONTROL:ROTATE:test_session.csv`) to auto-validate and capture the `PASS ✅`.

---

## Recording checklist (for the report)
1. Startup banner — Snort + RF + AE + REST all loaded.
2. `/ips/status` JSON (before/after topology).
3. `pingall` 0% + REGISTER lines.
4. IDS ALERT boxes (Snort), one per attack type.
5. `[ML-OBSERVE]` + `[AE-OBSERVE]` confidence lines per attack.
6. REST block: POST JSON + `/ips/blocked` + BLOCK log + before/after ping.
7. (opt) Snort-reader → REST block.
8. AUTHORIZE BLOCK box + UNBLOCK recovery.
9. `dataset.csv` labeled rows (or a `PASS ✅` validation).

`controller_run.log` (Step 1 `tee`) is the master record.

## Notes / gotchas
- The merged controller starts its **own** Snort (SnortManager). The REST API is an
  *additional* block channel — use curl (Step 6) for the simplest proof; Step 7 is only if
  you want Snort-driven REST blocks.
- DETECT OFF + OBSERVE → RF scores every flow (you see its verdict on floods);
  DETECT ON → rate/Snort tiers label first (the deployed/layered behavior).
- If `curl` to :8080 is refused, the WSGI server didn't start — check Step 1's log for
  `REST IPS API on :8080` and that nothing else holds 8080.
- RF needs sklearn 1.6.1 in Ryu's interpreter; the AE needs only NumPy.
- OpenFlow version: the merged controller is **OF 1.0** (the team switch speaks it). The
  REST block uses OF 1.0 (`dl_src` MAC DROP, or `nw_src` IP DROP fallback) — not the OF 1.3
  matches from the original `ryu_ips_app.py`, which were dropped on purpose.
