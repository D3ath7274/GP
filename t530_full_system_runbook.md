# HP t530 — Full System Runbook (clone → run → test → record)

*One ordered path to stand up and test the **whole IPS** on the HP t530 (controller) +
the Mininet machine, from a fresh git clone. Snort 3 + Random Forest (Tier 3) +
Autoencoder (Tier 4) + the REST API all run together via `Controller_main_Claude.py`.
Do each step, pass its **GATE**, capture the **RECORD** item. Detailed sub-runbooks are
referenced inline; this file is the spine.*

Roles: **t530 = controller** (Ryu + Snort 3 + ML + REST). **Mininet machine** = the
SDN topology (separate box). They connect over OpenFlow 6633 + UDP 9999, and Snort is
fed by the permanent VXLAN `br-snort` bridge. Static IPs (lab default): controller
`192.168.1.200`, mininet `192.168.1.201` — substitute your real `<T530_IP>`/`<MININET_IP>`.

---

## PART 1 — One-time t530 setup

**1. Clone the repo (t530 + mininet machine).**
```bash
cd ~/Desktop && git clone <your GP repo URL> GP && cd GP && git status
```
- **GATE:** `Controller/`, `SDN Topology/`, and `Controller/snort3/` are present.

**2. System deps + Snort 3 from source (t530).** Follow `SDN_IPS_Snort_Installation_Runbook.pdf`
§4 (apt deps + OVS) and **§5 (build Snort 3 — do NOT `apt install snort`, that's v2)**.
- **GATE:** `/usr/local/bin/snort -V` prints **Snort++ 3.x**.

**3. ML runtime deps — in Ryu's interpreter (t530).**
```bash
pip3 install --user "scikit-learn==1.6.1" "pandas<2.3" "numpy<2.3" joblib
```
- The **AE needs none of these** (pure NumPy); these are for the **RF**. `webob` ships with Ryu.
- **GATE:** `python3 -c "import sklearn,numpy,pandas,joblib,webob,ryu; print(sklearn.__version__)"` → `1.6.1`,
  run with the *same* `python3` Ryu uses. **Do not repoint the system python** (breaks Ryu).

**4. Static IPs (both machines).** See `t530_bridge_setup.md` §A (netplan for `<T530_IP>` and
`<MININET_IP>`). - **GATE:** `ip -br addr` shows the static IPs; the two machines can ping each other.

**5. Install the Snort 3 config + rules (t530).**
```bash
cd ~/Desktop/GP && sudo mkdir -p /etc/snort/rules /var/log/snort
sudo cp Controller/snort3/sdn_ips.lua /etc/snort/sdn_ips.lua
sudo cp Controller/snort3/sdn_ips_local.rules /etc/snort/rules/sdn_ips_local.rules
sudo /usr/local/bin/snort -T -c /etc/snort/sdn_ips.lua -i ens33   # config self-test (no bridge yet)
```
- **GATE:** snort `-T` validates the Lua config cleanly.

**6. Confirm the ML models shipped with the clone (t530).**
```bash
ls -l Controller/ml_models/rf_pipeline.joblib Controller/ml_models/ae_bundle.joblib
```
- **GATE:** **both** files exist. If `ae_bundle.joblib` is missing, it wasn't committed —
  copy it over (`scp`) or rebuild it (see `context_claude.md` §5 / the notebook export).

**7. Permanent VXLAN `br-snort` bridge (both machines).** Follow `t530_bridge_setup.md`
§B (t530 `br-snort.service`) and §C (mininet `mininet-snort-mirror.service`), filling in
`<T530_IP>`/`<MININET_IP>` and VXLAN keys s1=100 / ap1=101.
- **GATE:** on the t530, `sudo ovs-vsctl show` lists `br-snort` with `vxlan-s1`/`vxlan-ap1`;
  `sudo /usr/local/bin/snort -T -c /etc/snort/sdn_ips.lua -i br-snort` validates.

---

## PART 2 — Launch (t530 + mininet)

**8. Start the merged controller (t530) — record the whole run.**
```bash
cd ~/Desktop/GP/Controller
sudo SNORT_IFACES=ens33,br-snort IPS_NO_TAP=1 IPS_V2_FEATURES=1 \
     ryu-manager Controller_main_Claude.py 2>&1 | tee controller_run.log
```
- `SNORT_IFACES=ens33,br-snort` + `IPS_NO_TAP=1` → Snort consumes the VXLAN bridge (not the
  redundant OpenFlow TAP). Drop these two for the TAP path if you're not using the bridge.
- **GATE / RECORD #1:** the banner shows `Feature schema mode: v2 (corrected)`,
  `ML engine loaded … pipeline (7 classes)`,
  `AE engine loaded …/ae_bundle.joblib (60 features, threshold=0.03750, 4 layers)`,
  `Snort on … started`, `REST IPS API on :8080 …`, `UDP command listener started on port 9999`.

**9. Confirm REST API + bring up the topology.**
```bash
# t530 (2nd terminal)
curl -s http://127.0.0.1:8080/ips/status
# mininet machine
cd ~/Desktop/GP/"SDN Topology"
sudo mn -c && sudo CONTROLLER_IP=<T530_IP> python3 topology.py
```
Register the two IoT devices, then `pingall`.
- **GATE / RECORD #2-3:** `/ips/status` JSON; `pingall` = 0% loss; controller logs REGISTER
  lines and `/ips/switches` now shows 1.

---

## PART 3 — Test all subsystems together (then record)

Run the gated steps in **`Controller_main_test_guide.md`** (Steps 4–9) — they apply verbatim
on the t530:
- **Step 4 — Snort IDS:** run an attack, see `🚨 IDS ALERT` boxes. **RECORD #4.**
- **Step 5 — RF + AE confidence:** `CONTROL:DETECT:OFF` + `CONTROL:ML:OBSERVE` +
  `CONTROL:ML:FLAG:0.60` + `CONTROL:ML:BLOCK:0.80`; run attacks; capture `[ML-OBSERVE]` +
  `[AE-OBSERVE]` lines per class. **RECORD #5** (your ML evidence).
- **Step 6 — REST block:** `curl -X POST …/ips/block -d '{"src_ip":"10.0.0.1",...}'`, show the
  DROP + before/after ping, then `DELETE …/ips/block/10.0.0.1`. **RECORD #6.**
- **Step 7 (opt) — Snort-reader → REST** (only if you want Snort-driven REST blocks).
- **Step 8 — AUTHORIZE blocking:** `CONTROL:DETECT:ON` + `CONTROL:ML:AUTHORIZE`; see the
  `ATTACKER BLOCKED` box (tier in `reason`), then `CONTROL:UNBLOCK:<ip>`. **RECORD #8.**
- **Step 9 — dataset evidence:** rows in `dataset.csv` (or `CONTROL:ROTATE:test.csv` → `PASS ✅`). **RECORD #9.**

**t530-specific GATE (resources):** during an attack, watch RAM (8 GB) and the window
compute time (`meta_controller_load`, must stay **< 5000 ms**). No window backlog.

---

## PART 4 — Recording checklist (for the report)
1. Startup banner — Snort + RF + AE + REST all loaded (on the t530).
2. `/ips/status` JSON (before/after topology).
3. `pingall` 0% + REGISTER lines.
4. Snort IDS ALERT boxes (one per attack type).
5. `[ML-OBSERVE]` + `[AE-OBSERVE]` confidence lines per attack.
6. REST block: POST JSON + `/ips/blocked` + BLOCK log + before/after ping.
7. (opt) Snort-reader → REST block.
8. AUTHORIZE BLOCK box + UNBLOCK recovery.
9. `dataset.csv` labeled rows (or a `PASS ✅`).
10. t530 resource note: RAM headroom + window compute < 5 s under flood.

`controller_run.log` (Step 8 `tee`) is the master record.

---

## Quick gotchas (t530)
- **Snort 2 vs 3:** if `snort -V` says 2.x, the wrong binary is on PATH — use `/usr/local/bin/snort`.
- **`ae_bundle.joblib`/`rf_pipeline.joblib` missing** → AE/RF tier disables; confirm Step 6.
- **`curl :8080` refused** → WSGI didn't start; check Step 8 log for `REST IPS API on :8080`.
- **`br-snort: No such device`** → `sudo systemctl start br-snort.service`.
- **No live traffic** → confirm `topology.py` reached `<T530_IP>` (env `CONTROLLER_IP`) and the
  mininet mirror service is up (`sudo systemctl status mininet-snort-mirror`).
- **sklearn import error in Ryu** → RF deps not in Ryu's interpreter (Step 3); AE still runs.

## Related docs
- `t530_bridge_setup.md` — the permanent VXLAN bridge (Part 1 §7).
- `Controller_main_test_guide.md` — the detailed test/record steps (Part 3).
- `context_claude.md` — full project/codebase reference. `SDN_IPS_Snort_Installation_Runbook.pdf` — deps/Snort 3 build.
