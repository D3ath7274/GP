# Comprehensive Project Context — SDN-based IoT IPS (current state)

**Purpose:** master context file for any LLM/AI agent. It reflects the **current** system (a
4-tier adaptive IPS with two ML models, a merged controller, REST API + dashboard, deployed on an
HP t530 thin client). It **supersedes** earlier descriptions that mention "3 tiers", "49 features",
"Z-score Tier 3", or IPs `.19/.26` — those are obsolete. Deeper narrative lives in
`PROJECT_EXPLAINER.md`; this file is the dense technical index.

---

## 1. System architecture
Two machines on one LAN:
- **Controller — HP t530 thin client** (Ubuntu 22.04 / **Python 3.10**, NIC `enp1s0`, hostname
  `ipsdwan`). Runs the merged Ryu controller, Snort 3, both ML engines, the REST API + dashboard.
  IP is **DHCP and changes** (seen as .65 → .69 → .4) — pin via a router reservation; the topology
  must target the *current* IP. (Original lab used two VMs at `192.168.1.200/.201`.)
- **Mininet VM** — runs `SDN Topology/topology.py` (Mininet-WiFi): stations `sta1/sta2`, AP `ap1`,
  wired hosts `h1/h2`, OVS switch `s1`, plus dynamically-registered IoT devices `TempSensor`
  (10.0.0.5) and `Cam` (10.0.0.6). Source of simulated traffic + attacks (hping3, nmap, arpspoof).
- **Links:** OpenFlow **6633** (control), UDP **9999** (out-of-band commands), REST/dashboard
  **:8081** on the t530 (8080 is taken by nginx there).

---

## 2. The merged controller — `Controller/Controller_main_Claude.py`
A single Ryu app (OpenFlow 1.0 learning switch) that combines everything (it merged the old
`Controller.py` + `ryu_ips_app.py`). Run as ONE process:
```bash
sudo SNORT_PHYS_IFACE=enp1s0 SNORT_IFACES=snort_tap IPS_V2_FEATURES=1 python3 -c "import collections,collections.abc; collections.MutableMapping=collections.abc.MutableMapping; from ryu.cmd.manager import main; main()" Controller_main_Claude.py --wsapi-port 8081
```
Responsibilities: L2 forwarding; **mirror every data-plane packet to the controller**
(`output:CONTROLLER`, with an amplification guard so flow-rule copies aren't re-forwarded); feed
the feature extractor + Snort; run RF + AE; ARP-spoof (DAI) detection; IoT/gateway discovery;
UDP-9999 command listener; OpenFlow-DROP enforcement; WSGI REST API + dashboard.

**Data-flow dependency (critical):** the feature extractor is fed by **OpenFlow `packet_in`**. If
the switch isn't connected to the controller (wrong `CONTROLLER_IP`), the controller sees nothing,
`dataset.csv` is never written, and ML/AE stay silent — *even though `pingall` still works*
(OVS fail-mode forwards on its own). Always verify `GET /ips/switches` = 1 and that `dataset.csv`
grows.

---

## 3. The four-tier detection engine (block if ANY tier fires, in AUTHORIZE)
- **Tier 1 — Snort 3 signatures** (`snort_monitor.py` + `snort3/sdn_ips.lua` +
  `sdn_ips_local.rules`): curated rules for the 6 attack classes + the `port_scan` and `arp_spoof`
  inspectors; consumes `alert_json`; suppresses known-benign noise by **(GID, SID)** pairs
  (`_blocked_gid_sids`, e.g. 129:4 PAWS, 116:414 broadcast, 112:1 gratuitous ARP).
- **Tier 2 — Rate counters + DAI:** per-host sliding counters confirm a flood/scan only after **N
  consecutive windows** (hysteresis, suppresses single-window spikes); Dynamic ARP Inspection
  flags IP↔MAC binding changes. State in `_confirmed_attackers`; a global `CONTROL:CLEAR` resets it.
- **Tier 3 — Random Forest** (`ml_inference.py`, `ml_models/rf_pipeline.joblib`): supervised
  scikit-learn + imbalanced-learn pipeline, classifies a window into the 6 attack classes.
- **Tier 4 — Autoencoder** (`ae_inference.py`, `ml_models/ae_bundle.joblib`): unsupervised,
  trained on **normal only**; high reconstruction error = anomaly (zero-day). Runs as a
  **pure-NumPy** forward pass (no TensorFlow). Current model: 60→64→16→64→60, MSE.

**Confidence banding** (the adaptive, low-noise behaviour): `conf < 0.60` → **silent**; flag band
→ evidence only; **block** band (RF ≥ 0.80, AE ≥ 0.73 confidence) → OpenFlow DROP in AUTHORIZE.
RF bands tunable live (`CONTROL:ML:FLAG/BLOCK`). AE confidence = `error/(error+threshold)`.

---

## 4. Feature pipeline — `traffic_capture.py`
- Consumes `packet_in`, aggregates into **5-second windows per flow key** `(src,dst,dst_port,proto)`,
  computes the **102-column "v2" feature schema** (`IPS_V2_FEATURES=1`), writes one row per
  flow/window to `dataset.csv`, and is the **live inference feed** for Tiers 2/3/4 (same code path
  → no train/serve skew).
- Feature groups (rationale in `feature_engineering_rationale.docx`): per-flow volume/rate, TCP
  flags, port-spread + `sequential_port_score`, inter-arrival timing/burstiness, session
  completion, **Shannon entropy** (dst-port/payload/src-port/icmp-type), per-device baselines,
  network-level context, ARP features.
- **Leakage guard:** `meta_*` columns (window id, device name, attack tool, controller load,
  backlog drops, session id) are audit-only and **stripped from the training file**.
- **2-pass labeling:** an attacker confirmed in pass 1 has its other same-window flows relabeled in
  pass 2 (no "normal" rows mid-attack). A protocol-consistency guard stops cross-protocol bleed;
  the validator catches residual sticky/rate bleed.

---

## 5. ML model lifecycle
- **RF:** scikit-learn **1.6.1** + imbalanced-learn pipeline (`rf_pipeline.joblib`, 7 classes incl.
  normal). Class imbalance handled at **train time** (SMOTE + class weights), never by deleting data.
- **AE:** trained in `ml_models/Grad_Autoencoder_4.ipynb` on `dataset_v4_master_training.csv`
  (normal rows only; drop ~36 columns; one-hot `protocol`; StandardScaler; threshold = p99 of
  validation reconstruction error). Deployed via **`ml_models/build_ae_bundle.py`**, which reads
  the trained `.h5` + the CSV and writes `ae_bundle.joblib` = `{features, mean, scale, threshold,
  layers}` — no TensorFlow at runtime. `ae_inference.py` loads any layer list (transparent to
  architecture changes).

---

## 6. Control channel + REST + dashboard
- **UDP 9999 out-of-band commands** (reach the controller even under a flood). Send with
  **`Controller/ipsctl.py`** (pure-Python; `nc` is unreliable on the t530):
  `python3 ipsctl.py CONTROL:DETECT:ON|OFF`, `CONTROL:ML:OFF|OBSERVE|AUTHORIZE[:thr]`,
  `CONTROL:ML:FLAG:<x>`, `CONTROL:ML:BLOCK:<x>`, `CONTROL:ML:STATS`, `CONTROL:CLEAR[:ip]`,
  `CONTROL:UNBLOCK:<ip>`, `CONTROL:ROTATE:<file>`. Also `REGISTER:`, `ATTACK_START/STOP`,
  `LABEL_OVERRIDE`, `MININET_EVENT`. Topology helpers: `py net.detect_on/off(net)`,
  `py net.register_iot_device(...)`, `py net.run_attack_session(net,'<kind>')`.
- **Modes:** DETECT OFF/ON (capture-only vs label+rate/DAI); ML OFF/OBSERVE/AUTHORIZE
  (idle / log-only / blocking). OBSERVE is for verifying accuracy before authorizing blocks.
- **REST API (`IPSRestController`, :8081):** `GET /` (serves the dashboard), `/ips/status`,
  `/ips/metrics` (per-attack + per-tier counts, confirmed attackers, **psutil CPU/RAM/disk**),
  `/ips/alerts`, `/ips/blocked`, `POST/DELETE /ips/block`. Integration point for SIEM/SOAR.
- **Dashboard:** `Dashboard/index.html` (vanilla JS + SVG, no CDN) — status, threat level,
  per-tier tiles, attack bar-chart, blocked table + Unblock, event timeline, t530 health.

---

## 7. Data collection pipeline (`SDN Topology/topology.py` + `Controller/*`)
- One-command automated capture: `py net.run_full_collection_hy(net)` (1 normal + 6 attack
  sessions) or hands-free `sudo AUTO_COLLECT=1 CONTROLLER_IP=<t530> python3 topology.py`.
- **Flow-collapse fix:** floods use **concurrent multi-target** from 6 sources (register
  TempSensor+Cam) → ~5× rows so minority classes aren't starved.
- **Session-boundary reset:** each session sends a global `CONTROL:CLEAR` so a prior session's
  confirmed attacker doesn't bleed its label into the next (the validator flagged this as
  sticky-confirm RATE BLEED).
- **Merge/validate/salvage:** `dataset_merge.py` (hard 102-col schema guard, strips meta →
  `_training.csv`), `validate_dataset.py` (protocol/rate label-integrity), `fix_label_bleed.py`
  (relabel cross-type bleed back to normal without recapture).

---

## 8. Deployment notes (t530)
- Snort 3 **built from source** (`/usr/local/bin/snort`; apt = v2, wrong).
- Ryu 4.34 on **Python 3.10** needs: patch `ryu/app/wsgi.py` (`ALREADY_HANDLED = []`),
  `dnspython>=2.6`, `eventlet 0.41`, and the `collections.MutableMapping` shim in the launch line.
- `psutil` for the dashboard health panel. nginx holds :8080 → controller on **:8081**.
- Graceful degradation: a missing model file or dep disables only that tier; the rest run.

---

## 9. New/important code files (quick index)
| File | Role |
|---|---|
| `Controller/Controller_main_Claude.py` | merged controller (switch + Snort + RF + AE + DAI + REST/dashboard + UDP control) |
| `Controller/traffic_capture.py` | packet_in → 5s windows → 102 features → dataset.csv + live inference feed |
| `Controller/snort_monitor.py` | Snort 3 launch + alert_json parse + (GID,SID) noise suppression |
| `Controller/ml_inference.py` | Random Forest engine (Tier 3) |
| `Controller/ae_inference.py` | Autoencoder engine (Tier 4), pure-NumPy |
| `Controller/ml_models/build_ae_bundle.py` | rebuild `ae_bundle.joblib` from a trained `.h5` + CSV |
| `Controller/ipsctl.py` | UDP-9999 control command sender |
| `Controller/dataset_merge.py` / `validate_dataset.py` / `fix_label_bleed.py` | dataset merge / validation / mislabel salvage |
| `Dashboard/index.html` | operator dashboard (served at `:8081/`) |
| `SDN Topology/topology.py` | Mininet-WiFi lab + automated attack/collection helpers |
| `PROJECT_EXPLAINER.md` | full A-Z developer + business explanation |
| `t530_full_system_runbook.md` | run + ML/AE test runbook (with data-flow gates) |
| `Chapter4_figure_capture_guide.md` | how to capture the 21 thesis figures |
