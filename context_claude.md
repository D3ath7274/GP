# Project Context — Adaptive IPS for IoT in SD-WAN

*Single reference of everything known about this project and codebase, for fast
re-onboarding (human or AI). Last updated alongside the autoencoder Tier-4 integration.*

---

## 1. Goal & security posture
- **Adaptive IPS for IoT devices in an SD-WAN**, deployable **controller-only on an HP
  t530 thin client (8 GB RAM)**.
- **Posture:** *approach zero false negatives, tolerate false positives.* A wrongly
  blocked host can be admin-unblocked, so we spend FP budget to buy recall.
- Attackers appear as **authorized hosts** (no device excluded) → detect infected
  devices, malware spread, post-breach lateral movement.

## 2. Testbed / architecture (two VMs on one LAN)
**STATIC IPs (install runbook `SDN_IPS_Snort_Installation_Runbook.pdf`):** controller VM
= **192.168.1.200**, mininet VM = **192.168.1.201**, external test machine = 192.168.1.202.
`topology.py` `CONTROLLER_IP` defaults to `192.168.1.200` (override via env `CONTROLLER_IP`).
- **VM2 — Topology (192.168.1.201):** Mininet-WiFi (`SDN Topology/topology.py`), Open
  vSwitch `s1`, access point `ap1`. Hosts: `sta1` 10.0.0.1, `sta2` 10.0.0.2 (Wi-Fi,
  MACs 42:00:00:00:00:00 / :01:00), `h1` 10.0.0.3, `h2` 10.0.0.4 (wired; **h2 = HTTP +
  iperf server**), IoT `TempSensor` 10.0.0.5, `Cam` 10.0.0.6 (registered by IP).
- **VM1 — Controller (192.168.1.200):** Ryu (`Controller/Controller.py` or
  `Controller_main_Claude.py`, **OpenFlow 1.0**), Snort 3, `traffic_capture.py`,
  `ml_inference.py` (RF), `ae_inference.py` (AE).
- **Channels:** OpenFlow **TCP 6633** (control plane); out-of-band **UDP 9999**
  (REGISTER / CONTROL / ATTACK_START-STOP).
- **Two Snort mirror paths (choose one):**
  1. **OpenFlow TAP (default in code):** every data-plane packet → `OFPP_CONTROLLER`
     (max_len 0xffff) → injected into TAP `snort_tap`; Snort watches `ens33` + `snort_tap`.
     The TAP path **doubles** raw packet/byte counts (ratios/entropy immune; raw PPS ~2×).
  2. **Permanent VXLAN `br-snort` bridge (install runbook, now the deployed path):** the
     mininet VM's OVS mirrors `s1` (VXLAN key 100) + `ap1` (key 101) to the controller's
     `br-snort`; the controller `tc`-mirrors `ens33` ingress into `br-snort` too. Made
     permanent via systemd: `br-snort.service` (controller) + `mininet-snort-mirror.service`
     (mininet VM). Snort then watches `ens33` + `br-snort`. Select it on the merged
     controller with env `SNORT_IFACES=ens33,br-snort` + `IPS_NO_TAP=1`.
     **This bridge must be replicated on the HP t530 (see `t530_bridge_setup.md`).**

## 3. Detection tiers — "block if ANY tier fires"
| Tier | Catches | File / artifact | Runtime deps | Bands |
|---|---|---|---|---|
| 1 Snort signatures | the 6 known attacks | `snort_monitor.py` + `snort3/sdn_ips.lua` | Snort 3 (else 2.x fallback) | signature match |
| 2 Rate counters + DAI | floods/scans + ARP spoof | `traffic_capture.py` | none | consecutive-window confirm |
| 3 Random Forest | *names* the 6 attacks | `ml_models/rf_pipeline.joblib` via `ml_inference.py` | scikit-learn 1.6.1 | flag 0.80 / block 0.90 |
| 4 Autoencoder | anomaly / unknown / zero-day | `ml_models/ae_bundle.joblib` via `ae_inference.py` | **pure NumPy** | flag 0.60 / block 0.73, silent <0.60 |

- **The 6 attacks:** ICMP Flood (`hping3 --icmp --flood`), SYN Flood (`hping3 -S --flood
  -p 80`), UDP Flood (`hping3 --udp --flood -p 53`), Port Scan (`nmap -sS -p 1-1000`),
  ARP Spoofing (`arpspoof`), Control Plane Saturation (`hping3 --udp --flood -p ++1`).
- **RF vs AE are CONCURRENT** (both score every `label==0` window row). RF = closed-world
  (known types); AE = open-world (zero-day net). Most-severe action wins.
- **DETECT gate:** `DETECT OFF` → `_compute_label` returns `normal` for all flows, but the
  ML hook still runs → RF+AE score **every** flow = the **pure-ML test mode**. `DETECT ON`
  → rate/DAI/Snort label first and the ML hook skips `label!=0` rows ("shadowing").

## 4. Feature engineering
- `traffic_capture.py` aggregates packet-ins into **5-second windows per flow key
  `(src_ip, dst_ip, dst_port, protocol)`** → **102-column row** (94 after meta strip).
- Groups: timing (`inter_arrival_cv`…), asymmetry/reply, TCP session, entropy, port
  behaviour, **device-relative deviation** (zero-day basis), network-level, ARP/DAI,
  broadcast/multicast, labels, meta. Doc: `feature_engineering_rationale_cited.md`.
- **`IPS_V2_FEATURES=1` is REQUIRED at launch** — only then does it emit the v2 schema
  (`traffic_capture.py:~509`). Log must read `Feature schema mode: v2 (corrected)`.
- **Feature counts:** RF uses **66** (drop-9 → one-hot protocol → scale(86) → select 66);
  AE uses **60** (its own drop list, see §6). 102 = full schema; 94 = meta-stripped.
- **Flow collapse:** rows = (concurrent flow keys) × (windows), NOT packet volume. A 1:1
  flood = 1 row/window → flood classes are row-thin.

## 5. The models
### Random Forest (Tier 3)
- `ml_models/rf_pipeline.joblib` = end-to-end sklearn Pipeline `[RFPreprocessor →
  RandomForestClassifier]`, **string** classes. Config: `n_estimators=200, max_depth=25,
  min_samples_leaf=2, class_weight='balanced'`, SMOTE on train fold. 20-fold CV
  macro-F1 = **0.9349**.
- `ml_inference.py`: `predict/predict_batch/get_stats/is_loaded`; **label 0=normal /
  2=attack**; confidence = `max(predict_proba)`. Prefers `rf_pipeline.joblib`, falls back
  to `rf_model.joblib` (bundle). `verify_inference.py` gates train/serve skew (must = 100%).
- `RFPreprocessor.transform` returns a **named DataFrame** (not `.values`) + a module-level
  `warnings.filterwarnings` — fixes the "X does not have valid feature names" spam (benign;
  flooded only with DETECT OFF since the RF then scores every flow).

### Autoencoder (Tier 4) — NEW, wired in
- `ml_models/ae_bundle.joblib` (pure NumPy; no TF, no sklearn). Keys: `features`(60),
  `mean`, `scale`, `threshold`=0.0375, `layers`(`60→64→32→64→60`, relu/relu/relu/linear).
- `ae_inference.py`: vectorize (one-hot protocol → reindex to 60 features → `(x-mean)/scale`)
  → NumPy forward → `error = MSE(in, recon)` → `conf = error/(error+threshold)` (0.5 at
  threshold) → `is_anomaly = error > threshold`. Disables gracefully if the bundle is absent.
- Source model: `ml_models/anomaly_detection_autoencoder_model.keras(.zip)` (Keras v3 =
  config.json + model.weights.h5) from `ml_models/Untitled5.ipynb`. Trained on **normal
  rows only** of `dataset_v2_master_training.csv`; threshold = p95 of normal recon error.
- **Bundle was rebuilt locally** (h5py weights + scaler/features/threshold re-derived from
  the CSV) and **validated**: p95≈0.0347 vs the notebook's 0.0375; via the engine,
  **normal mean-conf 0.16, attack 0.73, ~47% of attack windows ≥0.73**.
- **Quirk:** the notebook's `get_dummies` also one-hot'd `attack_type` → a constant
  `protocol_normal` feature. Harmless during DETECT-OFF testing; clean at next retrain.

## 6. AE feature drop lists (to reproduce the 60-feature set)
From `dataset_v2_master_training.csv`, normal rows only:
- **Drop set 1 (ids/leakage, 9):** timestamp, src_ip, dst_ip, src_port, dst_port,
  top_dst_port, snort_sid, active_snort_alerts, distinct_alert_types.
- **Drop set 2 (~27):** incomplete_ratio, packets_per_second, total_bytes,
  device_pkt_rate_deviation, is_broadcast_dst, arp_reply_request_ratio,
  device_byte_rate_deviation, arp_gratuitous_count, inter_arrival_std, is_registered_iot,
  ip_mac_binding_changes, rst_count, arp_unsolicited_count, well_known_port_ratio,
  burst_duration_avg, broadcast_ratio, arp_reply_rate, burst_count, psh_count,
  device_unique_dst_ips, mac_ip_binding_changes, device_avg_byte_rate, device_age_seconds,
  network_avg_flow_duration, inter_arrival_max, dst_port_std, inter_arrival_min.
- Then drop `label`, `attack_type`; `pd.get_dummies(prefix='protocol')`; `StandardScaler`.
- Note it **excludes raw volume** (good for surge-tolerance) but also drops several
  **device-relative** features (revisit on retrain).

## 7. Operator control channel (UDP 9999)
- `CONTROL:DETECT:ON|OFF` — enable/disable labeling+blocking (capture-only when off).
- `CONTROL:ML:OFF|OBSERVE|AUTHORIZE[:thr]|STATS` — OFF (no ML); OBSERVE (predict+log, no
  block; RF logs every non-normal verdict, AE logs only conf≥0.60); AUTHORIZE (block).
- `CONTROL:ML:FLAG:<thr>` / `CONTROL:ML:BLOCK:<thr>` — tune RF bands live.
- `CONTROL:CLEAR[:ip]` — release detection state (collection; 30 s drain cooldown per IP).
- `CONTROL:ROTATE:<file>[:type]` — save `dataset.csv` under name + auto-run
  `validate_dataset.py` (logs PASS/ISSUES). Names starting `_` = discard (no validate).
- `CONTROL:UNBLOCK:<ip>` → `manual_unblock`. `LABEL_OVERRIDE:ip:type`. `ATTACK_START/STOP`.
  `REGISTER:NAME:name:ip` / `REGISTER:IOT:ip:type`.
- AE bands live on the controller: `_ae_flag_threshold=0.60`, `_ae_block_threshold=0.73`
  (no live command yet; edit in `Controller.py`).

## 8. Data collection tooling (`topology.py`, run from `mininet-wifi>` via `py net.…`)
- `run_full_collection(net)` — 7 sessions (normal + 6 attacks), **sequential single-target**
  → thin floods. Original automatic collector.
- `run_full_collection_hy(net)` — **NEW**, one command: normal + 6 attacks using
  **concurrent multi-target floods** (~5× rows on flood classes). Use this for fresh data.
- `run_topup_session(net, kind, rotate_as=…)` — one class, concurrent multi-target.
- `run_full_topup(net)` — automated top-up of the thin classes (udp/icmp/syn/arp).
- Helpers: `launch_attack`, `launch_attack_multi`, `run_attack_session`, `wait`,
  `detect_on/off`, `_bump_conntrack` (raises `nf_conntrack_max` — floods overflowed it).
- During collection: **ML OFF**, **DETECT ON only labels** (never blocks); each session
  saved + validated via `CONTROL:ROTATE`. Background traffic must run ≥180 s so device
  baselines mature (`is_baseline_mature`).
- **Merge:** `dataset_merge.py <sessions…> --output master.csv` (hard 102-col guard) →
  master + `_training` (meta-stripped). Append new sessions to the existing master to grow it.

## 9. Datasets
- **`ML dataset/dataset_v2_master.csv` (and `new dataset for verification/`):** 19,532 rows,
  7 classes. normal 17,189 · CPS 1,683 · Port Scan 259 · **ICMP 153 · UDP 96 · SYN 85 ·
  ARP 67** (the thin flood classes). `dataset_v2_master_training.csv` = 94 cols (meta-stripped).
- Plan: collect more (high-yield), merge into a **bigger master**, retrain RF + AE.

## 10. Snort
- Controller VM currently runs **Snort 2.x** → `snort_monitor.py` auto-falls back to
  `/etc/snort/snort.conf` + `alert_fast` (noisy community rules, e.g. SID 469). Works for
  collection (labels via canonical guard + rate/DAI).
- **Snort 3 schema (in repo, preferred):** `snort3/sdn_ips.lua` + `sdn_ips_local.rules` —
  ICMP `SID 1000001`, SYN `1000002`, UDP `1000003`, CPS `1000004`; **Port Scan** =
  `port_scan` inspector (GID 122); **ARP** = `arp_spoof` inspector (GID 112). Install via
  `scripts/install_snort3_ips_config.sh`; `snort_monitor.py` detects Snort 3 → uses the lua
  + `alert_json`. **Needs the Snort 3 binary installed** (then `snort -V` reports v3).
- **Friend's standalone IPS** (separate flow, NOT the team path): `ryu_ips_app.py` (OF1.3 +
  REST block), `snort_ryu_bridge.py`, `snort_alert_reader.py`; blocks inside hosts via
  OpenFlow DROP and outside IPs via iptables. Documented in `docs/SNORT_RYU_INTEGRATION.md`.

## 11. Known issues solved / gotchas
- **sklearn feature-names warning** — RFPreprocessor passed a bare array; fixed (DataFrame
  + warnings filter). Floods only under DETECT OFF (RF scores every flow). The backup's
  RF joblib lacks `feature_names_in_` so it never warned.
- **nf_conntrack table full** during floods → dropped packets; `_bump_conntrack` raises the
  limit (1,048,576).
- **DETECT OFF but Snort still alerts** — Snort is a separate process; alerts are
  informational and do NOT label flows when DETECT is off. Harmless.
- **Python/deps** — Ryu is pinned to its install's python; **do NOT repoint system python**
  (broke `ryu-manager`). RF needs **Python ≥3.9 + scikit-learn==1.6.1, pandas<2.3,
  numpy<2.3, joblib** in **Ryu's** interpreter. **AE needs none of these (pure NumPy).**
- **Label-integrity fixes (collection):** decay/miss-tolerance on the confirm counter;
  `CONTROL:CLEAR` + 30 s drain cooldown; protocol-guarded label inheritance; 7 s flush-grace
  before clear. SYN-session bleed went 96.5% → ~0.1%.
- **"ML did nothing during a SYN flood"** — RF skips `label!=0`, so DETECT ON shadows it;
  DETECT OFF lets the RF/AE score everything (pure-ML test).
- **`run_full_collection` died mid-session-6 once** — likely OOM/conntrack; `run_full_collection_hy`
  + conntrack bump address the row-yield + drop issues.

## 12. t530 deployment constraints
- 8 GB RAM, controller-only. Launch `sudo IPS_V2_FEATURES=1 ryu-manager Controller.py`.
- RF: `scikit-learn==1.6.1` (+pandas<2.3/numpy<2.3/joblib) **in Ryu's interpreter**. AE:
  **no TensorFlow, no sklearn** (pure NumPy). Window compute must stay **< 5000 ms** under flood.
- Staged go-live: capture-only → OBSERVE → AUTHORIZE (conservative bars). Rollback =
  `CONTROL:ML:OFF` + `CONTROL:DETECT:OFF`.

## 13. Repo layout & branches
- **Main working repo:** project root (`GP/`) — has the Snort 3 integration, high-yield
  collection, the RF warning fix, and the **wired AE** (`ae_inference.py`, AE hook in
  `traffic_capture.py`, `Controller.py` wiring, `ml_models/ae_bundle.joblib`).
- **Backup:** `Backup/GP-4d943a4…/` (+ `.zip`) — pristine commit `4d943a4` (good for
  1-command collection + RF testing; **no Snort 3, no high-yield, no AE**). Kept untouched.
- **Branch:** `integrate-snort-ryu` (working); `main` = default. Commit messages end with
  the Co-Authored-By trailer.
- **Deploy note:** code lives here (Windows); the VMs/t530 are separate — `git pull` / scp
  to them, including `ml_models/*.joblib`.

## 14. Key code anchors (main repo)
- `Controller/Controller.py`: UDP handler `~:289`; `block_attacker` `~:531`;
  `_handle_snort_alert` `~:229`; RF+AE engine instantiation `~:186`; Snort config_path =
  `/etc/snort/sdn_ips.lua`.
- `Controller/traffic_capture.py`: 5 s flush + RF hook `~:1122`; **AE hook** right after
  (`[AE-OBSERVE]`); `manual_unblock` `~:1674`; `_v2_features` env gate `~:509`;
  `CANONICAL_ATTACKS` + `_attack_protocol_matches` `~:1829`.
- `Controller/ml_inference.py` (RF), `Controller/ae_inference.py` (AE).
- `SDN Topology/topology.py`: collection commands (§8); `_send_to_controller`, REGISTER.

## 15. Plan / doc index
- **`t530_Deployment_and_Test_Plan.md`** — staged deploy + test (lab→t530→real), AE wired.
- **`ml_test_and_t530_deploy_plan.md`** — quick test + t530 deploy step-by-step.
- `data_collection_plan.md` — full automatic collection + merge (Snort 3 activation in §0).
- `topup_collection_plan.md`, `topup_and_rf_test_runbook.md`, `rf_model_test_plan.md`,
  `live_ml_test_plan.md` — collection top-up + RF before/after testing.
- `system_flowchart.md` — full system flowchart (master + per-tier; Excalidraw-ready Mermaid).
- Background: `feature_engineering_rationale(_cited).md/.docx`, `anomaly_framework_plan.md`,
  `Autoencoder_Training_Plan.md`, `Final_Report_and_Autoencoder_Plan.md`,
  `V2_Dataset_Collection_Plan.md`, `Pipeline Retrain.md`, `accomplished.md`, `issues_solved.md`.

## 16. Open / future work
- Install the **Snort 3 binary** on the controller (then the 6-attack schema activates).
- **Retrain RF + AE on the bigger dataset** (after high-yield collection); rebuild
  `ae_bundle.joblib` (same format) and drop it in — no code change.
- Clean the AE **`protocol_normal`** feature artifact at retrain.
- Optional: operator-initiated **`CONTROL:BLOCK:<ip>`**; **CUSUM** low-and-slow on the AE
  error stream; real-data threshold re-baselining (Stage C).
