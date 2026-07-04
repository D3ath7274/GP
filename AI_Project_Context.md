# Comprehensive Project Context — SDN-based IoT IPS (current state)

**Purpose:** master context file for any LLM/AI agent. It reflects the **current** system (a
4-tier adaptive IPS with two ML models, a merged controller, REST API + dashboard, deployed on an
HP t530 thin client). It **supersedes** earlier descriptions that mention "3 tiers", "49 features",
"Z-score Tier 3", or IPs `.19/.26` — those are obsolete. It also **absorbs and replaces the old
`context_claude.md`** (now deleted): everything that file held — the two Snort mirror paths, the
br-snort/VXLAN bridge, AE feature-drop lists, feature counts, dataset row counts, solved-issue
notes, repo/branch layout, and code anchors — lives in §10–§17 below. Deeper narrative lives in
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

## 1A. System model & operation (thesis summary)

**System model.** The system is modelled as a software-defined network in which a logically
centralised controller mediates all data-plane forwarding for a set of IoT/edge devices. Formally
there are three planes: (i) a **data plane** of OpenFlow switches (Open vSwitch) to which end
devices — IoT sensors, cameras, wired/wireless hosts, and any external client reaching the network
through the gateway — attach; (ii) a **control plane** consisting of the Ryu controller that installs
forwarding rules and holds the global network view; and (iii) a **security/management plane** layered
onto the controller, comprising the four detection tiers, the policy/enforcement logic, and the
REST + dashboard interface. The trust model assumes the controller and switches are trusted, while
**any host — internal or external — is a potential adversary**; threats considered are the six
canonical attack classes (ICMP/SYN/UDP floods, connection-per-second exhaustion, port scanning, and
ARP spoofing) plus **unknown/zero-day** anomalies. Because every packet that crosses a
controller-managed switch is mirrored to the controller, the detection engine observes flows
regardless of whether the source is inside the SDN or an outsider transiting the gateway, making the
model applicable to generic networks (IoT, SD-WAN, campus/ATM) rather than a single testbed.

**System operation.** Operation follows a continuous *observe → decide → enforce* loop. (1) **Observe:**
each `packet_in` is aggregated by `traffic_capture.py` into 5-second per-flow windows and reduced to a
fixed feature vector — the *same* code path feeds both the recorded dataset and live inference, so
there is no train/serve skew. (2) **Decide:** every window is evaluated by the four tiers in parallel
— signature (Snort 3), rate/ARP-inspection counters, the supervised Random Forest (known classes),
and the unsupervised Autoencoder (open-world anomalies). Each tier emits a confidence, and outputs are
combined under a confidence-banding policy (*silent → flag → block*); a flow is actioned if **any**
tier crosses its block band. (3) **Enforce:** in `AUTHORIZE` mode the controller installs an
OpenFlow **DROP** rule against the offending source, cutting the attack at the ingress switch within
a fraction of a second; in `OBSERVE` mode the same decision is logged but not enforced, allowing
accuracy to be validated before authority is granted. Operators supervise and retune the system out
of band (UDP-9999 control channel + REST/dashboard), toggling detection, switching modes, adjusting
per-tier thresholds, and clearing or unblocking hosts — so the IPS is *adaptive*: its policy and
sensitivity change at runtime without restarting the control plane.

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
- **Dashboard:** `Dashboard/index.html` — **shadcn/ui design language** (zinc dark theme tokens,
  Card/Badge/Button/Progress/Table, lucide icons) implemented with **hand-written CSS + vanilla JS,
  zero dependencies** (no CDN, no build) so it renders offline/in any sandbox and is served by the
  controller at `GET /` unchanged. Panels: status bar (DETECT/ML mode, switches), threat level,
  KPI cards (attackers / alerts-60s / blocked), per-tier tiles (with loaded dots from
  `rf_loaded`/`ae_loaded`/`snort_running`), attacks-by-type bars, blocked table + Unblock, event
  timeline, t530 health (RAM/CPU/disk progress).

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
| `Controller/snort_alert_reader.py` | standalone Snort-3 alert-reader (tails `alert_json`, blocks via REST/iptables) — see §10 path B |
| `Controller/snort_ryu_bridge.py` | bridge :9000 → Ryu REST `/ips/block` (standalone path) |
| `Dashboard/index.html` | operator dashboard, shadcn/ui zero-dep (served at `:8081/`) |
| `SDN Topology/topology.py` | Mininet-WiFi lab + automated attack/collection helpers |
| `PROJECT_EXPLAINER.md` | full A-Z developer + business explanation |
| `t530_full_system_runbook.md` | **single end-to-end runbook**: install→run→test all tiers→dashboard→figures |
| `Chapter4_figure_capture_guide.md` | how to capture the 21 Ch.4 thesis figures |
| `Chapter5_results_outline.md` | Ch.5 results chapter outline + required-evidence map |
| `SDN_IPS_Snort_Installation_Runbook.pdf` | clean-machine install (deps, Snort 3 build, VXLAN br-snort, startup) |

---

## 10. Snort mirror paths + the standalone alert-reader pipeline (absorbed from context_claude.md)
Snort must *see* the data-plane traffic. There are two mirror paths and two ways to consume alerts.

**Mirror paths (how packets reach Snort):**
- **A — OpenFlow TAP (default in the merged controller):** the controller mirrors every packet to
  `OFPP_CONTROLLER` and injects into TAP `snort_tap`; select with `SNORT_IFACES=snort_tap`. Simple,
  single-machine; the TAP doubles raw packet/byte counts (ratios/entropy are immune).
- **B — Permanent VXLAN `br-snort` bridge (the team install runbook / two-VM path):** the Mininet
  VM's OVS mirrors `s1` (VXLAN key 100) + `ap1` (key 101) to the controller's `br-snort`; the
  controller `tc`-mirrors its ext iface into `br-snort`. Made permanent via systemd
  `br-snort.service` (controller) + `mininet-snort-mirror.service` (Mininet VM). Select with
  `SNORT_IFACES=ens33,br-snort` + `IPS_NO_TAP=1`. **Replicate on the t530 — see `t530_bridge_setup.md`.**

**Alert consumers (how a Snort alert becomes a block):**
- **Merged controller (team path, preferred):** `Controller_main_Claude.py` starts its **own** Snort
  via `SnortManager`, parses `alert_json` internally, and blocks via OpenFlow DROP. No reader/bridge
  needed.
- **Standalone reader (the friend's path, documented in `SDN_IPS_Snort_Installation_Runbook.pdf`):**
  a separate Snort 3 writes `/var/log/snort/alert_json.txt`; `snort_alert_reader.py` tails it and,
  for the canonical SIDs, POSTs to `snort_ryu_bridge.py` (:9000) which calls the Ryu REST
  `/ips/block`; **external** (non-`10.0.0.0/8`) attackers are blocked directly with `iptables`.
  `PROTECTED_IPS` = controller/Mininet/loopback. Use this path for explicit IDS-ALERT boxes and
  external-IP blocking; point its bridge at the merged controller's REST port if you run both.

**Two local-rules files exist — do not confuse them:**
- `Controller/snort3/sdn_ips_local.rules` (repo, **canonical 6-attack project schema**):
  ICMP `1000001`, SYN `1000002`, UDP `1000003`, CPS `1000004`; Port Scan = `port_scan` inspector
  (GID 122), ARP = `arp_spoof` inspector (GID 112). `snort_monitor.classify_attack()` maps each
  `msg` to a canonical class so the controller labels+blocks correctly.
- The PDF install runbook lists a slightly different teaching set (adds SSH-bruteforce `1000003`,
  Ryu-REST-flood `1000005`; "text rules: 5"). The repo file is authoritative for the ML/labeling
  pipeline; install the **repo** `.rules` for project tests.

## 11. Feature counts & AE drop lists (reproducing the 60-feature AE set)
- 102 = full v2 schema; **94** after meta-strip; **RF uses 66** (drop-9 → one-hot protocol →
  scale(86) → select 66); **AE uses 60** (own drop list below). `IPS_V2_FEATURES=1` is REQUIRED at
  launch or the v2 schema isn't emitted (`traffic_capture.py:~509`; log: `Feature schema mode: v2 (corrected)`).
- AE drop set 1 (ids/leakage, 9): timestamp, src_ip, dst_ip, src_port, dst_port, top_dst_port,
  snort_sid, active_snort_alerts, distinct_alert_types.
- AE drop set 2 (~27): incomplete_ratio, packets_per_second, total_bytes, device_pkt_rate_deviation,
  is_broadcast_dst, arp_reply_request_ratio, device_byte_rate_deviation, arp_gratuitous_count,
  inter_arrival_std, is_registered_iot, ip_mac_binding_changes, rst_count, arp_unsolicited_count,
  well_known_port_ratio, burst_duration_avg, broadcast_ratio, arp_reply_rate, burst_count, psh_count,
  device_unique_dst_ips, mac_ip_binding_changes, device_avg_byte_rate, device_age_seconds,
  network_avg_flow_duration, inter_arrival_max, dst_port_std, inter_arrival_min.
- Then drop `label`, `attack_type`; `get_dummies(protocol)`; `StandardScaler`. The set **excludes
  raw volume** (surge-tolerant) but also drops several device-relative features (revisit on retrain).
  Notebook quirk: `get_dummies` also one-hot'd `attack_type` → a constant `protocol_normal` feature;
  `ae_inference._vectorize` forces it to 1.0 to match training. Clean this at the next retrain.

## 12. The 6 attacks (exact generators) + concurrency model
- ICMP `hping3 --icmp --flood`; SYN `hping3 -S --flood -p 80`; UDP `hping3 --udp --flood -p 53`;
  Port Scan `nmap -sS -p 1-1000`; ARP `arpspoof`; CPS `hping3 --udp --flood -p ++1` (incrementing
  dst ports → distinguishes it from UDP-flood-on-53).
- **RF and AE score CONCURRENTLY** on every `label==0` window row (RF = closed-world named class;
  AE = open-world anomaly). Most-severe action wins.
- **DETECT gate:** OFF → `_compute_label` returns normal for all flows but the ML hook still runs →
  RF+AE score **every** flow (pure-ML test mode). ON → rate/DAI/Snort label first, ML skips
  `label!=0` rows ("shadowing", the deployed/layered behavior).

## 13. Datasets (current)
- `ML dataset/dataset_v2_master.csv`: 19,532 rows, 7 classes — normal 17,189 · CPS 1,683 ·
  Port Scan 259 · **ICMP 153 · UDP 96 · SYN 85 · ARP 67** (thin flood classes; hence high-yield
  concurrent collection). `_training.csv` variants are meta-stripped. Newer AE trained on
  `dataset_v4_master_training.csv`. Plan: keep growing the master, retrain RF + rebuild AE bundle.

## 14. Solved issues / gotchas
- **sklearn feature-names warning** — `RFPreprocessor` now returns a named DataFrame + a warnings
  filter (spam appeared only under DETECT OFF when RF scores every flow).
- **`nf_conntrack table full`** during floods → dropped packets; `_bump_conntrack` raises the limit.
- **AE "cannot reindex on duplicate labels"** (every row → AE scored nothing) — fixed in
  `_vectorize`: one-hot ONLY `protocol`, assemble vector by position (commit `eada0aa`).
- **OBSERVE log-flood froze the eventlet hub** — fixed: summary logging + `IPS_MAX_SCORE_ROWS` cap
  (loudest-first) + GIL yield every 16 rows (the t530 hang).
- **ML/AE silent** — almost always **no `packet_in`** (stale `CONTROLLER_IP` / switch not connected);
  `pingall` still works because OVS fail-mode forwards on its own. Verify `/ips/switches`=1 + growing
  `dataset.csv`.
- **Do NOT repoint system `python3`** (breaks `ryu-manager`/apt on the VMs). RF needs sklearn 1.6.1
  in **Ryu's** interpreter; AE needs only NumPy.
- **Snort 2 vs 3** — use `/usr/local/bin/snort` (apt installs v2, wrong). `apt install snort` is banned.

## 15. Repo layout & branches
- **Main working repo:** project root (`GP/`) — Snort 3 integration, high-yield collection, RF
  warning fix, wired AE, merged controller, shadcn dashboard.
- **Backup:** `Backup/GP-4d943a4…/` — pristine commit `4d943a4` (no Snort 3 / no high-yield / no AE).
  **Keep untouched** (apply fixes to the live repo, never the backup).
- **Branch:** work on `integrate-snort-ryu`; `main` is default; the t530 clones from `main`, so a fix
  only reaches it after a PR merge **and** a `git pull` on the t530. Commits end with the
  Co-Authored-By trailer.
- Code lives on Windows; VMs/t530 are separate — `git pull`/scp to them, **including `ml_models/*.joblib`**.

## 16. Key code anchors (merged controller)
- `Controller_main_Claude.py`: packet_in mirror `~:1128` (amplification guard right after); RF+AE
  engine instantiation + `controller=self` to TrafficCapture `~:149`; REST routes
  `IPSRestController` `~:1203–1318` (`/`, `/ips/status|metrics|alerts|blocked|switches`,
  `POST/DELETE /ips/block`); port-status logging demoted to debug `~:1173`.
- `traffic_capture.py`: `_flow_lock = threading.Lock()` `~:387`; real flush thread `~:607`;
  RF hook + AE hook (`[ML-OBSERVE]`/`[AE-OBSERVE]` summary logging) inside `_flush_flows`;
  `IPS_MAX_SCORE_ROWS` scoring cap; CSV write at end of `_flush_flows`.
- `ae_inference.py` (`score()` → `(is_anom, conf, error)`, conf=`error/(error+threshold)`);
  `ml_inference.py` (RF). `snort_monitor.py` (Snort 3 launch + `alert_json` + (GID,SID) suppression).

## 17. Open / future work
- Retrain RF + AE on the bigger dataset; rebuild `ae_bundle.joblib` (same format, no code change);
  clean the AE `protocol_normal` artifact. See `ml_ae_confidence_boost_plan.md` for the train/serve
  skew remediation if RF predicts `normal` on real attacks.
- Optional: operator-initiated `CONTROL:BLOCK:<ip>`; CUSUM low-and-slow on the AE error stream;
  real-data AE threshold re-baselining.

## 18. Enforcement, defence & confidence hardening (current)
This block records changes made after the merged-controller baseline. All verified with
`py_compile`; deploy = commit + `git pull` on the t530 + restart.

**AI confidence — retrain on v4 (RF drift fix).** Chapter 5 showed the deployed RF was trained
on **v2** but the live/eval data is **v4** (`dataset_v4_master_training.csv`, 110,839 rows, 7
classes — verified by `value_counts`), so recall on the minority flood/scan/spoof classes fell
(macro-F1 dropped from the 0.9349 20-fold CV to ~0.60 on the fresh v4 split; per-class precision
stayed high). Fix: **`Controller/ml_models/retrain_rf_v4.py`** — inherits the EXACT schema from the
deployed pipeline (11 drop cols, 86 one-hot cols, 66 selected cols, RF hyperparams
`n_estimators=200, max_depth=25, min_samples_leaf=2, class_weight=balanced`), re-fits only the
StandardScaler + RF on v4, and re-pickles `[RFPreprocessor → RF]` against `ml_inference.RFPreprocessor`
(module-level, so it loads on the controller). `--smote` optional. **Run on the training machine with
scikit-learn 1.6.1** (a newer sklearn pickle may not load on the controller's 1.6.1). AE side: re-run
`build_ae_bundle.py --csv …v4… --h5 autoencoder_tighter_bottleneck_16units.h5 --percentile <p>`;
lowering `--percentile` below 99 raises attack sensitivity/confidence (at some normal-FP cost). The
AE block band is also tunable **live** now — see below.

**Outsider defence (management plane).** OpenFlow DROP only stops traffic crossing an OVS switch; a
scan/flood aimed at the **controller's own NIC** (e.g. a Kali host on the LAN) bypasses the SDN.
Snort on the physical iface (`SNORT_IFACES=enp1s0,…`) sees it, and `_handle_snort_alert` now routes
**external** sources to a **host iptables DROP** (`_block_external_ip`, INPUT+FORWARD) instead of the
useless OpenFlow path. Guards: opt-in **`IPS_EXTERNAL_BLOCK=1`** (root + lock-out risk); whitelist =
`127.0.0.1`, `192.168.1.200/.201`, plus `IPS_MGMT_WHITELIST=<csv>`; `10.0.0.0/8` is never
iptables-blocked (that's OpenFlow's job). `_is_external_ip()` decides; `CONTROL:UNBLOCK:<ip>` removes
the iptables rule too (`_unblock_external_ip`). A Kali attack **through** the SDN (via
`net.expose_service`, §7/topology) still transits `s1` → all 4 tiers → OpenFlow DROP with the real
external IP. Defending the **Mininet VM's own** NIC needs a host firewall / the standalone
`snort_alert_reader.py` (its `PROTECTED_IPS` + external-IP iptables path) on that VM — the controller
can't firewall another host.

**Permanent blocks + real unblock.** Tier blocks are now **permanent** by default (OpenFlow DROP with
`hard_timeout=0`, `until=inf`); `IPS_BLOCK_SECONDS=<n>` restores timed blocks. Because they no longer
self-expire, UNBLOCK had to actually delete the rule: `_do_unblock_attacker` (deletes the dl_src
priority-65000 DROP) + a hub-safe `unblock_attacker` shim routed through `_block_q` (op-tagged;
`_block_worker` dispatches block/unblock). REST/UDP unblock both call it. **Rule: `CONTROL:CLEAR`
alone no longer lifts a DROP — use `CONTROL:UNBLOCK:<ip>`.**

**Snort gated by DETECT (not ML mode).** The Snort instant-block in `_handle_snort_alert` now checks
`self._detection_enabled` instead of `_ml_mode=='AUTHORIZE'`. So the tier-isolation matrix works:
`DETECT:OFF + ML:AUTHORIZE` = RF/AE only (Snort silent); `DETECT:ON + ML:OFF` = Snort/rate only;
`DETECT:ON + ML:AUTHORIZE` = full stack. DAI (ARP box) is detection-only — it logs + `record_alert`,
never blocks.

**New live controls (`ipsctl.py`).** `CONTROL:ML:RF:ON|OFF`, `CONTROL:ML:AE:ON|OFF`,
`CONTROL:ML:DEFER:ON|OFF` (AE stays silent on RF-known attacks), and
`CONTROL:ML:AE:BLOCK:<x>` / `CONTROL:ML:AE:FLAG:<x>` (tune the AE bands live — raise BLOCK ~0.85 to
suppress the known IoT-camera false positive while real attacks at ≥0.95 still block).

**New docs/scripts:** `retrain_rf_v4.py` (RF retrain), `demo_video_runbook.md` (90-s operational
video shot list), `Chapter5_figure_capture_runbook.md` (9-figure capture guide). `snort_ryu_bridge.py`
default REST URL corrected to `:8081` (was `:8080`=nginx) and now honours `RYU_API_URL`.
