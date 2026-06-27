# Adaptive IPS for IoT in SD-WAN — Project Documentation

*What was built, why, and how it would live in a real Security Operations Center. This is the
narrative/engineering record behind the code; the operational steps live in
`t530_full_system_runbook.md` + `Controller_main_test_guide.md`, and the full technical
reference in `context_claude.md`.*

---

## 1. Objective
A layered, **adaptive Intrusion Prevention System** for IoT devices on an SD-WAN, deployable on a
**single low-power thin client (HP t530, 8 GB)** as the SDN controller. It must *detect and
actively block* the common IoT/SDN attacks — ICMP/SYN/UDP floods, Nmap port scans, ARP
spoofing, and control-plane saturation — and also flag **unknown/zero-day** behaviour, without a
human watching a console.

## 2. Architecture — four concurrent detection tiers
Traffic from a Mininet-WiFi topology (Open vSwitch `s1`/`ap1`) is mirrored to the controller; the
Ryu controller (OpenFlow 1.0 learning switch) runs all four tiers and enforces blocks inline via
OpenFlow DROP rules. **Block if *any* tier fires** (in AUTHORIZE mode):

| Tier | Engine | Catches |
|---|---|---|
| 1 | **Snort 3** signatures (`sdn_ips.lua`, curated rules) | known attack patterns (the 6 classes) |
| 2 | **Rate counters + Dynamic ARP Inspection** | volumetric floods / ARP spoofing by behaviour |
| 3 | **Random Forest** (supervised) | closed-world attack *classification* |
| 4 | **Autoencoder** (unsupervised, reconstruction error) | open-world **anomaly / zero-day** |

Tiers 3 and 4 run **concurrently per 5-second window** with **confidence banding**: below 60 %
the verdict is *silent* (no log, no action), a middle band *flags* (evidence captured, no block),
and a high band *blocks* (RF ≥ 0.80, AE ≥ 0.73). This banding is the core "adaptive + low-noise"
behaviour.

---

## 3. Work completed (engineering record)

**1. Feature-engineering rationale.** Defined a **102-column v2 feature schema** with a written
rationale for every feature group: per-flow volume/rate (pps, bps, packet sizes), TCP flag
counts (SYN/ACK/FIN/RST), port-diversity and scan signals (`unique_dst_ports`,
`sequential_port_score`), inter-arrival timing/burstiness, session-completion ratios, entropy
features (payload, src-port, ICMP-type), **device-level** behavioural baselines, **network-level**
context, ARP-specific features (gratuitous/unsolicited/binding-changes), and Snort-alert features.
A key principle was **leakage avoidance**: `meta_*` columns (window id, device name, attack tool,
controller load, etc.) are *audit-only* and **stripped from the training file** so the model can't
cheat off collection artefacts.

**2. Feature extraction from live Mininet traffic.** Implemented `traffic_capture.py` to compute
those 102 features **per 5-second window, per flow key `(src, dst, dst_port, proto)`** from the
mirrored data plane, emitting one labelled row per flow/window into `dataset.csv`. This is the
bridge from raw packets to ML-ready rows, and it doubles as the live inference feed for Tiers 3/4.

**3. Snort 3 signature tier.** Curated `sdn_ips.lua` + local rules detecting exactly the 6 attack
classes (rate-filtered flood/scan rules + the `arp_spoof` and `port_scan` inspectors), consumed
via `alert_json`. Added a **precise (GID,SID) noise-suppression** layer so mirror artefacts (PAWS
re-ordering, broadcast decoder events, gratuitous ARP) don't pollute the console or the labels.

**4. Rate-counter + DAI tier.** Per-host sliding counters confirm a flood/scan only after N
consecutive windows over threshold (suppresses one-off spikes); DAI catches ARP spoofing by
MAC↔IP binding changes — independent of Snort.

**5. Random Forest (Tier 3).** A scikit-learn + **imbalanced-learn** pipeline
(`rf_pipeline.joblib`) classifying each window into the attack classes, pinned to sklearn 1.6.1.

**6. Autoencoder (Tier 4).** Re-implemented the trained Keras autoencoder as a **pure-NumPy
bundle** (`ae_bundle.joblib`: weights + scaler + threshold) so the thin client needs **no
TensorFlow** — it flags windows whose reconstruction error exceeds a learned threshold as
anomalies ("zero-day net").

**7. Controller integration.** Merged the data-plane controller and the REST IPS app into
`Controller_main_Claude.py`: OF 1.0 learning switch + traffic mirror, in-process Snort, both ML
tiers, IoT discovery, a **UDP 9999 control channel** (DETECT/ML mode, label override, rotate,
clear), and a **WSGI REST API on :8080** (`/ips/block`, `/ips/blocked`, `/ips/switches`,
`/ips/status`) for external/automated control — the integration point for a SOC.

**8. SDN topology & transport.** Mininet-WiFi topology (stations, hosts, IoT `TempSensor`/`Cam`,
AP, switch) with OVS mirroring to the controller, plus a **VXLAN `br-snort` bridge** so Snort sees
the full data plane across machines (with a bridge-free OpenFlow-TAP fallback).

**9. Dataset pipeline.** One-command **automated high-yield collection** (`run_full_collection_hy`
/ `AUTO_COLLECT`) using concurrent multi-target floods from 6 sources to defeat "flow collapse"
(thin flood classes); **top-up** for under-represented classes; **schema-guarded merge +
validation** (`dataset_merge.py`, `validate_dataset.py`); a **label-integrity validator** that
flags protocol/rate "bleed"; and a fix + salvage for **cross-session sticky-confirmation
mislabels**. Class imbalance is handled at *training* time (SMOTE + class weights), not by
deleting data.

**10. Thin-client deployment.** Static-IP/bridge setup, Snort 3 **built from source** (not the
apt v2), and a **Python 3.9** runtime (deadsnakes) so sklearn 1.6.1 + Ryu coexist on Ubuntu 20.04.

**11. Operator dashboard (this folder).** A dependency-free web view that replaces the flooded log
with current state: modes, threat level, per-tier activity, attack breakdown, blocked hosts (with
unblock), a deduped event timeline, and t530 resource health.

---

## 4. Deploying in a SOC (Security Operations Center)

**Where it sits.** This system is a **distributed network sensor + inline enforcement point** for
the IoT/SD-WAN edge. Unlike a passive IDS, the SDN controller can **block in the data plane**
(OpenFlow DROP) the moment any tier confirms — so it is simultaneously the *detection sensor* and
the first *automated response*. In a SOC topology you would run one instance per SD-WAN site /
IoT segment (it's light enough for a thin client at remote sites) reporting to a central SOC.

**Integration with the SOC stack.**
- **→ SIEM** (Splunk / Elastic / Wazuh / QRadar): forward the labelled events and Snort
  `alert_json` as **syslog/CEF/JSON** for correlation across sites, long-term retention, and
  cross-source detection. The per-window labelled rows are already structured for this.
- **→ SOAR**: the inline OpenFlow block is effectively an *automated containment playbook*
  already; the `/ips/block` REST API lets a SOAR tool push or release blocks as part of a wider
  response (e.g., also disable a switch port or notify NAC).
- **Tier-1 view**: this dashboard is the at-a-glance console for the on-shift analyst — "what is
  attacking, which tier caught it, is it contained, is the box healthy" — without reading raw logs.

**Why it fits a SOC's biggest problems.**
- **Alert fatigue**: the 4-tier + confidence-banding design (silent < 60 %, dedup, aggregate)
  surfaces *confirmed* events, not a per-packet firehose — directly reducing noise that drowns
  analysts.
- **MTTR (mean time to respond)**: inline auto-block contains an attack in seconds, before a human
  triages — the response is co-located with detection.
- **Edge coverage**: runs on commodity/thin hardware at remote SD-WAN/IoT sites that can't host a
  heavyweight appliance.

**What a production SOC still needs around it (honest gaps).** This is a *sensor + local
enforcer*, not a full platform: it does **not** provide long-term log storage, multi-sensor
aggregation/correlation, threat-intel enrichment, case/ticket management, RBAC/multi-tenancy,
on-call alerting, or compliance reporting. Those are the SIEM/SOAR's job — this feeds them.

---

## 5. Comparison with existing solutions

| Solution | Detection | Zero-day | Inline block | SDN-native | IoT/edge focus | Footprint | Notes |
|---|---|---|---|---|---|---|---|
| **This project** | Signatures + rate/DAI + **RF + AE** (4 tiers) | **Yes** (AE) | **Yes** (OpenFlow) | **Yes** | **Yes** | **Thin client** | layered + confidence-banded; lab-trained |
| Snort 3 (alone) | Signatures (+inspectors) | No | Yes (inline mode) | No | Partial | Low | the Tier-1 we build on |
| Suricata | Signatures, multi-threaded, some anomaly | Limited | Yes | No | Partial | Medium | faster Snort-alternative |
| Zeek (Bro) | Network analytics / scripting | Behavioural | No (monitor) | No | Partial | Medium | rich logs, not a blocker |
| NGFW/NGIPS (Palo Alto, Cisco Firepower, Fortinet) | Sig + ML + threat-intel | Yes | Yes | No | Some | Appliance | powerful, **costly**, not SDN-controller-native |
| SIEM + EDR (Splunk, Elastic, Wazuh) | Correlation/analytics | Some | No (orchestrates) | No | No | Heavy | the *platform* we'd feed, not a sensor |
| Academic ML-NIDS (CICIDS-trained, etc.) | ML classifier | Varies | Usually offline | Rarely | Sometimes | Varies | often detection-only, not deployed inline |

**What differentiates this work.**
- **SDN-native inline response** — detection and OpenFlow enforcement in one controller; most
  IDS/ML-NIDS only *detect*, and NGFWs aren't SDN-controller-native.
- **Layered supervised + unsupervised** — RF (known attacks) *and* an autoencoder (zero-day) run
  concurrently with confidence banding, rather than relying on a single model or signatures alone.
- **IoT-in-SD-WAN scope on a thin client** — runs where a full appliance won't, with IoT-aware
  device baselining and ARP/DAI for the IoT threat model.

**Honest limitations.** Models are trained/validated on **self-generated Mininet lab data** (not
production traffic), so generalisation to real networks is unproven; the signature set covers the
**6 target classes**; there is **no encrypted-traffic analysis**, **no external threat-intel
feed**, and a **single controller** (scalability/HA not yet addressed); the AE needs ongoing
false-positive tuning. It is a research prototype, not a hardened product.

## 6. Future work
Real-traffic validation and online learning; HA/clustered controllers; richer signature/inspector
coverage; encrypted-flow features; SIEM/SOAR connectors (CEF/syslog out-of-the-box); and promoting
the dashboard's metrics endpoints to a first-class, authenticated API.
