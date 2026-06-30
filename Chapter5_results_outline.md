# Chapter 5 — Results and Analysis (outline + required evidence)

> Companion to `Chapter4_figure_capture_guide.md`. Chapter 4 (System Implementation) is
> assumed done; this chapter **proves the system delivers the solution promised in Ch.1–2**.
> Every subsection lists (a) what to write and (b) the **screenshot / figure / table** that
> backs the claim. Capture commands assume the t530 runbook environment
> (`t530_full_system_runbook.md`): controller on `:8081`, Mininet-WiFi topology VM as source.

The golden rule for a results chapter: **each thesis claim must map to one piece of measured
evidence.** Section 5.12 is that map — build the chapter so every row in it is backed earlier.

---

## 5.1 Introduction
- One paragraph: purpose of the chapter — empirically validate the four-tier hybrid IPS against
  the gaps identified in §2.5 (zero-day blindness, no integrated IPS, centralized bottleneck,
  no IoT-aware behavioral detection, slow response).
- State what is measured: per-tier detection quality, combined-system detection, real-time
  mitigation latency, resource cost on constrained hardware, and a comparative analysis.
- *No screenshot.*

## 5.2 Experimental Setup (brief recap — defer detail to Ch.4)
- Topology recap: Mininet-WiFi hybrid network (IoT sensors + user hosts) → OVS (OpenFlow) →
  Ryu controller (t530), VXLAN `br-snort` bridge feeding Snort 3, control channel UDP 9999.
- Hardware honesty note: thesis design targeted a Raspberry Pi 3; the **realized testbed runs on
  an HP t530 thin client (Ubuntu 22.04, Python 3.10)** — state this explicitly so the resource
  numbers in §5.8 are interpreted against the right platform.
- **Figure 5.1** — testbed/topology diagram (reuse Ch.3 Fig.27 or a photo of the t530 + a
  `sudo ovs-vsctl show` / `/ips/switches` screenshot proving the switch is connected).
- **Figure 5.2** — controller boot log screenshot showing all four tiers loading:
  `AE engine loaded … (60 features, threshold=0.482…)`, RF pipeline loaded, Snort started,
  `IPS_V2_FEATURES=1`. (Proves the full stack is live, not a subset.)

## 5.3 Evaluation Datasets
- Describe `dataset_v4_master_training.csv`: 102-column v2 schema (→ 60 model features after
  dropping meta/leakage columns), per-attack-class row counts, normal vs attack split.
- Explain the train/test methodology: stratified split, `random_state=42`; AE trained on
  **normal-only** (so attacks are genuinely unseen at AE training time).
- **Table 5.1** — dataset composition: rows per class (normal, ICMP/UDP/SYN flood, port scan,
  ARP spoofing, control-plane saturation, …). Screenshot of `value_counts()` or a notebook cell.
- **Figure 5.3** — class-balance bar chart (pre- and post-balancing/SMOTE if used).

## 5.4 Evaluation Metrics (definitions)
- Detection quality: Accuracy, Precision, Recall, F1, False-Positive Rate, ROC-AUC, PR-AUC,
  confusion matrix. Define each in one line (examiners expect formulas).
- Operational metrics: **detection-to-block latency** (ms), throughput (pps / Mbps the controller
  sustains), per-window compute time, CPU/RAM/disk on the t530.
- *No screenshot — this is the definitions section.*

## 5.5 Tier-by-Tier Results

### 5.5.1 Tier 1 — Signature Detection (Snort 3)
- Claim proven: **fast, accurate detection of *known* attacks** (§2.5.3 "signature for known").
- **Figure 5.4** — Snort alert fired on a known attack: screenshot of `/ips/alerts` feed (or the
  dashboard "Recent events" panel) showing SID, src→dst, attack_type during a scripted attack.
- **Table 5.2** — known-attack catalogue: attack launched → SID matched → detected? (yes/no).
- Note the deliberately-removed noise SIDs (PAWS 4, ARP 1, broadcast 414) to show tuning, not
  raw noise.

### 5.5.2 Tier 2 — Rate Counters + Dynamic ARP Inspection
- Claim proven: volumetric flood + ARP-spoofing detection independent of signatures.
- **Figure 5.5** — flood confirmation: log/dashboard showing a source crossing the rate threshold
  → `confirmed_attackers` increments → block. (Use the "Active attackers" KPI before/after.)
- **Figure 5.6** — ARP spoofing caught by DAI (MAC/IP binding violation log line).

### 5.5.3 Tier 3 — Random Forest (supervised behavioral)
- Claim proven: **behavioral classification** of flows beyond signatures.
- **Figure 5.7** — RF **confusion matrix** (test set) — the single most important ML figure.
- **Figure 5.8** — per-class Precision/Recall/F1 (sklearn `classification_report` screenshot or
  bar chart) + overall ROC curve with AUC.
- **Figure 5.9** — feature-importance plot (top ~15 features) — doubles as light explainability
  (addresses the §2.5.3 "explainability gap", honestly framed as feature attribution, not full XAI).
- **Figure 5.10** — live RF verdict during an attack: `[ML-OBSERVE] window: N flows scored —
  <attack>:N` summary line proving it scores real traffic, not just the offline test set.

### 5.5.4 Tier 4 — Autoencoder (anomaly / zero-day) — the headline result
- Claim proven: **detection of attacks the model was never trained on** (the §2.5.1 zero-day gap —
  "80% of breaches are zero-day").
- **Figure 5.11** — reconstruction-error histogram: normal (low, below threshold 0.482) vs attack
  (high, above) — the visual that justifies the threshold.
- **Figure 5.12** — AE ROC/PR curve + AUC on a **held-out attack class excluded from any training**
  (the explicit zero-day experiment — design it so one attack type is never seen by RF *or* the AE
  normal baseline, then show the AE flags it).
- **Figure 5.13** — live `[AE-OBSERVE] window: … max conf=… flagged=N` during that unseen attack,
  and the resulting `Anomaly (AE)` block. This is the proof that survives examiner scrutiny.
- **Table 5.3** — AE normal vs attack mean confidence (e.g. normal ≈ 0.16, attack ≈ 0.73).

## 5.6 Integrated Hybrid System Results (decision fusion)
- Claim proven: **hybrid signature + behavior** (§2.5.3 Problem 1) — block if ANY tier fires.
- Run a mixed scenario (known + unknown attacks + normal background) and report combined
  detection rate and FPR vs each tier alone — shows the union beats any single tier.
- **Table 5.4** — comparison: Snort-only / RF-only / AE-only / **Combined** → detection rate,
  FPR, missed classes. (The cell that proves "both, not either".)
- **Figure 5.14** — attacks-by-type panel of the dashboard after a multi-attack session.

## 5.7 Real-Time Mitigation and Enforcement
- Claim proven: **millisecond-level automated response** + **lateral-movement prevention**
  (§2.5.1 Problem 3, §2.5.4 Gap 3) — and that enforcement is at the OVS data plane, not manual.
- **Figure 5.15** — flow table *before* vs *after* a block: two `sudo ovs-ofctl dump-flows`
  screenshots, the second showing the high-priority drop rule for the attacker IP.
- **Figure 5.16** — detection-to-block latency: timestamp of detection log vs timestamp of the
  installed drop rule (and/or attacker's traffic stopping in a `ping`/`iperf` window). Report the
  measured ms and put N samples in **Table 5.5**.
- **Figure 5.17** — lateral-movement containment: attacker can no longer reach a second host
  after being blocked, while legitimate hosts keep communicating (split-terminal screenshot).

## 5.8 System Performance and Resource Efficiency (constrained hardware)
- Claim proven: runs on constrained/edge hardware (§2.5.3 Problem 3 scalability; Ch.3.4 RPi note).
- **Figure 5.18** — t530 resource usage under attack load: the dashboard "System health" panel
  (RAM/CPU/disk) **and/or** a `/ips/metrics` JSON screenshot during a flood.
- **Table 5.6** — sustained throughput (pps) and per-window compute time vs load; note the
  `IPS_MAX_SCORE_ROWS` cap and GIL-yield as the engineering that keeps the hub responsive.
- Discuss the documented data-rate ceiling (≈7 Mbps on RPi3 / measured value on t530) honestly.

## 5.9 Live Operations View (the dashboard)
- Claim proven: centralized **visibility** (§2.5.2 Gap 3, §2.5.4 — the "no visibility" gap).
- **Figure 5.19** — full dashboard screenshot at `http://<t530>:8081/` during an active attack:
  threat level UNDER ATTACK, tiers lit, blocked-hosts table populated, event feed scrolling.
- One paragraph: how an operator uses it (mode badges, Unblock button → `DELETE /ips/block/<ip>`).

## 5.10 Attack Scenario Walkthroughs (narrative validation)
- Reproduce the Ch.3.3.2 smart-factory scenario end-to-end as a timed sequence with evidence:
  1. compromised IoT sensor starts known-malware-pattern flow → Snort SID hit (Fig.5.4 style),
  2. controller installs drop rule (Fig.5.15), sensor isolated,
  3. an employee host then shows an *anomalous* (unseen) pattern → AE flags + quarantines,
  4. legitimate production traffic continues (iperf throughput unaffected).
- **Figure 5.20** — annotated timeline/sequence screenshot tying logs + dashboard + flow rules.

## 5.11 Comparative Analysis
- Validate the §2.5.5 gap table with *your measured* outcomes (turn the conceptual table into an
  evidenced one).
- **Table 5.7** — feature/capability comparison: Signature-only IDS · Anomaly-only IDS ·
  Commercial SD-WAN (no integrated IPS) · **This system**, across: zero-day detection,
  hybrid detection, IoT-aware, distributed enforcement, real-time auto-response, runs on
  constrained HW, open/programmable. Cite §2.4 references for the comparators; cite your own
  figures (5.7–5.18) for this system's column.

## 5.12 Discussion — claim → evidence map (put this table in the chapter)

| Thesis claim (Ch.1–2) | Evidence in Ch.5 | Verdict |
|---|---|---|
| Detects known attacks (signatures) | Fig.5.4, Table 5.2 | ✔ |
| Detects zero-day / unseen attacks | Fig.5.11–5.13, Table 5.3 | ✔ |
| Hybrid (signature **and** behavior) | Table 5.4 | ✔ |
| Real-time automated blocking (ms) | Fig.5.15–5.16, Table 5.5 | ✔ |
| Prevents lateral movement | Fig.5.17, §5.10 | ✔ |
| Centralized, programmable enforcement (Ryu/OVS) | Fig.5.15, §5.7 | ✔ |
| Runs on constrained/edge hardware | Fig.5.18, Table 5.6 | ✔ (with caveats) |
| Network-wide visibility | Fig.5.19 | ✔ |
| IoT-over-SD-WAN protection | §5.10 scenario | ✔ (emulated) |

## 5.13 Limitations and Threats to Validity (be honest — examiners reward this)
- **Emulated, not physical SD-WAN:** results come from Mininet-WiFi + OVS, not real MPLS/5G
  underlays or commercial CPE. The detection logic is transport-agnostic, but WAN-scale latency,
  multi-site overlay, and ZTP were not measured.
- **Train/serve distribution:** RF/AE trained on your own generated dataset; generalization to a
  different production network requires retraining the AE normal baseline.
- **Scope vs Ch.2 ambitions:** SASE/SSE, IPsec/TLS inspection, MUD profiles, and full **XAI/SHAP**
  were surveyed but **not implemented** — frame these as future work, not delivered results.
  (Feature importance in Fig.5.9 is partial explainability only.)
- **Throughput ceiling:** packet mirroring to the controller does not scale to core-link rates;
  state the measured ceiling and that sampled telemetry would be needed beyond it.

## 5.14 Summary
- Restate, in two paragraphs, that each §2.5 gap was addressed with measured evidence (point back
  to the §5.12 table), and what the numbers say about deployability on edge hardware.

---

## Quick capture cheat-sheet (commands → figure)
| Need | How to capture |
|---|---|
| Tiers loaded (Fig.5.2) | controller startup log — screenshot the AE/RF/Snort load lines |
| RF confusion/ROC/importance (5.7–5.9) | run the RF training notebook cells; screenshot plots |
| AE error histogram / ROC (5.11–5.12) | AE notebook (`Grad_Autoencoder_4.ipynb`) eval cells |
| Live ML/AE verdicts (5.10, 5.13) | `CONTROL:ML:OBSERVE` then read controller log summary lines |
| Flow rule before/after (5.15) | `sudo ovs-ofctl dump-flows <bridge>` x2 around a block |
| Latency (5.16) | diff detection-log timestamp vs flow-install timestamp |
| Resource use (5.18) | dashboard health panel or `curl http://<t530>:8081/ips/metrics` |
| Dashboard (5.19) | browser at `http://<t530>:8081/` during an attack |
| by_attack / blocked (5.14, 5.19) | dashboard panels after a multi-attack `run_topup_session` |
