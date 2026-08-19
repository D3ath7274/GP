# Session Handoff — 2026-08-19

Context carry-over for continuing this work in a new session. Written after a remote
Claude Code session (cloud container, fresh clone). Read this first, then
`AI_Project_Context.md` for the technical index.

---

## 1. What happened in that session

Four threads, in order:

1. Read `IPS_Project_Assessment_260816_102803.pdf` (an external assessment of the project —
   **not in this repo**, it was an uploaded file).
2. Analysed strengths/weaknesses for an **edge firewall deployment**.
3. **Updated `README.md`** — the only code/docs change made (commit `ccec2fb`).
4. Scoped a **new project phase**: turning the system into a plugin that auto-audits
   firewalls (Fortinet, Palo Alto, etc.), plus adding L7 / OT coverage.

---

## 2. Facts from the assessment PDF (authoritative — correct any contrary belief)

The assessment is of "Adaptive Multi-Tier IPS for IoT in SD-WAN", prepared 2026-08-15.

**⚠ "No train/serve skew" is listed as a STRENGTH, not a weakness.** Exact wording:
*"the same traffic-capture code produces both the training dataset and the live features —
structurally preventing a classic ML-ops failure mode."*
(Earlier in the session this was initially stated backwards and then corrected. The strength
reading is the correct one.)

The related weakness that DOES exist is different: models were trained on a **simulated
Mininet testbed** with a 2× mirror double-count, so they must be retrained on real traffic
or they false-positive on legitimate devices. That is a training-data realism gap, not skew.

**Assessment strengths:** layered defence in depth (4 tiers) · zero-day detection (AE on
normal-only) · SDN-native enforcement · agentless & IoT-appropriate · privacy-preserving (no
DPI) · no train/serve skew · graduated safe enforcement · concurrency-correct core (hub-safe
block queue vs eventlet) · adaptive/retrainable · low-cost commodity hardware.

**Assessment weaknesses:** placement & visibility limits (east-west blind; single-NIC t530
needs a 2nd port for true inline) · no L7 inspection · encrypted traffic opaque · trained on
simulated testbed · supervised-model/dataset dependence · adversarial robustness untested ·
single controller = SPOF · scale ceiling (SMB/branch) · legacy OpenFlow 1.0 · operational
fragility / manual MLOps.

**Maturity verdict:** strong research prototype / POC, roughly **TRL 4–5**. Commercial
category match: agentless IoT/IoMT NDR (Armis, Claroty/Medigate, Cynerio, Ordr).

**Top 3 readiness moves (from the assessment):**
1. Retrain on real traffic, validate in OBSERVE→AUTHORIZE before enabling blocking.
2. Add L7 coverage (WAF) + a managed firewall driven by the same detection brain.
3. Address availability (controller HA / defined fail-open policy) and adversarial robustness.

Note: the assessment references `firewall_waf_integration_plan.md`, which **does not exist
in this repo**. It is cited but never written.

---

## 3. Where the system sits in the network

Packets are **mirrored to the Ryu controller** over an Open vSwitch data plane; on
confirmation the controller installs a DROP at the switch (OpenFlow) or on the host
(iptables). Three deployment shapes:

| Mode | How | Blocking |
|---|---|---|
| A. Inline bridge/gateway | t530 with 2 NICs, OVS L2 bridge between LAN and router | ✅ OpenFlow DROP |
| B. t530 as the Wi-Fi AP | hostapd + OVS, devices associate directly | ✅ DROP, per-device MAC |
| C. SPAN/mirror | managed switch mirrors to t530 | ❌ detect-only |

Mode B is the recommended starting point. See `t530_mode_b_ap_setup.md`.

---

## 4. Repo change made — commit `ccec2fb`

**Only `README.md` was modified** (+217/−91). Nothing else in the codebase was touched.

Why: the README documented a two-node Mininet lab that no longer exists. Commit `8a07efc`
pruned the repo to the deployment set, deleting `SDN Topology/`, `QoS/`, and `ML dataset/`,
but the README still had a QoS section (linking to a now-missing `QoS/README.md`), a
Mininet-VM architecture diagram, and Mininet CLI attack commands. None of the seven
deployment runbooks added since were referenced.

What changed:
- Architecture diagram redrawn for the real Mode B deployment.
- Project structure corrected to match `git ls-files`; QoS section and Mininet attack sim removed.
- New: "Where it sits in the network" (A/B/C modes), `ips_config.json` documentation,
  launch env-var table, "Before you enable blocking" sequence, documentation map,
  known-limitations table.
- Corrected an unverifiable claim: commit `8a07efc`'s message says pruned material is
  recoverable via a `pre-deployment-cleanup` tag, but **that tag exists neither locally nor
  on the remote**. README now points at git history before that commit instead.

---

## 5. Verified technical facts about the current code

Checked directly against the source in that session — treat as reliable:

- **Feature extraction is purely L3/L4 statistical.** `payload_size_entropy` is packet-*size*
  entropy, not content entropy. No payload is ever inspected. The privacy-preserving claim holds.
- **Protocols parsed:** TCP, UDP, ICMP, ARP only. No DNS/HTTP/TLS parsing anywhere.
- **Feature schema:** 102-column v2, per-flow 5-second windows, written to `Controller/dataset.csv`.
  `IPS_V2_FEATURES=1` is mandatory at launch or the schema doesn't match training.
- **Config:** `Controller/ips_config.json` → `lan_cidr` (default `10.0.0.0/8` — must be changed
  for a real subnet), `ext_whitelist`, `protected_macs`.
- **Env vars:** `IPS_V2_FEATURES`, `SNORT_PHYS_IFACE`, `SNORT_IFACES`, `IPS_NO_TAP`,
  `IPS_EXTERNAL_BLOCK`, `IPS_MGMT_WHITELIST`, `IPS_BLOCK_SECONDS`, `IPS_HOST`, `IPS_PORT`,
  `IPS_GET_LOG`, `IPS_MAX_SCORE_ROWS`, `RYU_API_URL`.
- **REST routes:** `/ips/status`, `/ips/metrics`, `/ips/alerts`, `/ips/blocked`,
  `/ips/switches`, `/ips/block`, `/ips/block/<ip>`.
- **Confidence bands:** RF block ≥ 0.80, AE block ≥ 0.73; AE conf = `error/(error+threshold)`,
  threshold ≈ 0.482. AE topology `60→64→16→64→60`, pure NumPy.

### ⚠ The single most important finding

**Snort 3 is running at roughly 5% of its capability.** `Controller/snort3/sdn_ips.lua`
enables only: `stream`, `stream_tcp/udp/icmp`, `normalizer`, `arp_spoof`, `port_scan`,
`alert_json`, `alert_fast`. `RULE_PATH` includes **only** `sdn_ips_local.rules`, which
contains **4 local rules** (SIDs 1000001–1000004) plus 2 inspector-based detections.

Not enabled, but already compiled into the Snort 3 binary:
- `http_inspect`, `ssl`, `dns`, `ftp/telnet`, `smtp`, `file_id` — most of the L7 gap
- `appid` — application identification, the NGFW-defining feature
- `modbus`, `dnp3`, `s7commplus`, `cip`, `iec104` — most of the OT gap

Also: the free Snort **community ruleset (~4,000 rules)** and **registered ruleset (~50,000)**
drop straight in. Commercial NGFWs run 10k–50k signatures; this system runs 4.

**Implication:** a large fraction of the "missing" L7 and OT coverage is configuration and
rule-feed work, not new engineering. Caveats: enabling payload inspectors **forfeits the
privacy-preserving property** (make it a policy toggle, not a default), and L7 inspection on
mirrored traffic on a t530 will cost significant throughput.

---

## 6. New phase — direction agreed

**Goal:** a plugin that auto-audits firewalls from any vendor (Fortinet, Palo Alto, etc.),
plus adding L7 protection and/or OT firewall techniques.

### Key reframing

Measuring this system as an *NGFW competitor* is the wrong frame — it loses. An **auditor
doesn't implement NGFW features, it assesses them**. You don't need App-ID; you need to read
a FortiGate's App-ID policy and judge it.

**The defensible differentiator:** the system already collects **live per-flow ground truth**.
Static auditors (AlgoSec, Tufin, FireMon, Skybox) analyse config in isolation. This project
can do **policy-versus-observed-traffic reconciliation**:
- rules permitting traffic never actually seen → dead rules / attack surface
- traffic observed that no rule explains → shadow IT, misconfig, or a bypass path
- rules whose real usage contradicts stated intent
- Tier 4 AE flagging anomalies the firewall *permitted* → evidence of a policy gap

Positioning: not "a small IPS competing with Palo Alto", but **"the traffic-truth layer that
tells you whether your Palo Alto is configured correctly."**

### Auditor capabilities needed

| Capability | Notes |
|---|---|
| Vendor config ingestion (FortiOS CLI, PAN-OS XML/API, Cisco ASA/FTD, Check Point, iptables/nftables, OPNsense) | The real work — a normalizer per vendor |
| Rule-base analysis: shadowed, redundant, unused, overly-permissive (`any-any`) | Well-understood algorithms |
| Compliance mapping: CIS Benchmarks (PAN-OS/FortiOS), NIST 800-53, PCI-DSS 1.x, **IEC 62443** for OT | Rule packs |
| Firmware / CVE version checks | NVD feed |
| Zone & segmentation validation (Purdue model for OT) | Graph analysis |
| Config drift / change tracking | Diff + history |

---

## 7. Detection & analytics gap analysis

Peer group for detection is **NDR / IoT-NDR** (Armis, Claroty, Nozomi, Darktrace, Vectra,
ExtraHop, Corelight), not NGFW threat-prevention.

### Where this project genuinely wins
1. **Unsupervised zero-day detection on normal-only training** (Tier 4 AE) — architecturally
   closer to Darktrace than to a FortiGate.
2. **L2 attack detection (ARP/DAI) inside the detection stack** — neither NGFWs nor most NDR
   platforms do this; usually punted to switch features.
3. **Train/serve consistency + per-site retraining discipline** — commercial NDR ships generic
   models and tunes by exception.
4. **Privacy-preserving detection** — no payload, no DPI. Every L7 feature costs this.

### Covered today
Rate/volumetric thresholds (with hysteresis) · z-score statistical anomaly (threshold 8.0) ·
per-device behavioural baselining (EMA + payload variance) · network-wide entropy analytics ·
supervised ML classification (RF, 7 classes) · unsupervised anomaly (AE) · ARP/DAI ·
port scan · control-plane saturation · confidence scoring · graduated enforcement modes ·
per-tier/per-attack metrics.

### Not covered
Protocol anomaly · reputation/IoC · DNS analytics · beaconing/periodicity · encrypted traffic
analysis (JA3/JA4) · sandboxing · cross-host correlation (only `ML:DEFER`) · lateral movement ·
exfiltration detection · evasion resistance · low-and-slow DoS · web app attacks · CVE/exploit ·
malware/C2 · credential brute force · protocol tunnelling · OT protocol abuse · severity/risk
scoring · explainability · PCAP evidence · threat hunting/search · MITRE ATT&CK mapping ·
SIEM export · continuous learning · drift detection · model versioning · adversarial testing.

### Priority gaps, ranked by value-per-effort
1. **DNS analytics** (DGA, tunnelling, sinkhole) — IoT C2 lives in DNS; needs only query names,
   so the privacy property survives; Snort 3 `dns` inspector already in the binary.
2. **JA3/JA4 + certificate fingerprinting** — the only way to say anything useful about
   encrypted traffic without decrypting.
3. **Beaconing / periodicity detection** — built on the existing 5s flow windows, no new plumbing.
4. **Low-and-slow detection** — the obvious bypass of rate counters with hysteresis.
5. **MITRE ATT&CK mapping + SIEM export** — no detection gain, but makes output legible to a SOC.
6. **Explainability (feature attribution on AE alerts)** — biggest driver of operator trust;
   the usual reason ML tiers get switched off in production.
7. **OT protocol DPI** — largest coverage gap, but costs the privacy property.

Items 1–4 reuse the existing flow pipeline and keep the no-payload design intact.

---

## 8. Git state at handoff

| Ref | Commit |
|---|---|
| `main` (default) | `e23bee4` — "Add pre-production data-collection & learning runbook" |
| `claude/train-serve-skew-network-n4zfmc` (GitHub) | `ccec2fb` — the README update |

`ccec2fb` is a direct descendant of `e23bee4`, so merging is a **clean fast-forward**.

To merge locally:
```bash
git fetch origin
git checkout main
git merge origin/claude/train-serve-skew-network-n4zfmc
git push origin main
```

**Branch naming note:** `claude/train-serve-skew-network-n4zfmc` was named after the first
question asked in that session and does **not** describe the firewall-audit work. Start the
new phase on a fresh branch off the updated `main`.

---

## 9. Open decisions

1. **Merge `ccec2fb` into `main`** before starting new work, or it gets stranded.
2. **Scope of the new phase** — audit plugin, L7 coverage, and OT are three separable tracks.
   Which comes first? (Recommendation: the audit plugin, because it leverages the mature
   detection engine rather than competing on features this system will lose on.)
3. **Privacy trade-off** — enabling Snort L7/OT inspectors forfeits the no-payload property
   that the assessment names as a genuine advantage. Decide whether it becomes a policy toggle.
4. **Write `firewall_waf_integration_plan.md`** — referenced by the assessment, never written.
5. Two offers left open: sketching the **vendor-config normalizer schema**, and mapping
   **CIS / IEC 62443 controls to specific checks**.
