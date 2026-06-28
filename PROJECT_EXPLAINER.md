# The Project, End to End — Developer & Business Guide

*Read this once and you can explain the entire system to anyone — from a fellow engineer to a
non-technical business owner. It goes from the 60-second pitch down to every file and design
decision. Plain-English sections are marked 🟢 (for business owners); deeper technical sections
are marked 🔧 (for developers). A glossary at the end translates every acronym.*

---

## Part 0 — The 60-second pitch 🟢
We built a **smart, self-driving security guard for IoT networks**. Cheap smart devices
(cameras, sensors) are easy to hack and are a favourite launchpad for attacks. Our system sits
in the network, **watches all traffic**, and decides in real time whether each conversation is
normal or an attack. When it's sure, it **blocks the attacker automatically** — in seconds, with
no human needed. It uses **four independent "opinions"** (a rulebook, a rate watchdog, and two
different AI models) and only acts when the evidence is strong, so it rarely cries wolf. And it
runs on an **$80 thin client**, so it's cheap enough to put at every branch office or factory.

---

## Part 1 — The problem (why this matters) 🟢
- **IoT devices are weak and everywhere.** They ship with poor security, rarely get patched, and
  there are billions of them. Attackers hijack them to launch floods (DDoS), scan networks, and
  spread laterally.
- **Traditional security is a poor fit at the edge.** Big firewall appliances are expensive and
  built for data centres, not a remote site with a handful of sensors. Pure "signature" tools
  only catch attacks they already have a fingerprint for — they miss anything new.
- **Alert fatigue.** Most tools drown analysts in alerts. A small team can't watch a firehose of
  logs across dozens of sites.
- **Response is too slow.** By the time a human reads an alert and reacts, the damage is done.

**The gap:** something cheap, that runs at the edge, catches *both* known and unknown attacks,
acts on its own in seconds, and doesn't spam false alarms.

---

## Part 2 — The solution in plain English 🟢
An **Adaptive Intrusion Prevention System (IPS)** for IoT on an SD-WAN:
- **Adaptive** = it learns what *normal* looks like, so it can flag the *abnormal* — including
  attacks nobody has seen before.
- **Intrusion Prevention** (not just *Detection*) = it doesn't only raise an alarm, it **blocks**
  the attacker in the network itself.
- **SD-WAN / SDN** = the network is software-controlled, so a single "brain" (the controller) can
  watch all traffic and install a block instantly, everywhere.

It makes a decision every 5 seconds for every active conversation, using **four detectors at
once**, and only blocks when confident. An operator dashboard shows the whole thing at a glance.

---

## Part 3 — How it works, A→Z: the journey of one packet 🔧🟢
1. **Traffic is generated.** In the lab, a Mininet-WiFi network simulates IoT devices
   (`TempSensor`, `Cam`) and hosts talking through a Wi-Fi access point and an Open vSwitch (`s1`).
   In production this is your real network segment.
2. **The switch copies traffic to the brain.** Every flow the switch handles is also **mirrored
   to the controller** (OpenFlow `output:CONTROLLER`) — so the controller sees *everything*, even
   during a flood. (A guard prevents this from looping/amplifying.)
3. **The brain (Ryu controller) receives each packet** as a `packet_in` event.
4. **Two things happen in parallel:**
   - The packet is **mirrored to Snort 3** (the signature engine) via a tap.
   - The packet is handed to the **feature extractor** (`traffic_capture.py`).
5. **Every 5 seconds, the extractor "closes the books"** on that window: for each conversation
   (defined by source, destination, port, protocol) it computes **102 numerical features** —
   rates, packet sizes, TCP flag counts, port-spread, timing regularity, entropy, per-device and
   per-network baselines, ARP behaviour. One row per conversation per window.
6. **Four detectors weigh in on that window:**
   - **Tier 1 — Snort 3 signatures:** does this match a known attack pattern?
   - **Tier 2 — Rate counters + ARP inspection:** is the *rate* or *ARP behaviour* abnormal?
   - **Tier 3 — Random Forest (AI #1):** classify the conversation into a known attack type.
   - **Tier 4 — Autoencoder (AI #2):** does this look *unlike normal* (even if unknown)?
7. **Confidence banding decides the action.** Below 60% confidence → stay **silent** (no noise).
   Middle band → **flag** (save evidence, don't block). High band → **block**.
8. **Enforcement.** If any tier is confident, the controller installs an **OpenFlow DROP rule** —
   the attacker's traffic is dropped *in the network*, within seconds, automatically.
9. **Visibility.** Everything (modes, blocked hosts, per-tier activity, system health) is exposed
   on a REST API and an operator **dashboard**.

> The whole loop — see, decide, block — lives in **one process on one cheap box**.

---

## Part 4 — The four tiers, and why we layer them 🔧🟢
No single detector is enough, so we combine four with complementary strengths:

| Tier | Engine | Catches | Blind spot (covered by others) |
|---|---|---|---|
| 1 | **Snort 3** signatures | known attack patterns, fast | unknown/zero-day attacks |
| 2 | **Rate counters + DAI** | volumetric floods, ARP spoofing by behaviour | low-and-slow / non-volumetric |
| 3 | **Random Forest** (supervised AI) | *classifies* the 6 known attack types | attacks unlike its training data |
| 4 | **Autoencoder** (unsupervised AI) | **anything that isn't normal** (zero-day) | can't name the attack, only "abnormal" |

🟢 **Why four?** Think of airport security: an ID check (signatures), a metal detector (rate), a
trained officer who recognises known threats (Random Forest), and a behaviour-spotter who notices
"this person is acting unlike any normal traveller" (Autoencoder). Each catches what the others
miss. We **block if *any* of them is confident** — defence in depth.

🔧 **Why both a supervised *and* an unsupervised model?** The Random Forest is precise on the
attacks we trained it on but can't recognise novel ones. The Autoencoder is trained **only on
normal traffic**, so anything it reconstructs badly is "weird" — that's how it flags zero-days the
RF never saw. Running them concurrently gives closed-world precision *and* open-world coverage.

---

## Part 5 — The codebase, component by component 🔧
*(Everything lives under `Controller/` unless noted. The merged controller is the heart.)*

- **`Controller_main_Claude.py`** — the **merged controller** (a Ryu app). It's an OpenFlow 1.0
  learning switch + traffic mirror, it launches Snort, runs both ML tiers, does ARP-spoof
  detection, discovers IoT devices, listens for control commands on **UDP 9999**, and serves the
  **REST API + dashboard on :8080** (we use `:8081` on the t530 because nginx holds 8080).
  *Rationale:* one process = one thing to deploy on a thin client, and detection + enforcement
  co-located = sub-second response.
- **`traffic_capture.py`** — the **feature extractor**. Consumes `packet_in` events, aggregates
  them into **5-second windows per flow key**, computes the 102 features, writes `dataset.csv`,
  and is also the **live inference feed** for Tiers 2/3/4. *Rationale:* one code path produces
  both the *training data* and the *live features*, so there's no train/serve schema drift.
- **`snort_monitor.py`** — manages **Snort 3** (launches it on the right interfaces with our
  curated Lua config, parses its `alert_json`, suppresses known-benign noise by `(GID, SID)`).
- **`ml_inference.py`** — the **Random Forest** engine (scikit-learn pipeline, `rf_pipeline.joblib`).
- **`ae_inference.py`** — the **Autoencoder** engine, rewritten as a **pure-NumPy forward pass**
  (loads `ae_bundle.joblib`). *Rationale:* no TensorFlow on the thin client — the AE is just
  matrix multiplies, so it runs anywhere with NumPy.
- **`snort3/sdn_ips.lua` + `sdn_ips_local.rules`** — the curated Snort 3 config + rules for
  exactly the 6 attack classes (+ the `arp_spoof` and `port_scan` inspectors).
- **`ipsctl.py`** — a tiny UDP sender for control commands (because `nc` is unreliable on the t530).
- **`dataset_merge.py` / `validate_dataset.py` / `fix_label_bleed.py`** — the data pipeline:
  merge sessions with a hard schema guard, validate label integrity, and salvage mislabels.
- **`build_ae_bundle.py`** — rebuilds the AE bundle from a trained `.h5` + the training CSV (so we
  can update the model without shipping TensorFlow).
- **`SDN Topology/topology.py`** (separate machine) — the **Mininet-WiFi** lab network + the
  one-command automated **attack/collection** helpers (`run_attack_session`, `run_full_collection_hy`).
- **`Dashboard/index.html`** — the operator dashboard (vanilla JS + SVG, served by the controller).

---

## Part 6 — The data & ML story 🔧
- **Feature engineering rationale (102-column "v2" schema).** Every feature group is *justified*
  (see `feature_engineering_rationale.docx`): per-flow volume/rate, TCP flags, port-spread + a
  `sequential_port_score` for scans, inter-arrival timing & burstiness, session-completion,
  **Shannon entropy** (e.g. destination-port entropy separates a flood from a scan), per-device
  behavioural baselines, network-level context, and ARP features. *Key principle:* **no data
  leakage** — bookkeeping columns (`meta_*`: window id, device name, attack tool, controller load)
  are kept for auditing but **stripped from the training file**, so the model can't "cheat."
- **Dataset collection.** A one-command, automated capture from the Mininet lab. We hit a subtle
  trap — **"flow collapse"**: a flood from one source to one destination is a *single* flow key, so
  it produces few rows regardless of packet volume. Fix: **concurrent multi-target floods from 6
  sources** → ~5× the rows, so the minority attack classes aren't starved. Sessions are then
  **merged (with a hard 102-column schema guard)** and **validated** for label integrity.
- **Random Forest (Tier 3).** A scikit-learn + **imbalanced-learn** pipeline. Because attacks are
  rare vs normal, we balance at *training time* (SMOTE + class weights) — never by deleting data,
  which would hurt the "normal" class and inflate false positives.
- **Autoencoder (Tier 4).** Trained **only on normal traffic** to learn "what normal looks like."
  At runtime it tries to reconstruct each window; a high **reconstruction error** = "this isn't
  normal" = anomaly. We ship it as weights + scaler + threshold in `ae_bundle.joblib` so it runs
  TF-free. Confidence = `error / (error + threshold)`, so normal (low error) stays silent.

---

## Part 7 — Deployment: why a thin client at the edge 🟢🔧
The controller runs on an **HP t530 thin client (8 GB RAM, ~$80 used)** running Ubuntu. 🟢 That's
the point: security that's cheap enough to put at *every* branch/factory, not just HQ. 🔧 To make
it fit we: built **Snort 3 from source** (the apt package is the old v2), ran the ML stack under a
compatible **Python** (3.9 on the VM / 3.10 on the t530), and kept the AE **TensorFlow-free**. The
system watches its own **RAM and per-window compute time** (must stay < 5 s) to prove it lives
within the hardware budget — that resource headroom is itself a selling point.

---

## Part 8 — Key design decisions & their rationale (the "why we coded it this way") 🔧
1. **Block if *any* tier fires (defence in depth).** Maximises recall — the metric that matters
   for an IPS (catch every attack), accepting a small false-positive cost we control via banding.
2. **Confidence banding (silent < 60% · flag · block).** Real networks are noisy; surfacing every
   low-confidence guess = alert fatigue. Staying silent below 60% and only blocking when confident
   keeps the console (and the analyst) sane. This directly attacks the #1 SOC pain point.
3. **Supervised + unsupervised together.** Precision on known attacks (RF) *and* coverage of the
   unknown (AE) — neither alone is sufficient.
4. **One merged controller process.** Detection *and* enforcement in one place = sub-second
   response and one artifact to deploy. (We deliberately dropped a second OpenFlow-1.3 app to
   avoid two controllers fighting.)
5. **Same code makes training data and live features.** Eliminates train/serve skew — the model
   sees at inference exactly the schema it trained on.
6. **Pure-NumPy AE.** Keeps the thin client free of TensorFlow; anomaly detection becomes a few
   matrix multiplies.
7. **Resampling at train time, never deleting normal data.** Deleting majority data raises false
   positives and breaks the AE (which needs lots of normal). Class weights + SMOTE are reversible
   and honest.
8. **Aggregate-and-dedupe everywhere (dashboard + logs).** State and rates, not a per-packet
   firehose — the operator reads a glanceable view, not a scrolling log.
9. **Graceful degradation.** If a model file or dependency is missing, that tier disables itself
   and the rest keep running — the system never hard-fails because one piece is absent.

---

## Part 9 — Operating it (modes & controls) 🔧
- **DETECT OFF / ON** — OFF = capture only (all labels normal, used for collecting clean data);
  ON = signature + rate/DAI tiers label and (in AUTHORIZE) block.
- **ML OFF / OBSERVE / AUTHORIZE** — OFF = ML idle; OBSERVE = ML predicts and logs but never
  blocks (used to *verify* accuracy first); AUTHORIZE = ML blocks above the confidence threshold.
- **Control channel:** UDP 9999 via `python3 ipsctl.py CONTROL:…` (e.g. `CONTROL:DETECT:ON`,
  `CONTROL:ML:AUTHORIZE:0.80`, `CONTROL:CLEAR:<ip>`).
- **REST API (:8081):** `/ips/status`, `/ips/metrics`, `/ips/alerts`, `/ips/blocked`,
  `POST/DELETE /ips/block` — the integration point for a SIEM/SOAR, and what the dashboard reads.
- **Dashboard:** `http://<controller>:8081/` — status, threat level, per-tier activity, attack
  breakdown, blocked hosts (with Unblock), event timeline, and t530 health.

---

## Part 10 — How to explain it to a business owner 🟢
**The elevator pitch:** *"It's an AI security guard for your smart devices. It learns what your
network's normal day looks like, watches every device 24/7, and automatically blocks attacks —
known or brand-new — in seconds. It runs on an $80 box at each site, and it's smart about when to
act, so it doesn't bury your team in false alarms."*

**The analogy:** a security guard who (a) has a list of known troublemakers (signatures), (b)
notices someone trying every door in the building (rate/scan detection), (c) recognises known
attack tactics (the Random Forest), and (d) senses when someone is simply *behaving unlike any
normal visitor* (the Autoencoder) — and who locks the door automatically only when genuinely sure.

**The value, in business terms:**
- **Lower risk:** catches both known *and* novel attacks, and contains them automatically →
  smaller breach window, less damage.
- **Lower cost:** runs on commodity hardware at the edge; no expensive appliance per site.
- **Less analyst burden:** confidence banding + a glanceable dashboard mean fewer false alarms and
  faster triage — a small team can cover many sites.
- **Faster response (MTTR):** blocks in seconds, before a human could react.
- **Fits existing operations:** exposes a REST API to feed your SIEM/SOAR (Splunk, etc.).

**Honest framing (builds trust):** it's a research prototype validated in a lab; real-world
rollout needs validation on production traffic, high-availability, and threat-intel feeds (see
Part 11). Say this — it makes the rest credible.

---

## Part 11 — Limitations & roadmap (be honest) 🟢🔧
- Trained/validated on **self-generated lab data**, not production traffic → generalisation is
  unproven; first real step is on-site validation + (online) retraining.
- Covers the **6 target attack classes** for signatures; no encrypted-traffic analysis; no
  external threat-intel feed; single controller (no HA/clustering yet).
- The AE needs ongoing false-positive tuning per environment (re-fit its threshold to each site's
  "normal").
- Roadmap: real-traffic validation, HA controllers, SIEM/SOAR connectors out-of-the-box, richer
  signatures, encrypted-flow features, authenticated dashboard.

---

## Part 12 — Glossary (jargon → plain English)
- **IoT** — Internet of Things: small networked devices (cameras, sensors).
- **IDS / IPS** — Intrusion *Detection* System (alerts only) / *Prevention* System (alerts **and
  blocks**). Ours is an IPS.
- **SDN / SD-WAN** — Software-Defined Networking: the network is controlled by software (a
  "controller") instead of fixed hardware, so one brain can see and act everywhere.
- **OpenFlow** — the protocol the controller uses to tell switches what to do (e.g. "DROP this").
- **Ryu** — the Python SDN-controller framework we build on.
- **Open vSwitch (OVS) / Mininet-WiFi** — the software switch / the network emulator used in the lab.
- **Snort 3** — an open-source signature-based detection engine (our Tier 1).
- **DAI** — Dynamic ARP Inspection: catches ARP spoofing by watching IP↔MAC bindings.
- **Random Forest** — a supervised ML model (many decision trees voting) that *classifies* attacks.
- **Autoencoder** — an unsupervised neural net trained to reproduce *normal* data; high
  reconstruction error = anomaly.
- **Feature / feature vector** — the numbers describing one conversation (rate, sizes, flags, …)
  that the models read.
- **Flow / flow key** — one conversation, identified by (source, destination, port, protocol).
- **Entropy** — a measure of "spread"/randomness; e.g. high destination-port entropy ⇒ a scan.
- **Confidence banding** — only act when the model's confidence crosses thresholds (silent / flag / block).
- **SMOTE / class weights** — techniques to handle rare attack classes during training.
- **SIEM / SOAR** — central security log/correlation platform / automated response platform; we
  feed them via REST.
- **MTTR** — Mean Time To Respond; lower is better; our auto-block drives it down.

---

### Where to go next
- Run/test it: `t530_full_system_runbook.md` (PART 5 = tier-by-tier tests).
- Capture figures for the report: `Chapter4_figure_capture_guide.md`.
- Deeper technical reference: `context_claude.md`; SOC + competitor comparison: `Dashboard/PROJECT_DOCUMENTATION.md`.
