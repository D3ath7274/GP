# V2 Anomaly Framework — Design, Data Collection & 5-Day Execution Plan

*Companion to `feature_engineering_rationale_cited.md`. Written for the 5-day
deadline + controller-only deployment on the HP t530 thin client (8 GB RAM).*

---

## 0. The goal, stated precisely (and honestly)

**Objective:** maximize detection — *approach zero false negatives* — while
**tolerating false positives**, because a wrongly-blocked host can be released
later by an admin/authorized user (unblock authentication is out of scope for
now; see §6).

**Honesty up front:** literal "zero false negatives" cannot be *proven* for an
open-world anomaly detector. We *approach* it through two levers that we are
explicitly allowed to pull because FPs are acceptable:

1. **Layered detection** — an attack must evade *every* tier to be a false
   negative (§1).
2. **Recall-biased thresholds** — we set the anomaly threshold aggressively
   toward flagging, spending FP budget to buy near-total recall (§2.3).

This is the correct posture for an IPS where blocking is reversible.

---

## 1. Strategy: layered defense, the autoencoder as the safety net

Do **not** rely on one model. The controller already has detection tiers; the
autoencoder is the final net for the unknown:

| Tier | Mechanism | Catches | Status |
|---|---|---|---|
| 1 | Snort signatures | known attack signatures | exists |
| 2 | Per-host rate counters | volumetric floods / scans | exists |
| 3 | Supervised RF (`final_rf_model.joblib` + `scaler.joblib`) | the 6 known attack *types* (99.87%) | exists, names the attack |
| 4 | **Autoencoder (NEW)** | anything anomalous / zero-day / low-and-slow | this plan |

**Decision rule: block if *any* tier fires.** A flow is only a false negative if
it slips past Snort **and** the rate counters **and** the RF **and** the AE. That
redundancy is how we get near the "no false negatives" goal in 5 days without a
research project. Tier 3 tells you *what* it is; Tier 4 catches *that something
is wrong* even when nothing recognizes it.

---

## 2. Which autoencoder — and why (the core question)

### 2.1 Recommendation: a compact **denoising, undercomplete MLP autoencoder**

Trained on **normal traffic only**; reconstruction error is the anomaly score.

```
input (N shape features, standardized)
   → Dense(32) → ReLU
   → Dense(8)  → ReLU         # bottleneck (undercomplete = forced compression)
   → Dense(32) → ReLU
   → Dense(N)  → linear        # reconstruct the input
score = mean_squared_error(input, reconstruction)
```

- **Denoising**: add small Gaussian noise to the input during training only.
  Costs one line, makes the model reconstruct the *underlying normal manifold*
  instead of memorizing, which sharpens the gap between normal and anomalous.
- **Undercomplete (8-unit bottleneck)**: forces the network to learn the
  correlations that define normal behavior. Attack traffic breaks those
  correlations → high reconstruction error.

### 2.2 Why this type, grounded in the feature rationale

- The rationale's features are **per-5s-window, tabular, and ratio/shape-based**
  (`inter_arrival_cv`, `reply_rate`, `incomplete_ratio`, entropies, device
  z-scores). That is exactly the input a plain MLP autoencoder consumes — no
  sequence or image structure to justify anything heavier.
- Ratio/entropy features are **immune to the Mininet 2× TAP amplification**
  (rationale §II.B), so reconstruction error isn't polluted by the emulation
  artifact.
- The **device-relative deviation** features (rationale §XIII) are the stated
  mathematical basis for zero-day detection. An AE over them learns "this
  device's normal shape"; deviation = anomaly. This directly fulfills the
  thesis claim.

### 2.3 Thresholding for the "no false negatives" goal

Train on normal only, then set the threshold from the **normal reconstruction-
error distribution** — *no attack data needed to train*:

- Compute reconstruction error on held-out **normal** traffic.
- Set threshold at a **low percentile (p90–p95)** of that error.
  → By construction, ~5–10% of *normal* trips the alarm (accepted FP budget),
    and anything more anomalous than 90–95% of normal is flagged.
- This is deliberately recall-biased. We *spend* FP budget to *buy* recall,
  which is exactly the trade the project allows.

### 2.4 Catching low-and-slow without an LSTM: **CUSUM on the error stream**

A slow attack is invisible in any single window but leaves a small *persistent*
positive deviation. Instead of an expensive sequence model, run a **CUSUM
(cumulative sum) change detector on the per-window reconstruction error, per
device**:

```
S = max(0, S_prev + (error - (mean_normal + k)))   # k = slack
if S > h:  flag low-and-slow anomaly; reset S = 0
```

- ~5 floats of state per device, trivial on the t530.
- Accumulates slow drips until they cross `h`; benign transient spikes decay and
  never accumulate → surge-tolerant *and* slow-attack-sensitive at once.
- This is the single highest-leverage idea for the "immune to under-the-radar
  attacks" requirement, and it is cheap enough to ship in 5 days.

### 2.5 Alternatives considered and rejected (for the 5-day window)

| Option | Verdict |
|---|---|
| **Variational AE (VAE)** | Better-calibrated probabilistic score, but KL/reconstruction balancing is finicky to tune. Too risky in 5 days. *Future work.* |
| **LSTM / GRU autoencoder** | Best for temporal sequences, but needs sequence construction, more data, and is heavier on the t530. The CUSUM in §2.4 buys ~80% of the benefit for ~5% of the effort. *Future work.* |
| **Deep SVDD / One-Class NN** | Comparable quality, more to implement and tune. No advantage here. |
| **Isolation Forest (non-DL)** | Strong, cheap baseline — keep it as a *sanity cross-check* against the AE, but the AE is the thesis "deep learning" contribution. |

### 2.6 t530 deployment trick (avoid heavy runtimes on 8 GB)

Train the AE **offline on a dev machine** (PyTorch or Keras). Export the weights
to plain arrays and do **inference in pure NumPy** on the t530 (a 4-layer MLP is
~10 lines of matrix multiplies). Result: no TensorFlow/PyTorch runtime, no GPU,
a few MB of weights, microsecond inference. Same discipline as the RF: ship a
saved `ae_scaler.joblib` alongside it.

---

## 3. Feature set for the autoencoder

Use the **shape / ratio / device-relative** subset — *not* raw volume — so the AE
tolerates legitimate surges (a big download is high-volume but normal-shaped):

- Timing: `inter_arrival_cv`, `inter_arrival_std`, `burst_count`
- Asymmetry *(now populated by the capture fix)*: `reply_rate`,
  `fwd_bwd_packet_ratio`, `fwd_bwd_bytes_ratio`
- Session *(now populated)*: `incomplete_ratio`, `completed_sessions`
- Entropy: `src_port_entropy`, `network_entropy_dst_port`, `network_entropy_src_ip`
- Port behavior *(now populated)*: `dst_port_std`, `sequential_port_score`,
  `unique_dst_ports`
- Packet size: `pkt_size_std`, `small_pkt_ratio`, `large_pkt_ratio`
- Device-relative (zero-day basis): `device_pkt_rate_deviation`,
  `device_byte_rate_deviation`, `device_payload_size_deviation`,
  `device_new_dst_ratio`, `is_baseline_mature`
- ARP: `arp_unsolicited_count`, `mac_ip_binding_changes`

Standardize with a scaler **fit on normal only**, saved as `ae_scaler.joblib`.
Excluding raw `packets_per_second` / `total_bytes` is what keeps the AE from
firing on benign throughput spikes.

---

## 4. V2 data collection plan

Run with the **fixed `traffic_capture.py`** (the dead-feature fixes are what make
the §3 features real). Two capture phases, driven by the existing `topology.py`
and detection-mode toggle.

### 4.1 Phase A — clean NORMAL (this is the AE's training set; low risk)

Goal: a realistic "normal" that **includes surges**, so the AE learns they are
normal.

- Set controller detection mode **OFF** (all rows labeled `normal`, clean data).
- Let devices run ≥ **180 s** first so `is_baseline_mature` flips to 1 (rationale
  §XI.A) before you record the rows you'll train on.
- Generate a *variety* of benign traffic:
  - steady background: pings, periodic IoT sensor chatter
  - **bulk download / throughput**: `iperf`, `wget` a large file (the "user
    starts downloading" case)
  - **streaming-like**: sustained medium-rate bidirectional UDP/TCP
  - **`pingall` broadcast storm** (so the AE sees Mininet broadcast bursts as
    normal — rationale §X)
- Target volume: a few thousand normal windows across the device mix.

> Phase A alone is enough to train and threshold the AE. If the deadline gets
> tight, **stop here** — you still have a working zero-day detector.

### 4.2 Phase B — labeled ATTACKS (for validation + optional v2 RF retrain)

Re-run the **six existing attack scenarios** (`topology.py` already orchestrates
them). You are re-running, not building:

| Attack | Tool / trigger | Label source |
|---|---|---|
| ICMP Flood | hping3 `--icmp --flood` | rate counter / Snort |
| SYN Flood | hping3 `-S --flood` | rate counter / Snort |
| UDP Flood | hping3 `--udp --flood` | rate counter |
| Port Scan | nmap (sequential) | rate counter |
| Control Plane Saturation | UDP → incrementing ports | rate counter |
| ARP Spoofing | arpspoof | DAI / persistent binding |

- Detection mode **ON** so labels populate; for stealthy/slow variants use
  `set_label_override(src_ip, attack_type)` to inject ground truth (the slow
  attacks deliberately evade thresholds — that's the point).
- Keep each run short; you need a few hundred rows per class, not thousands.
- **Also run one "held-out" attack you do NOT train the RF on** (e.g., a slow
  nmap `-T1`) — this is your zero-day demo: the AE should flag it even though no
  tier was trained on it.

### 4.3 Validate the capture before trusting the data

Spot-check that the previously-dead features are now non-zero in the new CSV
(we already proved the mechanism: scan → `dst_port_std`/`sequential_port_score`
> 0, bidirectional → `bwd_packet_count`/`reply_rate` > 0, ARP → `is_broadcast_dst`
= 1). If they're still zero, the fix isn't being exercised by the scenario.

---

## 5. The 5-day schedule (risk-managed, always-demoable)

Each day ends with a **fallback** so you are never left with nothing.

| Day | Do | Fallback if behind |
|---|---|---|
| **1** | Phase A normal collection (fixed capture). Stand up the AE training script (PyTorch/Keras) on a dev machine. | If collection is flaky, shrink scenario; even 1–2k normal windows is enough. |
| **2** | Train AE on normal; set p90–p95 threshold; export weights → NumPy + `ae_scaler.joblib`. Phase B quick attack runs for validation. | If Phase B breaks, threshold from normal tail only — AE still ships. |
| **3** | Integrate AE as **Tier 4** in the controller inference path (mirror how the existing ML hook works in `traffic_capture.py`). Wire CUSUM on the error stream. Wire the simple block command (§6). | If integration is hard, run AE in **OBSERVE** mode (log, don't block) — still demoable. |
| **4** | Deploy controller on the **t530**; end-to-end run; tune threshold against live FP rate. (Optional) retrain v2 RF on the new schema. | If t530 misbehaves, demo from the dev machine; deployment is the stretch goal. |
| **5** | Buffer / debug. Dry-run the demo script: normal → no block; known attack → RF+block; held-out slow attack → AE+block; admin block command. | — |

**The order matters:** AE-on-normal first (low risk, high value), attacks second,
integration third, t530 last. The riskiest, most time-consuming step (full attack
re-collection) is *not* on the critical path to a working AE.

### Optional: v2 RF retrain
The friend's exact RF config is known from the model itself —
`RandomForestClassifier(class_weight='balanced', max_depth=20,
min_samples_leaf=10, n_estimators=200, random_state=42)` — plus a `StandardScaler`.
So a faithful v2 retrain on the new (fixed-schema) data is a few hours and removes
the 3-feature drift between v1 and the fixed capture. Do it only if Days 1–4 land
on time; otherwise keep v1 RF + the recovered scaler.

---

## 6. The simple block command (as specified — unauthenticated for now)

Per the requirement, ship a **minimal** block channel now; real authentication is
future work:

- **Accept a block request from any source IP** as long as (a) the message
  matches the expected syntax, and (b) the **destination IP == the controller's
  own IP**.
- Reuse the existing **out-of-band UDP control channel (port 9999)** that
  `topology.py` already uses, and call the controller's existing
  `block_attacker()` / install-DROP path.
- Suggested syntax: `BLOCK <target_ip> [duration_s]` → controller installs an
  OpenFlow DROP for `<target_ip>`. `UNBLOCK <target_ip>` → calls the existing
  `manual_unblock()`.
- **Write it down as a known gap:** this trusts any sender that can reach the
  controller IP. Acceptable for the demo; flag "add authentication" as future
  work so a reviewer doesn't mistake it for a design oversight.

---

## 7. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Full attack re-collection eats the week | High | AE trains on **normal only**; attacks are validation, not training. Off critical path. |
| t530 deployment friction | Medium | NumPy-only AE inference (§2.6); demo from dev machine as fallback. |
| v1 RF drift on 3 fixed features | Low | Retrain v2 RF (config known) *or* keep v1 + accept minor drift. |
| AE false-positive rate too high | Low (by design we tolerate it) | Raise threshold percentile; admin unblock command exists. |
| "Zero FN" over-claimed in thesis | — | Frame as *layered, recall-biased*; report measured recall, don't claim a proof. |
