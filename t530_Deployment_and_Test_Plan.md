# HP t530 Deployment & Staged Test Plan — Adaptive IPS for IoT in SD-WAN

*The autoencoder (Tier 4) is now **wired into the controller** alongside the Random
Forest (Tier 3). This is the step-by-step guide to test both models and deploy on the
HP t530 thin client, staged: lab → emulated-on-t530 → real data. Do each step, pass its
**GATE**, then continue.*

---

## 0. Current state — what is built and where

**Four detection tiers, decision rule = "block if ANY tier fires":**
| Tier | Mechanism | File / artifact | Runtime deps |
|---|---|---|---|
| 1 | Snort signatures (6 attacks) | `snort_monitor.py` + `snort3/sdn_ips.lua` (+rules) | Snort 3 (else 2.x fallback) |
| 2 | Per-host rate counters + DAI | `traffic_capture.py` | none |
| 3 | Random Forest (names 6 attacks) | `ml_models/rf_pipeline.joblib` via `ml_inference.py` | scikit-learn 1.6.1 |
| 4 | **Autoencoder (anomaly / zero-day)** | `ml_models/ae_bundle.joblib` via `ae_inference.py` | **pure NumPy** |

**AE wiring (done):** `ae_inference.py` (NumPy scorer), instantiated in `Controller.py`
as `self._ae_engine`, scored per window in `traffic_capture.py` **concurrently** with the
RF. Bands: **AE** flag 0.60 / block 0.73 (silent <0.60); **RF** flag 0.80 / block 0.90
(tune live via `CONTROL:ML:FLAG`/`BLOCK`). AE disables gracefully if its bundle is absent.

**AE bundle:** rebuilt from `anomaly_detection_autoencoder_model.keras` + the training
CSV; stores `features(60) / mean / scale / threshold=0.0375 / layers(60-64-32-64-60)`.
Validated: p95≈0.0375; normal mean-conf 0.16 vs attack 0.73 (≈47% of attack windows ≥0.73).

**Resolved (previously open) questions:**
- AE runtime → **pure NumPy** (no TensorFlow, no sklearn for the AE). t530-friendly.
- AE feature set → the notebook's **60 features** (baked into `ae_bundle.joblib`).
- Model files → **`rf_pipeline.joblib`** (RF) + **`ae_bundle.joblib`** (AE); the stray
  `full_ml_pipeline*.joblib` (wrong model) should be deleted if still present.

**Still open (not blockers):** Snort 3 binary install on the controller (else 2.x
fallback); operator-initiated `CONTROL:BLOCK:<ip>`; retrain the AE+RF on the bigger
dataset; the AE's `protocol_normal` feature quirk (clean at next retrain); CUSUM
low-and-slow add-on (not built).

---

## STAGE A — Test both models in the lab (dev/topology VM)

### A1 — Deploy the wired code + models to the controller VM
`git pull` (or scp) so the VM has: `ae_inference.py`, updated `Controller.py` +
`traffic_capture.py`, and `ml_models/{rf_pipeline.joblib, ae_bundle.joblib}`.
**GATE:** `ls Controller/ml_models/` shows both joblibs.

### A2 — RF train/serve-skew sanity
```bash
cd Controller && python3 verify_inference.py --model-dir ml_models \
    --data dataset_v2_master_training.csv --ref rf_reference_predictions.csv
```
**GATE:** `RESULT: PASS ✅` (deployed RF == notebook).

### A3 — Start the controller, confirm both engines load
```bash
sudo IPS_V2_FEATURES=1 ryu-manager Controller.py
```
**GATE:** log shows `Feature schema mode: v2 (corrected)`, `ML engine loaded … pipeline
(7 classes)`, and `AE engine loaded …/ae_bundle.joblib (60 features, threshold=0.03750,
4 layers)`.

### A4 — Pure-ML test mode (models classify on their own)
Send over UDP 9999: `CONTROL:DETECT:OFF` then `CONTROL:ML:OBSERVE`.
**Why DETECT OFF:** with it on, the rate/DAI/Snort tiers label floods first and the RF
hook skips them; off, every flow stays `label==0` so **both** RF and AE score every flow.
**GATE:** controller confirms `ML MODE: OBSERVE`.

### A5 — Drive attacks (topology VM)
```python
py net.run_full_collection_hy(net)        # all 6 attacks + normal, one command
# or per type: py net.run_attack_session(net,'syn')
```
**GATE:** attacks running; controller printing window activity.

### A6 — Read the confidence output (the deliverable)
Per window you'll see both models:
```
[ML-OBSERVE] 10.0.0.1 → 10.0.0.4  verdict=SYN Flood  conf=0.74  band=…
[AE-OBSERVE] 10.0.0.1 → 10.0.0.4  anomaly conf=0.81  err=0.1620  band=BLOCK
```
RF logs every non-normal verdict + conf; AE logs only conf ≥ 0.60 (silent below, so
normal traffic doesn't flood). **Record per class:** RF verdict + conf, AE anomaly conf,
and the % of attack windows each puts in flag/block bands.
**GATE:** real attacks surface with high confidence; normal stays quiet.

### A7 — (Optional) Confirm real blocking
Flip `CONTROL:ML:AUTHORIZE`: RF blocks ≥0.90 (tune via `CONTROL:ML:BLOCK:0.80`), AE blocks
≥0.73 (labels `Anomaly (AE)` for zero-day hits). Release with `CONTROL:UNBLOCK:<ip>`;
return to OBSERVE. **GATE:** blocks fire only at/above the bars.

---

## STAGE B — Emulated-live on the t530

### B1 — Verify the controller interpreter (the #1 risk)
The controller imports the models in-process, so Ryu's Python must satisfy them.
```bash
python3 -c "import sys; print(sys.version)"      # must be >= 3.9
```
**GATE:** `ryu-manager` runs on Python ≥ 3.9. **Do not repoint system python** (it broke
Ryu before) — use the interpreter Ryu is installed under.

### B2 — Install runtime deps (RF only; the AE needs none)
```bash
pip install --only-binary=:all: scikit-learn==1.6.1 "pandas<2.3" "numpy<2.3" joblib
```
**No TensorFlow** — the AE runs in pure NumPy.
**GATE:** in Ryu's interpreter, `python3 -c "import sklearn,numpy,pandas,joblib; print(sklearn.__version__)"` → `1.6.1`.

### B3 — Copy the project to the t530
Copy `Controller/` **including** `ml_models/{rf_pipeline.joblib, ae_bundle.joblib}`, plus
`SDN Topology/` if collecting there. **GATE:** both model files present on the t530.

### B4 — (Optional) Snort 3 schema
Install the Snort 3 binary, then `sudo ./scripts/install_snort3_ips_config.sh` +
`sudo snort -c /etc/snort/sdn_ips.lua -T`. Else the controller auto-falls back to Snort
2.x (detection still works). **GATE:** `snort -V` reports v3 (only if you want Snort 3).

### B5 — Launch + confirm load on the t530
`sudo IPS_V2_FEATURES=1 ryu-manager Controller.py` → **GATE:** same three load lines as A3.

### B6 — Resource + latency check under load
Run an attack session; on the t530 watch: **RAM** within 8 GB; **window compute time
< 5000 ms** under flood (`meta_controller_load`). **GATE:** no window backlog; RAM headroom.

### B7 — Repeat A4–A7 on the t530
Confirm the live `[ML-OBSERVE]`/`[AE-OBSERVE]` verdicts match the lab numbers (no
train/serve skew on the t530). **GATE:** verdicts consistent with Stage A.

---

## STAGE C — Real-data test (t530 on the real network)

### C1 — Place inline / on a mirror port; start safe
Begin **capture-only** (`DETECT:OFF`, `ML:OFF`). **GATE:** the t530 sees real traffic and
writes rows; v2 features look sane on real flows.

### C2 — Observe on real traffic (no blocking)
`DETECT:OFF` + `ML:OBSERVE`. Collect a **real-normal** confidence/error distribution.
**GATE:** normal real traffic stays low-confidence (RF ≈ normal, AE < 0.60). If the AE
fires often on real normal, its threshold needs re-baselining on real data (the lab p95
won't transfer perfectly — real traffic has no Mininet TAP 2× amplification).

### C3 — Re-baseline thresholds on real normal (if needed)
Recompute the AE threshold from real-normal reconstruction error (rebuild
`ae_bundle.joblib` with the new threshold) and/or adjust RF bars. **GATE:** real-normal
false-positive rate within your tolerance.

### C4 — Escalate to blocking, conservatively
`DETECT:ON` + `ML:AUTHORIZE` with conservative bars (RF block 0.90, AE block 0.73);
operator on call for `CONTROL:UNBLOCK:<ip>`. **GATE:** documented detections with
operator-reversible blocks; no controller saturation on real volume.

**Rollback at any stage:** `CONTROL:ML:OFF` + `CONTROL:DETECT:OFF` → instant capture-only.

---

## At-a-glance order
A1 deploy → A2 RF skew → A3 load RF+AE → A4 DETECT OFF + OBSERVE → A5 attacks →
A6 read RF+AE conf → A7 (opt) AUTHORIZE · B1 Ryu python → B2 deps (no TF) → B3 copy
models → B4 (opt) Snort 3 → B5 launch → B6 RAM/latency → B7 repeat A4–A7 ·
C1 capture-only → C2 observe real → C3 re-baseline → C4 authorize (conservative).

---

## Notes / future work
- AE uses the **small-data** weights now. After retraining on the bigger dataset, rebuild
  `ae_bundle.joblib` (same format: features/mean/scale/threshold/layers) and drop it in —
  no code change.
- Clean the AE `protocol_normal` feature artifact (the notebook one-hot also dummified
  `attack_type`) at the next retrain.
- Optional adds: operator `CONTROL:BLOCK:<ip>`; CUSUM low-and-slow on the AE error stream.
