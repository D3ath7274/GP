# ML + AE Confidence Boost for Real-Time Data — Plan

*Problem observed on the t530: live RF confidence on a sustained SYN flood was **0.61** (FLAG,
below the 0.80 block band) and the **AE produced no verdict** (silent < 0.60). Yet offline the
models scored well (AE: normal ~0.16, attacks ~0.73). That gap = **train/serve skew** + noisy
per-window scoring. This plan closes it, in priority order.*

---

## Phase 0 — Diagnose first (don't guess which problem you have)
The controller is already writing `dataset.csv` from the **live t530 feed**. Capture one labelled
attack run, then **score those exact rows offline** with `rf_pipeline.joblib` + `ae_bundle.joblib`:
- **Offline conf ≈ live conf (both ~0.6)** → it's the **model/data** → Phase 1–3.
- **Offline conf ≫ live conf** → a **live feature-path bug** (preprocessing differs at inference
  vs training) → Phase 4 first.

Also compare feature *distributions* (mean/std of `packets_per_second`, `syn_count`,
`unique_dst_ports`, inter-arrival) between t530-live windows and the training set. Large shifts =
the model is seeing a different world than it trained on. **This single check tells you where to spend effort.**

---

## Phase 1 — Retrain RF on the enlarged + deployment data (biggest lever)
The current models trained on **old VM-collected** data; the t530 + `snort_tap` feed differs.
- Retrain on `dataset_v3_master_training.csv` (richer, more balanced after the top-ups).
- **Best: add a fresh capture collected ON the t530** through the same live path, so the model
  learns the *deployment* distribution — this is what lifts live confidence most.
- Keep the **imbalanced-learn** pipeline: `SMOTE` + `class_weight='balanced'` so thin classes
  (UDP/SYN/Scan/ARP) become confident instead of split 0.6 votes.

## Phase 2 — Calibrate RF probabilities
RF "confidence" on imbalanced data is poorly calibrated, so 0.80 isn't really 80 %.
- Wrap the classifier in `CalibratedClassifierCV(method='isotonic')` (fit on a held-out split).
- After calibration, set the block/flag thresholds from the **calibrated** PR curve per class.
  Often a well-separated class (CPS, ICMP) can safely use a lower block threshold than SYN.

## Phase 3 — Re-fit the AE to the t530 baseline (why it's silent)
The AE's scaler (mean/scale) and threshold (**0.0375**) were derived from **old** normal traffic.
If the t530's "normal" reconstructs with higher baseline error, a fixed 0.0375 makes everything
look *less* anomalous → confidence stays under 0.60 → silent.
- Capture **10–20 min of pure t530 normal** traffic.
- Recompute the AE **scaler** (per-feature mean/std) and **threshold** (p95–p99 of reconstruction
  error on those normals); re-export `ae_bundle.joblib`.
- **Sanity gate:** after re-fit, a CPS or UDP flood **must** log `[AE-OBSERVE]` ≥ 0.60. If the AE
  is silent even on CPS, it's not sensitivity — it's a `score()` bug on live rows (Phase 4).

## Phase 4 — Real-time robustness (helps even without retraining)
- **Temporal aggregation (high ROI):** decide over a rolling window of **N=3–5 consecutive
  windows** (mean confidence, or k-of-n vote) instead of per-window. A SYN flood at 0.61 *every*
  window for 30 s becomes a confident sustained detection; one-off noise doesn't trip it. This is
  the rate-tier's "N consecutive" idea applied to ML — it raises effective confidence **and** cuts
  false positives. Add it in the per-window scoring loop in `traffic_capture.py`.
- **Feature-path parity:** confirm live preprocessing == training exactly (the `RFPreprocessor`
  DataFrame fix; the AE's `get_dummies(protocol) → reindex(features) → (x-mean)/scale → forward`
  order). Any silent mismatch (column order, missing feature → 0, wrong dtype) tanks confidence.
- **Per-class thresholds:** keep ambiguous pairs (SYN vs Port Scan) high and lean on Tier-2 rate
  confirmation; let clean classes block lower.

## Phase 5 — Validate
Re-run the full attack suite in OBSERVE mode and confirm per-class confidence now clears the bands;
report **per-class precision/recall/F1 + confusion matrix** (not accuracy). Only then move the
block thresholds and switch to AUTHORIZE.

---

## Priority if time-boxed
1. **Phase 4 temporal aggregation** — cheapest, biggest live-stability win, no retraining.
2. **Phase 3 AE re-fit to t530 normal** — fixes the "no AE verdict".
3. **Phase 1 retrain on v3 + t530 capture** — the durable accuracy lift.
4. Phase 2 calibration + Phase 5 validation to make the numbers trustworthy.
