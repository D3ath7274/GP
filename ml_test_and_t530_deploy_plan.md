# ML Test + HP t530 Deployment Plan (step by step)

*Now that the autoencoder (Tier 4) is wired into the controller alongside the Random
Forest (Tier 3), this plan (A) tests both models live with confidence output, then
(B) deploys on the HP t530 thin client. Do each step, pass its GATE, then continue.*

**What's in place (main repo):**
- `Controller/ml_models/rf_pipeline.joblib` — RF (Tier 3), needs scikit-learn.
- `Controller/ml_models/ae_bundle.joblib` — AE (Tier 4), **pure NumPy** (no TensorFlow,
  no sklearn). Rebuilt from your `.keras` + training CSV; validated (p95≈0.0375; normal
  mean-conf 0.16, attack mean-conf 0.73, ~47% of attack windows ≥0.73 block bar).
- `Controller/ae_inference.py` + AE hook in `traffic_capture.py` + wiring in `Controller.py`.
- Bands: **AE** flag 0.60 / block 0.73, silent <0.60. **RF** flag 0.80 / block 0.90
  (tune live with `CONTROL:ML:FLAG`/`BLOCK`).

---

## PART A — Test both ML models now

### A1. Deploy the updated files to the controller VM
`git pull` (or scp) so the VM has: `ae_inference.py`, the updated `Controller.py` +
`traffic_capture.py`, and **`ml_models/ae_bundle.joblib`** + `rf_pipeline.joblib`.
**GATE:** `ls Controller/ml_models/` shows both `rf_pipeline.joblib` and `ae_bundle.joblib`.

### A2. (Optional) RF train/serve-skew sanity
```bash
cd Controller && python3 verify_inference.py --model-dir ml_models \
    --data dataset_v2_master_training.csv --ref rf_reference_predictions.csv
```
**GATE:** `RESULT: PASS ✅` (RF deployed == notebook).

### A3. Start the controller
```bash
sudo IPS_V2_FEATURES=1 ryu-manager Controller.py
```
**GATE:** the log shows all three:
`Feature schema mode: v2 (corrected)` ·
`ML engine loaded end-to-end pipeline … (7 classes)` ·
`AE engine loaded …/ae_bundle.joblib (60 features, threshold=0.03750, 4 layers)`.

### A4. Put the system in pure-ML test mode (models classify on their own)
Send over UDP 9999:
```
CONTROL:DETECT:OFF       # so rate/Snort don't pre-label; RF+AE score every flow
CONTROL:ML:OBSERVE       # predict + log, NO blocking
```
**Why DETECT OFF:** with it on, the rate/DAI/Snort tiers label floods first and the RF
hook skips them; off, every flow stays label-0 so **both** RF and AE give their own
verdict. **GATE:** controller confirms `ML MODE: OBSERVE`.

### A5. Drive live attacks (topology VM)
```python
py net.run_full_collection_hy(net)        # all 6 attacks + normal, one command
# or per type: py net.run_attack_session(net,'syn')   ('icmp','udp','scan','arp','cps')
```
**GATE:** attacks running; controller printing window activity.

### A6. Read the confidence output (the deliverable)
You'll see, per window, **both** models' opinions:
```
[ML-OBSERVE] 10.0.0.1 → 10.0.0.4  verdict=SYN Flood   conf=0.74  band=…
[AE-OBSERVE] 10.0.0.1 → 10.0.0.4  anomaly conf=0.81  err=0.1620  band=BLOCK
```
- **RF** logs every non-normal verdict + confidence (regardless of how low).
- **AE** logs only conf ≥ 0.60 (silent below → normal traffic doesn't flood the log).
**Record per attack class:** RF verdict + conf distribution, AE anomaly conf, and the
% of attack windows each puts in flag (≥0.60/0.80) and block (≥0.73/0.90) bands.
**GATE:** real attacks surface with high confidence; benign/normal stays quiet.

### A7. (Optional) Confirm real blocking
Flip `CONTROL:ML:AUTHORIZE` on a throwaway run: RF blocks at ≥0.90 (tune via
`CONTROL:ML:BLOCK:0.80`), AE blocks at ≥0.73, `Anomaly (AE)` labels for zero-day hits.
Release with `CONTROL:UNBLOCK:<ip>`. Return to OBSERVE after.
**GATE:** blocks fire only at/above the bars; sub-band traffic is untouched.

---

## PART B — Deploy on the HP t530 thin client (8 GB)

### B1. Confirm the controller interpreter (the #1 risk)
The controller imports the models **in-process**, so Ryu's Python must satisfy them.
```bash
ryu-manager --version          # note its python
python3 -c "import sys; print(sys.version)"   # must be >= 3.9 for sklearn 1.6.1
```
**GATE:** `ryu-manager` runs on Python ≥ 3.9. **Do not repoint the system python** (it
broke Ryu before) — use the interpreter Ryu is installed under.

### B2. Install runtime deps (RF only — the AE needs none)
```bash
pip install --only-binary=:all: scikit-learn==1.6.1 "pandas<2.3" "numpy<2.3" joblib
```
**No TensorFlow, no extra ML libs** — the AE runs in pure NumPy (already present).
**GATE:** `python3 -c "import sklearn, numpy, pandas, joblib; print(sklearn.__version__)"`
prints `1.6.1` in *the same interpreter Ryu uses*.

### B3. Copy the project to the t530
Copy the `Controller/` dir **including** `ml_models/rf_pipeline.joblib` +
`ml_models/ae_bundle.joblib`, plus `SDN Topology/` if collecting there.
**GATE:** both model files present on the t530.

### B4. (Optional) Snort 3 schema
For the clean 6-attack signatures: install the Snort 3 binary, then
`sudo ./scripts/install_snort3_ips_config.sh` + `sudo snort -c /etc/snort/sdn_ips.lua -T`.
Otherwise the controller auto-falls back to Snort 2.x (collection/detection still work).
**GATE:** `snort -V` reports v3 (only if you want the Snort 3 schema).

### B5. Launch and confirm load
```bash
sudo IPS_V2_FEATURES=1 ryu-manager Controller.py
```
**GATE:** same three lines as A3 (v2 schema, RF loaded, AE loaded) — on the t530.

### B6. Resource + latency check under load
Run an attack session; watch on the t530:
- **RAM** stays within 8 GB (AE adds only ~MBs; RF pipeline ~tens of MB).
- **Window compute time** stays **< 5000 ms** under a flood (`meta_controller_load`);
  if it backs up, lower flood rate or shorten windows.
**GATE:** no window backlog; RAM headroom remains.

### B7. Staged go-live (reversible)
1. **Capture-only** (`DETECT:OFF`, `ML:OFF`) — confirm the t530 sees traffic and writes rows.
2. **Observe** (`DETECT:OFF` + `ML:OBSERVE`) — watch `[ML-OBSERVE]`/`[AE-OBSERVE]`; confirm
   verdicts match the lab test (A6). For the deployed/layered view, also try `DETECT:ON`.
3. **Authorize** (`DETECT:ON` + `ML:AUTHORIZE`) — start with conservative bars (RF block
   0.90, AE block 0.73); operator on call for `CONTROL:UNBLOCK:<ip>`.
**Rollback at any time:** `CONTROL:ML:OFF` + `CONTROL:DETECT:OFF` → instant capture-only.

---

## At-a-glance order
A1 deploy files → A2 RF skew → A3 start (RF+AE load) → A4 DETECT OFF + OBSERVE →
A5 run attacks → A6 read RF+AE confidence → A7 (opt) AUTHORIZE block check →
B1 verify Ryu python → B2 deps (no TF) → B3 copy models → B4 (opt) Snort 3 →
B5 launch on t530 → B6 RAM/latency under load → B7 staged go-live (capture→observe→authorize).

---

## Notes
- The AE uses the **small-data** weights for now. After you retrain on the bigger
  dataset, rebuild `ae_bundle.joblib` (same format) and drop it in — no code change.
- If you ever change the AE architecture, the bundle's `layers`/`features` must match;
  rebuild from the new `.keras` + CSV the same way this one was made.
- The AE's `protocol_normal` feature is a training artifact (the notebook one-hot also
  dummified `attack_type`); it is constant during DETECT-OFF testing, so it doesn't
  distort results there. Worth cleaning up at the next retrain.
