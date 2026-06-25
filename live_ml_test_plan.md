# Plan 2 — Live ML Test with Confidence (step by step)

*Watch the integrated models classify live attacks and report a **confidence number**.
Rule: **confidence < 60% → silently do nothing** (no log, no action); **60–80% → flag +
alert**; **≥ 80% → block** (Random Forest). The autoencoder is added later as a
concurrent Tier 4 with the same 60% silent floor and its own block bar (73%).*

---

## Step 1 — (prep) Implement the 60% silent floor

Target behaviour (per detector):

| Confidence | Random Forest | Autoencoder (later) |
|---|---|---|
| `< 60%` | **silent — do nothing** (no log) | silent — do nothing |
| `60–below block` | flag + alert | flag + alert |
| block bar | **≥ 80% → block** | **≥ 73% → block** |

- Set the live bars: `CONTROL:ML:FLAG:0.60` and `CONTROL:ML:BLOCK:0.80`.
- In **AUTHORIZE** mode the controller **already** ignores anything below the flag
  threshold (no action, no warning), so `FLAG:0.60` gives the silent floor for blocking.
- In **OBSERVE** mode the code currently logs **every** non-normal verdict regardless of
  confidence. To make OBSERVE respect the 60% floor (so the test only surfaces ≥ 60%),
  add a one-line gate in `traffic_capture.py` (the `[ML-OBSERVE]` block, ~line 1165):
  *only emit the log line when `ml_conf >= flag_thr`.* **(Small change — I can implement
  it on request.)**

**GATE:** bars set; OBSERVE gated at 0.60.

## Step 2 — Start the controller with the model loaded

```bash
cd ~/.../GP/Controller
sudo IPS_V2_FEATURES=1 ryu-manager Controller.py
```
**GATE:** log shows `ML engine loaded … pipeline` (the deployed `rf_pipeline.joblib`).

## Step 3 — Enable detection + observe mode (safe: no blocking)

Send over UDP 9999 (from VM2, or your control script):
```
CONTROL:DETECT:ON
CONTROL:ML:OBSERVE
CONTROL:ML:FLAG:0.60
CONTROL:ML:BLOCK:0.80
```
**GATE:** controller confirms `ML MODE: OBSERVE` and the new flag/block thresholds.

## Step 4 — Drive live attacks

From the topology VM, run attacks while watching the VM1 log. Either per type:
```python
py net.run_attack_session(net,'icmp')     # then 'syn','udp','scan','arp','cps'
```
or the high-yield top-up (`py net.run_full_topup(net)`) to exercise the thin classes.
**GATE:** attacks are running and the controller is printing window activity.

## Step 5 — Read the confidence output

In OBSERVE you will see lines like:
```
[ML-OBSERVE] 10.0.0.1 -> 10.0.0.4  verdict=SYN Flood  conf=0.82  band=BLOCK
```
With the 0.60 gate, **only predictions ≥ 60% appear**; anything weaker is silent.
**Record per class:** the correct-verdict rate and the confidence distribution, and how
many windows land in each band (`silent <60` / `flag 60–80` / `block ≥80`). This is the
real-time readiness of the **current RF** — the headline you wanted.

## Step 6 — (Optional) Confirm real blocking in AUTHORIZE

On a throwaway run, flip `CONTROL:ML:AUTHORIZE`. Verify: `conf ≥ 0.80` → OpenFlow DROP
installed; `0.60–0.80` → flagged + evidence, no block; `< 0.60` → nothing. Release with
`CONTROL:UNBLOCK:<ip>`. **GATE:** blocking fires only at/above the 0.80 bar; sub-60% is
silent. Return to OBSERVE for further testing.

## Step 7 — Record the result

PASS for the current RF if: true attacks surface at **conf ≥ 60%** with the correct
attack-type, the strong cases reach the **≥ 80% block** band, and benign/uncertain
windows stay **silent (< 60%)** — i.e. no log spam, no false blocks. Note any class that
sits stuck in 60–80% (flag-only); those are the ones the bigger dataset (Plan 1 retrain)
should push over 80%.

## Step 8 — Add the Autoencoder later (Tier 4, concurrent)

When the Keras AE is wired in (runs **concurrently** with the RF on the same window row):
- Map its reconstruction error → a 0–100% **anomaly confidence** (percentile of the
  normal-error distribution).
- Apply the same **60% silent floor**, with the AE block bar at **73%** (flag 60–73%).
- Re-run Steps 4–7; report **both** models' confidence side by side. Most-severe action
  wins (block > flag > silent), so an unknown/zero-day the RF misses can still be caught
  by the AE crossing its 73% bar.

---

## At-a-glance order
1 set 60% floor (FLAG 0.60 / BLOCK 0.80 + OBSERVE gate) → 2 controller up → 3 DETECT ON +
OBSERVE → 4 run attacks → 5 read conf, tally bands → 6 (opt) AUTHORIZE block check →
7 record RF result → 8 add AE (same floor, 73% block) and repeat.
