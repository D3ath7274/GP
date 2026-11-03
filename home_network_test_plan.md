# Home-Network Test Plan — HP t530, real data collection and online learning

How to take the IPS from the testbed onto a real home network. The plan has three goals:

1. Collect a real dataset in the existing 102-column schema.
2. Retrain the models on it.
3. Run a **guarded online-learning loop** that keeps the models current without letting an
   attacker teach them what "normal" is.

Enforcement comes last and stays reversible.

Related runbooks: [`pre_production_collection_runbook.md`](pre_production_collection_runbook.md)
(collection commands), [`red_team_test_runbook.md`](red_team_test_runbook.md) (attack
mechanics), [`production_readiness_results.md`](production_readiness_results.md) (KPI sheet).
This plan sequences them for a home network and adds what they lack.

---

## What exists today vs. what this plan adds

| Part | Today | This plan |
|---|---|---|
| Per-device baselines | **Already online** — EMA (α = 0.1) plus a running mean/variance (Welford), updated every 5 s window | Persist them across restarts |
| AE / RF models | Static. Retraining is a manual offline script, and loading a new model needs a **controller restart** | Nightly recalibration, shadow evaluation, promotion **without a restart** |
| Anti-poisoning | Attack-labelled flows never update a baseline — but in capture-only mode every flow is labelled normal, so the guard is off | An eligibility filter on what the models are allowed to learn from |
| `device_new_dst_ratio` | **Broken:** only ever `0.0` or `1.0` (verified on 33k rows). Both shipped models were trained on it | Fix **before** collecting |

---

## Phase overview

| # | Phase | Time | Exit gate |
|---|---|---|---|
| 0 | Code changes before collecting anything | 2–4 days dev | Fixes merged, unit-checked, schema unchanged |
| 1 | Hardware and inline bring-up (Mode A) | 1 evening | Internet works through the t530; the bypass is tested |
| 2 | Smoke test and performance baseline | 1 evening | Capture completeness, throughput, and disk budget measured and acceptable |
| 3 | Normal-traffic collection (capture-only) | ≥ 48 h, target 7 days | Every device mature, no gaps |
| 4 | Labelled attack captures (Kali) | 1–2 evenings | One capture per class, plus a held-out regression set |
| 5 | Retrain and validate in OBSERVE | 2–3 days | At-rest false-positive (FP) gate passes, held-out attacks detected |
| 6 | Online-learning loop | ≥ 2 weeks | Drift absorbed, poisoning resisted (both measured) |
| 7 | Controlled enforcement | 1 week | Red-team blocks work, zero collateral blocks |

---

## Phase 0 — Code changes (do these first; collected data depends on them)

Changing what a feature means **after** collecting makes the dataset inconsistent with the
live code — the train/serve skew this project is built to prevent. So fix features first and
collect second.

| # | Change | Why | Needed for |
|---|---|---|---|
| 0.1 | **Fix `device_new_dst_ratio`** in `traffic_capture.py` `DeviceProfile`. Record whether a destination is new *before* adding it to `all_dst_ips`, and keep a per-window `recent_new_dst_ips` set | Today it computes `recent − (all − recent)`, which equals `recent`, so the ratio is a constant. This is the feature that should catch a camera suddenly talking to new servers (C2, exfiltration) — the most useful real-world IoT signal | Phase 3 |
| 0.2 | **Persist device profiles**: snapshot every 10 min and on shutdown, load at startup | There is no persistence today, so every restart resets every device to cold-start (immature for 180 s and 20 flows) and discards the learned baselines | Phases 3, 6 |
| 0.3 | **Hot model reload**: `CONTROL:ML:RELOAD` and `CONTROL:ML:ROLLBACK` | Load the candidate bundle off the hot path, then swap the model reference in one assignment, so the flush thread sees the old model or the new one, never half of each. Keep the previous model for rollback. Without this, promoting a model means a restart, which (until 0.2) wipes the baselines | Phase 6 |
| 0.4 | **Model ledger** (`ml_models/ledger.jsonl`): version, training window, row count, threshold, gate results | Lets you explain why the model changed on any given day | Phase 6 |
| 0.5 | **`recalibrate_nightly.py` + `shadow_eval.py`** | Builds the candidate AE bundle from *eligible* rows, replays a holdout plus the attack regression set, then promotes or rejects. `ML model/eval_live.py` is stale (it points at a pipeline that no longer exists), so this is new | Phase 6 |
| 0.6 | **Time-based split** option in `build_ae_bundle.py` (`--time-split`) | The current random split puts neighbouring windows from the same minute in both train and validation. That makes the p99 threshold optimistic, which shows up as more FPs on genuinely new days | Phase 5 |
| 0.7 | **Daily rotate + gzip, plus a disk alarm** | See the Phase 2 disk budget — raw CSV can run to gigabytes per day on a busy home network | Phase 3 |

**Decision you'll face:** whether the device baseline should *forget*. Today the z-score
deviation uses a cumulative Welford mean, which never forgets.

- **Forgetting** (exponentially weighted variance) follows legitimate slow change, such as a
  new app or a firmware update.
- **But** it lets a patient attacker drift the baseline ("boiling frog").

Recommendation: keep it cumulative for now. Revisit only if Phase 6 drift monitoring shows
legitimate change producing persistent FPs.

---

## Phase 1 — Hardware and inline bring-up (Mode A, transparent bridge)

**Why Mode A:** the t530 has one NIC and no Wi-Fi radio. A second wired port turns it into
an invisible L2 bridge. Devices keep their IPs, their DHCP, and the home router as gateway.
It's the least disruptive inline mode and gives the cleanest data (no NAT and no hairpin
double-counting).

**Buy:** a USB 3.0 Gigabit Ethernet adapter (RTL8153 or AX88179 chipset, in-kernel), one
small unmanaged switch, and optionally an old Wi-Fi router set to **AP/bridge mode with its
DHCP off**.

```
ISP router 192.168.1.1  (keeps DHCP; its own Wi-Fi BYPASSES the IPS)
   │ LAN port
 [enp1s0] ── t530: OVS br-lan (transparent L2, fail-open) ── [enx<usb>]
                                                                 │
                                                       unmanaged switch
                                                ├── wired PC
                                                └── old router in AP mode, SSID "Home-IPS"
                                                      └── phones, cameras, IoT under test
```

**Placement rules (the visibility limits are physical):**
- Only devices **downstream** of the t530 are inspected. Move every test device to the
  `Home-IPS` SSID; anything left on the ISP router's Wi-Fi is invisible.
- Two downstream devices talking to each other cross the switch, **not** the t530, so that
  traffic is invisible. For the Kali tests, put Kali **upstream** (on the ISP router's
  Wi-Fi) and the victim downstream, so the attack crosses the bridge.

**Bring-up (at the t530's own console — the management IP moves):**
```bash
ip -br link                                   # find the USB NIC name: enx…
ls /etc/netplan/ && sudo cp /etc/netplan/*.yaml ~/netplan.backup/   # back up first
```
Persist it with netplan (`/etc/netplan/01-ips-bridge.yaml`). Pin `macaddress` to enp1s0's MAC
so the router's DHCP keeps handing the t530 the same IP (`192.168.1.36`):
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp1s0: {dhcp4: false}
    enx<usb>: {dhcp4: false}
  bridges:
    br-lan:
      interfaces: [enp1s0, enx<usb>]
      macaddress: <enp1s0 MAC>
      dhcp4: true
      openvswitch:
        fail-mode: standalone          # FAIL-OPEN: if the controller dies, the house stays online
        protocols: [OpenFlow10]
        controller:
          addresses: [tcp:127.0.0.1:6633]
```
```bash
sudo netplan try          # auto-reverts in 120 s unless you confirm — your safety net
```

**Configure `Controller/ips_config.json`** (check the subnet with `ip route`):
```json
{
  "lan_cidr": "192.168.1.0/24",
  "ext_whitelist": ["127.0.0.1", "::1", "192.168.1.1", "192.168.1.36", "<admin laptop IP>"],
  "protected_macs": ["<router MAC>", "<t530 br-lan MAC>", "<admin laptop MAC>"]
}
```
The **router MAC in `protected_macs` is mandatory**. A DROP on the router's MAC takes the
whole house offline.

**Exit gate:**
1. Internet works for downstream devices with the controller **stopped** (plain fail-open
   bridge).
2. You've rehearsed the **physical bypass**: unplug the t530 and connect the switch straight to
   the router.
3. Everyone in the house knows how to do step 2.

---

## Phase 2 — Smoke test and performance baseline

**Why this phase matters:** the controller installs every forwarding flow with an extra
`output:CONTROLLER` action (`Controller_main_Claude.py:1499`). Every packet is therefore also
copied up through `ovs-vswitchd` to a Python process. Forwarding stays in the kernel, so the
house mostly keeps working. The IPS, however, may only see **part** of the traffic under load,
and its features would then be computed on a sample. This is the scale ceiling from the
assessment, measured for real.

1. Launch in capture-only mode (launch line from the
   [collection runbook](pre_production_collection_runbook.md), Phase 1, with
   `IPS_V2_FEATURES=1`). Check `GET /ips/switches` = 1 and that `dataset.csv` is growing.
2. **Capture completeness**: over 10 minutes of normal use, compare the bridge's packet
   counters with what the controller saw:
   ```bash
   sudo ovs-ofctl dump-ports br-lan          # rx_packets per port, before and after
   ```
   against the sum of `total_packets` in `dataset.csv` for the same windows.
3. **User impact**: run a speed test and a ping/jitter test from a downstream laptop, once with
   the controller stopped and once running. Then do it again during a 4K stream or a video
   call.
4. **Controller health**: watch `meta_controller_load` (flush time; above 5000 ms is a
   problem), `meta_backlog_drops` (should stay ≈ 0), and CPU/RAM in `/ips/metrics`.
5. **Disk budget**: count rows per hour × bytes per row, then project per day. The t530 has
   about 18 GB free. If 7 days of raw CSV don't fit, the gzip rotation (0.7) is mandatory.

**Exit gate:**
- Completeness ≥ 95 % at normal load (record the figure under heavy load too — it's a result).
- Browsing and video calls are unaffected.
- Flush time < 5000 ms.
- The disk projection fits with a 30 % margin.

---

## Phase 3 — Normal-traffic collection (capture-only)

Leave DETECT and ML **off** (the startup default), so every row is written with label normal
and nothing is blocked.

- **Duration:** at least 48 h; ideally 7 days, so you capture weekday and weekend cycles,
  idle nights, and busy evenings.
- **Stable identities:** profiles are keyed by IP. Create **DHCP reservations** on the router
  for every test device, otherwise an IP change splits one device into two baselines.
  Phones: per-network private MACs are fine; *rotating* MAC modes are not.
- **Register devices** from the router's DHCP client list:
  ```bash
  python3 ipsctl.py REGISTER:NAME:frontcam:192.168.1.60
  python3 ipsctl.py REGISTER:IOT:192.168.1.60:IOT:Camera
  ```
- **Rules during collection:** Kali powered off, no scanners, no restarts (until 0.2 is in),
  daily `CONTROL:ROTATE` snapshot.
- **Keep a life log** (`collection_log.md`): firmware updates, guests, a new device, a
  speed test. Later, when a model flags a window, you can tell a legitimate novelty from an
  attack. Without the log, you can't.
- **Daily checks:** disk space; every registered IP appears as a source;
  `is_baseline_mature` = 1 for the established devices; `device_new_dst_ratio` takes values
  between 0 and 1 (proves 0.1 worked).

**Exit gate:** ≥ 48 h with no gaps, every device mature, life log kept.

---

## Phase 4 — Labelled attack captures (Kali, your own devices only)

Follow the [collection runbook](pre_production_collection_runbook.md), Phase 4
(`LABEL_OVERRIDE` per class, then a `CONTROL:ROTATE` snapshot). For a home network:

- **Victims are your own test devices, never the ISP router.** Start floods rate-limited
  (`hping3 -i u1000`) before trying `--flood`. A consumer router can crash and take the
  household down with it.
- **Include the evasive variants** the tiers are expected to miss — a slow scan
  (`nmap -T1`) and a low-rate SYN. A measured blind spot is a result, not a failure.
- **ARP spoofing** briefly disrupts the victim. Keep it short and aimed at a test device only.
- **Hold out one capture per class** and never train on it. It becomes the **regression set**
  that every future model must still detect (Phase 6).
- **Exclude victim backscatter from normal training.** `LABEL_OVERRIDE` labels only the
  attacker's rows; the victim's RST and ICMP replies stay labelled normal. Note the start and
  end time of every attack in the life log.

---

## Phase 5 — Retrain and validate in OBSERVE

- **AE:** build it from the **Phase 3 normal snapshots only** (not the merged file — see
  backscatter above), with the time split from 0.6:
  ```bash
  python3 ml_models/build_ae_bundle.py --csv real_normal.csv \
    --h5 ml_models/autoencoder_tighter_bottleneck_16units.h5 --percentile 99 \
    --out ml_models/ae_bundle.joblib
  ```
  This refits the scaler and the threshold; the network **weights stay testbed-trained**. The
  corrected `device_new_dst_ratio` is absorbed by the scaler but not learned. A full weight
  retrain needs the notebook (`git checkout pre-deployment-cleanup -- …`) plus TensorFlow on a
  laptop.
- **RF:** `retrain_rf_v4.py` (scikit-learn 1.6.1) on home normal plus home attack captures.
  **Don't merge old v4 testbed rows** — their `device_new_dst_ratio` means something different.
  **Split by time, not at random**: random splits leak neighbouring windows and inflate
  accuracy.
- **Validate:** `CONTROL:DETECT:ON` + `CONTROL:ML:OBSERVE` for 48 h of normal life.

**Gates:**
- **FP gate:** at most 1 flag per device per day at rest, and every flag explained by the life
  log.
- **Detection gate:** every regression-set class detected when replayed or re-run.
- **Record** FP per device per day, detection rate per class, and time to detect.

---

## Phase 6 — The online-learning loop (scheduled and guarded)

"Online learning" here works at three speeds. Only the slow two are new:

| Speed | What adapts | Mechanism |
|---|---|---|
| Seconds | Per-device baselines | Already online: EMA and running mean/variance every window (persisted after 0.2) |
| Nightly | AE scaler and threshold | `recalibrate_nightly.py` on a sliding 7-day window, then shadow evaluation, then promotion via `RELOAD` |
| Monthly / manual | RF, AE weights | Retrain with new labelled data; a human approves |

**Eligibility filter (anti-poisoning).** A row may train the model only if **all** of these
hold:
- `label == 0` and `is_baseline_mature == 1`
- the source isn't Kali and isn't quarantined
- no Snort alert, ML flag, or block for that source within ± 5 windows
- not inside a logged attack window ± a margin

**Promotion gates (all must pass):**
1. The candidate threshold is within ± 15 % of the current one. A bigger jump means drift or
   poisoning, so it goes to a human.
2. At-rest flag rate on the last day is no worse than the current model's.
3. The regression attack set is still detected at least as well.
4. A ledger entry is written; the previous model is kept for `ROLLBACK`.

**Drift monitoring** (daily, in the ledger): AE reconstruction-error percentiles, flags per
device, and a population-stability index on the top features.

**Why not true per-sample online learning?** If the model updated on every window, a slow
attacker could teach it that their behaviour is normal (boiling-frog poisoning). There would
also be no point at which a human could review a bad update, and no clean rollback. The
nightly loop with quarantine, gates, and a ledger is how production anomaly detectors work.

**Two experiments to run — these are your strongest thesis results:**
1. **Drift absorption:** add a new device (a smart plug) mid-phase. Expect it to be flagged at
   first and then absorbed once it's mature and eligible. Measure **days to absorb**.
2. **Poisoning resistance:** Kali runs a very slow scan for several days. The quarantine
   should keep it out of training, and the threshold should not creep. Measure the
   **threshold trajectory** with and without the eligibility filter.

---

## Phase 7 — Controlled enforcement

1. Re-check `protected_macs`: router, t530, admin laptop, and any device that must never be
   cut off.
2. Launch with `IPS_BLOCK_SECONDS=300` so a false positive heals itself in 5 minutes.
   Move to permanent blocks only after a clean week.
3. `CONTROL:DETECT:ON` + `CONTROL:ML:AUTHORIZE:0.85`.
4. Red-team from Kali per [`red_team_test_runbook.md`](red_team_test_runbook.md). Record
   time to block and collateral blocks (must be zero).

**Rollback, fastest first:**
- `CONTROL:ML:OFF` / `CONTROL:DETECT:OFF`
- `sudo ovs-vsctl del-controller br-lan` (becomes a plain fail-open bridge)
- unplug the t530 and connect the switch to the router

---

## Metrics to record (results-chapter ready)

| Metric | Phase |
|---|---|
| Capture completeness (%) at normal and heavy load | 2 |
| Throughput and latency with vs. without the controller | 2 |
| Flush time (ms), backlog drops, CPU, disk per day | 2–3 |
| FP per device per day at rest (before vs. after retraining) | 5 |
| Detection rate and time to detect per attack class, including evasive variants | 4–5 |
| Days to absorb a new device | 6 |
| Threshold trajectory under slow poisoning, with vs. without the eligibility filter | 6 |
| Time to block, collateral blocks | 7 |

## Home-specific risks

- **Household disruption.** The design is fail-open, the bypass is rehearsed, and attack tests
  happen in announced windows.
- **Privacy of the people you live with.** The dataset holds their IPs, destinations, and
  timing patterns. Tell them, keep the data on the t530, and anonymise IPs before anything
  appears in the thesis.
- **ISP router Wi-Fi bypasses the IPS.** Test devices must sit on the downstream SSID.
- **Device identity follows the IP.** DHCP reservations are mandatory, and rotating-MAC modes
  stay off on test phones.
