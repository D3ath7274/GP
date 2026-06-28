# Chapter 4 — Figure Capture Guide (all 21 figures)

*Exactly how to produce each figure on the t530 deployment. Three figure types:*
- 📸 **screenshot** (terminal / browser) — run the commands, capture the window
- 📊 **plot** (matplotlib) — run a small script, save the PNG
- ✏️ **diagram** — draw it (draw.io / Excalidraw); not a capture

Substitute `<T530>` = the t530's IP, `<MN>` = the Mininet VM's IP.

---

## Common setup (do once, leave running)

**Terminal A — controller (on the t530):**
```bash
cd ~/GP/Controller
sudo SNORT_PHYS_IFACE=enp1s0 SNORT_IFACES=snort_tap IPS_V2_FEATURES=1 python3 -c "import collections,collections.abc; collections.MutableMapping=collections.abc.MutableMapping; from ryu.cmd.manager import main; main()" Controller_main_Claude.py --wsapi-port 8081 2>&1 | tee controller_run.log
```
**Terminal B — topology (on the Mininet VM):**
```bash
cd ~/GP/"SDN Topology" && sudo mn -c && sudo CONTROLLER_IP=<T530> python3 topology.py
```
**In the Mininet CLI (Terminal B), register the two IoT devices:**
```python
py net.register_iot_device(net,'TempSensor','10.0.0.5/24','00:00:00:00:00:05','s1','IOT:TempSensor')
py net.register_iot_device(net,'Cam','10.0.0.6/24','00:00:00:00:00:06','s1','IOT:Camera')
```
**Control commands (UDP 9999)** — `nc` is often missing/incompatible on the t530, so use the
bundled sender **`Controller/ipsctl.py`** (pure Python). Run it **on the t530** (defaults to localhost):
```bash
cd ~/GP/Controller
python3 ipsctl.py CONTROL:DETECT:ON
python3 ipsctl.py CONTROL:DETECT:OFF
python3 ipsctl.py CONTROL:ML:OBSERVE
python3 ipsctl.py CONTROL:ML:AUTHORIZE:0.80
python3 ipsctl.py CONTROL:ML:OFF
```
From the Mininet VM instead: `IPS_HOST=<T530> python3 ipsctl.py CONTROL:DETECT:ON`. The topology's
`py net.detect_on(net)` / `py net.detect_off(net)` CLI helpers also still work for detection.
**Attacks** (Mininet CLI): `py net.run_attack_session(net,'<kind>')` — kinds: `icmp syn udp cps scan arp`.
**Terminal C** (t530 or your laptop) is for `curl`/screenshots so you don't disturb A.

---

## The figures

### Fig 4.1 — System architecture ✏️ diagram
Not a capture. Draw the data-plane → mirror → 4 tiers → OpenFlow-DROP flow (draw.io/Excalidraw).
*(I can generate an SVG/mermaid for this — just ask.)*

### Fig 4.2 — t530 system info 📸
On the t530:
```bash
sudo apt install -y neofetch   # once
neofetch
```
Screenshot the terminal (hostname, Ubuntu 22.04, CPU, 8 GB RAM). *(For RAM detail you can also show `free -h` / `htop`.)*

### Fig 4.3 — Runtime environment 📸
On the t530:
```bash
python3 --version
pip3 list | grep -Ei 'ryu|scikit-learn|imbalanced|joblib|numpy'
```
⚠️ **Caption says Python 3.9, but this t530 is Python 3.10** (Ubuntu 22.04). Either update the caption to 3.10, or capture this figure on the 3.9 controller VM. Don't ship a 3.9 caption over a 3.10 screenshot.

### Fig 4.4 — Network topology ✏️ diagram
Draw it: TempSensor/Cam/Host1/Host2 → ap1 → s1 → Ryu (OF 1.0) + br-snort → Snort 3. *(I can generate it.)*

### Fig 4.5 — Topology launch output 📸
Run **Terminal B** (above). Screenshot the console block: `*** Creating nodes / Creating links / Starting network`, the controller-connection line, and a `pingall` (type `pingall` in the CLI) showing 0% loss.

### Fig 4.6 — OVS mirror confirmation 📸
On the **Mininet VM** (after topology is up, and the mirror is configured per `t530_bridge_setup.md` Step 4 if you use the bridge):
```bash
sudo ovs-vsctl show
```
Screenshot the `s1` bridge with its ports + the mirror/vxlan port.

### Fig 4.7 — Sample dataset rows 📸
After traffic has flowed for ~30 s, on the t530 (102 cols is too wide — show a readable slice):
```bash
cd ~/GP/Controller
head -1 dataset.csv | tr ',' '\n' | head -15        # show the first 15 column names
head -3 dataset.csv | cut -d, -f1-10 | column -t -s,  # a few rows, first 10 cols
```
Screenshot. Mention in text that the full row is 102 cols incl. `meta_*` (stripped for training).

### Fig 4.8 — Class distribution bar chart 📊
On any machine with the dataset:
```bash
python3 - <<'PY'
import csv,collections,matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
c=collections.Counter(r['attack_type'] for r in csv.DictReader(open('ML dataset/dataset_v3_master_training.csv')))
k,v=zip(*c.most_common())
plt.figure(figsize=(8,4)); plt.bar(k,v); plt.yscale('log'); plt.ylabel('rows (log)')
plt.xticks(rotation=30,ha='right'); plt.title('Class distribution'); plt.tight_layout()
plt.savefig('fig_4_8_class_distribution.png',dpi=150)
print('saved')
PY
```

### Fig 4.9 — Snort alert_json during SYN flood 📸
Mininet CLI: `py net.run_attack_session(net,'syn')`. While it runs, on the t530:
```bash
sudo tail -n 5 "$(sudo find / -name 'alert_json*.txt' 2>/dev/null | head -1)"
```
Screenshot a few raw JSON records (GID/SID, timestamp, src/dst, msg).

### Fig 4.10 — GID/SID noise-suppression code 📸
⚠️ The suppression lives in **`snort_monitor.py`**, not `Controller_main_Claude.py` — update the caption/section to point there. Capture:
```bash
grep -n "_blocked_gid_sids" -A8 ~/GP/Controller/snort_monitor.py
```
or screenshot that block in an editor.

### Fig 4.11 — Tier 2 rate-counter confirmation + block 📸
Mininet CLI: `py net.detect_on(net)` then `py net.run_attack_session(net,'icmp')` (sustained). In **Terminal A** capture the sequence: `[⚠] SUSPECTED … 1/N`, `2/N`, `[⛔] ATTACK CONFIRMED`, then the DROP/`BLOCKED` box. (Rate tier blocks on confirmation when DETECT is ON.)

### Fig 4.12 — Random Forest classification report 📊
From your RF training/eval notebook, or a script on the held-out split:
```python
from sklearn.metrics import classification_report
import joblib, pandas as pd
# X_test, y_test = your held-out split
pipe = joblib.load('Controller/ml_models/rf_pipeline.joblib')
print(classification_report(y_test, pipe.predict(X_test)))
```
Screenshot the report (per-class precision/recall/F1/support).

### Fig 4.13 — RF confusion matrix 📊
Same eval context:
```python
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt
from sklearn.metrics import ConfusionMatrixDisplay
ConfusionMatrixDisplay.from_estimator(pipe, X_test, y_test, normalize='true', xticks_rotation=45)
plt.tight_layout(); plt.savefig('fig_4_13_confusion.png',dpi=150)
```

### Fig 4.14 — AE reconstruction-error histogram 📊
This comes straight from **`Grad_Autoencoder_4.ipynb`** — the cell that scores normal vs attack reconstruction error. Plot both distributions and draw the threshold line.
⚠️ Caption says **0.73** — that's the *confidence* block band, not the raw MSE threshold. Either plot the **normalised confidence** and mark 0.73, or plot **raw MSE error** and mark the model's actual error threshold. Pick one and make the axis label match.

### Fig 4.15 — ae_bundle.joblib keys 📸
On the t530:
```bash
cd ~/GP/Controller
python3 -c "import joblib; b=joblib.load('ml_models/ae_bundle.joblib'); print(list(b.keys())); print('threshold=',b.get('threshold'))"
```
Screenshot (shows scaler, weights/layers, threshold — proves TF-free inference).

### Fig 4.16 — GET /ips/status 📸
Terminal C:
```bash
curl -s http://<T530>:8081/ips/status | python3 -m json.tool
```
Screenshot the JSON.

### Fig 4.17 — GET /ips/blocked with an active block 📸
First create a block: on the t530 `python3 ipsctl.py CONTROL:ML:AUTHORIZE:0.80`, then in the
Mininet CLI `py net.detect_on(net)` and `py net.run_attack_session(net,'syn')`. Then Terminal C:
```bash
curl -s http://<T530>:8081/ips/blocked | python3 -m json.tool
```
Screenshot showing the block entry (IP, MAC, tier, attack type, time).

### Fig 4.18 — Live attack: Tier 1 + Tier 3 + DROP 📸
`py net.detect_on(net)` + ML AUTHORIZE (above) + `py net.run_attack_session(net,'syn')`. In **Terminal A** capture: `🚨 IDS ALERT` (Tier 1), `[ML] ATTACK (block) … conf=0.xx` (Tier 3), then `ATTACKER BLOCKED`.

### Fig 4.19 — Dashboard, idle 📸 (browser)
Controller up, no attack. Open `http://<T530>:8081/`. Screenshot: tiers green, threat **LOW/CLEAR**, blocked table empty.

### Fig 4.20 — Dashboard, during SYN flood 📸 (browser)
With the dashboard open, run the AUTHORIZE + SYN-flood sequence from 4.18. Screenshot while it's active: threat **HIGH/UNDER ATTACK**, attacker in the blocked table, event in the timeline.

### Fig 4.21 — Dashboard resource-health panel 📸 (browser, zoomed)
`/ips/metrics` now emits CPU/RAM/Disk (psutil). Install it once on the t530:
`sudo pip3 install psutil`, restart the controller, run a sustained attack, and screenshot the
zoomed health panel (RAM · CPU · Disk). If those read `—`, psutil isn't installed in the
interpreter Ryu runs under.

---

## Quick status
- **Ready now:** 4.2, 4.3, 4.5, 4.6, 4.7, 4.9, 4.10, 4.11, 4.15, 4.16, 4.17, 4.18, 4.19, 4.20.
- **Run a script:** 4.8, 4.12, 4.13, 4.14 (4.12–4.14 from your notebooks).
- **Draw:** 4.1, 4.4 (offer: I'll generate SVGs).
- **Ready (needs `sudo pip3 install psutil` once):** 4.21.
- **Caption fixes:** 4.3 (3.9→3.10), 4.10 (file is `snort_monitor.py`), 4.14 (0.73 is confidence, not MSE).
- **All control commands use `Controller/ipsctl.py`** (UDP 9999) — `nc` is unreliable on the t530.
