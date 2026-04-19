# Complete Implementation Instructions
## SDN-Based IoT IPS — Dataset Generation & Controller Enhancement

---

> **How to use this document**
> Every action is numbered. Every code change includes the exact location, the exact lines to touch, and the exact code to write. Read the reasoning block before each set of steps — it explains *why* you are doing something, not just what. Never skip a verification step. They exist because silent failures in this system compound — a wrong column count in Session 1 will corrupt all three sessions.

---

# PHASE 1 — Code Fixes (Do This Before Anything Else)

## Why Phase 1 must come first

You cannot collect a single row of useful data until the code is correct. The three bugs in `traffic_capture.py` are silent — they do not crash the program, they just corrupt behavior. The duplicate `set_detection_mode` stub means toggling detection on/off does not reset the rate counters, which means stale window data from your baseline phase bleeds into your attack phase and triggers false positives on the first attack window. That would corrupt your labels from minute one of Session 1. Fix the code first. Data collection second.

---

## Action 1.1 — Fix Bug: Duplicate `set_detection_mode` stub

**File:** `traffic_capture.py`
**Location:** Around line 833, just after `_compute_network_context` ends

**What the bug is:**
The full `set_detection_mode` implementation is at line ~336. It resets all rate counters, clears logged attackers, and logs a message. A second stub definition exists at line ~833 that only sets `self._detection_enabled = enabled` and does nothing else. In Python, when a class defines the same method name twice, the second definition silently replaces the first. The full implementation is dead code. Every time you send `CONTROL:DETECT:ON`, nothing gets reset.

**Steps:**

1. Open `traffic_capture.py` in your editor.

2. Use Ctrl+F (or your editor's search) to find the string `def set_detection_mode`. It will highlight two results. Note both line numbers.

3. Navigate to the **second** result (the one around line 833). It looks exactly like this:
   ```python
   def set_detection_mode(self, enabled):
       """Toggle true anomaly detection vs baseline capture."""
       self._detection_enabled = enabled
   ```

4. Select the entire method — that is, all 3 lines including the `def` line, the docstring line, and the `self._detection_enabled = enabled` line.

5. Delete those 3 lines completely. Do not leave a blank line in their place if it creates an awkward double-blank between `_compute_network_context` and `manual_unblock`. One blank line between methods is correct.

6. Verify: use Ctrl+F to search `def set_detection_mode` again. You should now see exactly one result, located around line 336.

**Verification:** The remaining implementation should look like this (your version may have minor differences but must contain the counter resets):
```python
def set_detection_mode(self, enabled):
    """Toggle anomaly detection on/off. When off, all traffic is labeled 'normal'."""
    self._detection_enabled = enabled
    if enabled:
        self._attack_confirmations = {}
        self._active_blocks = {}
        self._logged_attackers = set()
        with self._flow_lock:
            self._host_icmp_count = defaultdict(int)
            self._host_syn_count = defaultdict(int)
            self._host_ack_count = defaultdict(int)
            self._host_udp_count = defaultdict(int)
            self._host_dst_ports = defaultdict(set)
        self._log('info', 'Detection mode ENABLED — anomaly detection active (counters reset)')
    else:
        self._log('info', 'Detection mode DISABLED — capture only, all labels = normal')
```

---

## Action 1.2 — Fix Bug: Duplicate `label_features` assignment

**File:** `traffic_capture.py`
**Location:** Inside `_build_flow_row`, around lines 777–787

**What the bug is:**
The dictionary `label_features` is constructed and then immediately constructed again with identical content. This is harmless in terms of output but is a copy-paste artifact that signals the surrounding code was edited carelessly. Clean it now before your IDE's AI adds more code around it.

**Steps:**

1. Inside `_build_flow_row`, search for `label_features = {`. It will appear twice in close succession.

2. The block looks like this:
   ```python
   label_features = {
       'label': label,
       'attack_type': attack_type,
       'snort_sid': snort_sid,
   }

   label_features = {
       'label': label,
       'attack_type': attack_type,
       'snort_sid': snort_sid,
   }
   ```

3. Delete the **second** assignment block (lines 783–787 approximately) including the blank line before it. Keep only the first assignment.

4. The result should be a single `label_features = { ... }` block followed by a blank line and then the `# Merge all features` comment.

---

## Action 1.3 — Fix Bug: Unreachable dead code block

**File:** `traffic_capture.py`
**Location:** Inside `_build_flow_row`, around lines 797–803

**What the bug is:**
After the first `return row` statement (around line 795), there is an entire duplicate merge-and-return block that can never execute. Python executes `return` and exits the function immediately. Everything after it in the same scope is dead. It adds confusion and will cause your IDE's AI to get disoriented about what the actual return path is.

**Steps:**

1. After the `return row` statement inside `_build_flow_row`, look for another block that begins with `# Merge all features`. It looks like this:
   ```python
   return row

       # Merge all features
       row = {}
       row.update(flow_features)
       row.update(device_features)
       row.update(network_ctx)
       row.update(label_features)
       return row
   ```

2. Delete everything from the `# Merge all features` comment down to and including the second `return row`. The method should now end cleanly with a single `return row`.

3. The end of `_build_flow_row` should now look like:
   ```python
       row.update(flow_features)
       row.update(device_features)
       row.update(network_ctx)
       row.update(label_features)
       return row
   ```

4. Make sure `_compute_network_context` begins cleanly on the next line after one blank line.

---

## Action 1.4 — Add `COLLECTION_MODE` constant to Controller.py

**File:** `Controller.py`
**Location:** Near the top of the file, in the constants/configuration section

**Why this matters:**
This is the most operationally critical fix in the entire plan. Your controller mirrors every single data-plane packet to itself via `OFPP_CONTROLLER`. During a sustained 150,000 PPS flood, this creates an enormous processing queue. If you have any form of packet-in rate limiting, it will start dropping flood packets before they reach `record_packet()`. The result: your ICMP flood rows in the dataset will show `packets_per_second = 3,000` instead of `150,000` because the controller only processed every 50th packet. The model trained on this data will learn the wrong threshold for what constitutes a flood. This is an invisible corruption — the CSV looks normal, the labels look correct, but the feature values are wrong.

**Steps:**

1. Open `Controller.py`.

2. Find the section near the top where constants or configuration values are defined. If there is no such section, place this at the very top of the file, after the imports but before the class definition.

3. Add this block:
   ```python
   # ==========================================================================
   # DATA COLLECTION MODE
   # Set to True during all dataset collection sessions.
   # When True, ALL packet-in rate limiting is completely bypassed so that
   # attack traffic is recorded at full intensity in the dataset.
   # Set to False when deploying the trained model for live detection.
   # ==========================================================================
   COLLECTION_MODE = True
   ```

4. Now find every location in `Controller.py` where packets are dropped, throttled, or rate-limited before being passed to `capture.record_packet()`. This typically looks like one of these patterns:
   ```python
   if self._pkt_in_count > RATE_LIMIT:
       return
   ```
   or
   ```python
   if self._queue_size > MAX_QUEUE:
       return
   ```

5. For each such location, wrap the drop logic in a `COLLECTION_MODE` guard:
   ```python
   if not COLLECTION_MODE and self._pkt_in_count > RATE_LIMIT:
       return
   ```

6. If your `Controller.py` does not currently have any rate limiting code, add the constant anyway and add this comment next to it:
   ```python
   # NOTE: If you add rate limiting in the future, always guard it with:
   # if not COLLECTION_MODE: (your rate limit logic here)
   ```

**Verification:** After adding this, search `Controller.py` for every `return` statement inside your `packet_in` handler. For each one, verify it is either guarded by `not COLLECTION_MODE` or is a legitimate early-exit for a non-data reason (like an unknown packet type).

---

## Action 1.5 — Add ICMP type extraction in Controller.py

**File:** `Controller.py`
**Location:** Inside the `packet_in` handler, in the section where packet fields are extracted

**Why this matters:**
The `icmp_type_entropy` column in your dataset currently outputs `0.0` for every single row including ICMP flood rows. This means a column that should be one of your strongest ICMP flood indicators — ICMP floods use exclusively type 8 (echo request), giving entropy = 0, while normal ICMP traffic mixes type 0 and type 8, giving entropy > 0 — is completely useless. Fixing this requires one thing: passing the ICMP type value from the raw packet into `pkt_info` so `traffic_capture.py` can accumulate it.

**Steps:**

1. In `Controller.py`, find where you parse incoming packets in the `packet_in` handler. You are likely already extracting an `icmp` object from the packet using Ryu's packet library. It will look something like:
   ```python
   icmp_pkt = pkt.get_protocol(icmp.icmp)
   ```
   or
   ```python
   from ryu.lib.packet import icmp as icmp_proto
   icmp_pkt = pkt.get_protocol(icmp_proto.icmp)
   ```

2. After extracting `icmp_pkt`, add the following to pull out type and code:
   ```python
   icmp_type = icmp_pkt.type if icmp_pkt else None
   icmp_code = icmp_pkt.code if icmp_pkt else None
   ```

3. Find the location where you build the `pkt_info` dictionary that gets passed to `capture.record_packet(pkt_info)`. It currently looks something like:
   ```python
   pkt_info = {
       'src_ip': src_ip,
       'dst_ip': dst_ip,
       'src_port': src_port,
       'dst_port': dst_port,
       'protocol': protocol_str,
       'packet_size': msg.total_len,
       'eth_src': eth.src,
       'eth_dst': eth.dst,
       'tcp_flags': tcp_flags,
       'dpid': datapath.id,
       'in_port': in_port,
   }
   ```

4. Add `icmp_type` and `icmp_code` to this dictionary:
   ```python
   pkt_info = {
       'src_ip': src_ip,
       'dst_ip': dst_ip,
       'src_port': src_port,
       'dst_port': dst_port,
       'protocol': protocol_str,
       'packet_size': msg.total_len,
       'eth_src': eth.src,
       'eth_dst': eth.dst,
       'tcp_flags': tcp_flags,
       'icmp_type': icmp_type,   # NEW — None for non-ICMP packets
       'icmp_code': icmp_code,   # NEW — None for non-ICMP packets
       'dpid': datapath.id,
       'in_port': in_port,
   }
   ```

5. Now open `traffic_capture.py`. Find the `__init__` method. In the section labeled `--- Per-Host, Per-Window Rate Counters ---`, add a new accumulator for ICMP types:
   ```python
   self._host_icmp_types = defaultdict(lambda: defaultdict(int))
   # src_ip -> {icmp_type_int: count}
   # Used to compute icmp_type_entropy per flow window
   ```

6. Inside `record_packet`, find the block that handles `if protocol == 'ICMP':`. It currently just increments `self._host_icmp_count[src_ip]`. Add ICMP type tracking immediately after:
   ```python
   if protocol == 'ICMP':
       self._host_icmp_count[src_ip] += 1
       icmp_type = pkt_info.get('icmp_type')
       if icmp_type is not None:
           self._host_icmp_types[src_ip][icmp_type] += 1
   ```

7. Inside `_flush_flows`, find the section that snapshots and resets the per-host counters (around lines 521–530). Add the ICMP types snapshot and reset alongside the others:
   ```python
   host_icmp_types = dict(self._host_icmp_types)
   self._host_icmp_types = defaultdict(lambda: defaultdict(int))
   ```

8. The snapshot dict `host_icmp_types` needs to be passed through to `_build_flow_row`. Find the call to `_build_flow_row` inside the Pass 2 loop in `_flush_flows`:
   ```python
   row = self._build_flow_row(
       flow_key, flow_data, network_ctx, alerts,
       pps, bps, avg_size,
       inherited_label=inherited
   )
   ```
   Add `host_icmp_types` as a new parameter:
   ```python
   row = self._build_flow_row(
       flow_key, flow_data, network_ctx, alerts,
       pps, bps, avg_size,
       inherited_label=inherited,
       host_icmp_types=host_icmp_types
   )
   ```

9. Update the `_build_flow_row` method signature to accept the new parameter:
   ```python
   def _build_flow_row(self, flow_key, flow_data, network_ctx, alerts,
                       pps, bps, avg_size, inherited_label=None,
                       host_icmp_types=None):
   ```

10. Inside `_build_flow_row`, after the flow features dict is built, compute `icmp_type_entropy`. Find where `flow_features` is constructed and add these lines after it:
    ```python
    if protocol == 'ICMP' and host_icmp_types:
        icmp_type_counter = host_icmp_types.get(src_ip, {})
        icmp_type_ent = _shannon_entropy(icmp_type_counter)
    else:
        icmp_type_ent = 0.0
    ```

11. Add `'icmp_type_entropy': round(icmp_type_ent, 4)` to the `flow_features` dictionary.

12. Add `'icmp_type_entropy'` to `FLOW_COLUMNS` in the column definitions at the top of `traffic_capture.py`, after `'unique_dst_ports'`.

---

## Action 1.6 — Add `LABEL_OVERRIDE` UDP control message

**File:** `Controller.py` and `traffic_capture.py`
**Location:** UDP listener on port 9999 in `Controller.py`, and a new method in `traffic_capture.py`

**Why this matters:**
Slow and stealth attacks (nmap -T1, slow SYN at 1000 PPS) deliberately stay below your detection thresholds. The system will label their traffic as `0` (normal) because nothing triggers. Without this mechanism, you have two bad options: either include unlabeled attack data in your training set (teaches the model that scanning is normal) or exclude it entirely (loses valuable stealthy attack diversity). `LABEL_OVERRIDE` gives you a third option: manually inject the correct ground-truth label from the Mininet CLI while the attack is running.

**Steps — traffic_capture.py:**

1. Inside the `TrafficCapture.__init__` method, at the end of the `--- Detection Mode ---` section, add:
   ```python
   # --- Manual Label Override (for stealthy attacks below detection thresholds) ---
   self._label_overrides = {}
   # src_ip -> attack_type string
   # When set, ALL flows from this IP are labeled with this attack_type
   # regardless of what the detection engine decides.
   # Only active while DETECT:ON. Cleared by LABEL_OVERRIDE:ip:clear
   ```

2. Add a new public method to `TrafficCapture` (place it after `manual_unblock`):
   ```python
   def set_label_override(self, src_ip, attack_type):
       """
       Force all flows from src_ip to be labeled with attack_type.
       Used for stealthy attacks that stay below detection thresholds.
       Call with attack_type='clear' to remove the override.
       """
       if attack_type == 'clear':
           if src_ip in self._label_overrides:
               del self._label_overrides[src_ip]
               self._log('info',
                   f"[OVERRIDE] Label override cleared for {src_ip} — "
                   f"returning to automatic detection")
       else:
           self._label_overrides[src_ip] = attack_type
           self._log('info',
               f"[OVERRIDE] Label override SET: {src_ip} → {attack_type} "
               f"(all flows from this IP will be labeled as attack)")
   ```

3. Inside `_compute_label`, at the very beginning of the method, before any other logic, add the override check:
   ```python
   def _compute_label(self, src_ip, dst_ip, alerts, device_profile,
                      curr_pps=0, curr_bps=0, curr_avg_size=0, protocol='OTHER',
                      host_counters=None):

       # --- 0. Manual Label Override (highest priority) ---
       if src_ip in self._label_overrides:
           return 2, self._label_overrides[src_ip], 'manual_override'

       # --- 1. Detection Mode Gate ---
       ...
   ```
   This override runs before everything else — before confirmed attackers, before Snort, before rate counters.

**Steps — Controller.py:**

4. Find the UDP listener that handles port 9999 messages. It currently handles messages like `CONTROL:DETECT:ON`, `CONTROL:UNBLOCK:ip`, `REGISTER:NAME:hostname`, etc. Add a new message handler alongside the existing ones:
   ```python
   elif msg.startswith('LABEL_OVERRIDE:'):
       parts = msg.split(':')
       # Format: LABEL_OVERRIDE:src_ip:attack_type
       # Example: LABEL_OVERRIDE:10.0.0.3:Port Scan
       # Example: LABEL_OVERRIDE:10.0.0.3:clear
       if len(parts) >= 3:
           target_ip = parts[1]
           attack_type = ':'.join(parts[2:])  # rejoin in case attack_type has colons
           if hasattr(self, 'capture') and self.capture:
               self.capture.set_label_override(target_ip, attack_type)
   ```

5. Document the usage with a comment above the handler:
   ```python
   # LABEL_OVERRIDE — manually force a label for stealthy attacks
   # Usage from topology VM:
   #   echo "LABEL_OVERRIDE:10.0.0.3:Port Scan" | nc -u 192.168.1.19 9999
   # To clear:
   #   echo "LABEL_OVERRIDE:10.0.0.3:clear" | nc -u 192.168.1.19 9999
   ```

---

## Action 1.7 — Verification: run the standalone test

**Why this step exists:**
Every code change you made in Phase 1 was inside a running system. The standalone test at the bottom of `traffic_capture.py` simulates 70 packets and a Snort alert, then prints a column count and a sample row. Running it now costs 10 seconds and confirms you have not introduced a syntax error or broken the CSV output before you touch anything else.

**Steps:**

1. On the Controller VM, navigate to the directory containing `traffic_capture.py`.

2. Run:
   ```bash
   python3 traffic_capture.py
   ```

3. Wait approximately 5–8 seconds for the test to complete. You will see output ending with something like:
   ```
   ✅ Generated 3 rows
      Columns: 51
      Normal:  2
      Attack:  1
      Suspicious: 0

      Sample row:
        timestamp: 2024-...
        src_ip: 10.0.0.2
        ...
   ```

4. The column count must match `len(ALL_COLUMNS)` exactly. If you added `icmp_type_entropy` in Action 1.5 and your original schema had 50 columns, you now expect 51. If the number is wrong, do not proceed — check `FLOW_COLUMNS` and `ALL_COLUMNS` for mismatches.

5. Delete the `test_dataset.csv` file that was generated:
   ```bash
   rm test_dataset.csv
   ```

---

# PHASE 2 — Write `dataset_merge.py`

## Why Phase 2 before data collection

You need this tool ready before Session 1 begins — not after Session 3. The reason is that if you discover a schema inconsistency between sessions (for example, you added a column between Session 1 and Session 2), you need to know immediately so you can fix it before running another session. Without the merge tool, you would discover this problem only when trying to combine files at the end — by which point re-running sessions takes hours.

Write the tool, run it on dummy data, verify it catches schema mismatches. Then start collecting.

---

## Action 2.1 — Create `dataset_merge.py`

**File:** New file — `dataset_merge.py`
**Location:** Same directory as `traffic_capture.py` on the Controller VM

**Steps:**

1. Create a new file called `dataset_merge.py` in your project directory.

2. Write the following content in full:

```python
"""
dataset_merge.py — Session CSV Merger & Validator
===================================================
Merges multiple dataset collection session CSVs into a single
training-ready dataset. Performs schema validation, NaN auditing,
and label distribution reporting before writing the output.

Usage:
    python3 dataset_merge.py session1.csv session2.csv session3.csv
    python3 dataset_merge.py session1.csv session2.csv session3.csv --output final_dataset.csv

Outputs:
    dataset_master.csv  — Full merged file with all meta_ columns intact
    dataset_training.csv — meta_ columns stripped, ready for DL model input
"""

import sys
import os
import argparse
import pandas as pd
from datetime import datetime


# =========================================================================
# Configuration
# =========================================================================

# Minimum rows per attack type to be considered statistically sufficient
MIN_ROWS_PER_ATTACK = 2000

# Columns that are audit metadata — stripped from training file
META_COLUMNS = [
    'meta_window_id',
    'meta_src_mac_oui',
    'meta_device_name',
    'meta_attack_tool',
    'meta_attack_intensity',
    'meta_mininet_event',
    'meta_session_id',
    'meta_controller_load',
    'meta_backlog_drops',
]


# =========================================================================
# Validation
# =========================================================================

def validate_schema(dataframes, filenames):
    """
    Assert all input dataframes have identical column sets.
    Crashes loudly if any mismatch is detected.
    Never silently fills missing columns with NaN.
    """
    print("\n[1/5] Validating schemas...")
    reference_cols = list(dataframes[0].columns)
    reference_name = filenames[0]

    all_ok = True
    for df, name in zip(dataframes[1:], filenames[1:]):
        current_cols = list(df.columns)
        if current_cols != reference_cols:
            print(f"\n  [SCHEMA MISMATCH] {name} vs {reference_name}")
            missing = set(reference_cols) - set(current_cols)
            extra   = set(current_cols) - set(reference_cols)
            if missing:
                print(f"  Columns in {reference_name} but NOT in {name}: {sorted(missing)}")
            if extra:
                print(f"  Columns in {name} but NOT in {reference_name}: {sorted(extra)}")
            all_ok = False

    if not all_ok:
        print("\n  [ABORT] Schema mismatch detected. Fix column consistency before merging.")
        print("  Tip: Re-run the standalone test (python3 traffic_capture.py) on each")
        print("  session's capture environment to verify column counts match.")
        sys.exit(1)

    print(f"  OK — all {len(dataframes)} files share {len(reference_cols)} columns")


def audit_null_values(df):
    """
    Assert no NaN or infinite values exist in any numeric column.
    Prints offending column names and row counts.
    """
    print("\n[2/5] Auditing for NaN and infinite values...")
    issues_found = False

    for col in df.select_dtypes(include='number').columns:
        nan_count = df[col].isna().sum()
        inf_count = (df[col] == float('inf')).sum() + (df[col] == float('-inf')).sum()

        if nan_count > 0:
            print(f"  [NaN] Column '{col}': {nan_count} NaN values")
            issues_found = True
        if inf_count > 0:
            print(f"  [INF] Column '{col}': {inf_count} infinite values")
            issues_found = True

    if issues_found:
        print("\n  [WARNING] NaN/inf values detected. These will break most DL frameworks.")
        print("  Recommended fix: add .replace([float('inf'), float('-inf')], 0.0)")
        print("  and .fillna(0.0) in traffic_capture.py for the affected columns.")
        user_input = input("\n  Continue anyway? (yes/no): ").strip().lower()
        if user_input != 'yes':
            sys.exit(1)
    else:
        print(f"  OK — no NaN or infinite values found across {len(df)} rows")


def report_label_distribution(df):
    """
    Print label and attack_type distribution.
    Warn if any attack type is below the minimum row threshold.
    """
    print("\n[3/5] Label distribution report...")

    total = len(df)
    print(f"\n  Total rows: {total:,}")

    print("\n  By label:")
    for label_val, count in df['label'].value_counts().sort_index().items():
        pct = count / total * 100
        bar = '█' * int(pct / 2)
        print(f"    Label {label_val}: {count:>7,} rows  ({pct:5.1f}%)  {bar}")

    print("\n  By attack_type:")
    below_minimum = []
    for atype, count in df['attack_type'].value_counts().items():
        pct = count / total * 100
        flag = ''
        if atype != 'normal' and count < MIN_ROWS_PER_ATTACK:
            flag = f'  ⚠ BELOW MINIMUM ({MIN_ROWS_PER_ATTACK:,} required)'
            below_minimum.append(atype)
        print(f"    {atype:<20} {count:>7,} rows  ({pct:5.1f}%){flag}")

    if below_minimum:
        print(f"\n  [WARNING] These attack types need more data: {below_minimum}")
        print("  Run a targeted mini-session (10 min) for each under-represented type.")
        print("  Do not proceed to DL training with under-represented classes.")
    else:
        print(f"\n  OK — all attack types meet the minimum {MIN_ROWS_PER_ATTACK:,} row threshold")

    return below_minimum


# =========================================================================
# Main
# =========================================================================

def main():
    parser = argparse.ArgumentParser(description='Merge and validate dataset session CSVs')
    parser.add_argument('input_files', nargs='+', help='Session CSV files to merge')
    parser.add_argument('--output', default='dataset_master.csv',
                        help='Output filename for merged master file')
    args = parser.parse_args()

    if len(args.input_files) < 1:
        print("Error: provide at least one input CSV file")
        sys.exit(1)

    # --- Load all files ---
    print(f"\n{'='*60}")
    print(f"  Dataset Merge & Validation")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    print(f"\n[0/5] Loading {len(args.input_files)} session file(s)...")

    dataframes = []
    filenames  = []
    for i, filepath in enumerate(args.input_files, start=1):
        if not os.path.exists(filepath):
            print(f"  [ERROR] File not found: {filepath}")
            sys.exit(1)
        df = pd.read_csv(filepath)
        # Add session ID column for traceability
        df['meta_session_id'] = i
        dataframes.append(df)
        filenames.append(filepath)
        print(f"  Session {i}: {filepath} — {len(df):,} rows, {len(df.columns)} cols")

    # --- Validate ---
    validate_schema(dataframes, filenames)

    # --- Merge ---
    print("\n[4/5] Merging...")
    merged = pd.concat(dataframes, ignore_index=True)
    print(f"  Merged: {len(merged):,} total rows")

    # --- Audit ---
    audit_null_values(merged)

    # --- Report ---
    under_represented = report_label_distribution(merged)

    # --- Write master file ---
    print(f"\n[5/5] Writing output files...")
    master_path = args.output
    merged.to_csv(master_path, index=False)
    print(f"  Master file: {master_path} ({len(merged):,} rows, {len(merged.columns)} cols)")

    # --- Write training file (meta_ columns stripped) ---
    training_cols = [c for c in merged.columns if c not in META_COLUMNS]
    training_df = merged[training_cols]
    training_path = master_path.replace('.csv', '_training.csv')
    if training_path == master_path:
        training_path = 'dataset_training.csv'
    training_df.to_csv(training_path, index=False)
    print(f"  Training file: {training_path} ({len(training_df):,} rows, {len(training_df.columns)} cols)")

    print(f"\n{'='*60}")
    if under_represented:
        print(f"  STATUS: INCOMPLETE — collect more data for: {under_represented}")
    else:
        print(f"  STATUS: READY FOR DL TRAINING")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
```

3. Save the file.

4. Install pandas if not already present on the Controller VM:
   ```bash
   pip3 install pandas
   ```

5. Test the merge tool with a dummy schema mismatch to verify it catches errors:
   ```bash
   # Create two dummy CSVs with different columns to test the mismatch detection
   echo "col_a,col_b,label,attack_type" > test_s1.csv
   echo "1,2,0,normal" >> test_s1.csv
   echo "col_a,col_c,label,attack_type" > test_s2.csv
   echo "1,2,0,normal" >> test_s2.csv
   python3 dataset_merge.py test_s1.csv test_s2.csv
   ```
   You should see a clear `[SCHEMA MISMATCH]` error and the script should exit without producing output files.

6. Clean up the test files:
   ```bash
   rm test_s1.csv test_s2.csv
   ```

---

# PHASE 3 — Pre-Collection Checklist

## Why a pre-collection checklist

Data collection is the only phase you cannot redo cheaply. Code bugs can be fixed in minutes. A 25-minute collection session with a corrupted schema or a misconfigured detection mode means starting over. Every item in this checklist takes less than 2 minutes. Do all of them before every session.

---

## Action 3.1 — Pre-session checklist (run before every session)

**Run these steps before Session 1, Session 2, and Session 3:**

1. **Verify `COLLECTION_MODE = True`** in `Controller.py`:
   ```bash
   grep "COLLECTION_MODE" Controller.py
   ```
   Output must show `COLLECTION_MODE = True`. If it shows `False`, change it before proceeding.

2. **Verify column count** by running the standalone test:
   ```bash
   python3 traffic_capture.py
   ```
   Note the column count from the output. Write it down. It must be identical across all three sessions. If it differs between sessions, `dataset_merge.py` will catch it and abort — but you want to catch it before the session, not after.

3. **Delete or rename any existing `dataset.csv`** in the working directory:
   ```bash
   # Before Session 1:
   mv dataset.csv dataset_old_schema.csv  # rename the old 49-column file
   # Before Session 2:
   mv dataset.csv dataset_session1.csv
   # Before Session 3:
   mv dataset.csv dataset_session2.csv
   ```
   Never let two sessions write to the same file. The merge tool handles combining them.

4. **Verify both VMs can communicate:**
   ```bash
   # From the Topology VM, send a test UDP message to the Controller VM
   echo "PING" | nc -u 192.168.1.19 9999
   ```
   Check the Controller VM terminal for a received message log. If nothing appears, check the network bridge configuration before starting.

5. **Open three terminals on the Controller VM:**
   - Terminal 1: for running the controller (`python3 Controller.py`)
   - Terminal 2: for monitoring the dataset in real time (`watch -n 5 wc -l dataset.csv`)
   - Terminal 3: for sending UDP control messages

6. **Open two terminals on the Topology VM:**
   - Terminal 1: for running Mininet (`sudo python3 topology.py`)
   - Terminal 2: for running attack commands and sending UDP metadata messages

---

# PHASE 4 — Session 1: Baseline + Standard Attacks

## Why Session 1 is structured this way

Session 1 is the most important session. It establishes your "normal" class, which will make up 50–60% of your entire dataset. The baseline phase (DETECT:OFF) runs first because the DeviceProfile Z-score system requires a minimum of 20 flows and 180 seconds of observation before it can make meaningful deviation calculations. If you skip or shorten the baseline phase, your Z-score features will output `0.0` for the first several minutes of detection, making those rows less informative.

The DETECT:OFF period also serves as a data quality check — all rows during this phase should have `label = 0`. If any show `label = 1` or `label = 2`, something is wrong with your label override or confirmed attacker state from a previous run.

---

## Action 4.1 — Start the infrastructure

**Steps:**

1. On the **Controller VM**, start the controller:
   ```bash
   python3 Controller.py
   ```
   Wait until you see the startup log confirming the Ryu application is listening on OpenFlow port 6653 (or 6633 depending on your version) and the UDP control socket is bound to port 9999.

2. On the **Topology VM**, start the Mininet topology:
   ```bash
   sudo python3 topology.py
   ```
   Wait until you see the Mininet CLI prompt `mininet>`. Do not proceed until the prompt appears — the switch and hosts are not ready until then.

3. On the **Controller VM Terminal 3**, send the detection OFF command:
   ```bash
   echo "CONTROL:DETECT:OFF" | nc -u 192.168.1.19 9999
   ```
   Verify in Terminal 1 that the controller logs: `Detection mode DISABLED — capture only, all labels = normal`

4. Send the initial normal event tag:
   ```bash
   echo "MININET_EVENT:normal" | nc -u 192.168.1.19 9999
   ```

---

## Action 4.2 — Baseline phase (6 minutes, DETECT:OFF)

**Steps — run in the Mininet CLI terminal:**

1. **Minute 1:00** — First pingall:
   ```
   mininet> pingall
   ```
   While pingall is running, on Controller Terminal 3:
   ```bash
   echo "MININET_EVENT:pingall" | nc -u 192.168.1.19 9999
   ```
   After pingall completes:
   ```bash
   echo "MININET_EVENT:normal" | nc -u 192.168.1.19 9999
   ```

2. **Minute 2:00** — Directed pings:
   ```
   mininet> h1 ping -c 20 10.0.0.2
   mininet> h2 ping -c 20 10.0.0.4
   ```

3. **Minute 3:00** — Second pingall:
   ```
   mininet> pingall
   ```
   Tag it again:
   ```bash
   echo "MININET_EVENT:pingall" | nc -u 192.168.1.19 9999
   ```
   After completion:
   ```bash
   echo "MININET_EVENT:normal" | nc -u 192.168.1.19 9999
   ```

4. **Minute 4:00** — TCP iperf stream (requires iperf installed in Mininet hosts):
   ```
   mininet> h2 iperf -s &
   mininet> h1 iperf -c 10.0.0.4 -t 30
   ```

5. **Minute 4:30** — UDP iperf stream:
   ```
   mininet> h2 iperf -s -u &
   mininet> h1 iperf -c 10.0.0.4 -u -b 1M -t 30
   ```

6. **Minute 5:30** — Idle silence (60 seconds, do nothing):
   This generates "empty window" rows where most features are 0. These are valuable — they teach the model what a truly idle network looks like so it does not confuse silence with an anomaly.

7. **Minute 6:30** — Verify baseline rows look correct. On Controller Terminal 2:
   ```bash
   watch -n 2 wc -l dataset.csv
   ```
   You should see the row count increasing. Open the CSV and spot-check 5 rows — all `label` values should be `0` and `attack_type` should be `normal`.

---

## Action 4.3 — Enable detection and run standard attacks

**Steps:**

1. **Minute 7:00** — Enable detection:
   ```bash
   echo "CONTROL:DETECT:ON" | nc -u 192.168.1.19 9999
   ```
   Verify the controller logs: `Detection mode ENABLED — anomaly detection active (counters reset)`

2. **Attack 1 — ICMP Flood (Minute 7:30):**

   On Controller Terminal 3:
   ```bash
   echo "ATTACK_START:hping3:flood" | nc -u 192.168.1.19 9999
   ```
   In Mininet CLI (open an xterm for h1 first: `mininet> xterm h1`):
   ```bash
   hping3 --icmp --flood 10.0.0.2
   ```
   Let it run for **60 seconds**. Then press Ctrl+C in h1's xterm to stop it.
   ```bash
   echo "ATTACK_STOP" | nc -u 192.168.1.19 9999
   ```
   Wait **30 seconds** recovery before the next attack. During recovery, watch the controller terminal — you should see the `[⛔] ATTACK CONFIRMED` log appear within the first 15 seconds.

3. **Attack 2 — SYN Flood (Minute 9:30):**
   ```bash
   echo "ATTACK_START:hping3:flood" | nc -u 192.168.1.19 9999
   ```
   In h1's xterm:
   ```bash
   hping3 -S --flood -p 80 10.0.0.2
   ```
   Run 60 seconds, stop, send ATTACK_STOP, wait 30 seconds recovery.

4. **Attack 3 — UDP Flood (Minute 11:30):**
   ```bash
   echo "ATTACK_START:hping3:flood" | nc -u 192.168.1.19 9999
   ```
   In h1's xterm:
   ```bash
   hping3 --udp --flood -p 53 10.0.0.2
   ```
   Run 60 seconds, stop, send ATTACK_STOP, wait 30 seconds recovery.

5. **Attack 4 — Fast Port Scan (Minute 13:30):**
   ```bash
   echo "ATTACK_START:nmap:1000" | nc -u 192.168.1.19 9999
   ```
   In h1's xterm:
   ```bash
   nmap -sS -p 1-1000 10.0.0.2
   ```
   Wait for nmap to complete on its own (30–90 seconds depending on topology). Then:
   ```bash
   echo "ATTACK_STOP" | nc -u 192.168.1.19 9999
   ```
   Wait 30 seconds recovery.

6. **Attack 5 — ARP Spoofing (Minute 15:30):**
   ```bash
   echo "ATTACK_START:arpspoof:0" | nc -u 192.168.1.19 9999
   ```
   In h1's xterm:
   ```bash
   arpspoof -i h1-eth0 -t 10.0.0.2 10.0.0.1
   ```
   Let it run 60 seconds. Stop with Ctrl+C, then:
   ```bash
   echo "ATTACK_STOP" | nc -u 192.168.1.19 9999
   ```

7. **Minute 17:00** — Run 2 minutes of recovery normal traffic:
   ```
   mininet> pingall
   mininet> h1 ping -c 30 10.0.0.4
   ```

8. **Minute 19:00** — Disable detection:
   ```bash
   echo "CONTROL:DETECT:OFF" | nc -u 192.168.1.19 9999
   ```

9. **Minute 19:30** — Final pingall to verify network is still functional:
   ```
   mininet> pingall
   ```
   All hosts should respond. If any host is unreachable, run `mininet> h1 arp -d 10.0.0.2` to clear stale ARP entries left by the spoof attack.

10. **Minute 20:00** — Save Session 1 data:
    ```bash
    cp dataset.csv dataset_session1.csv
    ```
    Note the row count:
    ```bash
    wc -l dataset_session1.csv
    ```
    Expected: 400–1,200 rows (not 20,000 — see the realistic expectation note in Phase 1).

---

# PHASE 5 — Session 2: Varied Attacks + Multi-Host

## Why Session 2 needs a fresh start and different intensities

Session 1 gives you the "clean" signatures — standard flood tools at maximum intensity. Session 2 gives the model variety. A model that has only seen 150,000 PPS ICMP floods will fail to recognize a 50,000 PPS flood as an attack because the feature values are different in magnitude. Session 2 runs the same attack categories but with different payload sizes, different rates, and multiple simultaneous attackers so the model learns the *shape* of attacks, not just their volume.

---

## Action 5.1 — Prepare Session 2

**Steps:**

1. Stop the controller and topology from Session 1 if they are still running.

2. Rename the session 1 dataset:
   ```bash
   mv dataset.csv dataset_session1.csv
   ```

3. Run the pre-session checklist from Action 3.1.

4. Start fresh topology and controller as in Action 4.1.

---

## Action 5.2 — Run Session 2 attacks

**Steps:**

1. **Baseline (3 minutes, DETECT:OFF):**
   Run pingall, directed pings, and iperf as in Action 4.2 but compressed to 3 minutes. Session 2's baseline data is supplementary — Session 1 already covered normal traffic thoroughly.

2. **Enable detection:**
   ```bash
   echo "CONTROL:DETECT:ON" | nc -u 192.168.1.19 9999
   ```

3. **Attack 6 — Large-payload ICMP Flood:**
   ```bash
   echo "ATTACK_START:hping3:flood" | nc -u 192.168.1.19 9999
   ```
   ```bash
   hping3 --icmp --flood -d 1400 10.0.0.2
   ```
   Run 60 seconds. The `-d 1400` flag sends near-maximum-size ICMP packets. This will appear in the dataset with `large_pkt_ratio` near 1.0 and `pkt_size_std` near 0 — same attack category but different size fingerprint than Session 1.
   ```bash
   echo "ATTACK_STOP" | nc -u 192.168.1.19 9999
   ```
   Wait 30 seconds recovery.

4. **Attack 7 — UDP Amplification simulation:**
   ```bash
   echo "ATTACK_START:hping3:flood" | nc -u 192.168.1.19 9999
   ```
   ```bash
   hping3 --udp --flood -p 53 -d 512 10.0.0.2
   ```
   Run 60 seconds. The `-d 512` flag simulates a DNS amplification response size.
   ```bash
   echo "ATTACK_STOP" | nc -u 192.168.1.19 9999
   ```
   Wait 30 seconds recovery.

5. **Attack 8 — TCP RST Flood:**
   ```bash
   echo "ATTACK_START:hping3:flood" | nc -u 192.168.1.19 9999
   ```
   ```bash
   hping3 -R --flood -p 80 10.0.0.2
   ```
   Run 60 seconds. This generates `rst_count` spikes with `syn_count = 0` — a signature distinct from SYN flood.
   ```bash
   echo "ATTACK_STOP" | nc -u 192.168.1.19 9999
   ```
   Wait 30 seconds recovery.

6. **Attack 9 — Multi-target Port Scan:**
   ```bash
   echo "ATTACK_START:nmap:100" | nc -u 192.168.1.19 9999
   ```
   ```bash
   nmap -sS -p 1-100 10.0.0.1-4
   ```
   Wait for completion. This generates `device_unique_dst_ips = 4` and `device_new_dst_ratio` near 1.0, distinguishing it from a single-target scan.
   ```bash
   echo "ATTACK_STOP" | nc -u 192.168.1.19 9999
   ```
   Wait 30 seconds recovery.

7. **Attack 10 — Simultaneous dual-host attack:**
   This is the most complex attack in the plan. You need to start two attacks at the same time from different hosts.

   Open two xterm windows from Mininet:
   ```
   mininet> xterm h1 sta1
   ```

   On Controller Terminal 3:
   ```bash
   echo "ATTACK_START:hping3:flood" | nc -u 192.168.1.19 9999
   ```

   In h1's xterm window:
   ```bash
   hping3 --icmp --flood 10.0.0.2 &
   ```

   Immediately in sta1's xterm window:
   ```bash
   hping3 -S --flood -p 443 10.0.0.4
   ```

   Let both run for 60 seconds. Stop both (Ctrl+C in each xterm), then:
   ```bash
   echo "ATTACK_STOP" | nc -u 192.168.1.19 9999
   ```
   Wait 30 seconds recovery.

   After this attack, verify in `dataset.csv` that both `10.0.0.3` (h1) and `10.0.0.1` (sta1) have `label = 2` rows. Also check that `network_unique_src_ips` reflects 2 attackers during those windows.

8. **Recovery and close:**
   Run 2 minutes of normal pingall and directed pings, then:
   ```bash
   echo "CONTROL:DETECT:OFF" | nc -u 192.168.1.19 9999
   mv dataset.csv dataset_session2.csv
   wc -l dataset_session2.csv
   ```

---

# PHASE 6 — Session 3: Edge Cases

## Why Session 3 is scientifically the most valuable

Sessions 1 and 2 give you clean examples of attacks and normal traffic. Session 3 tests the boundaries — the cases where the system should *not* act but a naive threshold-based system would, and the cases where the label lock-in behavior produces a specific transition pattern in the dataset. These edge-case rows are what separates a robust dataset from a simple one.

---

## Action 6.1 — Run Session 3

**Steps:**

1. Prepare as per Action 3.1. Fresh dataset.csv, fresh topology.

2. **Brief baseline (1.5 minutes, DETECT:OFF):**
   Just one pingall and one round of directed pings. Session 3 is about edge cases, not baseline data.

3. **Enable detection:**
   ```bash
   echo "CONTROL:DETECT:ON" | nc -u 192.168.1.19 9999
   ```

4. **Edge Case 1 — Short burst that should NOT confirm (Minute 2:00):**
   ```bash
   echo "ATTACK_START:hping3:flood" | nc -u 192.168.1.19 9999
   ```
   In h1's xterm:
   ```bash
   hping3 --icmp --flood 10.0.0.2
   ```
   Run exactly **20 seconds**, then stop.
   ```bash
   echo "ATTACK_STOP" | nc -u 192.168.1.19 9999
   ```
   Wait **10 seconds**. At this point the controller should have logged `[⚠] SUSPECTED ATTACK — Window 1/3` but NOT `[⛔] ATTACK CONFIRMED`. If confirmation appeared, your `REQUIRED_CONSECUTIVE` threshold for ICMP is too low.

   Run the same burst again for 20 seconds immediately:
   ```bash
   echo "ATTACK_START:hping3:flood" | nc -u 192.168.1.19 9999
   hping3 --icmp --flood 10.0.0.2
   ```
   Stop after 20 seconds. The consecutive counter should have reset after the 10-second gap between bursts. This tests that your confirmation system correctly resets when an attack pauses.

   Wait 30 seconds recovery.

5. **Edge Case 2 — Sustained attack + lock-in + unblock (Minute 3:30):**
   ```bash
   echo "ATTACK_START:hping3:flood" | nc -u 192.168.1.19 9999
   ```
   ```bash
   hping3 -S --flood -p 80 10.0.0.2
   ```
   Run for **120 seconds** (2 minutes). After approximately 10–15 seconds you should see `[⛔] ATTACK CONFIRMED`. Let it continue running for the full 2 minutes to generate many lock-in rows.

   Stop the attack:
   ```bash
   echo "ATTACK_STOP" | nc -u 192.168.1.19 9999
   ```

   **Immediately** send 5 normal pings from h1 while it is still in the confirmed attacker state:
   ```
   mininet> h1 ping -c 5 10.0.0.2
   ```
   Check `dataset.csv` — these 5 pings should appear with `label = 2` and `attack_type = SYN Flood` because of the permanent lock-in. This is the expected and correct behavior.

   Now send the unblock command:
   ```bash
   echo "CONTROL:UNBLOCK:10.0.0.3" | nc -u 192.168.1.19 9999
   ```
   Verify in the controller log: `[✅] ADMIN MANUAL UNBLOCK: 10.0.0.3`

   Send 5 more pings from h1:
   ```
   mininet> h1 ping -c 5 10.0.0.2
   ```
   Check `dataset.csv` — these should now appear with `label = 0` and `attack_type = normal`. This validates the full lock-in → unblock → return-to-normal lifecycle.

   Wait 30 seconds recovery.

6. **Edge Case 3 — ARP spoof with simultaneous normal traffic (Minute 8:00):**

   Start arpspoof from h1 in the background:
   ```
   mininet> xterm h1 h2
   ```
   In h1's xterm:
   ```bash
   arpspoof -i h1-eth0 -t 10.0.0.2 10.0.0.1 &
   ```
   ```bash
   echo "ATTACK_START:arpspoof:0" | nc -u 192.168.1.19 9999
   ```
   Immediately in h2's xterm, run continuous pings:
   ```bash
   ping -c 30 10.0.0.1
   ```

   While both are running simultaneously, check `dataset.csv`. You should see:
   - h1 rows: `label = 1`, `attack_type = ARP Spoofing`
   - h2 rows: `label = 0`, `attack_type = normal`

   This validates that label inheritance does not bleed across different source IPs — h2's legitimate traffic stays clean even though h1 is attacking simultaneously.

   Stop everything:
   ```bash
   echo "ATTACK_STOP" | nc -u 192.168.1.19 9999
   ```

7. **Close Session 3:**
   ```bash
   echo "CONTROL:DETECT:OFF" | nc -u 192.168.1.19 9999
   ```
   ```
   mininet> pingall
   ```
   ```bash
   mv dataset.csv dataset_session3.csv
   wc -l dataset_session3.csv
   ```

---

# PHASE 7 — Stealthy Attack Collection (Separate File)

## Why this is separate from Sessions 1–3

Slow and stealthy attacks (nmap -T1, 1000 PPS SYN flood) deliberately evade your detection thresholds. They will be labeled `0` (normal) by the automatic system. Including unlabeled attack traffic in your main dataset trains the model that slow scanning is normal behavior — this is actively harmful. By collecting them separately with `LABEL_OVERRIDE` active, you get correctly labeled stealthy attack rows that you can either include as a supplementary training file or exclude entirely while keeping the main dataset clean.

---

## Action 7.1 — Collect stealthy attack data

**Steps:**

1. Start a fresh session with a new output file. Before starting the controller, temporarily change `output_path` in `TrafficCapture` initialization to `dataset_stealth.csv`, or rename the output afterward.

2. Run 2 minutes of baseline (DETECT:OFF) to establish device profiles.

3. **Enable detection:**
   ```bash
   echo "CONTROL:DETECT:ON" | nc -u 192.168.1.19 9999
   ```

4. **Stealthy Attack 1 — Slow port scan:**

   Activate the label override BEFORE starting the attack:
   ```bash
   echo "LABEL_OVERRIDE:10.0.0.3:Port Scan" | nc -u 192.168.1.19 9999
   ```
   Verify in the controller log: `[OVERRIDE] Label override SET: 10.0.0.3 → Port Scan`

   In h1's xterm:
   ```bash
   nmap -sS -T1 -p 1-100 10.0.0.2
   ```
   This scan runs slowly — it will take 3–5 minutes to complete. Let it finish. All rows from h1 during this time will be correctly labeled `Port Scan` despite the rate counter never triggering.

   After completion, clear the override:
   ```bash
   echo "LABEL_OVERRIDE:10.0.0.3:clear" | nc -u 192.168.1.19 9999
   ```

5. **Stealthy Attack 2 — Low-rate SYN flood:**
   ```bash
   echo "LABEL_OVERRIDE:10.0.0.3:SYN Flood" | nc -u 192.168.1.19 9999
   ```
   In h1's xterm:
   ```bash
   hping3 -S -i u1000 -p 80 10.0.0.2
   ```
   The `-i u1000` flag means one packet every 1000 microseconds = 1000 PPS. This is far below the 5000 PPS threshold. Run for 60 seconds.

   Stop and clear:
   ```bash
   echo "LABEL_OVERRIDE:10.0.0.3:clear" | nc -u 192.168.1.19 9999
   ```

6. Close and rename:
   ```bash
   mv dataset.csv dataset_stealth.csv
   ```

---

# PHASE 8 — Merge, Validate, Finalize

## Action 8.1 — Run dataset_merge.py

**Steps:**

1. Ensure all session files are in the same directory as `dataset_merge.py`:
   ```bash
   ls -lh dataset_session*.csv dataset_stealth.csv
   ```

2. Run the merge on the three main sessions:
   ```bash
   python3 dataset_merge.py dataset_session1.csv dataset_session2.csv dataset_session3.csv \
       --output dataset_master.csv
   ```

3. Read the output carefully:
   - If you see `[SCHEMA MISMATCH]`: identify which session has the different column count, check what changed in `traffic_capture.py` between sessions, and re-run that session.
   - If you see `[NaN]` or `[INF]`: note which column, then find the corresponding computation in `traffic_capture.py` and add a `or 0.0` guard.
   - If you see `⚠ BELOW MINIMUM` for any attack type: run a targeted 10-minute mini-session for that type only (attack + recovery, no baseline needed), save it as `dataset_extra_<type>.csv`, and re-run the merge including it.

4. After a clean merge, verify the output files:
   ```bash
   wc -l dataset_master.csv
   wc -l dataset_master_training.csv
   head -1 dataset_master.csv | tr ',' '\n' | wc -l  # column count
   ```

5. Optionally include the stealth dataset:
   ```bash
   python3 dataset_merge.py dataset_master.csv dataset_stealth.csv \
       --output dataset_master_with_stealth.csv
   ```
   Keep `dataset_master.csv` (without stealth) as your primary training file. Use `dataset_master_with_stealth.csv` only if you want the model to learn stealthy attack patterns.

---

# PHASE 9 — Final Verification

## Action 9.1 — Manual spot checks

**Steps:**

1. Open `dataset_master.csv` in a spreadsheet or with pandas:
   ```python
   import pandas as pd
   df = pd.read_csv('dataset_master.csv')
   print(df.groupby(['label', 'attack_type']).size())
   ```

2. Verify the lock-in narrative from Session 3:
   ```python
   # Find rows from 10.0.0.3 around the unblock event
   h1_rows = df[df['src_ip'] == '10.0.0.3'].sort_values('timestamp')
   print(h1_rows[['timestamp', 'label', 'attack_type']].tail(30))
   ```
   You should see a block of `label=2, attack_type=SYN Flood` rows transition cleanly to `label=0, attack_type=normal` after the unblock.

3. Verify `icmp_type_entropy` is no longer always 0:
   ```python
   icmp_rows = df[df['protocol'] == 'ICMP']
   print(icmp_rows['icmp_type_entropy'].describe())
   print(icmp_rows.groupby('attack_type')['icmp_type_entropy'].mean())
   ```
   Normal ICMP traffic (mixed type 0 and type 8) should have higher entropy than ICMP flood traffic (only type 8).

4. Verify ARP rows exist and have non-zero ARP features:
   ```python
   arp_rows = df[df['protocol'] == 'ARP']
   print(arp_rows[['arp_reply_rate', 'arp_unsolicited_count', 'mac_ip_binding_changes', 'label']].describe())
   ```

5. Verify `meta_attack_tool` is correctly populated:
   ```python
   print(df.groupby('meta_attack_tool')['label'].value_counts())
   ```
   Rows with `meta_attack_tool = hping3` should have `label = 2`. Rows with `meta_attack_tool = none` should be predominantly `label = 0`.

6. Final confirmation — print the complete dataset summary:
   ```python
   print(f"Total rows: {len(df):,}")
   print(f"Total columns: {len(df.columns)}")
   print(f"Normal rows: {(df['label']==0).sum():,}")
   print(f"Attack rows (confirmed): {(df['label']==2).sum():,}")
   print(f"Attack rows (Snort): {(df['label']==1).sum():,}")
   print(f"\nAttack type breakdown:")
   print(df[df['label']>0]['attack_type'].value_counts())
   ```

If all checks pass, your dataset is complete. `dataset_master_training.csv` is ready for your DL model.

---

# Summary Reference Card

| Phase | Action | File(s) | Status Check |
|-------|--------|---------|--------------|
| 1 | Fix 3 bugs | traffic_capture.py | Standalone test passes, correct column count |
| 1 | Add COLLECTION_MODE | Controller.py | grep shows True |
| 1 | Add ICMP type extraction | Controller.py + traffic_capture.py | icmp_type_entropy non-zero on ICMP flows |
| 1 | Add LABEL_OVERRIDE | Controller.py + traffic_capture.py | UDP message changes labels immediately |
| 2 | Write dataset_merge.py | dataset_merge.py | Schema mismatch test catches errors |
| 3 | Pre-session checklist | — | Column count written down, dataset.csv fresh |
| 4 | Session 1 | dataset_session1.csv | 400–1,200 rows, all attack types labeled |
| 5 | Session 2 | dataset_session2.csv | Multi-host rows have 2 attacker IPs |
| 6 | Session 3 | dataset_session3.csv | Lock-in transition visible in rows |
| 7 | Stealth collection | dataset_stealth.csv | LABEL_OVERRIDE rows labeled correctly |
| 8 | Merge + validate | dataset_master.csv | No schema errors, no NaN, all types ≥ 2000 rows |
| 9 | Final verification | — | icmp_type_entropy non-zero, ARP rows non-zero |
