# Progression Report: SDN IoT Intrusion Detection System

This document summarizes the major technical enhancements and bug fixes implemented across the SDN Controller, Traffic Capture Module, and Mininet-wifi Topology.

---

## 1. Traffic Capture & Dataset Generation (`traffic_capture.py`)

**Objective:** To generate high-fidelity datasets for Machine Learning that accurately label both known attacks (Snort) and suspicious behavioral deviations.

### Key Changes:
*   **Window-Wide Label Inheritance:**
    *   **Function:** Implemented a "two-pass" processing engine during the 5-second flow flush.
    *   **How it works:** In Pass 1, the system identifies any source IP that triggered a Snort alert or a behavioral anomaly. In Pass 2, **all flows** from that IP within the same window inherit that attack label. This ensures that a single malicious IP doesn't have "normal" looking rows in the middle of an attack.
*   **Baseline Integrity (0% False Poisoning):**
    *   **Function:** Protects the behavioral "Normal" profile from being corrupted by attack data.
    *   **How it works:** The `DeviceProfile.update` method now checks the computed label. If a flow is labeled as an attack, its volume (PPS, BPS, Payload size) is **excluded** from the historical average and variance calculations. This prevents attackers from slowly increasing their rate to "blend in."
*   **Granular Behavioral Labeling:**
    *   **Function:** Replaced generic "Anomaly" labels with specific attack types.
    *   **How it works:** Based on which feature triggered the Z-score threshold, the `attack_type` is dynamically set to `Scan: Port Sweep`, `Scan: Host Discovery`, `Flood: Volumetric`, or `Flood: Throughput`.
*   **False Positive Hardening:**
    *   **Function:** Minimized noise for cleaner ML training.
    *   **How it works:** Increased Z-score thresholds to **6.0** and added a **180-second stabilization period** for new devices. Behavioral analysis only begins once a device has a stable historical baseline.

---

## 2. Controller Logic (`Controller network only .py`)

**Objective:** To improve device identification and system stability.

### Key Changes:
*   **Registration Priority Fix:**
    *   **Function:** Prevents misidentification of IoT devices as Gateways.
    *   **How it works:** The controller now prioritizes "Explicit Registration" (UDP port 9999). If a device sends a registration packet, it is immediately marked as an IoT device, and any previous "Passive Discovery" flags (like being a Gateway based on OUI) are deleted.
*   **Log Flood Mitigation:**
    *   **Function:** Keeps the Ryu console readable.
    *   **How it works:** Added a `discovery_logged_macs` set. Passive discovery messages for a specific MAC address are now logged only **once per session** instead of for every packet.
*   **DPID Readability:**
    *   **Function:** Improved console debugging.
    *   **How it works:** Dynamic Gateway discovery now displays large Datapath IDs (DPIDs) in **Hexadecimal** (e.g., `0x1000...`) instead of long decimal strings, matching Mininet's output.

---

## 3. Snort IDS Integration (`snort_monitor.py`)

**Objective:** To ensure the IDS bridge across VMs is robust and doesn't crash the controller.

### Key Changes:
*   **Pipe Buffer/System Freeze Fix:**
    *   **Function:** Prevents the Ryu controller from hanging/freezing.
    *   **How it works:** Reassigned Snort's `stdout` and `stderr` to physical log files (`snort_stdout.log` and `snort_stderr.log`) instead of using Python subprocess pipes. This prevents Snort from "blocking" the entire controller script when the internal buffers got full.
*   **Enhanced Version Compatibility:**
    *   **Function:** Support for both Snort 2.x and Snort 3.
    *   **How it works:** The monitor now auto-detects the Snort version. If it finds Snort 2.x (installed by default on many Ubuntu versions), it automatically searches for legacy `/etc/snort/snort.conf` rather than failing on the newer Snort 3 `lua` files.

---

## 4. Mininet-wifi Topology Script (`topology .py`)

**Objective:** To allow seamless runtime addition of IoT devices.

### Key Changes:
*   **CLI Function Exposure:**
    *   **Function:** Allows the user to call registration functions directly from the Mininet CLI.
    *   **How it works:** Injected `register_iot_device` and `connect_iot_device` into the `net` object. Users can now run `py net.register_iot_device(...)`.
*   **Manual Linking Fix:**
    *   **Function:** Solves the "NoneType" error during dynamic addition.
    *   **How it works:** Switched from `net.addLink` (which can fail after network start) to manual `Link(host, switch)` creation. This forces the link to be created at the Linux kernel level even while the simulation is running.
*   **Non-Blocking Registration:**
    *   **Function:** Prevents terminal lockups.
    *   **How it works:** Used a **daemon thread** for the 2-second registration wait time. This allows the Mininet CLI to stay interactive while the host prepares to send its registration packet.
