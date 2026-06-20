# Machine Learning Rationale: SDN-Based IoT Intrusion Prevention System (IPS)

This document details the engineering and security rationale behind the machine learning architecture, feature selection, adaptive automation, and IoT threat modeling for the SDN IPS deployed on the HP t530 appliance.

---

1. Machine Learning Model Choice
   1.1. Binary Classifier: Ensemble Voting (3x LightGBM + 2x RandomForest)
        1.1.1. Purpose: Classify network flows as either Normal (0) or Attack (1).
        1.1.2. LightGBM (LGBM) Rationale: Provides fast gradient boosting utilizing histogram-based algorithms to minimize CPU and memory footprints. Compiles to optimized trees for sub-millisecond packet-in inference. Integrates scale_pos_weight to compensate for the 17.4:1 normal-to-attack class imbalance.
        1.1.3. RandomForest (RF) Rationale: Provides parallel tree bagging to minimize variance, offering robustness against feature noise and preventing overfitting.
        1.1.4. VotingClassifier (Soft Voting) Rationale: Smooths out individual model prediction errors, ensuring a stable boundary and eliminating single-tree classification anomalies.
   1.2. Attack Type Classifier: Multi-Class LightGBM (6 Classes)
        1.2.1. Purpose: Categorize confirmed attacks into one of six specific classes: ARP Spoofing, Control Plane Saturation, ICMP Flood, Port Scan, SYN Flood, or UDP Flood.
        1.2.2. Classifier Rationale: Employs a one-vs-all strategy and compute_sample_weight='balanced' to ensure low-frequency classes (e.g., ARP Spoofing with 116 samples) achieve high recall without being dominated by common attacks like Port Scans.
   1.3. Anomaly Detector: Isolation Forest (Zero-Day Detection)
        1.3.1. Purpose: Detect zero-day or unknown attacks absent from the training dataset.
        1.3.2. Model Rationale: Uses unsupervised partitioning trees. Anomalous points require fewer random splits to isolate than normal points, making them stand out.
        1.3.3. Training Setup: Trained exclusively on normal traffic, utilizing a custom evaluation-derived threshold (0.0151) to detect statistical deviations from normal behavior.

2. Feature Exclusion (Dropped Columns)
   2.1. Identifiers
        2.1.1. Dropped Columns: `timestamp`, `src_ip`, `dst_ip`
        2.1.2. Rationale: Prevents the model from memorizing specific host IP addresses or event times, forcing it to generalize based on traffic flow characteristics.
   2.2. Target Labels
        2.2.1. Dropped Columns: `label`, `attack_type`
        2.2.2. Rationale: Prevents direct target leakage, as these represent the ground truth the model is trained to predict.
   2.3. Critical Leakage
        2.3.1. Dropped Columns: `snort_sid`
        2.3.2. Rationale: The Snort Signature ID maps directly to attack classes, which would cause the model to rely entirely on static rules instead of learning behavioral flows, leading to failure if Snort is offline or misses an attack.
   2.4. Simulation Metadata
        2.4.1. Dropped Columns: `meta_window_id`, `meta_src_mac_oui`, `meta_device_name`, `meta_attack_tool`, `meta_attack_intensity`, `meta_mininet_event`, `meta_controller_load`, `meta_backlog_drops`
        2.4.2. Rationale: These columns are only available in simulated training environments and cannot be generated during live production runs on the HP t530.
   2.5. Constant-Zero Features
        2.5.1. Dropped Columns: `is_registered_iot`, `is_gateway`, `multicast_ratio`, `arp_gratuitous_count`, `arp_unsolicited_count`, `mac_ip_binding_changes`, `ip_mac_binding_changes`
        2.5.2. Rationale: Contain only zeros across all sessions, providing no variance or predictive value.
   2.6. Collinear/Redundant Features
        2.6.1. Dropped Columns: `pkt_size_variance`
        2.6.2. Rationale: Redundant with `pkt_size_std` (variance is std²), which is kept. Dropping it prevents multi-collinearity issues.

3. Rationale for Machine Learning in Automated IPS (Adaptive IPS)
   3.1. Need for Real-Time Adaptability: Traditional rule-based IPS (like Snort) use static signatures/thresholds that cannot adapt to natural traffic shifts (e.g., IoT firmware updates), resulting in high false alarm rates.
   3.2. Detection of Subtle and Distributed Behaviors: Advanced attacks (e.g., slow port scans or low-volume data exfiltration) bypass simple rate-limiters. AI models analyze relationships across 83 features (entropy, size deviations, timing) to identify anomalies.
   3.3. Closed-Loop Automated Mitigation: Automated blocking requires high confidence to prevent Denial of Service (DoS) on legitimate users. The ensemble provides real-time confidence scores, allowing the controller to safely deploy OpenFlow DROP rules only when predictions meet a strict threshold (e.g., >= 0.50 or >= 0.80).

4. Prominent IoT Attack Vectors and AI Mitigation
   4.1. Botnet Recruitment & Volumetric DDoS (Mirai-style)
        4.1.1. Threat Description: Attackers hijack vulnerable IoT devices to form botnets for volumetric floods (SYN, UDP, HTTP).
        4.1.2. AI Role: IoT devices have highly predictable communication footprints. The model learns this baseline, flagging and blocking device flows the moment volumetric rates, destination entropy, or payload characteristics deviate.
   4.2. Local Layer-2 Attacks (ARP Spoofing / Man-in-the-Middle)
        4.2.1. Threat Description: Attackers send forged ARP messages to intercept or alter local network traffic.
        4.2.2. AI Role: Analyzes specialized flow counters (ARP request/reply ratios and IP-MAC associations), detecting ARP anomalies with 100% recall and blocking the compromised switch port immediately.
