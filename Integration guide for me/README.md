Traffic Capture \& Snort Integration Walkthrough

Summary

We have enhanced the SDN controller with a Traffic Capture Module designed to generate high-quality datasets for ML/DL intrusion detection.



Key Capabilities:



Zero-Day Detection: Uses behavioral profiling (Z-score deviation) to spot unknown attacks.

Post-Compromise Detection: Identifies legitimate devices behaving anomalously (e.g., IoT device scanning the network).

Known Attack Labeling: Automatically labels flows using real-time Snort IDS alerts.

Bug Fixes Applied

Resolved Log Flooding: Added discovery\_logged\_macs to the controller. Passive discovery details are now logged only once per device per session.

Improved Device Identification: Added 00:00:00 and 32:46:1b to iot\_exclude\_prefixes. This prevents standard Mininet-wifi stations and virtual interfaces from being identified as IoT.

Reduced IDS Noise: Added 10+ common false positive SIDs (ICMP, ARP, UPnP) to the Snort suppression list and increased the suppression rate limit.

Files Created/Modified

Controller/traffic\_capture.py

&nbsp;\[NEW]: The core capture logic with 45+ features.

Controller/Controller network only .py

&nbsp;\[MODIFIED]: Integrated the capture module.

Controller/SNORT\_IDS\_README.md

&nbsp;\[MODIFIED]: Added documentation for the dataset feature.

Architecture

The controller now runs a parallel capture thread:



Packet In: Every packet (from Mininet or physical interface) is parsed.

Feature Extraction:

Flow: syn\_count, packet\_size, port\_diversity

Device Profile: avg\_packet\_rate (EMA), new\_dst\_ratio, proto\_dist

Network Context: active\_flows, entropy\_src\_ip

Labeling:

Checks recent Snort alerts.

Checks for significant behavioral deviation (Z-score > 3).

Output: Appends to dataset.csv every 5 seconds.

How to Verify

Start the Controller:



bash

\# On Controller VM (192.168.1.11)

ryu-manager "Controller network only .py"

You should see: \[TrafficCapture-INFO] Traffic capture started → dataset.csv



Generate Traffic:



bash

\# On Mininet VM (192.168.1.13)

sudo mn --custom ...

mininet> pingall

Simulate Attack (Optional):



bash

\# Flood attack from host h1

h1 hping3 -S --flood -p 80 192.168.1.11

Check Output:



bash

tail -f dataset.csv

Look for columns like device\_pkt\_rate\_deviation spiking during the attack, and label changing from 0 to 1 (Snort) or 2 (Behavioral).



Dataset Columns for ML

The CSV contains 45+ features ready for training:



Feature Category	Examples	Purpose

Flow	syn\_count, bytes\_per\_second	Detects volumetric attacks, scanning

Device Behavior	device\_new\_dst\_ratio, device\_pkt\_rate\_deviation	Detects Zero-Day \& Post-Compromise

Network Context	network\_entropy\_src\_ip, active\_snort\_alerts	Detects DDoS, widespread infection

Labels	label (0/1/2), attack\_type	Ground truth for supervised learning



