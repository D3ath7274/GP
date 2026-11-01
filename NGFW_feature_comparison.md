# Feature Comparison — this IPS vs. industry NGFWs (2026)

How the Adaptive Multi-Tier IPS compares with current next-generation firewalls, feature by
feature, and what that comparison says about where the project belongs.

> **Reference set:** the three Leaders in Gartner's first Magic Quadrant for **Hybrid Mesh
> Firewall** (August 2025) — Palo Alto Networks (PAN-OS / Strata), Fortinet (FortiGate /
> FortiOS), and Check Point (Quantum) — plus Cisco Secure Firewall. Vendor capabilities are
> described at the category level from public product material; check the exact model and
> license before quoting one. Every claim about this project is verified against the code in
> this repo.

---

## The verdict in two sentences

As an NGFW **replacement**, the project loses. An NGFW is a policy device that understands
applications, users, and content; this project has no policy engine at all. It forwards
everything and drops only hosts a detection tier has convicted. As an **IoT detection layer
next to an NGFW**, it wins in several places that matter, at a fraction of the cost.

## What "NGFW" means in 2026

The NGFW baseline has six parts:

- a stateful firewall
- application identification (App-ID)
- user identity
- signature IPS
- URL and DNS filtering
- TLS decryption

Most vendors add sandboxing, VPN and SD-WAN, and central management. Gartner now calls the
category **hybrid mesh firewall**: one policy enforced across hardware, virtual, and cloud
firewalls from a single cloud management plane. Recent additions include inline deep-learning
detection, TLS 1.3 decryption, post-quantum cryptography for decryption (PAN-OS 12.1), and
automatic IoT device identification.

**Legend:** ✅ has it · ◐ partial · ❌ missing · 🔧 **config gap** — the engine already ships
in Snort 3 and is just not enabled or loaded

---

## 1. Core firewalling

| Capability | Industry NGFW | This project | |
|---|---|---|---|
| Stateful L3/L4 policy (zones, allow/deny rules, default-deny) | Core function | None. OVS forwards everything; a DROP is installed only after a tier convicts a host | ❌ |
| NAT and routing | Built in | Only through host `iptables` MASQUERADE in Mode B — the OS provides it, not the product | ◐ |
| VPN (IPsec site-to-site, remote access / ZTNA) | Built in | None | ❌ |
| SD-WAN path steering | Built in (FortiGate, Prisma SD-WAN) | The QoS steering prototype was removed from the deployment repo in `8a07efc` | ❌ |
| High availability (active/passive, clustering, session sync) | Standard | Single controller, no failover | ❌ |
| Throughput | Multi-Gbps up to 100+ Gbps on custom silicon (Fortinet ASICs, Palo Alto single-pass) | Not measured. Every packet goes to the controller on a thin client; ML scoring is capped at 60 flows per 5 s window | ❌ |

## 2. Application, user and device awareness

| Capability | Industry NGFW | This project | |
|---|---|---|---|
| Application identification and control (App-ID) | The defining NGFW feature | None. Snort 3's `appid` module exists but is not enabled (it also needs OpenAppID detectors) | ❌🔧 |
| User-identity policy (AD / SSO / IdP) | Standard | None — hosts are identified by MAC/IP plus manually assigned names | ❌ |
| IoT device identification | Automatic profiling (Palo Alto Device-ID / IoT Security, FortiGuard IoT), often a separate license | Manual tagging only (`REGISTER:IOT`); no OUI or DHCP fingerprinting | ◐ |
| URL filtering / web categories | Standard subscription | None | ❌ |

## 3. Threat detection and prevention

| Capability | Industry NGFW | This project | |
|---|---|---|---|
| Signature IPS | Tens of thousands of signatures, updated daily by a vendor research team | Snort 3 engine, but only **4 local rules** plus the `port_scan` and `arp_spoof` inspectors. The free community and Talos registered rulesets are not loaded | ◐🔧 |
| Unknown / zero-day detection | Inline ML and deep learning trained centrally on global telemetry, payloads included (e.g. Palo Alto Advanced Threat Prevention) | Autoencoder trained on **this site's** normal traffic only, from flow features, with no payload | ✅ |
| Supervised ML classification | Inline ML for malware, phishing, C2 | Random Forest over flow features, 7 classes | ✅ |
| Volumetric DoS / floods | DoS and zone-protection profiles | Tier 2 rate counters with hysteresis, a z-score check, and Snort rate rules | ✅ |
| Reconnaissance / port scan | Zone protection | Tier 2 counters plus Snort `port_scan` | ✅ |
| L2 attacks (ARP spoofing) | Mostly left to the switch's DAI; some firewalls offer ARP inspection in transparent mode | DAI binding table inside the detection stack, instant block | ✅ |
| TLS decryption | TLS 1.3 inline decryption; post-quantum ciphers arriving (PAN-OS 12.1) | None, by design — the system never reads payload | ❌ |
| Encrypted-traffic analysis without decryption (JA3/JA4, certificate fingerprints) | Varies by vendor | None | ❌ |
| DNS security (DGA, tunnelling, sinkholing) | Standard subscription | None. Snort 3's `dns` inspector is available | ❌🔧 |
| Anti-malware / file blocking | Standard | None | ❌ |
| Sandboxing (WildFire, FortiSandbox, Threat Emulation) | Standard add-on | None | ❌ |
| Web-application attacks (SQLi, XSS) | Partly through IPS signatures; a full WAF is a separate product | None. Snort 3's `http_inspect` is available | ❌🔧 |
| OT / ICS protocols (Modbus, DNP3, S7, IEC-104) | Industrial product lines and OT signature packs | None. Snort 3's OT inspectors are available | ❌🔧 |
| Threat-intel / reputation feeds | Built-in global feeds | None | ❌ |

## 4. Operations and management

| Capability | Industry NGFW | This project | |
|---|---|---|---|
| Central multi-device management | Panorama / Strata Cloud Manager, FortiManager, Check Point management | Single-node web dashboard, REST API, and UDP control channel | ◐ |
| Logging, SIEM export (syslog / CEF), MITRE ATT&CK mapping | Standard | CSV dataset, Snort `alert_json`, and the REST API; no SIEM export or ATT&CK mapping | ◐ |
| Staged enforcement (alert first, then block) | Alert or block action per security profile | DETECT gate, ML OBSERVE→AUTHORIZE, confidence bands, and a protected-MAC never-block list | ✅ |
| Per-site learning and retraining | Rare — vendors ship global models and tune by exception | Built in: pre-production collection plus a retrain pipeline. Training data and live features come from the same code path | ✅ |
| Alert explainability | Threat IDs and verdict reasons | Tier name, RF class, and confidence; no per-feature attribution for AE alerts | ◐ |
| Certifications (Common Criteria, FIPS 140-3, ICSA, independent lab testing) | Standard for enterprise sales | None | ❌ |
| Vendor support, patching, threat research | Included in subscriptions | None | ❌ |

## 5. Cost and privacy

| Capability | Industry NGFW | This project | |
|---|---|---|---|
| Cost | Appliance plus yearly per-feature subscriptions | Commodity thin client and an open-source stack | ✅ |
| Payload privacy | Decrypts and inspects content by design | Never reads payload; scores flow statistics and packet-*size* entropy only | ✅ |

---

## Scorecard

| Area | ✅ | ◐ | ❌ | 🔧 closable by config |
|---|---|---|---|---|
| Core firewalling | 0 | 1 | 5 | 0 |
| Application / user / device awareness | 0 | 1 | 3 | 1 |
| Threat detection and prevention | 5 | 1 | 8 | 4 |
| Operations and management | 2 | 3 | 2 | 0 |
| Cost and privacy | 2 | 0 | 0 | 0 |
| **Total (33 capabilities)** | **9** | **6** | **18** | **5** |

The 9 strengths are almost all in **detection, enforcement discipline, cost, and privacy**. The
18 gaps are almost all in **the firewall core, content security, and enterprise operations**.
That split is the positioning argument in one table.

---

## Where it beats or matches an NGFW

1. **Zero-day detection without payload, learned on your own network.** NGFW inline ML is
   trained centrally and needs content to work. The autoencoder learns this site's normal
   traffic and flags deviations from flow statistics alone. In this respect it is closer to
   Darktrace than to a FortiGate.
2. **L2 attack detection.** ARP spoofing is caught inside the detection stack. NGFWs are L3
   devices and mostly leave this to switch features.
3. **Per-site retraining with no train/serve skew.** The same capture code produces the
   training data and the live features, and the retrain pipeline fits each site. Commercial
   products usually ship one global model.
4. **Privacy.** Nothing is decrypted or read. Every NGFW content feature gives up exactly this
   property.
5. **Cost and agentless deployment.** A thin client, no per-feature licensing, and nothing
   installed on the devices.

## Where it loses — and what kind of gap each is

- **Config and rule-feed gaps (days to weeks).** Load the Snort community and Talos rulesets.
  Enable the `dns`, `http_inspect`, `ssl`, `appid`, and OT inspectors. Two costs: each payload
  inspector gives up the privacy property, so put it behind an explicit policy toggle, and L7
  inspection of mirrored traffic will cut t530 throughput significantly.
- **Engineering gaps (months).** A stateful policy engine, controller HA, SIEM export, JA3/JA4
  fingerprinting, automatic device fingerprinting, and measured throughput with hardware
  offload.
- **Business gaps (no amount of code closes these).** Certifications, a threat research team,
  global threat intelligence, and a support and patching SLA. These win enterprise deals for
  NGFW vendors whatever the feature list says.
- **Gaps not worth closing.** TLS decryption, sandboxing, and VPN. Building them means
  rebuilding a firewall vendor, and decryption would discard one of the project's real
  advantages.

## The right frame

- **Peer group:** IoT network detection & response — Armis, Claroty, Nozomi, Darktrace, Vectra,
  ExtraHop, Corelight. Those are the products to benchmark against.
- **Placement:** next to the NGFW, on the IoT segment, either inline or on a SPAN port. The IPS
  supplies device-level behavioral detection, and the NGFW supplies policy, content
  inspection, and the perimeter.
- **Strongest position (the agreed next phase):** a **firewall-audit / traffic-truth layer**.
  It would reconcile a vendor firewall's policy against the per-flow traffic it actually
  observes:
  - rules that never match → dead rules and unnecessary attack surface
  - traffic that no rule explains → shadow IT or a bypass path
  - anomalies the firewall permitted → evidence of a policy gap

  Static auditors (AlgoSec, Tufin, FireMon) can't do this because they only read configs. See
  [`SESSION_HANDOFF.md`](SESSION_HANDOFF.md).

## Closing the most valuable gaps, ranked by value per effort

1. **Snort rule feeds + DNS analytics.** IoT command-and-control mostly runs over DNS. The
   `dns` inspector reads only query names, a small and well-understood privacy cost.
2. **JA3/JA4 and certificate fingerprinting.** The only way to say anything useful about
   encrypted traffic without decrypting it.
3. **Beaconing / periodicity detection.** Builds on the existing 5 s flow windows; no new
   plumbing.
4. **SIEM export and MITRE ATT&CK mapping.** No detection gain, but it makes the output usable
   by a security operations team.
5. **Controller HA, or a deliberately chosen fail-open policy.** The largest operational gap.
6. **A managed firewall and WAF driven by the same detection brain.** Turns detections into
   policy rather than one-off drops.

---

**Sources:** [Palo Alto — Gartner MQ for Hybrid Mesh Firewall 2025](https://www.paloaltonetworks.com/network-security/gartner-hybrid-mesh-firewalls-mq-2025) ·
[Fortinet — Gartner MQ for Hybrid Mesh Firewall](https://www.fortinet.com/resources/analyst-reports/gartner-magic-quadrant-hmf) ·
[Check Point named a Leader, 2025 HMF MQ](https://kbi.media/press-release/check-point-named-a-leader-in-the-2025-gartner-magic-quadrant-for-hybrid-mesh-firewall/) ·
[Palo Alto NGFW / PAN-OS documentation](https://docs.paloaltonetworks.com/ngfw) ·
[Palo Alto — ML-powered NGFW (inline ML, TLS 1.3 decryption)](https://www.paloaltonetworks.com/blog/?p=116051)
