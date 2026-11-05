# Adaptive IPS framework — developer study roadmap

Version: 2026-11-05. Project: **Adaptive IPS framework**.

## How to use this roadmap

This covers prerequisites even if you have studied them before. Mark each topic 0 (unfamiliar), 1 (can explain), 2 (can implement a small example), or 3 (can debug and test it). Progress is demonstrated by work, not by finishing a video or accepting an AI explanation.

You do not need to finish the whole roadmap before running Stage A of NO_VISIBILITY_PILOT_RUNBOOK.md. Learn Linux/Python fundamentals alongside capture qualification. Automatic containment and model promotion require the later evaluation/operations gates.

A planning pace of 6–10 focused hours per week over several months can build useful junior-level competence. Breadth, prior knowledge and repeated debugging determine the actual pace; this is not an expertise guarantee. Use short loops: read → predict the result → implement → deliberately break an isolated copy → investigate → explain → record evidence.

Keep a private learning log: hypothesis, command/test, actual result, cause, fix and remaining uncertainty. Never create intentional failures in a live home/industrial network.

## 0. Problem framing and engineering language

**Know:** assets, threat actor, trust boundary, observation point, evidence, hypothesis, classification, decision, policy, enforcement, verification, availability, false positive/negative, uncertainty and rollback. Distinguish IDS/NDR/IPS, network firewall, WAF and policy-management service.

**Project:** CODEBASE_AI_HANDOFF.md; docs-site/roadmap/final-service-scope.mdx; delivery-phases.mdx.

**Build:** draw the packet path and the management path for the home pilot and isolated lab. Write which device can see/drop each packet and which claim is not observable.

**Pass:** explain why an alert, a block API response, a configured rule and a failed attacker transaction are four different kinds of evidence. Explain why no finite feature set guarantees zero missed attacks.

## 1. Computer, operating-system and command-line fundamentals

**Know:** process versus program, parent/child lifetime, environment variables, PATH, working directory, users/groups, filesystem permissions, stdin/stdout/stderr, exit status, signals, sockets, ports, services and virtual versus physical interfaces.

**Project:** scripts/start_docs.cjs; start_docs.cmd; start_docs.ps1; Controller/scripts/apf-home.service.

**Build:** start a small HTTP server, verify the listening PID and response, redirect logs, stop it and explain the observed connection error. On Windows distinguish .cmd from .ps1 execution and Node from npm.

**Pass:** diagnose wrong working directory, missing executable, missing entry file, occupied port, child-process exit and server-not-ready separately. A printed startup message is not readiness. Do not solve environment problems by globally weakening security settings.

## 2. Python syntax and data structures

**Know:** variables/types, booleans versus integers, strings versus bytes, loops, comprehensions, functions, return values, scope, exceptions, modules/imports, classes, instance state, inheritance, dataclasses, context managers, pathlib and type hints.

**Project:** Controller/ipsctl.py; collection_io.py; site_features.py.

**Build:** parse a small JSON observation, validate fields, update a Counter/dictionary and serialize a summary. Write tests for missing keys, null, zero, negative values and nonfinite numbers.

**Pass:** trace a value from function argument to return; distinguish mutation from copying; explain why an IP string is not a packet, and why null does not mean zero.

## 3. Python environments, dependencies and packaging

**Know:** Python interpreter selection, venv, pip, requirements, optional imports, package version compatibility, reproducible environments and trusted model serialization. Learn that pickle/joblib can execute code while loading; do not load arbitrary artifacts.

**Project:** Controller/requirements-home.txt; ml_inference.py; ae_inference.py; model builders.

**Build:** create separate collection and legacy-model environments. Reproduce the same synthetic extraction in a clean environment and record exact versions.

**Pass:** explain why Python 3.10 collection support does not prove that a legacy Ryu/sklearn deployment supports every newer Python version. Explain why changing the system python3 symlink is a poor dependency fix.

## 4. Ethernet, switching and local identity

**Know:** frames, MAC addresses, EtherType, VLAN tags, unicast/broadcast/multicast, bridges, ARP, IPv6 neighbor discovery, DHCP, address reuse, MAC randomization and spoofing.

**Project:** site_features.decode; SimpleSwitch._packet_in_handler; DAI state; static site-policy inventory.

**Build:** annotate Ethernet/ARP/IPv4/IPv6/VLAN frames in Wireshark; compare a valid address announcement with a conflicting binding in an isolated fixture.

**Pass:** explain why a MAC address is not authentication, why ARP does not cover IPv6, and why a leased/reassigned IP cannot permanently identify one device.

## 5. IP, routing, transport and network visibility

**Know:** subnet/CIDR arithmetic, routes/default gateways, MTU, fragmentation, TTL/hop limit, TCP flags/handshake/state/retransmission, UDP, ICMP, DNS basics, NAT and asymmetric paths. Distinguish packet count, byte count, sessions, requests and goodput.

**Project:** home_sensor.record; site_features.decode; nft_quarantine; no-mirror pilot.

**Build:** route two virtual subnets through a namespace firewall and capture both sides. Predict which tuple changes under NAT in a separate controlled experiment.

**Pass:** explain why a normal router LAN port does not mirror other devices' traffic, why one-sided observations cannot prove missing replies, and why endpoint offloads can distort captures.

## 6. Linux administration and network tooling

**Know:** ip link/address/route/netns, veth, bridge, ss, tcpdump, journalctl, systemctl, capabilities, sudo, file ownership, locks, disk budgets and clock synchronization.

**Project:** NO_VISIBILITY_PILOT_RUNBOOK.md; apf-home.service; shell setup scripts.

**Build:** complete the namespace lab, retain before/after host state, stop its processes and remove only owned resources. Inspect a deliberately failed service in a disposable environment.

**Pass:** identify which command changes the host versus a namespace. Explain CAP_NET_RAW, why it is narrower than root, and what evidence is missing from an accelerated replay versus a live soak.

## 7. Network security mechanisms and attack models

**Know:** reconnaissance, spoofing, volumetric/state/resource exhaustion, credential abuse, lateral movement, command/control, exfiltration, exploitation, authorization abuse and application attacks. Study the violated mechanism and required observability rather than only tool names.

**Project:** feature-rationale.mdx G1–G24; Snort rules; security-campaign contract.

**Build:** for each attack hypothesis, write a matched benign control and an independent truth source. Start with a small scan versus approved discovery and request pressure versus legitimate downloads.

**Pass:** explain why a scan or high rate is contextual evidence, not proof of intent; why traffic metadata cannot establish application authorization; and why HTTPS encryption creates a specific inspection limit.

## 8. SDN, OpenFlow, OVS and Ryu

**Know:** control/data/management planes, datapath IDs, ports, table matching/order, priorities, PacketIn/PacketOut/FlowMod, table miss, flow expiry, counters, controller connection and failure behavior. The merged controller uses OpenFlow 1.0; do not silently substitute a 1.3 tutorial.

**Project:** Controller_main_Claude.py; traffic_mirror.py; VXLAN setup script.

**Build:** implement a minimal learning switch in an isolated OVS lab; inspect flows before/after a forwarding change and verify actual traffic.

**Pass:** explain the difference between OFPP_CONTROLLER output and observing every physical path; distinguish VXLAN transport from an SD-WAN controller/product. Identify whether the required topology file actually exists in your checkout.

## 9. Concurrency, event loops and backpressure

**Know:** OS threads, cooperative greenlets, eventlet hub, locks, queues, shared mutable state, GIL limits, deadlocks, bounded buffers, producer/consumer handoff and output backpressure.

**Project:** TrafficCapture._flush_loop/_flush_flows; SimpleSwitch.block_attacker/_block_worker/_do_block_attacker; TrafficMirror; RF n_jobs setting.

**Build:** a small producer/consumer with a queue and a simulated slow consumer. Test bounded work and shutdown. Draw the project's thread ownership without running an intentional deadlock on the real controller.

**Pass:** explain why worker threads enqueue while the hub sends OpenFlow messages; why n_jobs=-1 caused a historical joblib/eventlet issue; and why flooding a tee/SSH stream can stall useful work.

## 10. Statistics and feature engineering

**Know:** units/denominators, population versus sample statistics, online mean/variance, quantiles, ratios/smoothing, coefficient of variation, entropy, cardinality, support, censoring, missingness, baselines, seasonality and robust estimators.

**Project:** site_features.Moments/DeviceWindow/FeatureHistory; traffic_capture; feature catalog; golden fixtures.

**Build:** hand-calculate feature values for a tiny packet trace, then compare against extraction. Test singleton windows, boundary packets, loss, duplicates and IPv6.

**Pass:** explain legacy first-to-last duration versus site fixed windows; why low CV can be legitimate IoT telemetry; why sorted-port density is not arrival order; and why correlated features are not independent corroborating votes.

## 11. Collection correctness and data engineering

**Know:** event time versus processing time, window keys/completeness, schema versions, source provenance, capture loss, truncation, parser support, privacy, rotations, checkpoints, torn writes, restart continuity and retention.

**Project:** home_sensor.py; collection_io.py; collection_report.py; qualify_home_collection.py; qualify_home_runtime.py.

**Build:** complete the golden qualifier and first PC replay. Test interrupted state and schema mismatch in private copies; inspect why the auditor returns REVIEW.

**Pass:** explain why UNKNOWN stays UNKNOWN, why a zero parser count does not establish absence of an attack, why collector-directory limits do not cover inbox PCAPs, and why independent sessions are not a continuous learned profile.

## 12. Supervised ML and evaluation

**Know:** train/validation/calibration/test separation, group/time/campaign splits, leakage, preprocessing/feature selection inside training folds, imbalance, confusion matrices, precision/recall/F1, ROC/PR, prevalence, calibration, decision costs and uncertainty.

**Project:** ml_inference.RFPreprocessor; retrain_rf_v4.py; campaign evaluator.

**Build:** a simple baseline classifier with a held-out campaign or later time, compare against RF under the same features, report failure cases and calibration separately from classification.

**Pass:** explain why resampling before splitting leaks information; why random-row results do not prove new-device/site generalization; why an RF vote is not automatically a calibrated probability; and why a shared extractor reduces one class of mismatch without proving all train/serve equivalence.

## 13. Autoencoders, anomaly detection and model lifecycle

**Know:** vectorization, standardization, dense layers, matrix dimensions, activation, reconstruction MSE, threshold selection, novelty versus maliciousness, drift, poisoning, candidate versus approved models and shadow releases.

**Project:** ae_inference.py; build_ae_bundle.py; site_policy approved/candidate profiles.

**Build:** a small NumPy forward pass and reconstruction score; measure anomalies on held-out normal workloads as well as attacks. Compare a simple robust baseline before proposing a larger model.

**Pass:** derive confidence = error/(error+threshold), explain why it is not a posterior probability, and why recalibrating scaler/threshold is not training new AE weights. Explain why current descriptive profile updates are not online training of RF/AE.

## 14. Firewall semantics, WAFs and safe automation

**Know:** ordered first match, default action, stateful sessions, rule/object groups, NAT lookup stage, zones/VRFs, application predicates, IPv4/IPv6, policy revisions, temporary source quarantine, idempotency, expiry, read-back, traffic verification and reversal.

**Project:** nft_quarantine; firewall_policy; policy_audit; policy_change; policy_store; policy_http.

**Build:** reproduce a duplicate/union shadow and an order-dependent access change with a witness. Complete manual containment/recovery in the namespace lab before joining any model.

**Pass:** explain why unsupported conditions require INDETERMINATE; why equivalent header access does not prove native firewall safety; why a WAF needs application visibility; and why read-back differs from actual containment.

## 15. APIs, databases, dashboards and application security

**Know:** HTTP methods/status codes, JSON validation, finite numbers, duplicate keys, request limits, authentication/authorization, loopback versus public binding, SQLite transactions/read-only handles, integrity versus authenticity, frontend fetch/rendering and XSS boundaries.

**Project:** policy_store.py; policy_http.py; IPSRestController; Dashboard/index.html; local_docs.py.

**Build:** a read-only snapshot endpoint with invalid-input tests; render returned strings as text; prove that failure does not partially write data. Inspect a traversal-rejection test.

**Pass:** explain why JSON Infinity breaks clients, why a SHA-256 hash is not an approval/signature, why a 200 response can contain an indeterminate result, and why a UDP send message does not confirm controller acceptance.

## 16. Software engineering and reliability

**Know:** Git branches/diffs/reviews, ownership, small changes, test layers, independent oracles, CI, configuration validation, failure injection, observability, transactional boundaries, dependency pinning, deployment/rollback, backups and service recovery.

**Project:** tests; .githooks; .github/workflows/documentation.yml; documentation/source guards; handoff builder.

**Build:** one small feature/bugfix with a reproducer, necessary tests, updated docs, changelog and refreshed handoff. Explain every changed line and its tradeoff in a review.

**Pass:** distinguish mocked ruleset tests, exhaustive finite-policy checks, replay extraction, live kernel behavior and hardware throughput. Show a failed check, correction and passing evidence without silently changing the acceptance criteria.

## 17. Product and scientific qualification

**Know:** customer use case, installation prerequisites, compatibility matrices, threat/coverage matrices, independent labels, false alerts per device-day, false actions, missed/late/abstained attacks, time to verified containment, resource ceilings and operational support.

**Project:** S01–S70 matrix; P0–P13 phases; campaign scorecard; pilot results template.

**Build:** a release-evidence pack: exact code/model/schema/adapter versions, supported scope, independent held-out campaigns, benign workloads, failure limits and reversal procedure.

**Pass:** defend a narrow supported claim with evidence and identify the next missing gate. Do not equate a research demonstration, competitor-inspired requirement, installed function or attractive dashboard with a production-ready product.

## Suggested sequence and weekly routine

| Period | Focus | Deliverable |
| --- | --- | --- |
| First pass | 0–6 | Explain packet paths, use the environment correctly, run qualification and first endpoint capture |
| Second pass | 7–11 | Bounded feature extractor, independent tiny-trace expectations and failure handling |
| Third pass | 12–13 | Reproducible baseline/RF/AE experiments with held-out evaluation and honest uncertainty |
| Fourth pass | 8–9 and 14–16 | Trace the legacy system and test controlled firewall changes with review/rollback |
| Ongoing | 17 and repeated weak topics | Maintain release evidence and operate a narrow qualified pilot |

For each study session: 15 minutes recall, 30–60 minutes reading/packet inspection, 45–90 minutes coding/debugging, then a short written explanation. Adjust this schedule to your time.

**Use AI as a reviewer/tutor:** ask it to predict a failing case, question your explanation and review your implementation. First write your own hypothesis. Before merging generated code, explain inputs, outputs, state, failure path, resource cost, trust boundary and test evidence.

## Capstone: rebuild a thin slice without copying

1. Read a small Ethernet PCAP and identify one selected endpoint.
2. Produce five-second directional counts/rates with explicit incomplete windows and UNKNOWN truth.
3. Write an independent expected-value fixture and prove a boundary/loss/missingness case.
4. Add a simple reviewed-role finding in shadow mode.
5. Persist evidence/profile candidates without automatically approving them.
6. In the isolated lab, request a scoped temporary nftables quarantine manually.
7. Verify set membership, independent target receipts, innocent-client continuity, reversal and expiry.
8. Present the limitations before considering model-triggered automation.

Completion means you can build, explain, test and debug this slice. It does not require rebuilding every library or understanding every mathematical research area first.

## Primary references

- [Python tutorial](https://docs.python.org/3/tutorial/) and [threading](https://docs.python.org/3/library/threading.html)
- [Wireshark guide](https://www.wireshark.org/docs/wsug_html/) and [capture offloads](https://wiki.wireshark.org/capturesetup/offloading)
- [TCP specification, RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html)
- [Linux network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [Ryu application API](https://ryu.readthedocs.io/en/latest/ryu_app_api.html)
- [OVS OpenFlow FAQ](https://docs.openvswitch.org/en/latest/faq/openflow/)
- [NumPy beginner guide](https://numpy.org/doc/stable/user/absolute_beginners.html)
- [scikit-learn leakage/pitfalls](https://scikit-learn.org/stable/common_pitfalls.html), [evaluation splits](https://scikit-learn.org/stable/modules/cross_validation.html) and [calibration](https://scikit-learn.org/stable/modules/calibration.html)
- [Node child-process lifecycle](https://nodejs.org/api/child_process.html)

These teach concepts; their latest package versions are not an instruction to upgrade the legacy deployment. Preserve qualified interpreter/library/artifact versions and test migrations separately.
