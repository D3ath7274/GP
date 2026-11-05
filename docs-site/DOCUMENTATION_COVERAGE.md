# Source coverage

| Source | Site page |
| --- | --- |
| Controller launch and packet handler | Install the controller, Quickstart and Packet capture and enforcement |
| TrafficCapture, RF and AE | Packet capture and enforcement and Collect and validate site data |
| IPSRestController | Management API, seven JSON operations |
| Dashboard/index.html | Dashboard and unblock workflow, the sole dashboard screen |
| ipsctl and UDP listener | Detection modes and controls, UDP control protocol |
| Integrated Snort monitor and reference Lua/rules | Snort signature evidence: retained lab integration |
| OVS and host firewall | Select deployment placement and Configuration and management access |
| Four detection tiers and default thresholds | Detection tiers and decisions |
| Unblock and verification paths | Verify, contain and recover |
| Runtime modules and extension points | Develop and verify changes |
| Passive Ethernet capture, PCAP replay and dashboard | Test the passive sensor |
| Dedicated nftables set, temporary quarantine and removal CLI | Test temporary firewall quarantine |
| site_features.py, home_sensor.py, daily data audit and service | Collect home traffic for two weeks |
| site_policy.py, site_policy.example.json, review_site_baseline.py, policy API and dashboard | Shadow policy and reviewed baselines |
| Loopback documentation reader from Mintlify sources | Documentation access and updates |
| scripts/start_docs.ps1, background Mintlify preview and readiness logs | Documentation access and updates |
| Documentation map, Git hook, staged guard and push/PR validation | Develop and verify changes |
| User-supplied 70-capability product specification and current-source assessment | Final service scope and competitor coverage |
| Canonical delivery-phases, P0–P6 IPS gates and P7–P13 policy-management services | Delivery phases and service release gates |
| firewall_policy.py, policy_store.py, policy_http.py, policy_inventory.py and reference fixtures | Test the read-only policy workbench; Policy workbench: code and rationale |
| Ordinary router LAN connection, single-NIC switch/bridged-AP layout, management gates and timed PC/phone/Internet tests | Home pilot: one Ethernet port, wired and Wi-Fi; Select deployment placement |
| collection_io.py, pure collection contract, run fingerprints, preflight and golden/runtime qualifiers | Qualify collection before a long pilot; Qualification and audit: code and rationale |
| collection_report.py, audit_home_data.py, paired evidence and daily/device summaries | Qualify collection before a long pilot; Collect home traffic for two weeks |
| evaluate_security_campaign.py and examples/testing contracts | Run independent security campaigns; Qualification and audit: code and rationale |
| policy_audit.py, audit CLI/API/button and audit-reference.json | Audit the supported firewall-policy subset; Policy workbench read API; Qualification and audit: code and rationale |
| policy_change.py, impact/propose/verify-proposal, preview UI/API and change-reference fixtures | Develop and test while visibility is unresolved; Policy changes and feature rationale: code tour; Policy workbench read API |
| G1–G24, source-mapped feature-groups.json, check_feature_catalog.py and commit/CI guard | Why each behavioral feature group exists; Develop and verify changes; Policy changes and feature rationale: code tour |
| NO_VISIBILITY_PILOT_RUNBOOK.md, PILOT_RESULTS_TEMPLATE.md, endpoint PCAP replay and namespaced operator-run firewall exercise | Start testing without a traffic mirror; Collect home traffic for two weeks; Test temporary firewall quarantine |

Superseded root runbooks are removed. Current qualification/deployment pages and the no-mirror Markdown guide are canonical; see the scope ledger for recovery.

| Additional source | Site page |
| --- | --- |
| DEVELOPER_STUDY_ROADMAP.md | Study and rebuild the framework |
| CODEBASE_AI_HANDOFF.md, PROJECT_AI_HANDBOOK.md, file-purposes.json, codebase-snapshot.json and build_ai_handoff.py | AI continuation and codebase architecture; Develop and verify changes |
| start_docs.cmd/start_docs.cjs, tests/test_docs_launcher.cjs and Node CI check | Documentation access and updates; Develop and verify changes |


| Consolidated source | Site page |
| --- | --- |
| http_dashboard.py and import isolation / actual HTTP / legacy extraction tests | Dashboard; Home collection; Repository scope; Develop and verify changes |
| Removed alternate relays/helpers and duplicate runbooks; retained Ryu/DAI reference | Repository scope and preservation ledger; Legacy behavioral reference and replay; Snort signature evidence |
| Original proposed G11–G17 tables and current/planned G1–G24 status | Feature preservation and design lineage; Why each behavioral feature group exists |

## Task navigation

The site groups pages into Start here, Collect data, Audit firewalls, Develop and Reference. This changes only how readers find the existing routes; source-to-content mappings remain the same. The homepage supplies reading sequences and the docs README records tab ownership. Keep every authored page and each current/legacy API contract reachable when editing docs.json.


| Feature-method research source | Site page |
| --- | --- |
| behavioral_evidence.py, score_feature_groups.py and test_behavioral_evidence.py | Feature measurement methods and research; Inspect feature-group evidence offline; Feature-group evidence: code and rationale |
| feature-methods.json, G1/G6 site assignment and check_feature_catalog.validate_methods | Feature measurement methods and research; Why each behavioral feature group exists; Develop and verify changes |
