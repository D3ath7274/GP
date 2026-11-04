# APF implementation roadmap

APF will observe an SD-WAN, learn device behavior, flag suspicious activity, and request a scoped temporary quarantine from a qualified firewall when the evidence meets the enforcement threshold. The SOC can inspect and reverse the action. Firewall feedback establishes enforcement state. Independently reviewed evidence establishes whether the behavioral decision was correct.

## Starting point in this checkout

| Source | Reuse | Change required |
| --- | --- | --- |
| `Controller_main_Claude.py` packet handler and Snort callback | Existing OpenFlow and alert inputs | Put normalized observations behind an adapter so APF can run without Ryu. |
| `block_attacker`, `_block_worker`, `_do_block_attacker` | Hub-safe handoff for OpenFlow operations | The current block map can be populated before a rule is sent. A successful send does not confirm installation. Introduce an independent action lifecycle. Keep remote API calls off the Ryu hub. |
| REST block and unblock handlers | Existing operator workflow as a reference | A protected-MAC skip can be reported as success by its caller. Review broad OpenFlow delete matching and the separate host-firewall cleanup path before reusing either for automated actions. |
| `traffic_capture.py` | Window aggregation, feature extraction and per-IP profiles | Bound state, handle incomplete observations, separate identity from address, and prevent profile writes before final learning eligibility is decided. |
| `DeviceProfile.get_features` | Device novelty as a detection concept | The current set expression reduces to the recent set. Add a versioned correction against history frozen before the window. |
| RF and AE loaders | Frozen comparison baseline and batch RF entry point | Existing models load artifacts at startup. Add a qualified bundle lifecycle and separate anomaly scores from calibrated action confidence. |
| Dashboard and Mintlify site | Operator presentation and documentation | Add evidence and action state to a separately authenticated management interface. Preserve the existing lab API during migration. |

## Phase 0 — Freeze and reproduce the lab baseline

**Requires** the shipped models, exact feature settings, Python dependency versions, and a sanitized packet fixture or an authorized lab capture. Use the t530 for measurements and an isolated Linux/OVS lab for enforcement.

1. Record the code revision, artifact hashes, feature flags, Snort rule revision and observed dependency versions. Keep the original v2 artifacts intact.
2. Build a replay test that covers ordinary traffic, recon, flooding, ARP conflicts and incomplete traffic. Store fixture provenance and independently assigned labels. Compare features and decisions across repeated runs.
3. Reproduce the novelty defect, pending-versus-blocked ambiguity and protected-MAC response in tests. Verify the existing OpenFlow block and unblock path on a disposable bridge. Record whether unrelated flows survive removal.
4. Measure CPU, memory, scoring coverage, queue delay and storage growth. Capture a load profile for subsequent regression comparisons.

**Exit** a repeatable report distinguishes controller logs, installed rule state and verified traffic outcomes. Capture or test limitations are recorded. No live-network enforcement is needed to finish this phase.

## Phase 1 — Observation, identity and data quality

**Requires** the Phase 0 fixtures and an inventory of observation points. For a home pilot, use a verified TAP/SPAN path or a managed bridge. Measure which device-to-device paths bypass the sensor.

1. Introduce a separate APF package with versioned `Observation`, `Session` and `FeatureFrame` contracts. Each record carries event time, site, tenant, observation point, quality flags and evidence references.
2. Implement PCAP replay first, then passive capture. Adapt Ryu observations after replay parity is understood. Introduce flow exports and device logs as separate data sources with explicit sampling and field availability.
3. Add bounded bidirectional session state and windows of 1 s, 5 s, 1 min, 15 min and daily summaries. Preserve both directions across windows. Deduplicate repeated ingestion at a sensor while retaining distinct ingress and egress observations.
4. Join identity from lease, VLAN, interface, NAT and inventory history with validity intervals. Invalidate stale mappings. Keep shared-address and conflicting identities ambiguous. Attach capture loss, parser errors, missing directions and clock skew to dependent records.
5. Fix destination novelty in the new schema. Snapshot historical destinations before evaluating the window, then merge eligible destinations after scoring. Cover 0, 0.5, and 1 with deterministic tests.

**Exit** replay produces reproducible features and exposes missingness under one-sided capture, NAT reuse, IPv6, duplicated packets, out-of-order events and overload. Observe-only startup requires no firewall write credential.

## Phase 2 — Behavioral feature groups and evidence decisions

**Requires** the Phase 1 contracts, independently labeled lab campaigns, and benign lookalikes for each feature group.

1. Implement G11 recon, G12 protocol anomalies, G13 long-horizon behavior, G18 exhaustion and G19 identity conflict first. Use session completion, destination fan-out, role-relative rates and binding history as initial signals.
2. Add G20 management/routing anomalies and G21 credential/lateral activity with routing, configuration and authentication telemetry. Then add G14 service behavior, G15 DNS, G16 TLS/QUIC, G17 HTTP, G22 authorization abuse, G23 C2/exfiltration and G24 exploitation outcomes as their observation sources become available.
3. Give each group a feature card with units, formulas, key, window, minimum support, visibility requirements, memory budget, benign lookalikes, evasion variants and fixture IDs. Evaluate group ablation at the same false-alert budget. Keep weak groups diagnostic until they demonstrate added value.
4. Emit an immutable finding with mechanism, asset, evidence lineage, detector version, visibility and decision deadline. Use `NO_EVIDENCE`, `SUSPICIOUS`, `HIGH_RISK` and `DETECTED`. Keep ground-truth labels and enforcement state separate. Missing telemetry cannot increase confidence.
5. Reserve inference capacity for sparse activity and report eligible flows skipped under load. Keep signature verdicts optional and report behavioral-only results. Compare against signatures and fused decisions separately.

**Exit** the first groups separate attack fixtures from their hard negatives, including held-out tools and low-volume recon under load. Web payload and authorization claims cite proxy, application or endpoint evidence at an authorized observation point.

## Phase 3 — Scientific qualification of the decision

**Requires** a data ledger, a capture plan, a locked release suite and an independently established outcome for every mandatory attack fixture.

1. Gather normal workloads across several device roles and operating cycles. Include updates, backups, streaming, approved scans and failover. Use isolated attack campaigns with independent target instrumentation and matched benign controls. Keep ambient site observations unverified until reviewed.
2. Partition by campaign before preprocessing. Reserve later time periods, separate calibration data and independent sites where available. Hold out tools and attack families. Remove generator IDs, scenario labels, firewall verdicts and lab-only shortcuts from model inputs.
3. Compare deterministic thresholds and robust role baselines first. Retrain RF and compare with a boosted-tree candidate. Retrain AE weights and scaler together for the target schema. Add a sequence model only if it improves sparse or multistage results at the same alert budget.
4. Calibrate decision confidence on separate data. Report reliability plots, precision–recall, Brier score where probability is defined, cohort support and uncertainty at the action threshold. AE error remains anomaly evidence. RF and AE using the same flow are correlated.
5. Freeze a signed candidate bundle with schema, preprocessing, models, thresholds, evidence requirements, benchmark results and rollback compatibility. Count verified attacks receiving abstention, silence or late detection as misses in end-to-end recall.

**Exit** zero missed, late or abstained cases on the mandatory observable critical suite, zero erroneous actions proposed on the locked benign suite, and an explicit report of unobservable and underpowered cohorts. Publish campaign counts and uncertainty. Set per-mechanism detection deadlines before evaluation.

## Phase 4 — Durable enforcement and SOC reversal

**Requires** an isolated Linux firewall, a declared protection policy, a verified identity mapping, and separate detector and enforcement processes. Use nftables as the reference adapter.

1. Define an `ActionIntent` with an idempotency key, site and policy target, device identity and validity interval, selector, evidence IDs, expected policy revision, scope and expiry. Start with a five-minute temporary deny.
2. Store decisions and action transitions in a durable journal. Distinguish proposed, rejected, pending, effective, verified, unknown, partially applied, revoked and expired states. Store actor, timestamp, revision and evidence for each transition.
3. Implement adapter operations for capabilities, preflight, apply, read-back, reconcile and revoke. Prefer an APF-owned rule namespace and native TTL. Reject protected or ambiguous assets, stale policy revisions, excessive scope and unavailable verification or expiry. Serialize writes per policy target.
4. Run adapter I/O in a separate worker with scoped credentials and bounded retries. A timeout triggers read-back before retry. Confirm effective state on relevant targets, then use independent traffic or counters when safe. Test that cleanup only removes APF-owned changes.
5. Add authenticated SOC access with viewer and operator permissions, a reversal reason, an action-specific cooldown, and an emergency stop for new actions. Existing actions remain eligible for cleanup. Use a separate authorization boundary from the prototype REST and UDP endpoints.

**Exit** an identified lab source is quarantined while a separate benign client keeps access. Prove expiry, restart recovery, reversal, duplicate handling, lost acknowledgements, concurrent admin changes and partial enforcement. Any wrong-device or out-of-scope action fails the release.

## Phase 5 — First commercial firewall adapter and site pilot

**Requires** access to one customer-representative vendor lab, versioned management API credentials, and a documented change and rollback process. Choose the first vendor based on available equipment and safe write/read-back support.

1. Publish a capability matrix covering supported selectors, policy scope, commit and install semantics, HA visibility, TTL, revision checks and read-back. Use the same contract tests as the reference adapter. Fall back to findings and recommendations for unsupported enforcement paths.
2. Onboard a site in passive mode. Inventory protected assets and validate paths with benign transactions. Collect at least seven days initially, extending the period for sparse devices and unobserved workflows.
3. Run shadow actions and review proposed quarantines against independent investigation. Measure false high-risk alerts per device-day, proposed false quarantines, evidence latency and operator review burden.
4. Enable automatic action on a small approved segment only after the site and adapter pass their gates. Begin with a single concurrent quarantine per site and a single reapplication per device within an hour. Escalate further actions to the SOC. Verify each canary action before expanding.

**Exit** demonstrated containment, benign-client continuity, expiry and reversal on the vendor’s effective forwarding targets. Score uncertainty and missed detections by site and visibility profile. Publish supported firmware and management combinations before adding the next vendor.

## Phase 6 — Guarded learning and ongoing assurance

**Requires** the Phase 3 release harness, authenticated review feedback and evidence of safe rollback on the reference and commercial adapters.

1. Score before updating device profiles. Update only eligible observations with sufficient identity and visibility. Hold suspicious, unverified, attack-adjacent and degraded observations out of the approved baseline. Keep candidate state separate and bound drift per role.
2. Train candidates off-appliance from reviewed data. Shadow-score each candidate alongside the active bundle. Automatically promote only after the locked suite, site replay, action-rate limits, schema checks and rollback checks pass.
3. Freeze learning and new automatic containment when required sensors, calibration eligibility or adapter verification degrade. Continue collecting findings and reconciling existing actions. Retain the last approved bundle and compatible profile snapshot.
4. Exercise slow poisoning, natural drift, rollback, queue pressure and interrupted cleanup. Measure detection and enforcement separately. Track campaign recall, false quarantine burden, time to detection and effective containment, action scope, scoring omissions, expiry and reversal success.

**Exit** a seeded poisoning scenario cannot silently alter active enforcement, a qualified candidate can take over and roll back, and a failed candidate stays in shadow. The operator report distinguishes behavior, confidence, firewall response and independent confirmation.

## Change sequence for the first implementation PR

1. Add the baseline manifest and sanitized replay fixtures.
2. Add tests for repeated feature output, novelty and provisional block state.
3. Record the baseline results and link each defect to a later phase.

Keep feature changes and adapter writes in later PRs so the baseline remains comparable. For each implementation PR, update the relevant Mintlify page and dated changelog, update OpenAPI for contract changes, and record the checks actually run.
