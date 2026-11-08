# Adaptive IPS framework — authored AI continuation context

Version: 2026-11-05. Read this context before interpreting historical documents.

## Purpose, authority and freshness

The user is building **Adaptive IPS framework**, evolving from a four-tier SDN IoT IPS graduation project into evidence-backed behavioral security plus vendor-qualified firewall policy management. They want autonomous development with understandable rationale, detailed docs, staged phases and practical t530 testing.

PROJECT_AI_HANDBOOK.md combines this authored context with the purpose of every tracked file, a Python symbol/import index and local-only exclusions. It is the intended single Markdown document to give another AI. Source fingerprints are in docs-site/reference/codebase-snapshot.json; refresh/check them with scripts/build_ai_handoff.py. Fingerprints normalize text line endings and retain raw model bytes; they are not artifact signatures.

This context does not replace the user's current instructions or AGENTS.md, grant permission for actions or establish production correctness. The next AI should verify freshness, then read only the relevant implementation/functions/tests for the requested edit. A summary cannot remove that verification requirement. Do not claim complete comprehension from generated symbol names alone.

Historical duplicate runbooks and alternate Snort relays were consolidated in the 2026-11-05 cleanup. AI_Project_Context.md is now a short pointer. docs-site/developers/repository-scope.mdx lists exact deletions/replacements; the annotated pre-auto-audit-cleanup-2026-11-05 tag preserves the prior committed tree. docs-site/architecture/feature-lineage.mdx retains earlier G11–G17 proposal tables, while the source-mapped G1–G24 rationale remains canonical.

## Current goals and deployment facts

- Target hardware: HP t530, Ubuntu 22.04/Python 3.10 class environment, one physical Ethernet interface; no confirmed usable Wi-Fi adapter.
- The ISP ZTE H188A is both router and AP. Its ordinary LAN connection to the t530 has not provided a verified whole-home mirror. No added AP/switch/adapter deployment is established.
- Home use includes a gaming/work PC and family phones. Absence of suspected malicious activity is not an independent benign label.
- Immediate executable path: NO_VISIBILITY_PILOT_RUNBOOK.md and private-copy PILOT_RESULTS_TEMPLATE.md. Qualify software, capture selected real PC sessions, replay on t530 and test operator-run nftables containment in a namespace lab.
- An actual industrial firewall vendor/model/firmware has not been selected.
- Final goals include S01–S70 from the competitor-inspired requirements, governed by P0–P13 release phases. Most enterprise/vendor services remain planned. FireMon/AlgoSec-inspired policy management complements, rather than replaces, behavioral IPS.
- Desired learning policy: eligible profile adaptation and model promotion after shadow validation/release gates. Current code does not implement a fully online trained site-v3 detector or autonomous vendor-policy loop.
- Goal of high assurance is evaluated through observable coverage, independent campaigns, calibrated action criteria and reversal, not promised zero misses or artificially increased confidence scores.

## Collaboration constraints

Update affected docs-site pages plus a dated changelog for implementation changes; maintain API contracts, source map, navigation and service classifications. Run staged documentation, feature and handoff guards plus Mintlify checks. The exact commands are in docs-site/README.md.

Preserve Backup material if present. Do not repoint the system python3 symlink or install distribution Snort 2 as a substitute for the intended Snort 3 source installation. Do not add victim/server-specific block protection based on an old rejected proposal. Existing operator-configured protections are separate current behavior.

User expects rationale for design choices and coherent commits/pushes. Current development branch is docs/readme-ngfw-and-test-plans; inspect Git before acting. Do not stage the user's untracked dataset/model directories. Store private captures/addresses/credentials outside public examples and Git.

## Active product foundations and retained reference lanes

| Lane | Entry point | Observation/analysis | Enforcement authority |
| --- | --- | --- | --- |
| Legacy SDN IPS | Controller/Controller_main_Claude.py via ryu-manager | OpenFlow PacketIn → legacy 102-column flow/device/network schema, Snort, rate/DAI, RF and AE | Hub-installed OpenFlow drops; opt-in host iptables for designated external sources |
| Legacy standalone passive sensor | Controller/passive_ids.py | Scapy Ethernet interface or PCAP → the legacy TrafficCapture/models and shared dashboard | Capture/observe only; write endpoints rejected |
| Site-v3 home collector | Controller/home_sensor.py | Ethernet interface/PCAP → bounded 71-column device/VLAN windows, health, optional protocol metadata, shadow policy | No model inference, promotion or firewall writes |
| Read-only policy workbench | scripts/policy_inventory.py serve → policy_http.py | Operator-described apf-policy-v1 snapshots, header queries, audits, structural and hypothetical semantic changes | No native vendor import/apply; HTTP operations are read-only |

Controller/nft_quarantine.py is an additional **operator-run** adapter CLI for an explicitly provisioned Linux nftables set. None of the site collector/workbench/dashboard paths automatically calls it. A diagram connecting them is a future goal, not a current call graph.

Do not combine these lanes' schema, labels, thresholds, modes or API semantics merely because some endpoints/dashboard assets share names.

The active next-work order is collection correctness/visibility, supported policy fidelity and behavior-policy correlation with explicit uncertainty. Ryu and passive-v2 remain reference/test lanes, not deployment prerequisites. S01–S70 and P0–P13 are unchanged. Automatic vendor rules, calibrated site inference and guarded online model promotion remain planned.

## Legacy packet → detection → OpenFlow path

1. Ryu creates SimpleSwitch with OF 1.0, WSGI context, MAC/datapath registries, TrafficMirror, SnortManager, TrafficCapture and model engines.
2. _packet_in_handler parses Ethernet and supported IPv4/ARP information into packet_info. LLDP is ignored. It records observations, participates in DAI/learning and injects frames into the TAP path for Snort where enabled.
3. TrafficCapture.record_packet updates bounded packet/flow/device state and IP→MAC lookup. The per-flow key and pair reverse aggregation are different scopes.
4. TrafficCapture._flush_loop runs on an OS thread. _flush_flows takes a locked snapshot, computes network/device/flow features, labels rate/DAI/Snort evidence, then applies eligible RF and AE scoring and writes CSV.
5. SnortManager uses subprocesses and tailing threads. Parsed/classified alerts call SimpleSwitch._handle_snort_alert, which records labeling evidence and may request canonical signature enforcement when DETECT is on.
6. SimpleSwitch.block_attacker is an enqueue shim used from background threads. It also puts provisional state in _blocked_ips; this state is not a switch acknowledgment.
7. _block_worker is an eventlet hub greenlet. It drains the queue and invokes _do_block_attacker or _do_unblock_attacker.
8. _do_block_attacker sends source-MAC OF 1.0 FlowMods with priority 65000 and empty actions on known datapaths. A software count/banner means messages were sent, not independently confirmed containment.
9. REST handlers run in the hub context and can call the installer synchronously. With unknown MAC, rest_block_ip instead attempts priority-64000 IPv4 source rules.

**Concurrency invariant:** do not call datapath.send_msg directly from the flush/Snort OS threads. Queue work to the hub. RF inference is forced to n_jobs=1 with a threading joblib backend to avoid the historical multiprocessing/eventlet hang. Keep logging bounded; slow stdout/tee/SSH readers can introduce backpressure.

### Gates and defaults — source, not old demos

- DETECT starts OFF. It gates rate/DAI detection/enforcement and integrated Snort canonical blocking.
- ML starts OFF; OBSERVE scores/logs, AUTHORIZE permits model block requests when requirements are satisfied.
- Controller initial RF block/flag thresholds are **0.90 / 0.80**. Older commands such as AUTHORIZE:0.80 override these; do not describe demo values as startup defaults.
- AE block/flag bands are 0.73 / 0.60. Its normalized reconstruction error is not malicious probability.
- RF/AE enable switches and AE-defer switch exist. AE deferral checks each scored row's existing label, not a durable attack-type-wide exclusion. RF is processed first in the flush loop; models are not separate simultaneous worker engines.
- score_rows selection and existing labels determine which rows are evaluated. Treat DETECT-on tier interference and cooldowns explicitly during isolated tier tests.
- Tier MAC block lifetime uses IPS_BLOCK_SECONDS, default 0 = until manual removal. A finite future timestamp is used for JSON bookkeeping; do not reintroduce Infinity.
- REST unknown-MAC IP timeout handling is separate (default hard timeout 600); it is not globally identical to permanent tier-MAC behavior.
- CONTROL:CLEAR resets detection state and cooldown bookkeeping. CONTROL:UNBLOCK requests actual rule removal; do not substitute CLEAR for removal.
- IPS_EXTERNAL_BLOCK is opt-in; its scope/whitelist comes from config/environment. The alternate standalone reader was removed; this opt-in applies only to the retained Ryu host-blocking path.

### Detection tiers

1. Snort: signatures/inspectors → parsed/mapped messages; integrated callback only enforces canonical classes under DETECT.
2. Rate counters and DAI: window thresholds/hysteresis and binding-conflict checks with lab-specific assumptions.
3. RF: supervised known-class prediction from the legacy feature pipeline. Votes need evaluation/calibration; classification can fail on unseen distributions.
4. AE: reconstruction deviation from legacy inputs; can fire on unfamiliar benign traffic. High error is not proof of an actual zero-day exploit.

Snort rules/inspectors can overlap. A generic SYN or stream event is not proof that the attack metadata's tool/phase caused it. GID/SID, packet time, actual source and independent traffic matter.

## Model artifacts and training boundaries

- Legacy schema has 102 columns including metadata/labels; RF preprocessing drops identifiers/targets/metadata, one-hot encodes and uses its saved selected feature contract (historically 86 encoded → 66 selected).
- RFPreprocessor is conditionally defined in ml_inference.py when dependencies are available; AST inventory must include conditional classes. Artifact loading depends on compatible sklearn and class resolution.
- ae_bundle.joblib contains features, mean, scale, reconstruction threshold and dense NumPy layer arrays. Prior qualified bundle metadata was 60 inputs, bottleneck 16, threshold about 0.48213; verify actual artifact metadata/hash before changing/deploying it. Old AE docstrings refer to a different threshold/bottleneck.
- build_ae_bundle.py reads trained H5 weights and recalibrates a scaler/error threshold from supplied data; it is not full AE weight training. Its historical preprocessing/evaluation splitting needs scientific review before being reused for release claims.
- retrain_rf_v4.py inherits the deployed schema and refits scaler/RF, with optional train-side SMOTE. Its row-level stratified split is a legacy tool, not proof of later-time/new-device/site generalization.
- Both inference modules have error fallbacks that can look normal/zero-confidence. This is a current limitation to redesign toward explicit invalid/unavailable states in a qualified future lane, not evidence the network is safe.
- Do not feed site-v3 rows directly to legacy artifacts. Do not load arbitrary joblib files to inspect them; trusted artifacts and isolated version-compatible tooling are required.
- Current untracked data directories are not a reproducible training release or independently verified ground truth.

## Site-v3 data path

home_sensor.main → collection_lease → HomeCollection → collect → site_features.decode → record/advance → DeviceWindow → FeatureHistory.features → ShadowPolicy.evaluate → paired CSV/JSONL evidence → checkpoints and read APIs.

### Collection and timing

- 71 columns: 13 metadata/audit fields plus 58 measured features; key is local IP plus VLAN, normally five-second windows. Multiple IPs may be the same physical device.
- Supported raw framing is Ethernet; decoder handles applicable IPv4/IPv6 transport/header subsets. Do not assume a cooked/802.11/TUN capture is equivalent.
- Live AF_PACKET asks for kernel timestamps, samples packet-socket loss and skips PACKET_OUTGOING copies. This matters on endpoints and router egress; live mirror-oriented behavior is not automatically bidirectional endpoint sensing.
- PCAP replay uses event timestamps, marks replay provenance, finishes at processing speed and closes its temporary dashboard when done.
- Missing values, unsupported parsers, first/final incomplete windows, late packets, cap losses, reboot/warm-up and storage refusal remain evidence conditions.
- Novelty compares current peers with retained prior history before updating it. Caps/evictions limit cardinality/history meanings.
- Current extraction includes a bounded G11–G17 subset: recon/header signals, longer-horizon contacts, service-initiation evidence, opt-in DNS/TLS metadata and opt-in limited cleartext HTTP lexical features.
- DNS is limited supported UDP/53 parsing; TLS needs a complete supported ClientHello in one TCP packet (one leading TLS 1.3 compatibility ChangeCipherSpec record is skipped); HTTP needs a supported complete cleartext HTTP/1 header in one packet. No full TCP reassembly, HTTPS payload decryption, QUIC application coverage or complete authorization/exploit-outcome analysis exists.
- G18–G24 and advanced feature commitments remain planned; use feature-rationale.mdx and feature-groups.json for exact current ownership/limits.
- Storage defaults stop at configured directory/free-space budgets; inbox captures and other tools' outputs are outside that budget.

### Files and state

schema.json binds column/settings contract; features-DATE-RUN.csv holds UNKNOWN rows; policy-events-DATE-RUN.jsonl pairs evidence with rows; run-RUN.json records state/health/source provenance; profile-state.json persists bounded unverified descriptive history. Dates rotate in UTC; restarts use new run IDs.

collection_io.collection_lease provides an OS-managed exclusive nonblocking lease. Closing/crashing releases the lock. atomic_json replaces checkpoints; CSV and JSONL writes are paired but are not one database transaction. The stopped auditor detects torn/misaligned evidence instead of silently repairing it.

### Shadow policy and review

site_policy validates operator-defined expiring inventory and TCP-initiation role rules. IP/VLAN/source-MAC agreement is a consistency check, not authentication. Quality/identity findings and incident holds gate candidate summaries. Replay, unverified coverage or degraded data are held.

An eligible candidate means eligible for review, not approved benign. Approved descriptive profiles are frozen and policy/schema/provenance bound; residuals against them are separate from candidate updates. review_site_baseline refuses active writers, bad/final loss evidence, replay and conflicting/tampered provenance. A minimum accepted window count is a format/review prerequisite, not statistical proof of maturity.

No online site-v3 RF/AE training, automatic model promotion, production attack-sequence fusion or firewall action occurs in this lane.

## Policy-model path

scripts/policy_inventory.py import → firewall_policy.read_input/normalize → writable PolicyStore transaction. The store preserves normalized snapshots, original bytes/import observations, hashes and context lineage.

Read-only show/list/search/diff/audit/impact/propose/verify commands open read-only store connections. policy_http exposes a loopback prototype; it is not an authenticated enterprise API. Operator identity fields do not establish real tenant authorization.

### Supported semantics

apf-policy-v1 models operator-described ordered IPv4/IPv6 TCP/UDP/ICMP/ICMPv6 header conditions and explicit defaults. It is not a native commercial configuration parser. AddressResolver handles bounded objects/groups; unresolved predicates and global context remain uncertain.

PolicyEvaluator computes first-match results with ALLOW/DENY/REJECT/INDETERMINATE distinctions. It does not compute stateful routing/NAT/application/user/profile behavior or live reachability.

policy_audit represents supported header spaces as bounded boxes, subtracts prior effective space, and emits duplicate/union-shadow/redundancy/overlap/object/metadata findings with witnesses. Unsupported cases and budget failures do not become safe cleanup claims.

policy_change compares before/after effective partitions, preserving access, explicit logging, attribution and uncertainty separately. A known change disproves equivalence even when other space is unknown. Counts are symbolic region counts, not traffic/risk measurements.

proposal pins an exact base hash and supports bounded disable/remove/move-before operations. It deep-copies a hypothetical candidate and returns OFFLINE_REVIEW_REQUIRED / automatic_apply false / candidate_is_observed false. verify_proposal checks digest and deterministic replay against the engine manifest. Local hashes do not authenticate an approver or authorize writes.

### Interfaces and caps

- Workbench default loopback port 8082, eight GET operations: status, snapshots, snapshot detail, search, diff, audit, impact and preview.
- No native/apply/delete endpoint or commercial credentials are provided.
- Model import size cap 8 MiB; impact up to 200 rules/snapshot, 4096 regions, 250000 work units; display limit 1–200; proposal 1–16 operations.
- See policy-openapi.json and source for exact limits of each operation.
- Python 3.10 strict empty-query handling was fixed explicitly; preserve strict parsing for nonempty queries.

## Operator-run firewall adapter

nft_quarantine validates the dedicated inet apf_quarantine table, blocked_v4 timeout set and forward_guard source-set drop expression, then adds/removes only the requested IPv4 element and reads back membership.

CLI adds require scope, protected networks and TTL 1–300 seconds. Existing membership does not extend expiry. This targets forwarded traffic, not arbitrary management INPUT or every address family.

No automatic site-model callback invokes it. Current evidence includes mocks and an operator namespace recipe; actual installed-kernel JSON semantics, traffic containment/continuity and expiry still need recorded lab results.

## Signature and reference deployment boundary

The retained integrated lab path is SimpleSwitch → SnortManager → processes/log tails → callback. TrafficMirror can inject PacketIn frames into a TAP. The source Snort 3 config/rules and original Ryu DAI checks remain for comparison; no standalone reader/bridge, VXLAN installer, mixed-version installer or missing-app launcher remains active. Review HOME_NET/static bindings in a private site copy, use /usr/local/bin/snort version 3 and validate before launching. See docs-site/integrations/snort.mdx.

home_sensor.py now imports DashboardHandler from http_dashboard.py, not passive_ids.py. The neutral module serves static UI/docs and delegates read APIs without importing legacy models. passive_ids.py imports the same handler (preserving its former imported name), and remains the legacy observation lane. Neither read-only handler supports action writes. No feature formula, gate, schema or model byte changed during extraction.

## Ports, APIs and dashboard behavior

| Origin | Main purpose | Important boundary |
| --- | --- | --- |
| Ryu TCP 6633 | OpenFlow control | Not the observed user data stream itself |
| Legacy UDP 9999 | Mode/metadata/registration commands | No authenticated acknowledgment; trusted-network control surface |
| Ryu HTTP, usually configured 8081 | Mutating legacy block/unblock + status/metrics/dashboard | Legacy security and datapath assumptions; startup text still mentions 8080 |
| Home/passive HTTP default 8081 | Separate process, read-only collection/observation | Cannot coexist on the same address/port without configuration |
| Policy loopback 8082 | Separate read-only model workbench | Different contract/database/authority |
| Mintlify 3333 | Full workstation docs preview | Independent from t530/controller; not reboot autostart |
| Pilot replay 18081 | Temporary helper-selected dashboard | Closes after replay |

Dashboard/index.html is a dependency-free browser client used by multiple entry points. It fetches status/metrics/alerts/blocked data, includes collection/shadow views and can present legacy unblock controls depending on origin behavior. Backend enforcement of allowed methods is the authority; UI appearance does not grant writes. local_docs.py serves a lightweight read-only MDX/Markdown reader from docs-site, with path/traversal constraints; full Mintlify supports richer rendering.

The Ryu contract is docs-site/openapi.json, site collector contract collection-openapi.json, and policy workbench policy-openapi.json. Do not merge their similarly named routes into one service model.

## Docs startup failure and current remedy

The user's Windows PowerShell blocked .ps1 execution and did not find npm's global shim through PATH. A later Node log showed the presumed Mintlify entry file missing. On this session's inspection the package entry existed and mint@4.2.1195 version check worked; do not invent a proven historical cause such as corruption or a particular installer.

scripts/start_docs.cmd invokes start_docs.cjs through Node, using PATH or the standard Node install location. The Node helper validates docs.json, discovers a complete pinned local/global Mint package through package.json's bin, checks port/readiness, starts a hidden detached process with independent log descriptors and waits for actual HTTP success. It does not change execution policy or report startup merely because spawn returned.

Existing start_docs.ps1 remains available in an allowed PowerShell environment. The .cmd route is the straightforward Windows-user route. Logs/state live under ignored .local/docs-preview. A stale lock requires inspection; the helper never kills a PID on assumption. This is a developer preview, not reboot autostart or an internet-hosted service.

## Important current limitations and review queue

These are source-review findings/qualification needs, not all reproduced bugs:

1. Whole-home/SD-WAN observation remains unresolved; an unseen path cannot produce a reliable benign verdict.
2. Native vendor import, routes/NAT reachability, calibrated behavior-policy joins, production identity discovery and policy writes remain planned.
3. Legacy model exception fallbacks resemble normal/zero scores; explicit unavailable/abstain semantics need design and regression before future production use.
4. Legacy block records can be provisional and do not prove FlowMod acknowledgment/target containment; stale state/failure recovery/new-switch/restart reconciliation need qualification.
5. Current software maps/display paths do not uniformly represent host iptables and OpenFlow enforcement; audit every requested origin when verifying blocks.
6. rest_block_ip and protected/no-op paths need semantic review: a successful handler return must not be assumed to mean a rule was installed. Unknown-MAC IPv6 also needs explicit supported behavior; OF 1.0 IPv4-match helpers are not an IPv6 enforcement claim.
7. Unblock FlowMods use non-strict delete semantics; priority alone does not prove exclusive removal of one drop. Strong cookie/ownership/transaction semantics are future hardening work.
8. Legacy deterministic and RF/AE gates differ, and the passive reference runner does not start Snort. AE per-row deferral does not satisfy every possible type-/device-wide precedence policy.
9. Old training scripts' row splits/calibration and dataset provenance do not satisfy independent site/campaign deployment evidence.
10. Authenticated management/RBAC, durable action lifecycle, HA/failure policy and enterprise tenancy are not delivered by the prototype.
11. Testbed addresses/static bindings and stale comments survive in legacy assets. Do not copy those values into real-network configuration.
12. Empty local topology/QoS directories and absent notebooks are not current tracked runtime capabilities.
13. A passing offline suite does not verify t530 AF_PACKET behavior, industrial-firewall semantics, line rate, a multi-day soak or detector accuracy.
14. Historical relay/install/setup runbooks were removed rather than repaired into competing product entry points. The retained Ryu config is still a lab reference; do not copy static bindings/addresses into a real site.

Do not fix all of these opportunistically during a small unrelated task. Select a scoped next milestone with evidence, relevant tests, documentation and reversible deployment.

## Research methods and offline feature-group evidence

Controller/behavioral_evidence.py and scripts/score_feature_groups.py form a separate offline research lane. The CLI prepares bounded closed-CSV chronological slices, fits explicitly operator-reviewed references and scores later compatible site-v3 windows without updating them. It does not import an actuator or inference model, write through the dashboard or perform online adaptation.

Feature-specific fit medians and absolute-deviation empirical ranks feed max statistics within groups. Later calibration ranks each group and directly calibrates an overall maximum on complete rows. Inclusive ties and +1 smoothing preserve finite sample resolution; zero MAD remains explicit. Tail ranks are not malicious probabilities and no exchangeability/time-series/repeated-alert guarantee is claimed. Missing support, inspection mismatch, unknown identity, incomplete/overlapping/earlier windows and insufficient calibration retain refusal/abstention states. History warm-up gates only history-dependent measurements. References bind IP/VLAN and settings, not authenticated identity or proven physical capture quality.

Current schemas/formulas and model artifacts remain unchanged. Existing site interval mean/SD/CV are recataloged from BASE to G1, and site size SD to G6. docs-site/reference/feature-methods.json plus architecture/feature-methods.mdx cover 173 schema-qualified occurrences and seven planned G18–G24 groups with 26 primary references. check_feature_catalog now validates this companion coverage; the arithmetic/experimental correctness still needs review. The operator procedure is deployment/feature-evidence.mdx and function-level rationale is developers/feature-evidence-code-tour.mdx. Independent packet expectations and benign/attack campaigns remain separate gates. Source fingerprints, input hashes and profile digest detect drift, not reviewer authenticity; new-only outputs remain private.

## Testing and scientific evidence

The Python suite covers extraction, quality/restart/failure behavior, shadow review, policy-model/store/API semantics, bounded symbolic oracles, campaign metrics and mocked nftables. Separate Node tests cover the documentation launcher. They are not a live end-to-end attack qualification.

qualify_home_collection compares hand-derived packet feature expectations; qualify_home_runtime accelerates state/restart checks. home_preflight is noncreating configuration/permission/storage/visibility-evidence preparation. collection_report/audit_home_data assess closed files; REVIEW is not a fabricated PASS.

Campaign scoring keeps independent truth/qualified arrival/coverage, misses, false alerts, abstentions, rule read-back and traffic containment distinct. An unqualified example returns unavailable results rather than invented accuracy.

Future training must split by campaign/device/site/time before learned preprocessing/resampling, reserve calibration, include hard benign controls and evaluate false actions as well as recall. AE error, RF score, anomaly strength, business risk and calibrated action confidence are separate quantities. Eligible adaptation must score against frozen approved context before updating candidates, with poisoning/drift tests before promotion.

## How to continue without rereading everything

1. Follow the current user and repository instructions. Inspect git status/branch and preserve private/untracked inputs.
2. Run python scripts/build_ai_handoff.py to check source/path/index freshness. A failure means inspect the changed files and refresh the affected narratives; it is not permission to regenerate blindly.
3. Choose the correct runtime lane and relevant P/S milestone.
4. Use the generated file/symbol index to locate the functions, then read those implementations and their tests only.
5. Reproduce the issue or define the independent expected outcome. Explain why the design and test address it.
6. Make a coherent narrow change; preserve unknown/unsupported cases and current schema/adapter authority.
7. Update affected MDX/OpenAPI/service/feature rationale as required and add a dated changelog.
8. For new/deleted files update file-purposes.json, stage new paths, run the handoff builder --write, review and stage its output. Semantic prose needs human/AI review; generators cannot infer it reliably.
9. Run appropriate tests and the staged documentation, feature and handoff checks plus Mintlify validation/link/a11y checks.
10. Commit/push within the user's standing scope and report actual evidence/limits. Never claim a test or deployment that did not run.

Recommended next user action is Stage A of the no-mirror pilot and its redacted results handoff. Recommended next development work is bounded session/identity evidence, counter/usage continuity and a first selected vendor's read-only fixtures; site-model release and automatic actions remain later evidence gates.
