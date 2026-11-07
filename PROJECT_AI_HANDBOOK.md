# Adaptive IPS framework — complete AI handbook

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
- DNS is limited supported UDP/53 parsing; TLS needs a complete supported ClientHello in one TCP packet; HTTP needs a supported complete cleartext HTTP/1 header in one packet. No full TCP reassembly, HTTPS payload decryption, QUIC application coverage or complete authorization/exploit-outcome analysis exists.
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

---

# Complete tracked-file and symbol reference

Generated by scripts/build_ai_handoff.py from the authored file-purpose catalog and AST source index.
Read CODEBASE_AI_HANDOFF.md first. This index covers every tracked path, not every installed dependency/cache file.
Reference base: 8a24d8b41b045d2286bbe4978d09896f1e7e050b. Source fingerprints, rather than this base alone, identify the described implementation.
Do not treat file presence, a function name, comments or AST extraction as proof of runtime success.

## Every tracked file

| Path | Role and relationship |
| --- | --- |
| .githooks/pre-commit | Versioned local hook runs staged documentation, feature-catalog and AI-handoff guards; clone configuration and server-side rules remain separate. |
| .github/workflows/documentation.yml | Push/PR workflow qualifies offline Python, committed guards, Node launcher and Mintlify build/link/accessibility checks. |
| .gitignore | Excludes generated caches, local state, vendored setup material and Node dependencies from authored product commits. |
| AGENTS.md | Repository maintenance rules require source-related documentation, rationale, release honesty and fresh source-checked AI context. |
| AI_Project_Context.md | Short current product-context pointer replaces stale deployment recap and links the source-checked handbook, scope and preserved behavioral lineage. |
| CODEBASE_AI_HANDOFF.md | Authored continuation core explains goals, runtime lanes, call paths, authority, known risks and scoped next-work procedure. |
| Controller/Controller_main_Claude.py | Merged Ryu OF1.0 app owns datapaths, learning/DAI, Snort callbacks, hub block queue, UDP control and legacy REST handlers. |
| Controller/ae_inference.py | Legacy NumPy dense reconstruction scorer loads schema-specific trusted bundle weights/scaler/threshold and computes normalized error. |
| Controller/behavioral_evidence.py | Offline frozen feature-group reference mathematics, strict eligibility/profile checks, tie-aware ranks and explained abstaining observations without actuators. |
| Controller/collection_io.py | Exclusive nonblocking OS lease prevents concurrent writer/reviewer/report access and releases with handle or process closure. |
| Controller/collection_report.py | Stopped-run auditor validates paired rows/evidence/provenance and summarizes integrity, quality and coverage without assigning benign truth. |
| Controller/firewall_policy.py | Strict operator-model JSON/schema, bounded address/port resolution, ordered header queries and same-context structural differences. |
| Controller/home_sensor.py | Site-v3 lease/capture orchestration, paired evidence/checkpoints and shadow profiles; uses neutral HTTP transport without legacy inference imports. |
| Controller/http_dashboard.py | Neutral read-only static UI/docs and delegated JSON transport shared by site collection and legacy observation without inference imports. |
| Controller/ips_config.json | Retained Ryu lab configuration defaults and protection lists; not consumed by current site collector or policy workbench. |
| Controller/ipsctl.py | Text UDP control sender confirms only sending, not authenticated receipt, accepted configuration or actual containment. |
| Controller/local_docs.py | Read-only sensor documentation renderer confines requests to docs-site and rejects traversal while presenting lightweight Markdown. |
| Controller/ml_inference.py | Legacy RF loader and conditional RFPreprocessor preserve artifact columns, force single-job scoring and expose fallback/statistics behavior. |
| Controller/ml_models/ae_bundle.joblib | Opaque tracked legacy AE parameter bundle is not compatible with site-v3 rows merely because feature names overlap. |
| Controller/ml_models/autoencoder_tighter_bottleneck_16units.h5 | Tracked trained dense weight input for AE bundling; it does not supply a complete qualified future weight-training process. |
| Controller/ml_models/build_ae_bundle.py | Offline H5 weight bundler recalibrates data-derived preprocessing/error quantiles; it does not train new AE weights. |
| Controller/ml_models/retrain_rf_v4.py | Offline legacy RF retrainer inherits deployed schema/hyperparameters and refits preprocessing/classifier with optional training resampling. |
| Controller/ml_models/rf_pipeline.joblib | Opaque tracked legacy sklearn artifact fingerprinted without loading; compatible trusted inspection is needed for actual model metadata. |
| Controller/nft_quarantine.py | Operator-only scoped IPv4 timeout-set adapter validates dedicated nftables structure and reads back single-element add/remove results. |
| Controller/passive_ids.py | Retained legacy 102-column capture/observe runner uses shared read-only HTTP handler; not the active site collection or firewall plugin. |
| Controller/policy_audit.py | Bounded symbolic header-box algebra emits supported shadow/redundancy/overlap/object/metadata findings with witnesses and preserved uncertainty. |
| Controller/policy_change.py | Effective-partition comparisons and exact-base hypothetical edits generate review-only candidates and replay-verifiable receipts without native writes. |
| Controller/policy_http.py | Loopback read-only policy viewer/API exposes snapshots, queries, audits and hypothetical previews; enterprise authentication/native apply are absent. |
| Controller/policy_store.py | Transactional SQLite snapshot/raw/import history validates integrity and separates explicit imports from read-only query connections. |
| Controller/requirements-home.txt | Collection-only Scapy/Markdown dependency constraints are separate from the compatible legacy Ryu/model runtime environment. |
| Controller/scripts/apf-home.service | Dedicated-account systemd collection template defines raw-capture capability, private state, environment and controlled restart behavior. |
| Controller/scripts/apf-quarantine.nft | Dedicated timeout set and source-based forward drop must be provisioned only in the intended test/firewall namespace. |
| Controller/site_features.py | Ethernet IPv4/IPv6 decoder, online moments, bounded window state and historical features implement the current site measurement subset. |
| Controller/site_policy.example.json | Sanitized expiring inventory/observation/role example is a configuration template, not an approved household identity source. |
| Controller/site_policy.py | Strict inventory/role/profile validation produces shadow identity/quality findings and separates unverified candidates from approved profiles. |
| Controller/snort3/sdn_ips.lua | Retained integrated Snort 3 lab configuration with static testbed assumptions; inspect a private reviewed site copy before use. |
| Controller/snort3/sdn_ips_local.rules | Local lab flood signatures and inspector/fallback notes require workload qualification; labels do not establish universal detection. |
| Controller/snort_monitor.py | Integrated lab Snort process/JSON alert manager; diagnostic points to current preparation guide after alternate installers were removed. |
| Controller/traffic_capture.py | Legacy 102-column flow/device/network aggregation, rate labeling, flush-thread RF/AE scoring, CSV output and evidence capture. |
| Controller/traffic_mirror.py | Linux TAP writer accepts PacketIn copies through a bounded queue for Snort, with explicit injection/drop counters. |
| DEVELOPER_STUDY_ROADMAP.md | Current complete curriculum ties prerequisites to source, rebuild exercises, competency checks and scientific/operational evidence. |
| Dashboard/README.md | Dashboard operation notes require checking the serving backend lane before assuming actions or data semantics. |
| Dashboard/index.html | Shared dependency-free browser client reads runtime-origin metrics/status/alerts/blocks and collection/shadow views; backend authority remains decisive. |
| NO_VISIBILITY_PILOT_RUNBOOK.md | Standalone operator walkthrough covers t530 qualification, bounded endpoint replay, namespaced firewall checks and representative sessions. |
| PILOT_RESULTS_TEMPLATE.md | Blank handoff form is copied outside Git for actual redacted outcomes and uncertainty; successful tests are never prefilled. |
| PROJECT_AI_HANDBOOK.md | Generated single-file context includes authored architecture, every tracked file purpose and full Python symbol/import index. |
| README.md | Project entry page summarizes runtime lanes, present limits, learning/AI context and qualified operator documentation. |
| docs-site/AGENTS.md | Documentation rules require source coverage, navigation/contracts and actual validation evidence with implementation changes. |
| docs-site/DOCUMENTATION_AUDIT.md | Source-review findings record unresolved state/enforcement/visibility/model assumptions; a written audit is not a completed fix. |
| docs-site/DOCUMENTATION_COVERAGE.md | Human source-to-page coverage matrix complements first-match machine mapping and locates operator/implementation explanations. |
| docs-site/DOCUMENTATION_VALIDATION.md | Dated actual verification records distinguish syntax/replay/CI/source checks from unperformed live/hardware/production tests. |
| docs-site/NEED_ATTENTION.md | Pending checks highlight real forwarding/unblock, capture, management exposure and publication qualification needs. |
| docs-site/README.md | Docs startup/install/publishing/check instructions explain background lifecycle and required source/feature/handoff guards. |
| docs-site/api-reference/collection.mdx | Authored documentation page: Home collection read API. Collection health, schema and shadow-policy observations on port 8081. |
| docs-site/api-reference/overview.mdx | Authored documentation page: Management API. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/api-reference/policy-workbench.mdx | Authored documentation page: Policy workbench read API. Loopback operator-model queries on port 8082, separate from live collection and Ryu. |
| docs-site/architecture/data-flow.mdx | Authored documentation page: Packet capture and enforcement. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/architecture/detection.mdx | Authored documentation page: Detection tiers and decisions. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/architecture/feature-group-comparison.mdx | Comparative feature-group note links the editable presentation and distinguishes added information from measured superiority and planned capabilities. |
| docs-site/architecture/feature-lineage.mdx | Preserves original G11–G17 proposed measurements, corrections, implemented-versus-planned boundaries and the legacy/site behavioral lineage. |
| docs-site/architecture/feature-methods.mdx | Comprehensive per-feature/group scientific measurement recommendations, source links, current limits and model/evaluation choices with no universal guarantee. |
| docs-site/architecture/feature-rationale.mdx | Authored documentation page: Why each behavioral feature group exists. Source-mapped rationale, benign lookalikes, limits and qualification plans for G1–G24 and supporting evidence. |
| docs-site/assets/adaptive-ips-feature-group-comparisons.pptx | Editable forty-three-slide teaching presentation: a changes-since-thesis section, then G1–G24 comparisons with alternatives, benign controls, implementation limits and sourced speaker notes. |
| docs-site/collection-openapi.json | Site-v3 read-only schema/health/shadow contract provides observations without trained inference or firewall write authority. |
| docs-site/deployment/documentation-access.mdx | Authored documentation page: Documentation access and updates. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/deployment/feature-evidence.mdx | Optional post-qualification private-data prepare/fit/score walkthrough with sample resolution, exclusion, interpretation and campaign gates. |
| docs-site/deployment/home-collection.mdx | Authored documentation page: Collect home traffic for two weeks. Run the site-v3 collector on Ubuntu with daily CSVs, observation history and capture health. |
| docs-site/deployment/home-pilot-step-by-step.mdx | Authored documentation page: Home pilot: one Ethernet port, wired and Wi-Fi. A timed, command-by-command passive pilot with an external AP, ingress mirror and explicit management/visibility gates. |
| docs-site/deployment/nftables-lab.mdx | Authored documentation page: Test temporary firewall quarantine. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/deployment/no-mirror-pilot.mdx | Authored documentation page: Start testing without a traffic mirror. Qualify the t530, capture real PC workloads, test a namespaced firewall and return a structured results handoff. |
| docs-site/deployment/offline-policy-changes.mdx | Authored documentation page: Develop and test while visibility is unresolved. Exercise counterfactual policy changes, concrete impact witnesses and reproducible review receipts without a live firewall. |
| docs-site/deployment/passive-sensor.mdx | Authored documentation page: Test the passive sensor. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/deployment/placement.mdx | Authored documentation page: Select deployment placement. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/deployment/policy-audit.mdx | Authored documentation page: Audit the supported firewall-policy subset. Inspect duplicate, jointly shadowed and partially overlapping model rules with bounded deterministic evidence. |
| docs-site/deployment/policy-workbench.mdx | Authored documentation page: Test the read-only policy workbench. Exercise the first P7 slice without a firewall, then prepare a qualified vendor export. |
| docs-site/deployment/pretest-qualification.mdx | Authored documentation page: Qualify collection before a long pilot. Run preflight, independent packet expectations, restart/failure checks and closed daily quality reports. |
| docs-site/deployment/security-campaigns.mdx | Authored documentation page: Run independent security campaigns. Separate benign baselines, ground truth, detector verdicts and verified firewall outcomes. |
| docs-site/developers/ai-handoff.mdx | Authored documentation page: AI continuation and codebase architecture. Current runtime lanes, source-based data flows, authority boundaries, limitations and a freshness-checked continuation procedure. |
| docs-site/developers/feature-evidence-code-tour.mdx | Function-by-function rationale for frozen offline group calibration, provenance, eligibility, bounds and independent tests. |
| docs-site/developers/maintenance.mdx | Authored documentation page: Develop and verify changes. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/developers/policy-change-code-tour.mdx | Authored documentation page: Policy changes and feature rationale: code tour. Understand symbolic impact, hypothetical proposals, reproducibility receipts and source-to-rationale guards. |
| docs-site/developers/policy-workbench-code-tour.mdx | Authored documentation page: Policy workbench: code and rationale. Read the P7 slice by source line, understand its invariants and distinguish essential checks from implementation choices. |
| docs-site/developers/qualification-code-tour.mdx | Authored documentation page: Qualification and audit: code and rationale. Trace readiness, feature evidence, restart recovery, reports, campaign scoring and symbolic policy analysis. |
| docs-site/developers/repository-scope.mdx | Explains active product versus lab lanes, enumerates exact removed paths/replacements, recovery tag and feature/model preservation checks. |
| docs-site/developers/study-roadmap.mdx | Authored documentation page: Study and rebuild the framework. A complete prerequisite roadmap, source-linked exercises and competency checks from packets and Python to qualified adaptive response. |
| docs-site/docs.json | Mintlify branding/navigation selects authored pages and separate legacy-Ryu versus policy-workbench API groups. |
| docs-site/documentation-map.json | First-match source patterns define affected MDX pages eligible to satisfy the staged implementation documentation guard. |
| docs-site/getting-started/install.mdx | Authored documentation page: Install the controller. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/getting-started/quickstart.mdx | Authored documentation page: Verify your first capture. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/index.mdx | Authored documentation page: Adaptive IPS framework. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/integrations/snort.mdx | Authored documentation page: Snort and alternate reader path. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/openapi.json | Legacy merged-Ryu mutating management contract is separate from collection and read-only policy workbench APIs. |
| docs-site/operations/collection.mdx | Authored documentation page: Collect and validate site data. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/operations/dashboard.mdx | Authored documentation page: Dashboard and unblock workflow. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/operations/incident-response.mdx | Authored documentation page: Verify, contain and recover. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/operations/modes.mdx | Authored documentation page: Detection modes and controls. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/policy-openapi.json | Loopback read-only operator-model API contract documents snapshots/query/audit/impact/preview semantics and explicit limits. |
| docs-site/reference/change-log.mdx | Authored documentation page: Implementation changelog. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/reference/codebase-snapshot.json | Generated normalized source/raw-model fingerprints and Python metadata expose stale AI handoff data without importing runtime code. |
| docs-site/reference/control-protocol.mdx | Authored documentation page: UDP control protocol. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/reference/feature-groups.json | Authored current/planned G1-G24/supporting map assigns all legacy/site columns and rationale/model-use classifications. |
| docs-site/reference/feature-methods.json | Authored primary-source recommended measurement, units, current limits and qualification for all schema-qualified columns and planned groups. |
| docs-site/reference/file-purposes.json | Authored exact tracked-path roles and local-only exclusions drive complete handbook coverage without ingesting private data. |
| docs-site/roadmap/delivery-phases.mdx | Authored documentation page: Delivery phases and service release gates. Extend the IPS roadmap with read-only policy analysis, governance, application services and verified automation. |
| docs-site/roadmap/final-service-scope.mdx | Authored documentation page: Final service scope and competitor coverage. Trace all 70 specification capabilities to current code, planned phases and release evidence. |
| docs-site/security/configuration.mdx | Authored documentation page: Configuration and management access. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| docs-site/security/shadow-policy.mdx | Authored documentation page: Shadow policy and reviewed baselines. Set device roles before collection, hold unsuitable windows and approve descriptive profiles offline. |
| docs-site/troubleshooting/verification.mdx | Authored documentation page: Verify and troubleshoot. Operator/reference explanation with claims scoped by the associated source and qualified evidence. |
| examples/policies/audit-reference.json | Sanitized audit model exercises duplicates, union shadows, partial overlap, object findings and unresolved header predicates. |
| examples/policies/change-reference-v1.json | Known supported base snapshot supplies duplicate/web/partial-source/default cases for exact-base hypothetical change demonstrations. |
| examples/policies/change-reference-v2.json | Same-context later snapshot broadens supported web access and produces concrete semantic expansion witnesses. |
| examples/policies/disable-duplicate.request.json | Exact-base hypothetical duplicate-disable request produces a review-only receipt without importing or applying the candidate. |
| examples/policies/move-deny.request.json | Exact-base hypothetical reorder request demonstrates supported access restriction from changed first-match precedence. |
| examples/policies/reference-v1.json | First sanitized operator model includes address objects and an unsupported earlier predicate for conservative header search. |
| examples/policies/reference-v2.json | Second same-context operator snapshot changes selected rule fields/order to demonstrate structural revision comparison. |
| examples/testing/campaign-results.example.json | Unqualified campaign template preserves independent truth/coverage/outcome fields and unavailable metrics instead of fabricated attack success. |
| examples/testing/visibility.example.json | Deliberately unqualified sanitized visibility template requires actual dated path/direction evidence before meaningful operator attestation. |
| scripts/audit_home_data.py | Stopped-data audit CLI writes new private reports and exposes PASS/FAIL/REVIEW exit semantics from collection_report. |
| scripts/build_ai_handoff.py | Non-executing tracked-file/purpose/AST/fingerprint builder generates the complete handbook and checks staged or working-tree freshness. |
| scripts/check_docs_sync.py | Staged/PR/push Git guard binds implementation changes to a mapped affected MDX page and dated changelog entry. |
| scripts/check_feature_catalog.py | AST/index guard checks column ownership/current-planned rationale coverage without importing models or proving mathematical correctness. |
| scripts/evaluate_security_campaign.py | Independent campaign scorer validates truth/coverage/times and separates misses, abstentions, alerts, read-back and verified containment. |
| scripts/home_preflight.py | Noncreating environment/settings/permissions/clock/storage/dated-visibility preflight does not configure network mirroring or approve labels. |
| scripts/policy_inventory.py | Operator-model import/query/audit/proposal-receipt CLI also launches the read-only loopback viewer without native firewall credentials. |
| scripts/qualify_home_collection.py | Sanitized packet fixtures drive all-field golden extraction comparisons, including nonzero supported protocol/header subsets. |
| scripts/qualify_home_runtime.py | Accelerated synthetic state/restart exercise reports bounded resources/artifacts without proving real live throughput or multi-day stability. |
| scripts/review_site_baseline.py | Explicit stopped-run approval validates identity/schema/policy/quality/provenance and writes a new frozen descriptive profile. |
| scripts/score_feature_groups.py | Bounded new-only prepare/fit/score CLI snapshots site CSV bytes, records research provenance and never changes runtime models or firewall state. |
| scripts/start_docs.cjs | Node helper validates declared pinned Mint executable and port, launches hidden detached log-backed child and checks branded readiness. |
| scripts/start_docs.cmd | Windows wrapper locates Node through PATH/default installation and runs the Node helper without changing PowerShell execution policy. |
| scripts/start_docs.ps1 | Original PowerShell background/foreground helper requires permitted script-file execution and a resolvable global Mint shim. |
| tests/fixtures/site-v3-golden.json | Hand-derived independent feature expectations identify the extraction oracle; do not regenerate them blindly from the extractor. |
| tests/test_ai_handoff.py | Tests exact file-purpose coverage, conditional/nested AST extraction, private read boundaries, LF/raw hashing and staged readers. |
| tests/test_behavioral_evidence.py | Independent rank/median/MAD and missingness/chronology/correlation tests plus actual offline CLI slicing/reference/report preservation regressions. |
| tests/test_collection_readiness.py | Golden/restart/preflight/lease/storage/torn-evidence tests exercise bounded offline correctness and explicit failure reporting. |
| tests/test_docs_launcher.cjs | Node tests cover CLI bounds, declared executable failures, readiness/port checks, no-start failures and owned detached fixture lifecycle. |
| tests/test_docs_sync.py | Isolated Git tests verify affected/changelog/index/unmapped/missing documentation rules across staged and push/PR modes. |
| tests/test_feature_catalog.py | Coverage tests reject invented/missing/duplicate columns, planned false claims, predictor labels and stale index mappings. |
| tests/test_home_collection.py | Tests rates/history/timestamps, IPv4/IPv6, optional parsers, resource limits, corrupt rows and local-doc path rejection. |
| tests/test_nft_quarantine.py | Mocked adapter tests verify scope/protection/idempotency/read-back; actual kernel forwarding and expiry remain separate qualification. |
| tests/test_policy_audit.py | Independent finite-space oracle tests supported symbolic coverage/precedence, witness validity, uncertainty/budgets and read-only transport. |
| tests/test_policy_change.py | Independent before/after oracle and receipt/CLI/API tests preserve hypothetical access/logging distinctions and unchanged stored/native state. |
| tests/test_policy_workbench.py | Tests strict schema/resolvers, ordered uncertainty, SQLite integrity/transactions and read-only CLI/HTTP including empty-query compatibility. |
| tests/test_reference_preservation.py | Real loopback read/method tests, isolated home import and independently expected legacy packet-to-CSV math protect retained behavioral references. |
| tests/test_security_campaign.py | Metric tests preserve independent coverage/truth exclusions, abstentions, verified-traffic distinction and valid event chronology. |
| tests/test_site_policy.py | Shadow/profile/review tests reject replay, poor identity/quality, tampered evidence, active writers and unsafe candidate promotion. |

## Python symbols and direct imports

Line numbers identify this snapshot; verify fingerprints before using them. Conditional definitions and nested helpers are included.
Imports list direct source imports, including standard/optional dependencies; they do not assert that every branch runs.

### Controller/Controller_main_Claude.py

Merged Ryu OF1.0 app owns datapaths, learning/DAI, Snort callbacks, hub block queue, UDP control and legacy REST handlers.

Direct imports: ae_inference, datetime, eventlet.wsgi, ipaddress, json, logging, ml_inference, os, psutil, queue, ryu.app.wsgi, ryu.base, ryu.controller, ryu.controller.handler, ryu.lib, ryu.lib.mac, ryu.lib.packet, ryu.ofproto, snort_monitor, socket, struct, subprocess, sys, threading, time, traffic_capture, traffic_mirror, webob.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| _route_wsgi_access_log_to_file | function | 73–138 |
| _route_wsgi_access_log_to_file._FileLog | class | 96–110 |
| _route_wsgi_access_log_to_file._FileLog.write | function | 98–102 |
| _route_wsgi_access_log_to_file._FileLog.info | function | 103–104 |
| _route_wsgi_access_log_to_file._FileLog.flush | function | 106–110 |
| _route_wsgi_access_log_to_file._server | function | 132–133 |
| SimpleSwitch | class | 141–1557 |
| SimpleSwitch.__init__ | function | 147–412 |
| SimpleSwitch._handle_snort_alert | function | 417–465 |
| SimpleSwitch.close | function | 467–480 |
| SimpleSwitch._udp_command_listener | function | 485–766 |
| SimpleSwitch._ip_to_int | function | 776–777 |
| SimpleSwitch._resolve_mac | function | 779–786 |
| SimpleSwitch.rest_block_ip | function | 788–829 |
| SimpleSwitch.rest_unblock_ip | function | 831–853 |
| SimpleSwitch.get_blocked_list | function | 855–859 |
| SimpleSwitch.block_attacker | function | 864–900 |
| SimpleSwitch.unblock_attacker | function | 902–910 |
| SimpleSwitch._block_worker | function | 912–931 |
| SimpleSwitch._do_block_attacker | function | 933–1034 |
| SimpleSwitch._do_unblock_attacker | function | 1036–1058 |
| SimpleSwitch._load_ips_config | function | 1063–1077 |
| SimpleSwitch._is_protected_mac | function | 1079–1082 |
| SimpleSwitch._is_external_ip | function | 1084–1096 |
| SimpleSwitch._block_external_ip | function | 1098–1122 |
| SimpleSwitch._unblock_external_ip | function | 1124–1133 |
| SimpleSwitch.add_flow | function | 1135–1149 |
| SimpleSwitch.is_iot | function | 1151–1166 |
| SimpleSwitch.is_gateway | function | 1168–1177 |
| SimpleSwitch.register_gateway_dynamic | function | 1179–1196 |
| SimpleSwitch._packet_in_handler | function | 1199–1538 |
| SimpleSwitch._port_status_handler | function | 1541–1557 |
| IPSRestController | class | 1564–1686 |
| IPSRestController.__init__ | function | 1566–1568 |
| IPSRestController.block_ip | function | 1571–1587 |
| IPSRestController.unblock_ip | function | 1590–1591 |
| IPSRestController.list_blocked | function | 1594–1595 |
| IPSRestController.list_switches | function | 1598–1600 |
| IPSRestController.status | function | 1603–1611 |
| IPSRestController.metrics | function | 1614–1658 |
| IPSRestController.alerts | function | 1661–1669 |
| IPSRestController.dashboard | function | 1672–1682 |
| IPSRestController._json | function | 1684–1686 |

### Controller/ae_inference.py

Legacy NumPy dense reconstruction scorer loads schema-specific trusted bundle weights/scaler/threshold and computes normalized error.

Direct imports: joblib, numpy, os, pandas.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| AEInferenceEngine | class | 52–162 |
| AEInferenceEngine.__init__ | function | 55–65 |
| AEInferenceEngine._log | function | 67–71 |
| AEInferenceEngine._load | function | 73–97 |
| AEInferenceEngine._vectorize | function | 99–120 |
| AEInferenceEngine._forward | function | 122–128 |
| AEInferenceEngine.score | function | 130–154 |
| AEInferenceEngine.get_stats | function | 156–162 |

### Controller/behavioral_evidence.py

Offline frozen feature-group reference mathematics, strict eligibility/profile checks, tie-aware ranks and explained abstaining observations without actuators.

Direct imports: bisect, collections, copy, csv, datetime, hashlib, io, ipaddress, json, math, pathlib, re, statistics.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| digest | function | 34–36 |
| strict_json | function | 39–56 |
| strict_json.pairs | function | 42–48 |
| strict_json.constant | function | 49–50 |
| catalog_groups | function | 59–68 |
| number | function | 71–78 |
| timestamp | function | 81–88 |
| row_identity | function | 91–96 |
| row_issues | function | 99–122 |
| supported_value | function | 125–169 |
| read_dataset | function | 172–193 |
| read_rows | function | 196–197 |
| tail_rank | function | 200–202 |
| feature_score | function | 205–206 |
| group_score | function | 209–216 |
| chronological | function | 219–235 |
| fit_reference | function | 238–301 |
| validate_reference | function | 304–374 |
| validate_reference.vector | function | 329–333 |
| score_row | function | 377–423 |

### Controller/collection_io.py

Exclusive nonblocking OS lease prevents concurrent writer/reviewer/report access and releases with handle or process closure.

Direct imports: contextlib, fcntl, msvcrt, os, pathlib.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| collection_lease | function | 9–31 |

### Controller/collection_report.py

Stopped-run auditor validates paired rows/evidence/provenance and summarizes integrity, quality and coverage without assigning benign truth.

Direct imports: collection_io, collections, csv, datetime, ipaddress, itertools, json, math, pathlib, site_policy, sqlite3, tempfile.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| instant | function | 24–28 |
| report | function | 31–34 |
| _report | function | 37–191 |

### Controller/firewall_policy.py

Strict operator-model JSON/schema, bounded address/port resolution, ordered header queries and same-context structural differences.

Direct imports: dataclasses, datetime, hashlib, ipaddress, json, pathlib, re.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| canonical_bytes | function | 25–28 |
| sha256 | function | 31–32 |
| _unique_pairs | function | 35–41 |
| parse_json | function | 44–52 |
| parse_json.invalid_number | function | 47–48 |
| read_input | function | 55–58 |
| _fields | function | 61–63 |
| _text | function | 66–71 |
| _id | function | 74–77 |
| _conditions | function | 80–83 |
| _addresses | function | 86–100 |
| port_intervals | function | 103–126 |
| _ports | function | 129–133 |
| ResolvedAddresses | class | 137–139 |
| AddressResolver | class | 142–184 |
| AddressResolver.__init__ | function | 144–147 |
| AddressResolver._consume | function | 149–152 |
| AddressResolver.resolve | function | 154–184 |
| normalize | function | 187–253 |
| query | function | 256–272 |
| _address_match | function | 275–278 |
| _port_match | function | 281–286 |
| PolicyEvaluator | class | 289–336 |
| PolicyEvaluator.__init__ | function | 290–292 |
| PolicyEvaluator.match | function | 294–304 |
| PolicyEvaluator.search | function | 306–336 |
| diff_policies | function | 339–357 |
| diff_policies.changed | function | 343–350 |

### Controller/home_sensor.py

Site-v3 lease/capture orchestration, paired evidence/checkpoints and shadow profiles; uses neutral HTTP transport without legacy inference imports.

Direct imports: argparse, collection_io, collections, csv, datetime, functools, hashlib, http.server, http_dashboard, ipaddress, json, logging, math, os, pathlib, platform, psutil, scapy, scapy.error, scapy.layers.l2, scapy.utils, shutil, signal, site_features, site_policy, socket, struct, sys, threading, time, uuid.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| utc | function | 43–44 |
| collection_contract | function | 47–60 |
| atomic_json | function | 63–69 |
| StorageLimitError | class | 72–73 |
| HomeCollection | class | 76–295 |
| HomeCollection.__init__ | function | 77–150 |
| HomeCollection._check_storage | function | 152–159 |
| HomeCollection.record | function | 161–199 |
| HomeCollection.advance | function | 201–206 |
| HomeCollection._flush | function | 208–238 |
| HomeCollection.snapshot | function | 240–251 |
| HomeCollection.checkpoint | function | 253–262 |
| HomeCollection.read | function | 264–295 |
| collect | function | 298–365 |
| collect.ingest | function | 299–305 |
| collect.sample_kernel_statistics | function | 326–331 |
| main | function | 368–423 |

### Controller/http_dashboard.py

Neutral read-only static UI/docs and delegated JSON transport shared by site collection and legacy observation without inference imports.

Direct imports: http.server, json, local_docs, pathlib, urllib.parse.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| DashboardHandler | class | 12–44 |
| DashboardHandler.__init__ | function | 15–17 |
| DashboardHandler.do_GET | function | 19–33 |
| DashboardHandler.respond | function | 35–41 |
| DashboardHandler.log_message | function | 43–44 |

### Controller/ipsctl.py

Text UDP control sender confirms only sending, not authenticated receipt, accepted configuration or actual containment.

Direct imports: os, socket, sys.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| main | function | 31–41 |

### Controller/local_docs.py

Read-only sensor documentation renderer confines requests to docs-site and rejects traversal while presenting lightweight Markdown.

Direct imports: html, markdown, pathlib, re, urllib.parse.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| document | function | 12–54 |

### Controller/ml_inference.py

Legacy RF loader and conditional RFPreprocessor preserve artifact columns, force single-job scoring and expose fallback/statistics behavior.

Direct imports: __main__, joblib, numpy, os, pandas, sklearn.base, time, warnings.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| RFPreprocessor | class | 80–104 |
| RFPreprocessor.__init__ | function | 81–86 |
| RFPreprocessor.fit | function | 88–89 |
| RFPreprocessor.transform | function | 91–104 |
| MLInferenceEngine | class | 111–304 |
| MLInferenceEngine.__init__ | function | 114–131 |
| MLInferenceEngine._log | function | 133–137 |
| MLInferenceEngine._load | function | 139–188 |
| MLInferenceEngine._force_single_threaded | function | 190–208 |
| MLInferenceEngine._preprocess_bundle | function | 211–220 |
| MLInferenceEngine._infer | function | 222–250 |
| MLInferenceEngine._result | function | 252–256 |
| MLInferenceEngine.predict | function | 258–274 |
| MLInferenceEngine.predict_batch | function | 276–293 |
| MLInferenceEngine.get_stats | function | 295–304 |

### Controller/ml_models/build_ae_bundle.py

Offline H5 weight bundler recalibrates data-derived preprocessing/error quantiles; it does not train new AE weights.

Direct imports: argparse, h5py, joblib, numpy, pandas, sklearn.model_selection, sklearn.preprocessing.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| load_weights | function | 45–53 |
| forward | function | 56–61 |
| main | function | 64–105 |

### Controller/ml_models/retrain_rf_v4.py

Offline legacy RF retrainer inherits deployed schema/hyperparameters and refits preprocessing/classifier with optional training resampling.

Direct imports: argparse, imblearn.over_sampling, joblib, ml_inference, numpy, os, pandas, sklearn, sklearn.base, sklearn.metrics, sklearn.model_selection, sklearn.pipeline, sklearn.preprocessing, sys.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| build_encoded | function | 57–66 |
| main | function | 69–129 |

### Controller/nft_quarantine.py

Operator-only scoped IPv4 timeout-set adapter validates dedicated nftables structure and reads back single-element add/remove results.

Direct imports: argparse, ipaddress, json, subprocess.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| nft | function | 14–17 |
| read_set | function | 20–38 |
| members | function | 41–43 |
| change | function | 46–65 |
| main | function | 68–87 |

### Controller/passive_ids.py

Retained legacy 102-column capture/observe runner uses shared read-only HTTP handler; not the active site collection or firewall plugin.

Direct imports: ae_inference, argparse, collections, datetime, functools, http.server, http_dashboard, logging, ml_inference, os, pathlib, scapy.layers.inet, scapy.layers.l2, scapy.utils, signal, socket, struct, threading, time, traffic_capture.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| packet_info | function | 31–60 |
| PassiveSensor | class | 63–107 |
| PassiveSensor.__init__ | function | 64–74 |
| PassiveSensor.on_detection_observed | function | 76–82 |
| PassiveSensor.read | function | 84–107 |
| capture_packets | function | 110–143 |
| capture_packets.record | function | 111–114 |
| main | function | 146–180 |

### Controller/policy_audit.py

Bounded symbolic header-box algebra emits supported shadow/redundancy/overlap/object/metadata findings with witnesses and preserved uncertainty.

Direct imports: dataclasses, firewall_policy, ipaddress, itertools.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| AuditBudgetError | class | 10–11 |
| Budget | class | 14–22 |
| Budget.__init__ | function | 15–17 |
| Budget.tick | function | 19–22 |
| Box | class | 26–35 |
| Box.witness | function | 31–35 |
| intersection | function | 38–43 |
| subtract | function | 46–61 |
| difference | function | 64–72 |
| regions | function | 75–94 |
| audit_policy | function | 97–184 |
| audit_policy.finding | function | 104–107 |

### Controller/policy_change.py

Effective-partition comparisons and exact-base hypothetical edits generate review-only candidates and replay-verifiable receipts without native writes.

Direct imports: copy, dataclasses, firewall_policy, hashlib, pathlib, policy_audit, sys.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| EffectiveRegion | class | 22–27 |
| universe | function | 30–37 |
| overlaps | function | 40–49 |
| possible_envelope | function | 52–58 |
| effective_regions | function | 61–90 |
| outcome | function | 93–97 |
| impact | function | 100–163 |
| proposal | function | 166–224 |
| verify_proposal | function | 227–243 |

### Controller/policy_http.py

Loopback read-only policy viewer/API exposes snapshots, queries, audits and hypothetical previews; enterprise authentication/native apply are absent.

Direct imports: firewall_policy, http.server, json, local_docs, policy_audit, policy_change, policy_store, sqlite3, urllib.parse.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| _arguments | function | 55–61 |
| read_policy_api | function | 64–110 |
| PolicyHandler | class | 113–153 |
| PolicyHandler.do_GET | function | 114–137 |
| PolicyHandler.json_response | function | 139–140 |
| PolicyHandler.respond | function | 142–150 |
| PolicyHandler.log_message | function | 152–153 |
| make_server | function | 156–161 |

### Controller/policy_store.py

Transactional SQLite snapshot/raw/import history validates integrity and separates explicit imports from read-only query connections.

Direct imports: datetime, firewall_policy, os, pathlib, re, sqlite3.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| PolicyStore | class | 33–143 |
| PolicyStore.__init__ | function | 34–71 |
| PolicyStore.__enter__ | function | 73–74 |
| PolicyStore.__exit__ | function | 76–77 |
| PolicyStore.import_snapshot | function | 79–110 |
| PolicyStore.list_snapshots | function | 112–118 |
| PolicyStore.get_snapshot | function | 120–129 |
| PolicyStore.provenance | function | 131–143 |

### Controller/site_features.py

Ethernet IPv4/IPv6 decoder, online moments, bounded window state and historical features implement the current site measurement subset.

Direct imports: collections, dataclasses, hashlib, math, re, scapy.layers.dns, scapy.layers.inet, scapy.layers.inet6, scapy.layers.l2, statistics, struct.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| entropy | function | 21–24 |
| Moments | class | 28–41 |
| Moments.add | function | 33–37 |
| Moments.summary | function | 39–41 |
| bounded_add | function | 44–50 |
| client_hello | function | 53–113 |
| client_hello.vector | function | 66–76 |
| decode | function | 116–205 |
| DeviceWindow | class | 209–307 |
| DeviceWindow.observe | function | 246–307 |
| FeatureHistory | class | 310–411 |
| FeatureHistory.__init__ | function | 311–315 |
| FeatureHistory.features | function | 317–411 |

### Controller/site_policy.py

Strict inventory/role/profile validation produces shadow identity/quality findings and separates unverified candidates from approved profiles.

Direct imports: collections, copy, datetime, hashlib, ipaddress, json, math, pathlib, re.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| digest | function | 27–29 |
| load_json | function | 32–36 |
| timestamp | function | 39–45 |
| identifier | function | 48–51 |
| keys | function | 54–56 |
| validate_policy | function | 59–125 |
| in_interval | function | 128–129 |
| quality_for | function | 132–151 |
| update_summary | function | 154–167 |
| ShadowPolicy | class | 170–293 |
| ShadowPolicy.__init__ | function | 171–188 |
| ShadowPolicy._validate_approved | function | 190–213 |
| ShadowPolicy.evaluate | function | 215–275 |
| ShadowPolicy._residuals | function | 277–284 |
| ShadowPolicy.snapshot | function | 286–293 |

### Controller/snort_monitor.py

Integrated lab Snort process/JSON alert manager; diagnostic points to current preparation guide after alternate installers were removed.

Direct imports: collections, datetime, json, os, re, signal, subprocess, sys, threading, time.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| classify_attack | function | 99–121 |
| _protocol_aware_reclassify | function | 124–139 |
| parse_alert_line | function | 178–239 |
| _json_endpoint | function | 253–274 |
| parse_alert_json_line | function | 277–325 |
| SnortManager | class | 332–789 |
| SnortManager.__init__ | function | 352–433 |
| SnortManager._log_info | function | 437–441 |
| SnortManager._log_warning | function | 443–447 |
| SnortManager._log_error | function | 449–453 |
| SnortManager._detect_snort_version | function | 457–470 |
| SnortManager.start_snort | function | 472–560 |
| SnortManager.stop_snort | function | 562–595 |
| SnortManager.start_monitoring | function | 599–625 |
| SnortManager._tail_alert_file | function | 627–668 |
| SnortManager._process_alert_line | function | 670–753 |
| SnortManager.get_recent_alerts | function | 757–760 |
| SnortManager.get_alert_count | function | 762–765 |
| SnortManager.get_alerts_by_type | function | 767–774 |
| SnortManager.get_alerts_by_source | function | 776–783 |
| SnortManager.is_snort_running | function | 785–789 |
| on_alert_callback | function | 840–841 |

### Controller/traffic_capture.py

Legacy 102-column flow/device/network aggregation, rate labeling, flush-thread RF/AE scoring, CSV output and evidence capture.

Direct imports: collections, csv, datetime, math, os, random, statistics, struct, threading, time.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| _shannon_entropy | function | 161–172 |
| _safe_div | function | 175–176 |
| _is_broadcast | function | 179–185 |
| _is_multicast | function | 188–194 |
| DeviceProfile | class | 201–350 |
| DeviceProfile.__init__ | function | 215–245 |
| DeviceProfile.update | function | 247–275 |
| DeviceProfile.update_metadata | function | 277–289 |
| DeviceProfile._z_score | function | 291–299 |
| DeviceProfile.is_mature | function | 302–305 |
| DeviceProfile.get_features | function | 307–345 |
| DeviceProfile.reset_recent | function | 347–350 |
| TrafficCapture | class | 357–2187 |
| TrafficCapture.__init__ | function | 371–511 |
| TrafficCapture._log | function | 515–519 |
| TrafficCapture.set_detection_mode | function | 523–546 |
| TrafficCapture.set_label_override | function | 548–564 |
| TrafficCapture.set_attack_metadata | function | 566–570 |
| TrafficCapture.clear_attack_metadata | function | 572–576 |
| TrafficCapture.set_mininet_event | function | 578–581 |
| TrafficCapture.start | function | 583–614 |
| TrafficCapture.stop | function | 616–624 |
| TrafficCapture.rotate | function | 626–645 |
| TrafficCapture.record_packet | function | 647–804 |
| TrafficCapture.record_alert | function | 806–818 |
| TrafficCapture._flush_loop | function | 822–829 |
| TrafficCapture._flush_flows | function | 831–1353 |
| TrafficCapture._build_flow_row | function | 1356–1779 |
| TrafficCapture._compute_network_context | function | 1781–1813 |
| TrafficCapture.manual_unblock | function | 1815–1845 |
| TrafficCapture.clear_detection_state | function | 1847–1897 |
| TrafficCapture._write_pcap | function | 1901–1913 |
| TrafficCapture._capture_evidence | function | 1915–1966 |
| TrafficCapture._attack_protocol_matches | function | 1976–1989 |
| TrafficCapture._compute_label | function | 1991–2163 |
| TrafficCapture._write_csv | function | 2165–2187 |

### Controller/traffic_mirror.py

Linux TAP writer accepts PacketIn copies through a bounded queue for Snort, with explicit injection/drop counters.

Direct imports: fcntl, os, queue, struct, subprocess, threading.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| TrafficMirror | class | 28–137 |
| TrafficMirror.__init__ | function | 35–45 |
| TrafficMirror._log | function | 47–51 |
| TrafficMirror.start | function | 53–93 |
| TrafficMirror._writer_loop | function | 95–109 |
| TrafficMirror.inject | function | 111–121 |
| TrafficMirror.stop | function | 123–137 |

### scripts/audit_home_data.py

Stopped-data audit CLI writes new private reports and exposes PASS/FAIL/REVIEW exit semantics from collection_report.

Direct imports: argparse, collection_report, json, os, pathlib, sys.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| audit | function | 13–14 |
| main | function | 17–34 |

### scripts/build_ai_handoff.py

Non-executing tracked-file/purpose/AST/fingerprint builder generates the complete handbook and checks staged or working-tree freshness.

Direct imports: argparse, ast, check_docs_sync, hashlib, json, pathlib, subprocess.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| tracked | function | 17–19 |
| read | function | 21–24 |
| symbols | function | 26–47 |
| symbols.Visitor | class | 29–43 |
| symbols.Visitor.__init__ | function | 30–31 |
| symbols.Visitor.record | function | 32–37 |
| symbols.Visitor.visit_ClassDef | function | 38–39 |
| symbols.Visitor.visit_FunctionDef | function | 40–41 |
| symbols.Visitor.visit_AsyncFunctionDef | function | 42–43 |
| build | function | 49–105 |
| main | function | 107–137 |

### scripts/check_docs_sync.py

Staged/PR/push Git guard binds implementation changes to a mapped affected MDX page and dated changelog entry.

Direct imports: argparse, fnmatch, json, pathlib, re, subprocess, sys.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| is_implementation | function | 22–34 |
| git_diff | function | 37–38 |
| snapshot_file | function | 41–44 |
| load_map | function | 47–70 |
| related_pages | function | 73–78 |
| main | function | 81–126 |

### scripts/check_feature_catalog.py

AST/index guard checks column ownership/current-planned rationale coverage without importing models or proving mathematical correctness.

Direct imports: argparse, ast, collections, json, pathlib, subprocess.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| source_columns | function | 17–39 |
| validate | function | 42–77 |
| validate_methods | function | 80–116 |
| main | function | 119–133 |
| main.read | function | 123–126 |

### scripts/evaluate_security_campaign.py

Independent campaign scorer validates truth/coverage/times and separates misses, abstentions, alerts, read-back and verified containment.

Direct imports: argparse, collections, datetime, hashlib, json, math, os, pathlib, statistics, sys.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| timestamp | function | 21–25 |
| score | function | 28–114 |
| score.ratio | function | 101–101 |
| score.summary | function | 102–106 |
| main | function | 117–135 |

### scripts/home_preflight.py

Noncreating environment/settings/permissions/clock/storage/dated-visibility preflight does not configure network mirroring or approve labels.

Direct imports: argparse, collection_io, datetime, hashlib, home_sensor, importlib, ipaddress, json, math, os, pathlib, scapy.utils, shutil, site_policy, socket, subprocess, sys.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| visibility | function | 21–55 |
| visibility.instant | function | 28–32 |
| preflight | function | 58–151 |
| preflight.add | function | 60–61 |
| main | function | 154–175 |

### scripts/policy_inventory.py

Operator-model import/query/audit/proposal-receipt CLI also launches the read-only loopback viewer without native firewall credentials.

Direct imports: argparse, firewall_policy, json, os, pathlib, policy_audit, policy_change, policy_http, policy_store, sqlite3, sys.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| main | function | 15–128 |

### scripts/qualify_home_collection.py

Sanitized packet fixtures drive all-field golden extraction comparisons, including nonzero supported protocol/header subsets.

Direct imports: argparse, csv, hashlib, home_sensor, json, math, pathlib, scapy.layers.dns, scapy.layers.inet, scapy.layers.inet6, scapy.layers.l2, scapy.utils, struct, sys, threading, types.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| hello | function | 24–33 |
| fixtures | function | 36–63 |
| fixtures.frame | function | 37–42 |
| fixtures.close | function | 59–62 |
| qualify | function | 66–106 |
| qualify.compare | function | 72–79 |
| main | function | 109–115 |

### scripts/qualify_home_runtime.py

Accelerated synthetic state/restart exercise reports bounded resources/artifacts without proving real live throughput or multi-day stability.

Direct imports: argparse, collection_report, csv, home_sensor, json, pathlib, psutil, scapy.layers.inet, scapy.layers.l2, site_features, sys, time.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| exercise | function | 19–68 |
| main | function | 71–79 |

### scripts/review_site_baseline.py

Explicit stopped-run approval validates identity/schema/policy/quality/provenance and writes a new frozen descriptive profile.

Direct imports: argparse, collection_io, contextlib, csv, datetime, hashlib, itertools, json, os, pathlib, site_policy, sys.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| stopped_collection | function | 21–27 |
| file_hash | function | 30–35 |
| approve | function | 38–125 |
| main | function | 128–158 |

### scripts/score_feature_groups.py

Bounded new-only prepare/fit/score CLI snapshots site CSV bytes, records research provenance and never changes runtime models or firewall state.

Direct imports: argparse, behavioral_evidence, collections, csv, hashlib, json, pathlib, sys.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| source_hash | function | 17–18 |
| write_new | function | 21–27 |
| main | function | 30–118 |

### tests/test_ai_handoff.py

Tests exact file-purpose coverage, conditional/nested AST extraction, private read boundaries, LF/raw hashing and staged readers.

Direct imports: build_ai_handoff, copy, json, pathlib, subprocess, sys, tempfile, unittest, unittest.mock.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| HandoffTests | class | 14–63 |
| HandoffTests.catalog | function | 15–19 |
| HandoffTests.test_conditional_class_nested_symbols_and_imports | function | 21–25 |
| HandoffTests.test_exact_path_purpose_coverage_and_no_private_reads | function | 27–37 |
| HandoffTests.test_lf_normalization_and_raw_artifact_fingerprints | function | 39–51 |
| HandoffTests.test_staged_reader_does_not_substitute_unstaged_source | function | 53–63 |

### tests/test_behavioral_evidence.py

Independent rank/median/MAD and missingness/chronology/correlation tests plus actual offline CLI slicing/reference/report preservation regressions.

Direct imports: behavioral_evidence, copy, csv, datetime, home_sensor, json, pathlib, subprocess, sys, tempfile, unittest.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| rows | function | 20–39 |
| EvidenceTests | class | 42–210 |
| EvidenceTests.setUp | function | 43–46 |
| EvidenceTests.model | function | 48–50 |
| EvidenceTests.later | function | 52–53 |
| EvidenceTests.test_inclusive_rank_arithmetic_and_ties | function | 55–58 |
| EvidenceTests.test_zero_mad_change_is_unusual_instead_of_fabricated_zero_z | function | 60–71 |
| EvidenceTests.test_duplicate_correlated_features_do_not_sum_votes | function | 73–78 |
| EvidenceTests.test_median_mad_and_rank_are_independently_expected | function | 80–86 |
| EvidenceTests.test_review_split_overlap_and_resolution_are_required | function | 88–100 |
| EvidenceTests.test_missing_sparse_and_nonfinite_measurements_abstain | function | 102–106 |
| EvidenceTests.test_context_change_warmup_capped_unknown_and_past_rows_abstain | function | 108–115 |
| EvidenceTests.test_inconsistent_rates_or_fractional_counters_are_not_attack_findings | function | 117–123 |
| EvidenceTests.test_warmup_is_feature_specific_instead_of_discarding_all_rhythm | function | 125–131 |
| EvidenceTests.test_scoring_is_frozen_and_audit_support_fields_are_excluded | function | 133–139 |
| EvidenceTests.test_optional_parsers_are_unqualified_when_inspection_is_disabled | function | 141–145 |
| EvidenceTests.test_reference_validation_rejects_hash_sorting_and_authority_tampering | function | 147–157 |
| EvidenceTests.test_strict_json_and_csv_reject_ambiguous_input | function | 159–166 |
| EvidenceTests.test_real_cli_roundtrip_does_not_overwrite_or_update_reference | function | 168–191 |
| EvidenceTests.test_real_cli_roundtrip_does_not_overwrite_or_update_reference.write | function | 171–175 |
| EvidenceTests.test_prepare_preserves_chronology_reports_omissions_and_refuses_existing_directory | function | 193–210 |

### tests/test_collection_readiness.py

Golden/restart/preflight/lease/storage/torn-evidence tests exercise bounded offline correctness and explicit failure reporting.

Direct imports: argparse, collection_io, collection_report, copy, csv, home_preflight, home_sensor, json, pathlib, qualify_home_collection, qualify_home_runtime, socket, subprocess, sys, tempfile, test_home_collection, unittest, unittest.mock.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| ReadinessTests | class | 27–173 |
| ReadinessTests.sample | function | 28–34 |
| ReadinessTests.test_all_feature_columns_match_independent_wire_fixture | function | 36–40 |
| ReadinessTests.test_restart_soak_keeps_rates_counts_novelty_and_unknown | function | 42–47 |
| ReadinessTests.test_atomic_replace_failure_preserves_previous_checkpoint | function | 49–58 |
| ReadinessTests.test_corrupt_restart_profile_is_rejected_without_replacing_it | function | 60–69 |
| ReadinessTests.test_invalid_packet_timestamp_is_counted_without_an_observation | function | 71–77 |
| ReadinessTests.test_process_lease_conflict_and_crash_release | function | 79–88 |
| ReadinessTests.test_offline_report_refuses_active_writer | function | 90–95 |
| ReadinessTests.test_report_catches_interrupted_two_file_write | function | 97–104 |
| ReadinessTests.test_report_verifies_evidence_digest_and_all_numeric_features | function | 106–121 |
| ReadinessTests.test_storage_failure_does_not_flush_pending_window | function | 123–131 |
| ReadinessTests.test_report_does_not_infer_idle_gaps_or_parser_counts_are_attacks | function | 133–141 |
| ReadinessTests.test_visibility_requires_bound_dated_bidirectional_evidence | function | 143–158 |
| ReadinessTests.test_preflight_is_noncreating_and_rejects_changed_contract | function | 160–173 |

### tests/test_docs_sync.py

Isolated Git tests verify affected/changelog/index/unmapped/missing documentation rules across staged and push/PR modes.

Direct imports: check_docs_sync, json, pathlib, subprocess, sys, tempfile, unittest.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| DocsSyncTests | class | 20–116 |
| DocsSyncTests.setUp | function | 21–38 |
| DocsSyncTests.tearDown | function | 40–41 |
| DocsSyncTests.git | function | 43–44 |
| DocsSyncTests.write | function | 46–51 |
| DocsSyncTests.record | function | 53–54 |
| DocsSyncTests.guard | function | 56–58 |
| DocsSyncTests.test_requires_changelog_and_affected_page | function | 60–68 |
| DocsSyncTests.test_unstaged_page_does_not_satisfy_commit | function | 70–76 |
| DocsSyncTests.test_deleted_documentation_cannot_satisfy_guard | function | 78–82 |
| DocsSyncTests.test_unmapped_code_requires_developer_page | function | 84–89 |
| DocsSyncTests.test_missing_map_blocks_implementation | function | 91–96 |
| DocsSyncTests.test_pr_and_push_diff_modes | function | 98–107 |
| DocsSyncTests.test_docs_only_and_runtime_dependency_classification | function | 109–116 |

### tests/test_feature_catalog.py

Coverage tests reject invented/missing/duplicate columns, planned false claims, predictor labels and stale index mappings.

Direct imports: check_feature_catalog, copy, json, pathlib, shutil, subprocess, sys, tempfile, unittest.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| read | function | 17–18 |
| CatalogTests | class | 21–88 |
| CatalogTests.test_all_columns_and_numbered_groups_are_covered | function | 22–25 |
| CatalogTests.test_missing_invented_duplicate_columns_and_groups_fail | function | 27–38 |
| CatalogTests.test_planned_group_cannot_claim_implemented_measurements | function | 40–44 |
| CatalogTests.test_missing_empty_rationale_and_label_predictors_fail | function | 46–52 |
| CatalogTests.test_dynamic_feature_definition_requires_an_explicit_checker_update | function | 54–59 |
| CatalogTests.test_dynamic_feature_definition_requires_an_explicit_checker_update.altered | function | 55–57 |
| CatalogTests.test_staged_check_uses_git_index_instead_of_unstaged_rationale_map | function | 61–75 |
| CatalogTests.test_method_recommendations_cover_every_schema_column | function | 77–78 |
| CatalogTests.test_missing_misgrouped_unsourced_or_empty_method_is_rejected | function | 80–88 |

### tests/test_home_collection.py

Tests rates/history/timestamps, IPv4/IPv6, optional parsers, resource limits, corrupt rows and local-doc path rejection.

Direct imports: audit_home_data, collections, csv, home_sensor, json, local_docs, pathlib, scapy.layers.dns, scapy.layers.inet, scapy.layers.inet6, scapy.layers.l2, site_features, struct, sys, tempfile, unittest.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| observation | function | 23–27 |
| HomeTests | class | 30–175 |
| HomeTests.collector | function | 31–33 |
| HomeTests.test_novelty_is_measured_before_history_update | function | 35–40 |
| HomeTests.test_window_rate_counts_and_ipv6 | function | 42–54 |
| HomeTests.test_daily_rotation_state_reload_and_schema_guard | function | 56–71 |
| HomeTests.test_late_and_capacity_loss_are_explicit | function | 73–80 |
| HomeTests.test_storage_limit_stops_writes | function | 82–85 |
| HomeTests.test_rolling_buckets_expire | function | 87–92 |
| HomeTests.test_dns_is_opt_in_and_names_are_reduced | function | 94–99 |
| HomeTests.test_http_is_opt_in_and_fragmented_inputs_do_not_get_full_parse | function | 101–107 |
| HomeTests.test_complete_tls_and_incomplete_tls | function | 109–121 |
| HomeTests.test_capped_cardinality_is_recorded | function | 123–129 |
| HomeTests.test_audit_detects_corrupted_rates | function | 131–146 |
| HomeTests.test_local_docs_route_and_traversal | function | 148–153 |
| HomeTests.test_pair_periodicity_has_sample_support | function | 155–162 |
| HomeTests.test_broadcast_does_not_create_a_device_profile | function | 164–168 |
| HomeTests.test_ethernet_padding_is_not_application_payload | function | 170–175 |

### tests/test_nft_quarantine.py

Mocked adapter tests verify scope/protection/idempotency/read-back; actual kernel forwarding and expiry remain separate qualification.

Direct imports: ipaddress, nft_quarantine, pathlib, sys, unittest, unittest.mock.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| QuarantineTests | class | 11–49 |
| QuarantineTests.test_add_and_verify | function | 15–21 |
| QuarantineTests.test_protected_and_out_of_scope | function | 23–28 |
| QuarantineTests.test_remove_only_owned_element | function | 30–37 |
| QuarantineTests.test_failed_readback_is_not_success | function | 39–42 |
| QuarantineTests.test_existing_entry_does_not_extend_ttl | function | 44–49 |

### tests/test_policy_audit.py

Independent finite-space oracle tests supported symbolic coverage/precedence, witness validity, uncertainty/budgets and read-only transport.

Direct imports: copy, firewall_policy, ipaddress, itertools, json, pathlib, policy_audit, policy_http, policy_store, random, subprocess, sys, tempfile, threading, unittest, urllib.parse, urllib.request.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| rule | function | 25–28 |
| policy | function | 31–34 |
| findings | function | 37–38 |
| oracle_matches | function | 41–50 |
| oracle_matches.ports | function | 42–47 |
| AuditTests | class | 53–163 |
| AuditTests.test_union_of_prior_rules_shadows_without_pairwise_containment | function | 54–59 |
| AuditTests.test_prior_action_and_logging_differences_prevent_behavior_equivalence | function | 61–66 |
| AuditTests.test_shadowing_uses_effective_first_match_not_all_prior_actions | function | 68–70 |
| AuditTests.test_partial_overlap_has_covered_and_uncovered_witnesses | function | 72–76 |
| AuditTests.test_unresolved_predecessor_global_context_and_disabled_are_conservative | function | 78–88 |
| AuditTests.test_ipv6_and_source_port_dimensions | function | 90–99 |
| AuditTests.test_object_findings_are_explicitly_model_scoped | function | 101–108 |
| AuditTests.test_caps_fail_without_publishing_a_partial_proof | function | 110–114 |
| AuditTests.test_whitespace_comment_is_missing_documentation | function | 116–119 |
| AuditTests.test_exhaustive_oracle_checks_shadow_redundancy_and_witnesses | function | 121–144 |
| AuditTests.test_cli_and_http_audit_remain_read_only | function | 146–163 |

### tests/test_policy_change.py

Independent before/after oracle and receipt/CLI/API tests preserve hypothetical access/logging distinctions and unchanged stored/native state.

Direct imports: copy, firewall_policy, itertools, json, pathlib, policy_audit, policy_change, policy_http, policy_store, random, subprocess, sys, tempfile, test_policy_audit, threading, unittest, urllib.error, urllib.parse, urllib.request.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| base | function | 27–28 |
| request | function | 31–33 |
| ChangeTests | class | 36–171 |
| ChangeTests.test_duplicate_disable_is_access_equivalent_but_default_logging_is_unqualified | function | 37–45 |
| ChangeTests.test_reorder_has_concrete_restriction_and_remove_has_attribution_change | function | 47–55 |
| ChangeTests.test_broadening_and_default_or_deny_reject_changes | function | 57–66 |
| ChangeTests.test_logging_change_is_not_access_change | function | 68–72 |
| ChangeTests.test_unknown_envelope_does_not_hide_known_changes_elsewhere | function | 74–84 |
| ChangeTests.test_unresolved_address_and_disabled_unknown_are_not_fabricated_matches | function | 86–92 |
| ChangeTests.test_ipv6_source_port_change_and_display_cap_do_not_skip_analysis | function | 94–101 |
| ChangeTests.test_context_limits_stale_target_and_operation_validation | function | 103–115 |
| ChangeTests.test_receipt_tampering_and_even_rehashed_false_state_are_rejected | function | 117–122 |
| ChangeTests.test_independent_exhaustive_oracle_for_access_changes | function | 124–141 |
| ChangeTests.test_independent_exhaustive_oracle_for_access_changes.verdict | function | 127–128 |
| ChangeTests.test_cli_receipt_and_http_preview_are_read_only | function | 143–171 |

### tests/test_policy_workbench.py

Tests strict schema/resolvers, ordered uncertainty, SQLite integrity/transactions and read-only CLI/HTTP including empty-query compatibility.

Direct imports: contextlib, copy, firewall_policy, json, pathlib, policy_http, policy_store, sqlite3, subprocess, sys, tempfile, threading, unittest, unittest.mock, urllib.error, urllib.parse, urllib.request.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| model | function | 28–29 |
| point | function | 32–33 |
| PolicyModelTests | class | 36–152 |
| PolicyModelTests.test_normalization_is_stable_and_rejects_duplicate_json_keys | function | 37–41 |
| PolicyModelTests.test_native_vendor_or_unknown_fields_are_never_silently_normalized | function | 43–51 |
| PolicyModelTests.test_groups_cycles_missing_objects_and_unresolved_selectors | function | 53–63 |
| PolicyModelTests.test_strict_networks_port_ranges_and_bool_rejection | function | 65–73 |
| PolicyModelTests.test_duplicate_rule_id_or_position_rejected | function | 75–80 |
| PolicyModelTests.test_resource_limits_nonfinite_and_unknown_rule_fields | function | 82–90 |
| PolicyModelTests.test_allow_deny_default_and_disabled_search_are_distinct | function | 92–102 |
| PolicyModelTests.test_unknown_earlier_rule_cannot_be_overridden_by_later_deny | function | 104–108 |
| PolicyModelTests.test_unknown_after_decisive_match_does_not_override_model_order | function | 110–113 |
| PolicyModelTests.test_global_context_unknown_and_missing_source_port | function | 115–124 |
| PolicyModelTests.test_ipv6_udp_and_invalid_query_contracts | function | 126–134 |
| PolicyModelTests.test_search_limit_does_not_skip_effective_rules | function | 136–140 |
| PolicyModelTests.test_diff_has_explicit_context_and_no_actor_guess | function | 142–152 |
| PolicyStoreTests | class | 155–283 |
| PolicyStoreTests.create | function | 156–160 |
| PolicyStoreTests.test_duplicate_import_and_raw_history_preserve_one_snapshot | function | 162–179 |
| PolicyStoreTests.test_wrong_raw_model_pair_and_transaction_failure_leave_no_partial_snapshot | function | 181–194 |
| PolicyStoreTests.test_missing_read_store_and_unrelated_database_are_not_overwritten | function | 196–207 |
| PolicyStoreTests.test_snapshot_tampering_is_detected | function | 209–217 |
| PolicyStoreTests.test_raw_export_tampering_is_detected_during_read_and_reimport | function | 219–230 |
| PolicyStoreTests.test_cli_validate_import_list_search_and_diff | function | 232–247 |
| PolicyStoreTests.test_cli_validate_import_list_search_and_diff.run | function | 235–239 |
| PolicyStoreTests.test_http_read_only_dashboard_queries_and_invalid_requests | function | 249–283 |

### tests/test_reference_preservation.py

Real loopback read/method tests, isolated home import and independently expected legacy packet-to-CSV math protect retained behavioral references.

Direct imports: csv, functools, http.server, http_dashboard, json, os, pathlib, subprocess, sys, tempfile, threading, traffic_capture, unittest, unittest.mock, urllib.error, urllib.request.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| ReferencePreservationTests | class | 25–106 |
| ReferencePreservationTests.test_home_import_needs_no_legacy_runner_or_inference | function | 26–41 |
| ReferencePreservationTests.test_shared_read_transport_serves_ui_docs_json_and_rejects_writes | function | 43–72 |
| ReferencePreservationTests.test_shared_read_transport_serves_ui_docs_json_and_rejects_writes.Sensor | class | 44–46 |
| ReferencePreservationTests.test_shared_read_transport_serves_ui_docs_json_and_rejects_writes.Sensor.read | function | 45–46 |
| ReferencePreservationTests.test_original_packets_still_produce_full_legacy_schema_and_known_math | function | 74–106 |

### tests/test_security_campaign.py

Metric tests preserve independent coverage/truth exclusions, abstentions, verified-traffic distinction and valid event chronology.

Direct imports: copy, evaluate_security_campaign, json, pathlib, sys, unittest.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| record | function | 14–18 |
| CampaignTests | class | 21–56 |
| CampaignTests.test_counts_abstention_and_window_denominators | function | 22–29 |
| CampaignTests.test_unknown_and_unseen_traffic_are_excluded_not_true_negative | function | 31–36 |
| CampaignTests.test_readback_is_separate_from_verified_traffic_containment | function | 38–48 |
| CampaignTests.test_duplicate_mixed_revision_invalid_times_and_inconsistent_verdict_fail | function | 50–56 |

### tests/test_site_policy.py

Shadow/profile/review tests reject replay, poor identity/quality, tampered evidence, active writers and unsafe candidate promotion.

Direct imports: collections, copy, csv, functools, home_sensor, http.server, json, passive_ids, pathlib, review_site_baseline, scapy.layers.inet, scapy.layers.l2, scapy.utils, site_features, site_policy, socket, subprocess, sys, tempfile, threading, unittest, urllib.error, urllib.request.

| Symbol | Kind | Source lines |
| --- | --- | --- |
| policy | function | 33–38 |
| packet | function | 41–44 |
| PolicyTests | class | 47–308 |
| PolicyTests.create | function | 48–55 |
| PolicyTests.closed_run | function | 57–64 |
| PolicyTests.review | function | 66–68 |
| PolicyTests.test_policy_rejects_typo_duplicate_and_invalid_binding | function | 70–84 |
| PolicyTests.test_role_violation_is_shadow_and_cannot_enter_candidate | function | 86–102 |
| PolicyTests.test_tcp_reply_and_udp_are_unassessed_by_initiation_policy | function | 104–109 |
| PolicyTests.test_quality_failure_freezes_later_candidates | function | 111–125 |
| PolicyTests.test_identity_change_and_expiry_are_not_approved | function | 127–140 |
| PolicyTests.test_partial_replay_unverified_and_stale_windows_are_held | function | 142–151 |
| PolicyTests.test_approved_baseline_is_frozen_and_bound_to_policy | function | 153–176 |
| PolicyTests.test_review_rejects_replay_even_if_early_windows_look_eligible | function | 178–184 |
| PolicyTests.test_policy_snapshot_does_not_expose_mutable_candidate_state | function | 186–191 |
| PolicyTests.test_review_rejects_post_window_loss_and_missing_evidence | function | 193–205 |
| PolicyTests.test_review_rejects_hidden_device_id_and_feature_tampering | function | 207–217 |
| PolicyTests.test_review_rejects_an_active_writer | function | 219–224 |
| PolicyTests.test_csv_contract_and_unconfigured_collection_remain_compatible | function | 226–234 |
| PolicyTests.test_review_cli_creates_loadable_profile_and_refuses_overwrite | function | 236–252 |
| PolicyTests.test_policy_http_dashboard_docs_and_rejected_write | function | 254–279 |
| PolicyTests.test_home_cli_replay_emits_shadow_evidence_and_unknown_csv | function | 281–308 |

## Local-only and excluded material

- **ML model/eval_live.py**: Observed untracked historical evaluator imports absent column_dropper and expects a separate untracked pipeline; it is not a supported reproducible runtime entry.
- **ML dataset/dataset_final_predictions.csv**: Observed untracked local CSV; rows/private identities were not copied or interpreted. Dataset provenance and labels are unqualified.
- **new dataset for verification/dataset_session1_normal.csv**: Observed untracked session CSV. A filename containing normal is not independent benign truth; contents remain excluded.
- **new dataset for verification/dataset_session2_icmp_c.csv**: Observed untracked experiment CSV with unqualified capture scope/truth; no rows are included in the handbook.
- **new dataset for verification/dataset_session3_syn.csv**: Observed untracked experiment CSV with unqualified capture scope/truth; no rows are included in the handbook.
- **new dataset for verification/dataset_session4_udp.csv**: Observed untracked experiment CSV with unqualified capture scope/truth; no rows are included in the handbook.
- **SDN Topology/ and QoS/**: Local directories had no source files at audit time and are not tracked deliverables. Historical topology/QoS commands are not evidence of runnable current code.
- **Quality Of Service  part/**: Ignored local vendored-material location had no observed project files in this bounded audit; it is not integrated functionality.
- **.claude/settings.local.json and .cursor/**: Local agent/editor configuration is not product source or authority. Private settings were not copied or interpreted.
- **.git/, .local/, .venv/, node_modules/, __pycache__/**: Version-control internals, private runtime logs/captures, installed dependencies and generated caches are excluded from authored per-file inventory.
- **Chapter4_System_Implementation (1).docx/.pdf**: Ignored local thesis artifacts are retained unchanged and were not parsed as current code or release evidence.
- **Backup/ if present**: Preserve pristine; never edit/delete or promote contents into runtime without explicit user direction.

No dataset rows, agent-local permissions, credentials or binary model contents are embedded here.
Binary artifacts are fingerprinted, not executed/unpickled by the builder.
To refresh after edits, update file-purposes.json for new/deleted files, stage new paths, run the builder with --write, review, then stage the generated files.
The checker can detect hash/path/index drift; it cannot prove that authored prose correctly explains changed semantics.
