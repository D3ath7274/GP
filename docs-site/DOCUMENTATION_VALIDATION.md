# Validation

## Product rename and final-service traceability · 2026-11-04

Compared the supplied specification's Section 85 directly with the authored service matrix: all 70 capability names match in order, each appears once under S01–S70, and every row has source-section references and delivery/acceptance criteria. Current-source review classifies 10 rows as partial foundations, four as legacy lab capabilities and 56 as planned. These classifications do not establish production readiness. Additional custom-risk, audit-reporting, application-profile and evidence-contract requirements are recorded outside the numbered table. The requirements source filename and SHA-256 are preserved in the matrix.

Forty-three existing Python tests passed. PowerShell syntax parsing passed, the launcher reused the renamed running site, and HTTP checks returned 200 with Adaptive IPS framework branding for the homepage, service matrix, delivery phases and access guide. Documentation/API display names match the requested name. Runtime API paths, schema identifiers and model artifacts were not migrated. Mintlify build/validation, broken-link and accessibility checks passed, with the existing AA-versus-AAA color advisory. The new service plans are not executable features; their release evidence remains future work.

## Restore port 3333 and strengthen documentation checks · 2026-11-04

The initial check found no listener on port 3333. Mintlify started successfully from docs-site. The Windows launcher then started a separate hidden process and exited after readiness; subsequent HTTP checks returned 200 for the homepage, documentation-access, home-collection, shadow-policy and changelog pages. Repeated launch reused the healthy preview. PowerShell parsing and Python compilation passed. Browser rendering and Windows reboot autostart were not tested; after reboot the documented launcher must be run again.

Forty-three Python tests passed, including seven isolated Git repository tests for the stronger documentation guard. The guard rejects a changelog without an affected page, unrelated/unstaged/deleted pages, missing maps and undocumented subsequent commits. Documented PR/push comparisons and the unmapped-code fallback passed. Requirements files, model/rule files, CI and Git hooks are classified as implementation. The GitHub workflow now checks pushes and PRs and validates Mintlify sources; GitHub-hosted execution and required branch settings remain unverified locally.

The staged documentation guard passed. Mintlify build/validation, broken-link and accessibility checks passed, with the existing primary-color AA-versus-AAA advisory. These validate documentation sources; they do not publish a hosted site.

## Shadow policy and reviewed profiles · 2026-11-04

Thirty-six Python tests passed, including the existing collection/quarantine tests and new checks for TCP initiation scope, role violations, binding conflicts/expiry, run-latched quality and incident holds, incomplete/replay/stale observations, immutable reviewed profiles, policy/schema mismatch rejection and detached API snapshots. Review tests reject active writers, missing/misaligned/tampered evidence and final-run faults reported after an initially eligible window. A CLI test created a loadable profile from synthetic reviewed windows and refused to overwrite it. A real home-collector CLI replay emitted shadow findings, separate evidence and UNKNOWN CSV rows. An HTTP test fetched the policy API, dashboard HTML and local policy guide, and confirmed POST rejection. Synthetic live-health counters exercise gate behavior without establishing actual Linux capture quality. The CSV contract remains 71 columns with UNKNOWN labels.

Compilation and sample policy validation passed. Linux final socket-statistics read, actual device bindings/visibility, hardware throughput/storage, browser rendering and real-data calibration remain unverified. No automatic firewall integration, attack-sequence detector or model promotion was added by this change.

Dashboard JavaScript and documentation JSON syntax checks passed. Mintlify build/validation, broken-link and accessibility checks passed from docs-site; the existing primary-color AA-versus-AAA advisory remains. The documentation guard passed against the staged implementation and documentation.

## Extended home collection · 2026-11-04

Twenty Python tests passed, including corrected prior-history novelty, IPv4/IPv6 byte and rate accounting, Ethernet padding exclusion from payload length, daily rotation, state reload, settings mismatch rejection, late observations, source/cardinality limits, storage-stop behavior, DNS/HTTP opt-ins, complete/incomplete TLS, periodicity support, CSV corruption detection and local documentation traversal rejection. A separate CLI replay covered eight event-time dates, produced eight daily CSV files from sixteen packets and passed CSV integrity checks. The audit explicitly reported unavailable kernel-loss measurement during replay. This was a simulated date-span test, not a live multi-day soak.

An HTTP smoke test passed for dashboard HTML, all seven collection read routes, formatted local documentation tables and rejected POST writes. Mintlify build/validation and broken-link checks passed, with the existing AA-versus-AAA color advisory in accessibility checks.

The site-v3.0 CSV contract currently contains 71 columns and is separate from the v2 per-flow contract. The extended collector uses bounded per-device windows. Header and limited application measurements are documented group by group rather than represented as full protocol/session coverage.

Live Linux AF_PACKET collection, CAP_NET_RAW systemd deployment, actual interface loss rates and a two-week soak require the t530. Protocol feature coverage is limited to the parsers documented in the guide. No site-v3 model has been trained or qualified for enforcement.

## Home data readiness review · 2026-11-04

An isolated in-memory check confirmed that a previously seen destination returns novelty 1.0 after recent tracking resets. A v2 singleton check produced one 60-byte packet, a 1 ms duration, flow PPS 1000 and configured-window network PPS 0.2. These results establish a feature defect and different rate denominators. Existing five mocked quarantine tests passed, but they do not validate capture accuracy. The home collection guide now records pending capture health, timing, resource and IPv6 qualifications.

## Reference firewall adapter · 2026-11-04

Python compilation and five mocked nftables tests passed. Tests cover add and read-back, protected and out-of-scope rejection, removal, failed verification and duplicate adds without extending expiry. The Windows workstation has no installed WSL distribution. Linux ruleset loading, native expiration and forwarding impact require the isolated Linux lab procedure.

## Passive sensor update · 2026-11-04

Python compilation and a synthetic Ethernet PCAP smoke test passed. The test launched the standalone process in capture-only mode, checked replay completion, verified TCP and ARP CSV rows, loaded the dashboard HTML, checked the status, metrics and blocked JSON endpoints, and confirmed that POST to the block endpoint was rejected. Live Linux capture, model effectiveness and browser rendering remain unverified.

Mintlify reported no broken links after adding the passive guide. Both shipped models loaded locally. The RF loader emitted a scikit-learn version mismatch warning (artifact 1.6.1, local runtime 1.7.2). Use the artifact's version for qualification.

Mintlify CLI 4.2.1195 reported a successful build and validation. The broken-link check found no broken links. The accessibility check passed after adjusting dark-mode contrast, with an advisory that the primary accent achieves AA contrast and could be improved to AAA.

The expanded site contains 17 authored MDX pages and an OpenAPI specification for seven JSON operations. The dashboard HTML route is described in the operator manual.

The documentation guard was tested in an isolated Git repository. It rejected a staged implementation change without notes and accepted the same change with a dated entry and notes. It also accepted the committed change in PR comparison mode. The versioned hook ran successfully in this checkout. GitHub-hosted execution and branch protection remain unverified.

The local preview did not answer HTTP requests during this run. Browser rendering, responsive layout, search and theme switching remain unverified. The controller and t530 datapath were reviewed through their source and runbooks. Live enforcement tests were outside this documentation run.
