# Validation

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
