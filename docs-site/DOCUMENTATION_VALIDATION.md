# Validation

## Reference firewall adapter · 2026-11-04

Python compilation and five mocked nftables tests passed. Tests cover add and read-back, protected and out-of-scope rejection, removal, failed verification and duplicate adds without extending expiry. The Windows workstation has no installed WSL distribution. Linux ruleset loading, native expiration and forwarding impact require the isolated Linux lab procedure.

## Passive sensor update · 2026-11-04

Python compilation and a synthetic Ethernet PCAP smoke test passed. The test launched the standalone process in capture-only mode, checked replay completion, verified TCP and ARP CSV rows, loaded the dashboard HTML, checked the status, metrics and blocked JSON endpoints, and confirmed that POST to the block endpoint was rejected. Live Linux capture, model effectiveness and browser rendering remain unverified.

Mintlify reported no broken links after adding the passive guide. Both shipped models loaded locally. The RF loader emitted a scikit-learn version mismatch warning (artifact 1.6.1, local runtime 1.7.2). Use the artifact's version for qualification.

Mintlify CLI 4.2.1195 reported a successful build and validation. The broken-link check found no broken links. The accessibility check passed after adjusting dark-mode contrast, with an advisory that the primary accent achieves AA contrast and could be improved to AAA.

The expanded site contains 17 authored MDX pages and an OpenAPI specification for seven JSON operations. The dashboard HTML route is described in the operator manual.

The documentation guard was tested in an isolated Git repository. It rejected a staged implementation change without notes and accepted the same change with a dated entry and notes. It also accepted the committed change in PR comparison mode. The versioned hook ran successfully in this checkout. GitHub-hosted execution and branch protection remain unverified.

The local preview did not answer HTTP requests during this run. Browser rendering, responsive layout, search and theme switching remain unverified. The controller and t530 datapath were reviewed through their source and runbooks. Live enforcement tests were outside this documentation run.
