# Adaptive IPS framework — no-mirror pilot results

Keep the completed private copy outside Git. Return a redacted version using device aliases.
Use PASS / FAIL / REVIEW / NOT_RUN / UNMEASURED. Unperformed tests are not PASS.

## Session and scope

- Guide version: 2026-11-08
- Code commit:
- UTC time range:
- OS / Python / kernel:
- Last completed guide step:
- First unresolved issue:
- Whole-home visibility: UNRESOLVED
- Real observation scope: PC-1 endpoint only / explicitly described other scope
- IPv4 coverage:
- IPv6 coverage: OBSERVED_WITH_LISTED_ADDRESSES / UNOBSERVED / PARTIAL
- Ground truth: UNKNOWN except separately documented lab events
- Site-v3 trained inference: NOT_ENABLED
- Automatic behavior-to-firewall loop: NOT_TESTED
- Private addresses/identifiers/credentials removed from this copy: YES / NO

## A. Software qualification

| Check | Actual result | Evidence / first error |
| --- | --- | --- |
| Regression test count / outcome | | |
| Golden status / comparisons / failures | | |
| Golden fixture SHA-256 | | |
| Runtime status / checked rows | | |
| Runtime two distinct run IDs | | |
| Runtime elapsed seconds | | |
| Runtime artifact bytes | | |
| Runtime sampled peak RSS or UNMEASURED | | |
| Runtime retained profiles | | |
| Free disk before / after | | |
| Clock synchronized before live tests | | |

First relevant redacted traceback; write NONE if absent:

~~~text
Paste here.
~~~

## B. Endpoint sessions

| Session alias | Activity | Actual duration | PCAP bytes / SHA-256 | v4/v6 scope | Rows / columns | Out/in packets | Audit |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PC-SESSION-01 | | | | | | | |

- Dumpcap / driver version:
- Ethernet link type confirmed:
- Capture losses: value / UNMEASURED
- Stop reason: duration / size / manual / error
- Offload observations / review:
- Address changes or omitted addresses:
- UNKNOWN labels only:
- Unexpected device rows:
- Integrity issues:
- Quality counters requiring review:
- DNS query / response counts:
- Complete TLS ClientHello count:
- Complete cleartext HTTP request count:
- Unsupported protocol observations:
- Per-session history reset acknowledged: YES / NO
- Raw captures/manifests omitted from handoff: YES / NO

Explain REVIEW conditions instead of replacing them with PASS.

## C. Isolated firewall lab

- Setup: NOT_RUN / PASS / FAIL
- Root physical interfaces/routes unchanged:
- Namespace errors:
- HTTP target ready:
- Both client baselines succeeded:
- Bounded recon outcome / approximate duration:
- Firewall PCAP captured / received by filter / dropped by kernel:
- Independent target PCAP captured / received by filter / dropped by kernel:
- Quarantine provisioning / read-back:
- Selected-client membership active during blocked probe:
- Selected-client curl exit:
- Innocent-client success during block:
- Target log lacks blocked request:
- Firewall PCAP confirms attempts in probe interval:
- Target PCAP confirms no new selected-client attempt in same interval:
- Probe time bounds / evidence aliases:
- Manual removal read-back:
- Recovery after removal:
- Membership absent after 15-second TTL / 20-second wait:
- Recovery after expiry:
- Protected / out-of-scope negative tests:
- Lab replay rows / columns:
- Lab audit / integrity issues:
- Foreground services/captures stopped:
- Owned namespaces removed:
- Conclusions limited to operator-run enforcement: YES / NO
- Detection accuracy / automatic-response latency: NOT_MEASURED

## D. Workload coverage

| Day | Session aliases | Workloads | Missing contexts / issues |
| --- | --- | --- | --- |
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |
| 7 | | | |

- Private raw storage used:
- Free space remaining:
- Settings/version changes:
- Further collection needed and why:

## E. Next session request

- Exact failing command, private values replaced by aliases:
- Actual error/output:
- Expected output:
- Changes since the last passing step:
- Preferred next task: fix qualification / review endpoint data / fix lab / plan model evidence
