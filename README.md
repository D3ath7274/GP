# Adaptive IPS framework

Behavioral traffic analysis and firewall-policy audit, evolving toward qualified multi-vendor adaptive response. The project preserves its four-tier SDN research foundation while building a vendor-neutral evidence and policy layer. It is a development prototype, not a finished FireMon/AlgoSec replacement or a universal firewall plugin.

## What to work on and test now

| Track | Entry points | Delivered scope | Boundary |
| --- | --- | --- | --- |
| Site observations and profiles | Controller/home_sensor.py, site_features.py, site_policy.py | Bounded IPv4/IPv6 measurements, daily paired evidence, quality counters, shadow findings and reviewed descriptive profiles | UNKNOWN ground truth; no site-model scoring, automatic promotion or firewall writes |
| Firewall-policy analysis | scripts/policy_inventory.py and Controller/policy_*.py | Operator-described snapshots, ordered-header search, audit witnesses, revision impact and hypothetical change receipts | Read-only model subset; no native vendor parser, NAT/route reachability or live policy deployment |
| Controlled response qualification | Controller/nft_quarantine.py | Operator-run temporary scoped IPv4 set membership with read-back/removal | Separate namespace lab; not automatically connected to detection |
| Behavioral reference and regression | traffic_capture.py, passive_ids.py, Controller_main_Claude.py, RF/AE, Snort 3 sources | Original 102-column features, model experiments, rate/ARP evidence and OpenFlow lab comparison | Historical lab assumptions and models require independent qualification |

The product goal remains the complete [S01–S70 service scope](docs-site/roadmap/final-service-scope.mdx), delivered through [P0–P13 gates](docs-site/roadmap/delivery-phases.mdx). Cleanup changes neither those requirements nor their implementation status.

## Behavioral features remain the core

- **G1–G10 and supporting device/network context:** original timing, directionality, TCP lifecycle proxies, entropy, ARP binding behavior, sizes, port structure, broadcast context, flow pressure and provenance.
- **G11–G17:** a separately versioned, bounded site measurement subset for reconnaissance, headers, long horizons, service initiation, DNS, TLS/QUIC evidence and cleartext HTTP lexical evidence. Optional inspection is explicitly configured; encrypted content is not magically visible.
- **G18–G24:** planned resource, identity, SD-WAN management, credential/lateral, authorization, C2/exfiltration and exploitation-outcome evidence.

[Feature rationale](docs-site/architecture/feature-rationale.mdx) records the actual semantics, benign lookalikes, missingness and scientific tests. [Design lineage](docs-site/architecture/feature-lineage.mdx) preserves earlier proposed measurements not yet implemented. The machine-readable catalog covers **102 legacy and 71 site columns**, including audit fields excluded from predictors. They are different schemas; the shipped models cannot be treated as qualified site-v3 models.

## Start here

1. Read [placement and visibility](docs-site/deployment/placement.mdx). A normal router LAN port does not mirror household Wi-Fi/unicast traffic.
2. While mirroring is unresolved, follow [NO_VISIBILITY_PILOT_RUNBOOK.md](NO_VISIBILITY_PILOT_RUNBOOK.md). It includes commands, waits, endpoint captures, replay and a separate firewall lab. Keep a private copy of [PILOT_RESULTS_TEMPLATE.md](PILOT_RESULTS_TEMPLATE.md).
3. Run [pre-test qualification](docs-site/deployment/pretest-qualification.mdx), then [site collection](docs-site/deployment/home-collection.mdx). Use the [timed home pilot](docs-site/deployment/home-pilot-step-by-step.mdx) only after an observation path exists. Fourteen days is an initial workload sample after qualification, not a guarantee of detection accuracy.
4. Test the [policy workbench](docs-site/deployment/policy-workbench.mdx), [bounded audit](docs-site/deployment/policy-audit.mdx) and [offline changes](docs-site/deployment/offline-policy-changes.mdx) independently of packet visibility.
5. Use [independent security campaigns](docs-site/deployment/security-campaigns.mdx) before making detection or containment claims. A high anomaly score is not calibrated malicious probability.

### Offline developer checks

From the repository root, using a virtual environment with the collection dependencies:

```bash
python -m pip install -r Controller/requirements-home.txt
python -m unittest discover -s tests
python scripts/check_feature_catalog.py
python scripts/policy_inventory.py --help
```

Live packet capture requires Linux and a qualified observation point. Offline tests require neither Ryu, Snort nor firewall credentials. Shipped trusted model artifacts require a separate compatible environment; do not install them as a prerequisite for site collection.

## Documentation and continuation

On Windows, start the independent background docs preview with:

```powershell
.\scripts\start_docs.cmd
```

Open [the local docs](http://localhost:3333/). The launcher verifies readiness and records logs in .local/docs-preview; it does not change PowerShell execution policy or create reboot autostart. See [documentation access](docs-site/deployment/documentation-access.mdx).

[DEVELOPER_STUDY_ROADMAP.md](DEVELOPER_STUDY_ROADMAP.md) gives prerequisites and rebuild exercises. [PROJECT_AI_HANDBOOK.md](PROJECT_AI_HANDBOOK.md) is the single-file continuation reference with source fingerprints, every tracked file's purpose and Python symbol/import index. Read relevant source/tests before editing even when the index is fresh.

Implementation changes must include an affected docs page and dated changelog entry. Before committing, stage the intended files and run the documentation, feature-catalog and AI-handoff guards described in [docs-site/README.md](docs-site/README.md).

## Cleanup and recovery

[The preservation ledger](docs-site/developers/repository-scope.mdx) lists every removed obsolete helper/runbook and its replacement. The annotated **pre-auto-audit-cleanup-2026-11-05** tag preserves the prior committed tree. Original feature extractors, inference loaders and model/training artifacts are preserved; local private datasets and Backup are outside cleanup.

Legacy Ryu/UDP identifiers remain for research compatibility. Their retained code is not the main home-pilot deployment instruction. The active architecture still needs native vendor adapters, identity/NAT/session joins, calibrated models, authenticated approvals, durable apply/read-back/rollback and independently measured safety before automatic production policy changes.
