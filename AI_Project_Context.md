# Adaptive IPS framework — project context

The active goal is evidence-backed behavioral firewall auto-audit and, after qualification, adaptive response across supported firewall vendors. The thesis feature-group method remains the core rather than being replaced by policy parsing.

Read PROJECT_AI_HANDBOOK.md for the complete, source-checked continuation document. CODEBASE_AI_HANDOFF.md is its authored architecture core; docs-site/roadmap/final-service-scope.mdx and delivery-phases.mdx are the canonical requirements and release gates.

Current paths are site-v3 observation/shadow profiles, read-only operator-model policy audit/change review, and a separate operator-run nftables lab adapter. Original Ryu/TrafficCapture/Snort/RF/AE code remains a behavioral reference lane, not qualified production firewall automation.

Both old/new feature schemas, G1–G24 rationale, shipped artifacts and rebuilding scripts are retained. docs-site/architecture/feature-lineage.mdx preserves proposed measurements; docs-site/developers/repository-scope.mdx records exact cleanup decisions and the pre-auto-audit-cleanup-2026-11-05 recovery tag. Private/untracked data and Backup are not cleanup targets.

Do not revive historical runbooks or treat training scores as calibrated deployment confidence. Verify current source fingerprints, then inspect the relevant implementation/tests for each new task.
