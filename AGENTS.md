# Repository instructions

When changing executable code, runtime configuration, deployment scripts, Snort rules or model artifacts, update the affected documentation under `docs-site/` and add an entry to `docs-site/reference/change-log.mdx` in the same change. Record behavior, operator impact and verification. For an internal-only change, record the reason and checks in the changelog.

Check the coverage matrix to locate the relevant page. Update `docs-site/openapi.json` when REST contracts change and update navigation for new pages. Keep runtime claims tied to implementation. Exclude real addresses, device data and credentials from examples. Leave planned capabilities marked as planned.

Run the documentation guard and Mintlify checks described in `docs-site/README.md` before submitting.
