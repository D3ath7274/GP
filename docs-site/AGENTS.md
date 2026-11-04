# Documentation maintenance

Follow the repository instructions and the [coverage matrix](DOCUMENTATION_COVERAGE.md). Keep paths in `docs.json` synchronized with authored pages. Document observable behavior, defaults, authorization boundaries and how to verify results. Update the OpenAPI contract with REST changes. Record actual validation outcomes in `DOCUMENTATION_VALIDATION.md`.

The guard requires an affected MDX page plus a dated changelog entry. Source-to-page rules are in `documentation-map.json`, using first-match order. Keep those rules aligned with the coverage matrix. Preview locally with `mint dev --port 3333 --no-open` from this directory, or use the Windows background launcher `scripts/start_docs.ps1` from the repository root. Local commits and GitHub push/PR checks verify documentation inclusion; review its accuracy as part of each change.
