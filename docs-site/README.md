# Preview and publish

These are the documentation sources for **Adaptive IPS framework**. Product requirements and current implementation limits are tracked in [final service scope](roadmap/final-service-scope.mdx) and [delivery phases](roadmap/delivery-phases.mdx).

On Windows, run `.\scripts\start_docs.ps1` from the repository root, then open **http://localhost:3333/**. The launcher starts Mintlify in a hidden background process, verifies an HTTP 200 response and reuses an already healthy preview. Logs are in the Git-ignored `.local/docs-preview/` directory. It runs without the controller or sensor. After a Windows restart, run the launcher again.

For a foreground preview, use `.\scripts\start_docs.ps1 -Foreground` or run `mint dev --port 3333 --no-open` from docs-site. Keep that terminal open. Port 3333 is explicit; `mint dev` alone uses its default port. A refused connection means the local preview is not listening at the requested address. Localhost refers to the computer running your browser.

The running home or passive sensor also serves a lightweight documentation reader at `/docs` on its loopback dashboard origin. See [documentation access](deployment/documentation-access.mdx) and [home collection](deployment/home-collection.mdx). It reads this checkout on each request. The hosted Mintlify site updates after the connected GitHub branch is pushed and built.

Install the tested CLI with `npm install --global mint@4.2.1195` if it is absent. From `docs-site`, run `mint validate`, `mint broken-links` and `mint a11y`. Select this directory as the source in the Mintlify deployment configuration. Review visibility before publication.

[Mintlify CLI](https://www.mintlify.com/docs/cli/install) · [Local preview](https://www.mintlify.com/library/how-to-turn-markdown-files-into-a-docs-website)

## Keep documentation synchronized

Run this once from the repository root to opt in to the versioned local hook.

```bash
git config --local core.hooksPath .githooks
```

On Unix-like systems, run `chmod +x .githooks/pre-commit` if the hook was checked out without execute permission.

Stage an implementation change together with an affected MDX page and a new dated heading/notes in `reference/change-log.mdx`. Include behavior, operator impact and verification. For an internal change, update the developer page with the reason and checks. Update the corresponding OpenAPI contract when REST contracts change.

Run `python scripts/check_docs_sync.py --staged` from the repository root. The guard reads the Git index, so unstaged documentation cannot satisfy it. `documentation-map.json` defines source-to-page rules using first-match order; keep specific patterns before broader ones. Unknown code requires developers/maintenance.mdx until a more specific rule is added. Deleted/missing mapped pages fail validation. Requirements files, firewall rules, model artifacts, CI and Git hooks are included. A changelog alone or an unrelated page is insufficient. Reviewers still verify accuracy, completeness and API changes.

Also run `python scripts/check_feature_catalog.py --staged` locally and its default working-tree mode during development. The hook runs both guards; CI checks the committed feature map. Update architecture/feature-rationale.mdx and reference/feature-groups.json whenever current columns/group meaning or planned feature commitments change. The guard checks source-name/status/heading coverage, not detection quality or formula correctness.

The offline-qualification workflow job also runs the offline test suite on Ubuntu 22.04/Python 3.10 with the collection requirements. Its result is independent of Mintlify publication and physical capture qualification; review the remote job after pushing.

The GitHub workflow checks pushes and pull requests. Its docs-sync job checks changed source against the committed documentation. Its docs-build job installs the pinned CLI and runs Mintlify validation, link and accessibility checks. These checks validate the source; they do not publish a hosted site or keep a local process running.

Require **docs-sync** and **docs-build** in the target branch ruleset, with pull requests required, to block merging failed checks. Repository-owner GitHub settings control that enforcement; the workflow alone cannot prevent a permitted direct push. Local hooks apply per clone and can be bypassed, so use the server-side required checks as well.
