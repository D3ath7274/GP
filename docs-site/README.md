# Preview and publish

The running home or passive sensor also serves a lightweight documentation reader at `/docs` on its loopback dashboard origin. See [documentation access](deployment/documentation-access.mdx) and [home collection](deployment/home-collection.mdx). It reads this checkout on each request. The hosted Mintlify site updates after the connected GitHub branch is pushed and built.

Install `mint` with npm. From `docs-site`, run `mint dev`, `mint validate` and `mint broken-links`. Select this directory as the source in the Mintlify deployment configuration. Review visibility before publication.

[Mintlify CLI](https://www.mintlify.com/docs/cli/install) · [Navigation reference](https://docs.retellai.com/general/introduction)

## Keep documentation synchronized

Run this once from the repository root to opt in to the versioned local hook.

```bash
git config --local core.hooksPath .githooks
```

On Unix-like systems, run `chmod +x .githooks/pre-commit` if the hook was checked out without execute permission.

Stage an implementation change together with its documentation. Update the relevant page and add a new dated heading and notes to `reference/change-log.mdx`. Include the affected behavior, operator impact and verification. For an internal change, state why the public behavior stays the same. Update OpenAPI when REST contracts change.

Run `python scripts/check_docs_sync.py --staged` from the repository root to check the index manually. The GitHub workflow applies the same rule to the full PR diff. A changelog heading is the automated check. Reviewers verify the related page and accuracy of the entry.

Require the **docs-sync** status check in the target branch ruleset to enforce the check before merging. To enforce it on the protected branch, require pull requests there. Local hooks apply per clone.
