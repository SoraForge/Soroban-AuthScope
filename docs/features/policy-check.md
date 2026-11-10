# Offline Scope Policy Check CLI

`tools/policy-check/index.mjs` provides a standalone, offline CLI around `src/features/scope-policy` so CI pipelines and reviewers can evaluate a v1 `Comparison` JSON report against a declarative JSON policy file without writing TypeScript code.

## Exit Codes & Semantics

- **`0` (`approved`)**: All scope changes (or an unchanged comparison) matched explicit policy allowlists and multiplicity bounds.
- **`1` (`review`)**: One or more changes require human review (including unapproved non-blocked signers, removals when `allowRemovals` is `false`, or redacted/unreadable change metadata).
- **`2` (`invalid input`)**: Missing or unreadable files, files exceeding 4 MiB, non-v1 `Comparison` reports, or malformed/wildcard policy rules.
- **`3` (`blocked`)**: One or more added changes violated an explicit blocking rule (`blockUnapprovedAuthorizers`, `blockUnapprovedContracts`, or `maxAddedOccurrencesPerPath`).

A `blocked` or `review` result is a local policy decision, not a security vulnerability verdict. Redacted or incomplete report metadata never silently passes as `approved`.

## Usage

```bash
npm ci --ignore-scripts
npm run build
node tools/policy-check/index.mjs --diff schemas/fixtures/valid-comparison-v1.json --policy tools/policy-check/sample-policy.json
node tools/policy-check/index.mjs --diff schemas/fixtures/valid-comparison-v1.json --policy tools/policy-check/sample-policy.json --json
node --test tests/policy-check.test.mjs
```
