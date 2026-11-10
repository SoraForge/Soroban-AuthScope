# SARIF 2.1.0 Scope Diff Export

`tools/sarif-export/index.mjs` converts a v1 `Comparison` JSON report into a conservative [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) log suitable for code-scanning and review collectors.

## Rules & Conservative Defaults

- **`AUTHSCOPE001` (`AuthorizationScopeAdded`, level `"warning"`)**: Emitted for added root authorizations or added nested contract sub-invocations.
- **`AUTHSCOPE002` (`AuthorizationScopeRemoved`, level `"note"`)**: Emitted for removed root authorizations or removed nested sub-invocations.
- **Never `"error"` level:** Authorization-scope differences indicate changes that require human review; they do not prove an exploit or vulnerability.
- **No fabricated locations:** By default, `locations` is empty (`[]`). Physical artifact URIs are attached only when the caller supplies a validated repository-relative `--source-map <map.json>` mapping contract IDs (`C...`) to relative repository files, and line numbers are never fabricated.

## Usage

```bash
npm ci --ignore-scripts
npm run build
node tools/sarif-export/index.mjs schemas/fixtures/valid-comparison-v1.json
node tools/sarif-export/index.mjs schemas/fixtures/valid-comparison-v1.json --output review.sarif
node --test tests/sarif-export.test.mjs
```

**Exit codes:** `0` when `changed` is `false`; `1` when `changed` is `true`; `2` on invalid input, invalid source map, or existing output file.
