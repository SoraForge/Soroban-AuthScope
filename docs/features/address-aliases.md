# Local Address & Contract Aliases

`src/features/address-aliases` provides a pure, offline, view-only resolver that annotates v1 `Snapshot` and `Comparison` structures with caller-supplied human-readable labels (such as `Treasury Vault` or `DAO Multisig Root`) while keeping canonical Stellar contract IDs (`C...`) and public authorizer keys (`G...` / `M...`) intact.

## Security & Verification Boundaries

- **View-only and additive:** Canonical `contract`, `authorizer`, and `path` values are never overwritten or mutated. Aliases are attached in separate fields (`contractAlias`, `authorizerAlias`, `contractDisplay`, `authorizerDisplay`, `appliedAliases`).
- **Offline only:** Aliases are resolved strictly from the caller-provided local map. AuthScope never queries Horizon, Soroban RPC, stellar.toml, or external directories to infer on-chain identity.
- **No trust or authenticity claim:** Local aliases reflect caller-supplied labels for review convenience; they do not prove contract identity, ownership, or safety.
- **Strict validation:**
  - Keys are validated with `@stellar/stellar-sdk` `StrKey` (`isValidContract`, `isValidEd25519PublicKey`, `isValidMed25519PublicKey`). Secret seeds (`S...`) and malformed addresses are rejected.
  - Labels are bounded to `1..64` printable characters. HTML/XSS angle brackets (`<`, `>`), backticks, control characters, bidirectional overrides, duplicate/conflicting labels, and StrKey-shaped labels are rejected.
  - Alias maps are capped at 256 entries.

## Usage

```bash
npm ci --ignore-scripts
npm run check
npm test
node --test tests/address-aliases.test.mjs
```

```js
import { resolveSnapshotAliases, resolveComparisonAliases } from "./dist/features/address-aliases/index.js";

const aliasedSnapshot = resolveSnapshotAliases(snapshot, {
  schemaVersion: 1,
  aliases: {
    CADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP5KR: "Treasury Vault"
  }
});
```
