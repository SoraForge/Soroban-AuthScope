# Authorization-entry XDR compatibility diagnostics (Issue #23)

The pure, offline TypeScript function `checkAuthorizationXdr(base64)` lives in
`src/features/xdr-compat/index.ts` and uses the repository-pinned
`@stellar/stellar-sdk@17.2.1`. Build first, then import from
`dist/features/xdr-compat/index.js`.

It enforces **canonical padded base64**, a **128 KiB decoded entry cap**,
SDK decode/re-encode byte equality, and traversal limits (2,000 nodes, depth 24).
Known credential discriminants are 0 (source account), 1 (legacy address),
2 (addressV2), and 3 (address with delegates). Authorized-function variants
include contract invocation, contract creation, and v2 contract creation.

A result is one of:
- `supported`: SDK-decoded, losslessly re-encoded, all inspected union arms known;
  reports credential type, invocation kinds/count, maximum depth and byte count.
- `unsupported`: previously unknown credential/function arm or an SDK-supported
  entry containing a variant AuthScope does not recognize. **Requires review**.
- `malformed`: invalid/noncanonical base64, malformed/oversized XDR or exceeded
  tree limits. **Requires review**.

The validator never reveals raw XDR, signatures, nonces, or argument contents.
For non-source credentials, an unknown future nested arm may be indistinguishable
from corrupt XDR under the pinned SDK; such undecodable input is classified as
`malformed` and still fails closed, **not** approved or supported.
This checks byte-format compatibility, **not** signature validity, ledger status,
on-chain authorization, exploitability, or transaction safety.

Run with Node 22:

```bash
npm ci --ignore-scripts
npm run check
npm test
node --test tests/xdr-compat.test.mjs
```

Tests use SDK-created source-account, address, addressV2, delegated, nested and
contract-creation fixtures plus the previously captured public Testnet fixture.
No wallet connection, private key, signing, RPC or transaction submission is used.
Stellar XDR reference: https://github.com/stellar/stellar-xdr
