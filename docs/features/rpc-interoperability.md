# Offline simulateTransaction interoperability conformance (Issue #22)

The version-tagged matrix in **fixtures/rpc-interop/cases.v1.json** contains
24 distinct deterministic scenarios. The **tests/rpc-interoperability.test.mjs**
harness resolves placeholders with the pinned Stellar SDK and exercises both
`normalizeSimulation` and `inspect` without network access.

## Provenance

- **recorded-public-testnet** uses the existing
  **examples/real-simulation/captured.json**, a previously recorded successful
  Stellar Testnet `simulateTransaction` fixture. Capture time, network,
  contract, SDK version and ledger appear in that file; see
  **docs/features/real-world-validation.md**. No fresh capture is claimed.
- **synthetic-derived-from-recorded** reconstructs raw/SDK response envelopes
  around the saved authorization XDR. These wrappers are not additional captures.
- **sdk-synthetic** uses Stellar SDK XDR constructors to generate nested calls,
  source-account, legacy address, addressV2 and delegated credentials.
- **synthetic** and **synthetic-adversarial** are handcrafted positive/negative
  response shapes, clearly distinct from recorded network evidence.

Assertions cover exact authorization count, credential type, root method and
child count; raw JSON-RPC, SDK-parsed and flattened responses; and
`authorized` versus `no-authorizations` versus rejected malformed or
incomplete input. An error response or missing `auth` is never treated as
successful empty authorization. Invalid XDR may pass the shape normalizer,
but the inspector must reject it.

Run from the repository root using **Node 22**:

```bash
npm ci --ignore-scripts
npm run check
npm test
node --test tests/rpc-interoperability.test.mjs
```

The suite uses no private keys, wallet connections, signatures, live RPC calls
or transaction submission. Conformance is a statement about the *supported
saved response shapes*, not a claim that transactions are valid, signed,
submitted, exploitable, or safe.

Reference: https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/simulateTransaction
