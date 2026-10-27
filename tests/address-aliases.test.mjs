import test from "node:test";
import assert from "node:assert/strict";
import { Address, Keypair, StrKey, xdr } from "@stellar/stellar-sdk";
import { compare, inspect } from "../dist/index.js";
import {
  MAX_ALIAS_ENTRIES,
  formatAliasedAddress,
  resolveComparisonAliases,
  resolveSnapshotAliases,
  validateAliases
} from "../dist/features/address-aliases/index.js";

const vaultContract = StrKey.encodeContract(Buffer.alloc(32, 11));
const routerContract = StrKey.encodeContract(Buffer.alloc(32, 22));
const unknownContract = StrKey.encodeContract(Buffer.alloc(32, 33));
const treasurySigner = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 44));
const delegateSigner = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 55));

function makeSignedEntry(contractAddr, method, subContractAddr) {
  const subInvocations = subContractAddr
    ? [
        new xdr.SorobanAuthorizedInvocation({
          function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
            new xdr.InvokeContractArgs({
              contractAddress: Address.fromString(subContractAddr).toScAddress(),
              functionName: "transfer",
              args: []
            })
          ),
          subInvocations: []
        })
      ]
    : [];

  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddressV2(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(treasurySigner).toScAddress(),
        nonce: 7n,
        signatureExpirationLedger: 100,
        signature: xdr.ScVal.scvVoid()
      })
    ),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: Address.fromString(contractAddr).toScAddress(),
          functionName: method,
          args: []
        })
      ),
      subInvocations
    })
  }).toXdr("base64");
}

test("resolves known contract and signer aliases beside untouched canonical IDs while leaving unknown addresses unchanged", () => {
  const snapshot = inspect([makeSignedEntry(routerContract, "swap", vaultContract), makeSignedEntry(unknownContract, "ping")]);
  snapshot.entries[0].delegates = [delegateSigner];
  snapshot.entries[0].delegateTree = [{ address: delegateSigner, children: [] }];
  const originalSnapshot = structuredClone(snapshot);

  const aliasMap = {
    schemaVersion: 1,
    aliases: {
      [vaultContract]: "Treasury Vault",
      [routerContract]: "AMM Router",
      [treasurySigner]: "DAO Multisig Root",
      [delegateSigner]: "Ops Operator"
    }
  };

  const resolved = resolveSnapshotAliases(snapshot, aliasMap);

  // Input snapshot is never mutated
  assert.deepEqual(snapshot, originalSnapshot);

  // Known contract and authorizer have additive alias & display fields; canonical IDs stay intact
  const first = resolved.entries[0];
  assert.equal(first.authorizer, treasurySigner);
  assert.equal(first.authorizerAlias, "DAO Multisig Root");
  assert.equal(first.authorizerDisplay, `DAO Multisig Root (${treasurySigner})`);
  assert.equal(first.delegateTree[0].address, delegateSigner);
  assert.equal(first.delegateTree[0].alias, "Ops Operator");
  assert.equal(first.root.contract, routerContract);
  assert.equal(first.root.contractAlias, "AMM Router");
  assert.equal(first.root.contractDisplay, `AMM Router (${routerContract})`);
  assert.equal(first.root.children[0].contract, vaultContract);
  assert.equal(first.root.children[0].contractAlias, "Treasury Vault");

  // Unknown contract stays unchanged with null alias
  const second = resolved.entries[1];
  assert.equal(second.root.contract, unknownContract);
  assert.equal(second.root.contractAlias, null);
  assert.equal(second.root.contractDisplay, unknownContract);

  // Applied aliases are sorted deterministically by canonical address
  const sortedExpected = [vaultContract, routerContract, treasurySigner, delegateSigner].sort((a, b) => a.localeCompare(b));
  assert.deepEqual(
    resolved.appliedAliases.map(item => item.address),
    sortedExpected
  );
});

test("resolves comparison deltas without mutating canonical authorizer or path tuples", () => {
  const before = inspect([]);
  const after = inspect([makeSignedEntry(vaultContract, "withdraw")]);
  const comparison = compare(before, after);
  const originalComparison = structuredClone(comparison);

  const resolved = resolveComparisonAliases(comparison, {
    [vaultContract]: "Treasury Vault",
    [treasurySigner]: "DAO Multisig Root"
  });

  assert.deepEqual(comparison, originalComparison);
  assert.equal(resolved.changes.length, 1);
  const delta = resolved.changes[0];
  assert.equal(delta.authorizer, comparison.changes[0].authorizer);
  assert.equal(delta.path, comparison.changes[0].path);
  assert.equal(delta.authorizerPrincipal, treasurySigner);
  assert.equal(delta.authorizerAlias, "DAO Multisig Root");
  assert.equal(delta.steps[0].contract, vaultContract);
  assert.equal(delta.steps[0].contractAlias, "Treasury Vault");
  assert.equal(delta.steps[0].contractDisplay, `Treasury Vault (${vaultContract})`);
});

test("rejects malformed StrKeys, secret seeds, duplicate conflicting labels, XSS/control payloads, and oversized maps", () => {
  const secretSeed = Keypair.random().secret();

  const invalidCases = [
    // Malformed StrKey
    { "not-a-stellar-key": "Treasury Vault" },
    // Secret seed (S...) must never be accepted in alias mappings
    { [secretSeed]: "Leaked Seed" },
    // Duplicate conflicting labels (exact and case-insensitive)
    {
      [vaultContract]: "Treasury Vault",
      [routerContract]: "Treasury Vault"
    },
    {
      [vaultContract]: "Treasury Vault",
      [routerContract]: "treasury vault"
    },
    // XSS / HTML injection in label
    { [vaultContract]: "<script>alert(1)</script>" },
    { [vaultContract]: "Vault <img src=x onerror=alert(1)>" },
    // Control characters / newlines
    { [vaultContract]: "Vault\nInjected" },
    { [vaultContract]: "Vault\u0000Null" },
    // Address spoofing (label looks like another Stellar StrKey)
    { [vaultContract]: routerContract },
    // Empty or untrimmed or oversized label (> 64 chars)
    { [vaultContract]: "" },
    { [vaultContract]: "  Leading Space" },
    { [vaultContract]: "A".repeat(65) }
  ];

  for (const bad of invalidCases) {
    assert.throws(() => validateAliases(bad), TypeError);
  }

  // Oversized map (> 256 entries)
  const oversized = {};
  for (let i = 0; i < MAX_ALIAS_ENTRIES + 1; i++) {
    const buf = Buffer.alloc(32);
    buf.writeUInt32BE(i + 1, 0);
    oversized[StrKey.encodeContract(buf)] = `Contract Label ${i + 1}`;
  }
  assert.throws(() => validateAliases(oversized), TypeError);

  // Valid formatAliasedAddress helper fallback
  const validMap = validateAliases({ [vaultContract]: "Treasury Vault" });
  assert.equal(formatAliasedAddress(vaultContract, validMap), `Treasury Vault (${vaultContract})`);
  assert.equal(formatAliasedAddress(unknownContract, validMap), unknownContract);
});
