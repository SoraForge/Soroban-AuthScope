import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Address, StrKey, xdr } from "@stellar/stellar-sdk";
import { compare, inspect } from "../dist/index.js";
import {
  RULE_ADDED_ID,
  RULE_REMOVED_ID,
  comparisonToSarif,
  main as runSarifCli,
  validateSarifLog
} from "../tools/sarif-export/index.mjs";

const rootContract = StrKey.encodeContract(Buffer.alloc(32, 10));
const childContract = StrKey.encodeContract(Buffer.alloc(32, 20));
const signer = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 30));

function makeAuthEntry({ withNestedChild = false, method = "transfer" } = {}) {
  const subInvocations = withNestedChild
    ? [
        new xdr.SorobanAuthorizedInvocation({
          function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
            new xdr.InvokeContractArgs({
              contractAddress: Address.fromString(childContract).toScAddress(),
              functionName: "mint_reward",
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
        address: Address.fromString(signer).toScAddress(),
        nonce: 1n,
        signatureExpirationLedger: 50,
        signature: xdr.ScVal.scvVoid()
      })
    ),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: Address.fromString(rootContract).toScAddress(),
          functionName: method,
          args: []
        })
      ),
      subInvocations
    })
  }).toXdr("base64");
}

test("golden SARIF conversion distinguishes added nested child and removed root without false locations or error levels", () => {
  const before = inspect([makeAuthEntry({ withNestedChild: false, method: "revoke" })]);
  const after = inspect([makeAuthEntry({ withNestedChild: true, method: "transfer" })]);
  const comparison = compare(before, after);

  const sarif = comparisonToSarif(comparison);
  const conformance = validateSarifLog(sarif);
  assert.equal(conformance.valid, true, conformance.errors.join("; "));
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].invocations[0].properties.status, "changed");

  const results = sarif.runs[0].results;
  assert.equal(results.length, 3);

  // Added nested child call
  const addedNested = results.find(
    r => r.ruleId === RULE_ADDED_ID && r.properties.isNested === true
  );
  assert.ok(addedNested, "expected added nested child result");
  assert.equal(addedNested.level, "warning");
  assert.equal(addedNested.properties.scopeLevel, "nested");
  assert.equal(addedNested.properties.invocationDepth, 2);
  assert.equal(addedNested.properties.rootContract, rootContract);
  assert.equal(addedNested.properties.leafContract, childContract);
  assert.equal(addedNested.properties.leafMethod, "mint_reward");
  assert.deepEqual(addedNested.locations, []);

  // Removed root authorization
  const removedRoot = results.find(
    r => r.ruleId === RULE_REMOVED_ID && r.properties.isNested === false
  );
  assert.ok(removedRoot, "expected removed root result");
  assert.equal(removedRoot.level, "note");
  assert.equal(removedRoot.properties.scopeLevel, "root");
  assert.equal(removedRoot.properties.invocationDepth, 1);
  assert.equal(removedRoot.properties.leafMethod, "revoke");
  assert.deepEqual(removedRoot.locations, []);
});

test("validated repository-relative sourceMap attaches file URI without fabricated line numbers", () => {
  const comparison = compare(inspect([]), inspect([makeAuthEntry({ withNestedChild: true })]));
  const sarif = comparisonToSarif(comparison, {
    sourceMap: {
      [childContract]: "contracts/reward/src/lib.rs"
    }
  });
  assert.equal(validateSarifLog(sarif).valid, true);
  const childResult = sarif.runs[0].results.find(r => r.properties.leafContract === childContract);
  assert.equal(childResult.locations.length, 1);
  assert.equal(childResult.locations[0].physicalLocation.artifactLocation.uri, "contracts/reward/src/lib.rs");
  assert.equal(childResult.locations[0].physicalLocation.region, undefined);

  // Unsafe sourceMap paths (traversal, absolute, URLs, line fragments) are rejected
  for (const unsafePath of ["../secret.rs", "/etc/passwd", "https://example.com/a.rs", "src/lib.rs#L10"]) {
    assert.throws(
      () => comparisonToSarif(comparison, { sourceMap: { [childContract]: unsafePath } }),
      TypeError
    );
  }
});

test("sanitizes hostile method strings and distinguishes unchanged (0), changed (1), and error (2) CLI statuses", async () => {
  const hostCraftedComparison = {
    schemaVersion: 1,
    changed: true,
    beforeCount: 0,
    afterCount: 1,
    changes: [
      {
        kind: "added",
        authorizer: JSON.stringify(["sorobanCredentialsSourceAccount", "transaction source", []]),
        path: JSON.stringify([
          "contract",
          rootContract,
          "evil<script>alert(1)</script>\nmethod",
          "a".repeat(64)
        ]),
        count: 1
      }
    ]
  };

  const sarif = comparisonToSarif(hostCraftedComparison);
  assert.equal(validateSarifLog(sarif).valid, true);
  const text = sarif.runs[0].results[0].message.text;
  assert.ok(!text.includes("<script>"));
  assert.ok(text.includes("&lt;script&gt;"));

  const dir = await mkdtemp(join(tmpdir(), "authscope-sarif-"));
  try {
    const unchangedPath = join(dir, "unchanged.json");
    const changedPath = join(dir, "changed.json");
    const invalidPath = join(dir, "invalid.json");
    const outPath = join(dir, "out.sarif");

    await writeFile(
      unchangedPath,
      JSON.stringify({ schemaVersion: 1, changed: false, beforeCount: 0, afterCount: 0, changes: [] })
    );
    await writeFile(changedPath, JSON.stringify(hostCraftedComparison));
    await writeFile(invalidPath, "{not valid json");

    assert.equal(await runSarifCli([unchangedPath, "--output", outPath]), 0);
    // Refuses to overwrite existing output file
    assert.equal(await runSarifCli([unchangedPath, "--output", outPath]), 2);
    assert.equal(await runSarifCli([changedPath, "--output", join(dir, "changed.sarif")]), 1);
    assert.equal(await runSarifCli([invalidPath]), 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
