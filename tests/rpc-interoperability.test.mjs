import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Address, StrKey, xdr } from "@stellar/stellar-sdk";
import { inspect, normalizeSimulation } from "../dist/index.js";

const matrix = JSON.parse(readFileSync("fixtures/rpc-interop/cases.v1.json", "utf8"));
const captured = JSON.parse(readFileSync(matrix.recordedFixture, "utf8"));

function makeSyntheticEntries(recordedXdr) {
  const recorded = xdr.SorobanAuthorizationEntry.fromXdr(recordedXdr, "base64");
  const nestedChild = new xdr.SorobanAuthorizedInvocation({
    function: recorded.rootInvocation.function, subInvocations: []
  });
  const nested = new xdr.SorobanAuthorizationEntry({
    credentials: recorded.credentials,
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: recorded.rootInvocation.function, subInvocations: [nestedChild]
    })
  }).toXdr("base64");

  const account = Address.fromString(StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 20))).toScAddress();
  const contract = Address.fromString(StrKey.encodeContract(Buffer.alloc(32, 30))).toScAddress();
  const addressCredentials = () => new xdr.SorobanAddressCredentials({
    address: account, nonce: 1n, signatureExpirationLedger: 100,
    signature: xdr.ScVal.scvVoid()
  });
  const invocation = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: contract, functionName: "permit", args: []
      })
    ),
    subInvocations: []
  });
  const encode = credentials => new xdr.SorobanAuthorizationEntry({
    credentials, rootInvocation: invocation
  }).toXdr("base64");

  const signer = new xdr.SorobanDelegateSignature({
    address: account, signature: xdr.ScVal.scvVoid(), nestedDelegates: []
  });
  return {
    recorded: recordedXdr,
    nested,
    source: encode(xdr.SorobanCredentials.sorobanCredentialsSourceAccount()),
    legacy: encode(xdr.SorobanCredentials.sorobanCredentialsAddress(addressCredentials())),
    addressV2: encode(xdr.SorobanCredentials.sorobanCredentialsAddressV2(addressCredentials())),
    delegated: encode(xdr.SorobanCredentials.sorobanCredentialsAddressWithDelegates(
      new xdr.SorobanAddressCredentialsWithDelegates({
        addressCredentials: addressCredentials(), delegates: [signer]
      })
    ))
  };
}
function resolveTemplates(input, entries) {
  if (typeof input === "string" && input.startsWith("$")) {
    const key = input.slice(1);
    assert.ok(Object.hasOwn(entries, key), "Unknown fixture placeholder");
    return entries[key];
  }
  if (Array.isArray(input)) return input.map(item => resolveTemplates(item, entries));
  if (input !== null && typeof input === "object") {
    return Object.fromEntries(Object.entries(input).map(([key, val]) =>
      [key, resolveTemplates(val, entries)]
    ));
  }
  return input;
}

test("corpus integrity: 24 distinct cases with explicit provenance; only referenced fixture is recorded", () => {
  assert.equal(matrix.schemaVersion, 1);
  assert.equal(matrix.sdk, "@stellar/stellar-sdk@17.2.1");
  assert.equal(matrix.cases.length, 24);
  assert.equal(new Set(matrix.cases.map(item => item.id)).size, matrix.cases.length);
  assert.equal(captured.provenance.kind, "live-testnet-simulation");
  assert.equal(captured.provenance.network, "Stellar Testnet");
  assert.equal(captured.provenance.sdk, "@stellar/stellar-sdk 17.2.1");
  assert.equal(captured.result.results[0].auth.length, 1);
  assert.equal(matrix.cases.filter(x => x.origin === "recorded-public-testnet").length, 1);
  assert.ok(matrix.cases.every(x => x.origin && x.expect?.outcome));
  assert.doesNotMatch(JSON.stringify(matrix), /"secret"|"privateKey"|"authorizationHeader"|"bearerToken"/i);
});

const encoded = makeSyntheticEntries(captured.result.results[0].auth[0]);
for (const scenario of matrix.cases) {
  test("RPC conformance v1: " + scenario.id, () => {
    const input = scenario.inputRef === "recordedFixture"
      ? captured
      : resolveTemplates(scenario.input, encoded);
    if (scenario.expect.outcome === "reject-normalizer") {
      assert.throws(() => normalizeSimulation(input));
      assert.throws(() => inspect(input));
      return;
    }
    if (scenario.expect.outcome === "reject-inspector") {
      const normalized = normalizeSimulation(input);
      assert.equal(normalized.shape, scenario.expect.shape);
      assert.equal(normalized.classification, "authorized");
      assert.throws(() => inspect(input), /Invalid/);
      return;
    }
    const normalized = normalizeSimulation(input);
    assert.equal(normalized.classification, scenario.expect.outcome);
    assert.equal(normalized.shape, scenario.expect.shape);
    assert.equal(normalized.authorizations.length, scenario.expect.count);
    const report = inspect(input);
    assert.equal(report.schemaVersion, 1);
    assert.equal(report.authorizationCount, scenario.expect.count);
    assert.deepEqual(report.entries.map(x => x.credential), scenario.expect.credentials);
    assert.deepEqual(report.entries.map(x => x.root.method), scenario.expect.rootMethods);
    assert.deepEqual(report.entries.map(x => x.root.children.length), scenario.expect.nestedChildren);
    if (scenario.origin === "recorded-public-testnet") {
      assert.equal(report.entries[0].root.contract, captured.provenance.contract);
      assert.equal(report.entries[0].root.method, captured.provenance.function);
    }
  });
}

test("aggregate limits and inconsistent mixed results fail closed, not empty", () => {
  assert.throws(() => normalizeSimulation({ auth: Array(129).fill(encoded.source) }));
  assert.throws(() => inspect({ results: [{ auth: [encoded.source] }, { auth: null }] }));
  assert.throws(() => inspect({ result: { results: [{ auth: [encoded.source] }, {}] } }));
  assert.notEqual(normalizeSimulation({ result: { results: [] } }).classification, "authorized");
});
