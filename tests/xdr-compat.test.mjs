import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Address, StrKey, xdr } from "@stellar/stellar-sdk";
import {
  MAX_AUTHORIZATION_XDR_BYTES, checkAuthorizationXdr
} from "../dist/features/xdr-compat/index.js";

const account = Address.fromString(StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 11))).toScAddress();
const contract = Address.fromString(StrKey.encodeContract(Buffer.alloc(32, 7))).toScAddress();
const sign = () => new xdr.SorobanAddressCredentials({
  address: account, nonce: 123n, signatureExpirationLedger: 999,
  signature: xdr.ScVal.scvBytes(Buffer.from("never-disclose-this-signature"))
});
const delegate = () => new xdr.SorobanDelegateSignature({
  address: account, signature: xdr.ScVal.scvVoid(), nestedDelegates: []
});
function contractCall(name, children = []) {
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({ contractAddress: contract, functionName: name, args: [] })
    ),
    subInvocations: children
  });
}
const encode = (credentials, root = contractCall("approve")) =>
  new xdr.SorobanAuthorizationEntry({ credentials, rootInvocation: root }).toXdr("base64");

test("all pinned credential arms round-trip exactly; nested calls are counted", () => {
  const cases = [
    ["sorobanCredentialsSourceAccount", xdr.SorobanCredentials.sorobanCredentialsSourceAccount()],
    ["sorobanCredentialsAddress", xdr.SorobanCredentials.sorobanCredentialsAddress(sign())],
    ["sorobanCredentialsAddressV2", xdr.SorobanCredentials.sorobanCredentialsAddressV2(sign())],
    ["sorobanCredentialsAddressWithDelegates",
      xdr.SorobanCredentials.sorobanCredentialsAddressWithDelegates(
        new xdr.SorobanAddressCredentialsWithDelegates({
          addressCredentials: sign(), delegates: [delegate()]
        })
      )
    ]
  ];
  for (const [credential, value] of cases) {
    const base64 = encode(value, contractCall("approve", [contractCall("nested")]));
    const result = checkAuthorizationXdr(base64);
    assert.equal(result.status, "supported", JSON.stringify(result));
    assert.equal(result.credential, credential);
    assert.equal(result.invocationCount, 2);
    assert.equal(result.maximumDepth, 1);
    assert.deepEqual(result.invocationKinds, ["sorobanAuthorizedFunctionTypeContractFn"]);
    assert.deepEqual(checkAuthorizationXdr(base64), result);
    const text = JSON.stringify(result);
    assert.doesNotMatch(text, /never-disclose|signature|nonce|999|123/);
  }
});

test("create-contract host-function arms (v1 and v2) use SDK XDR constructors", () => {
  const preimage = xdr.ContractIdPreimage.contractIdPreimageFromAddress(
    new xdr.ContractIdPreimageFromAddress({ address: account, salt: Buffer.alloc(32, 9) })
  );
  const executable = xdr.ContractExecutable.contractExecutableWasm(Buffer.alloc(32, 5));
  const args = { contractIdPreimage: preimage, executable };
  const functions = [
    xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeCreateContractHostFn(
      new xdr.CreateContractArgs(args)
    ),
    xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeCreateContractV2HostFn(
      new xdr.CreateContractArgsV2({ ...args, constructorArgs: [] })
    )
  ];
  for (const fn of functions) {
    const base64 = encode(xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
      new xdr.SorobanAuthorizedInvocation({ function: fn, subInvocations: [] }));
    const result = checkAuthorizationXdr(base64);
    assert.equal(result.status, "supported", JSON.stringify(result));
    assert.deepEqual(result.invocationKinds, [fn.type]);
  }
});

test("the existing recorded testnet entry passes without a network request", () => {
  const captured = JSON.parse(readFileSync("examples/real-simulation/captured.json", "utf8"));
  const encoded = captured.result.results[0].auth[0];
  const result = checkAuthorizationXdr(encoded);
  assert.equal(result.status, "supported", JSON.stringify(result));
  assert.equal(result.credential, "sorobanCredentialsSourceAccount");
});

test("malformed base64, corrupt XDR, unknown union arms and size limits fail closed", () => {
  const valid = encode(xdr.SorobanCredentials.sorobanCredentialsSourceAccount());
  const unknownCredential = Buffer.from(valid, "base64");
  unknownCredential.writeInt32BE(0x42424242, 0);
  const unknownFunction = Buffer.from(valid, "base64");
  unknownFunction.writeInt32BE(0x42424242, 4);
  assert.deepEqual(checkAuthorizationXdr(unknownCredential.toString("base64")), {
    status: "unsupported", reviewRequired: true, reason: "unknown-credential-arm"
  });
  assert.deepEqual(checkAuthorizationXdr(unknownFunction.toString("base64")), {
    status: "unsupported", reviewRequired: true, reason: "unknown-function-arm"
  });
  for (const bad of [
    null, "", "AAAA", "AAAAAA", "not-base64*", "/x==", valid.slice(0, -4),
    Buffer.alloc(64, 0).toString("base64")
  ]) {
    const result = checkAuthorizationXdr(bad);
    assert.equal(result.status, "malformed", JSON.stringify(result));
    assert.equal(result.reviewRequired, true);
  }
  const tooLarge = Buffer.alloc(MAX_AUTHORIZATION_XDR_BYTES + 1).toString("base64");
  assert.deepEqual(checkAuthorizationXdr(tooLarge), {
    status: "malformed", reviewRequired: true, reason: "oversized-entry"
  });
});

test("no diagnostic result leaks a raw entry or argument contents", () => {
  const valid = encode(xdr.SorobanCredentials.sorobanCredentialsAddressV2(sign()));
  for (const sample of [valid, valid.slice(0, -4), "untrusted-secret-string"]) {
    const result = checkAuthorizationXdr(sample);
    const text = JSON.stringify(result);
    assert.ok(!text.includes(valid));
    assert.doesNotMatch(text, /never-disclose|untrusted-secret|nonce|signatureExpirationLedger/);
  }
});
