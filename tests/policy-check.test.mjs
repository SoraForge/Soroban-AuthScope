import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { Address, StrKey, xdr } from "@stellar/stellar-sdk";
import { compare, inspect } from "../dist/index.js";
import {
  EXIT_APPROVED,
  EXIT_BLOCKED,
  EXIT_INVALID,
  EXIT_REVIEW,
  main as runPolicyCheck
} from "../tools/policy-check/index.mjs";

const execFileAsync = promisify(execFile);
const samplePolicyPath = join(process.cwd(), "tools/policy-check/sample-policy.json");
const allowedContract = "CADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP5KR";
const blockedContract = StrKey.encodeContract(Buffer.alloc(32, 99));
const newSigner = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 42));

function buildEntry(method, { contract = allowedContract, signed = false } = {}) {
  return new xdr.SorobanAuthorizationEntry({
    credentials: signed
      ? xdr.SorobanCredentials.sorobanCredentialsAddressV2(
          new xdr.SorobanAddressCredentials({
            address: Address.fromString(newSigner).toScAddress(),
            nonce: 5n,
            signatureExpirationLedger: 200,
            signature: xdr.ScVal.scvVoid()
          })
        )
      : xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: Address.fromString(contract).toScAddress(),
          functionName: method,
          args: []
        })
      ),
      subInvocations: []
    })
  }).toXdr("base64");
}

function captureIo() {
  let out = "";
  let err = "";
  return {
    stdout: { write(chunk) { out += chunk; } },
    stderr: { write(chunk) { err += chunk; } },
    get stdoutText() { return out; },
    get stderrText() { return err; }
  };
}

test("evaluates unchanged, allowlisted, review-required, blocked, redacted, and invalid cases with distinct exit codes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "authscope-policy-cli-"));
  try {
    const unchangedPath = join(dir, "unchanged.json");
    const allowlistedPath = join(dir, "allowlisted.json");
    const newSignerPath = join(dir, "new-signer.json");
    const blockedContractPath = join(dir, "blocked-contract.json");
    const redactedPath = join(dir, "redacted.json");
    const badPolicyPath = join(dir, "bad-policy.json");

    await writeFile(unchangedPath, JSON.stringify(compare(inspect([]), inspect([]))));
    await writeFile(allowlistedPath, JSON.stringify(compare(inspect([]), inspect([buildEntry("approve")]))));
    await writeFile(
      newSignerPath,
      JSON.stringify(compare(inspect([]), inspect([buildEntry("approve", { signed: true })])))
    );
    await writeFile(
      blockedContractPath,
      JSON.stringify(compare(inspect([]), inspect([buildEntry("approve", { contract: blockedContract })])))
    );

    const redactedComparison = compare(inspect([]), inspect([buildEntry("approve")]));
    redactedComparison.changes[0].path = "[redacted]";
    await writeFile(redactedPath, JSON.stringify(redactedComparison));

    await writeFile(
      badPolicyPath,
      JSON.stringify({ schemaVersion: 1, allowedContracts: [{ address: "*", functions: ["*"] }] })
    );

    // 1. Permitted unchanged -> EXIT_APPROVED (0)
    const ioUnchanged = captureIo();
    assert.equal(
      await runPolicyCheck(["--diff", unchangedPath, "--policy", samplePolicyPath], ioUnchanged),
      EXIT_APPROVED
    );
    assert.match(ioUnchanged.stdoutText, /Decision: approved/);

    // 2. Permitted allowlisted -> EXIT_APPROVED (0)
    const ioAllowlisted = captureIo();
    assert.equal(
      await runPolicyCheck(["--diff", allowlistedPath, "--policy", samplePolicyPath, "--json"], ioAllowlisted),
      EXIT_APPROVED
    );
    assert.equal(JSON.parse(ioAllowlisted.stdoutText).decision, "approved");

    // 3. New signer needs review (blockUnapprovedAuthorizers: false) -> EXIT_REVIEW (1)
    const ioReview = captureIo();
    assert.equal(
      await runPolicyCheck(["--diff", newSignerPath, "--policy", samplePolicyPath, "--json"], ioReview),
      EXIT_REVIEW
    );
    const reviewBody = JSON.parse(ioReview.stdoutText);
    assert.equal(reviewBody.decision, "review");
    assert.ok(reviewBody.findings[0].ruleIds.includes("unapproved-authorizer"));

    // 4. Blocked added contract (blockUnapprovedContracts: true) -> EXIT_BLOCKED (3)
    const ioBlocked = captureIo();
    assert.equal(
      await runPolicyCheck(["--diff", blockedContractPath, "--policy", samplePolicyPath, "--json"], ioBlocked),
      EXIT_BLOCKED
    );
    const blockedBody = JSON.parse(ioBlocked.stdoutText);
    assert.equal(blockedBody.decision, "blocked");
    assert.ok(blockedBody.findings[0].ruleIds.includes("unapproved-contract-function"));

    // 5. Redacted / incomplete path metadata never silently passes -> EXIT_REVIEW (1)
    const ioRedacted = captureIo();
    const redactedCode = await runPolicyCheck(["--diff", redactedPath, "--policy", samplePolicyPath], ioRedacted);
    assert.equal(redactedCode, EXIT_REVIEW);
    assert.match(ioRedacted.stdoutText, /unreadable-change-metadata/);

    // 6. Malformed policy and missing input -> EXIT_INVALID (2)
    assert.equal(
      await runPolicyCheck(["--diff", allowlistedPath, "--policy", badPolicyPath], captureIo()),
      EXIT_INVALID
    );
    assert.equal(
      await runPolicyCheck(["--diff", join(dir, "missing.json"), "--policy", samplePolicyPath], captureIo()),
      EXIT_INVALID
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("subprocess CLI execution produces stable exit codes and stdout/stderr streams", async () => {
  const cliPath = join(process.cwd(), "tools/policy-check/index.mjs");
  const validDiffPath = join(process.cwd(), "schemas/fixtures/valid-comparison-v1.json");

  const { stdout, stderr } = await execFileAsync(process.execPath, [
    cliPath,
    "--diff",
    validDiffPath,
    "--policy",
    samplePolicyPath,
    "--json"
  ]);
  assert.equal(stderr, "");
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.decision, "approved");
});
