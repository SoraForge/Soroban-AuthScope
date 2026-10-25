import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  auditPackageMetadata,
  auditManifest,
  auditCliShebang,
  executeCli,
  FORBIDDEN_PATTERNS
} from "../tools/package-smoke/index.mjs";

test("package.json complies with distribution requirements", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url)));
  const audit = auditPackageMetadata(pkg);

  assert.equal(audit.valid, true, `Expected valid package metadata: ${audit.errors.join(", ")}`);
  assert.equal(pkg.license, "Apache-2.0");
  assert.equal(pkg.type, "module");
  assert.equal(pkg.bin?.authscope, "./dist/cli.js");
  assert.match(pkg.engines?.node, />=22/);
});

test("package metadata audit rejects invalid or missing configurations", () => {
  assert.equal(auditPackageMetadata(null).valid, false);
  assert.equal(auditPackageMetadata({}).valid, false);

  const missingNode22 = auditPackageMetadata({
    name: "test",
    type: "module",
    license: "Apache-2.0",
    bin: { authscope: "./dist/cli.js" },
    engines: { node: ">=18" }
  });
  assert.equal(missingNode22.valid, false);
  assert.ok(missingNode22.errors.some(e => e.includes("engines.node")));

  const nonEsm = auditPackageMetadata({
    name: "test",
    type: "commonjs",
    license: "Apache-2.0",
    bin: { authscope: "./dist/cli.js" },
    engines: { node: ">=22" }
  });
  assert.equal(nonEsm.valid, false);
  assert.ok(nonEsm.errors.some(e => e.includes("module")));

  const wrongLicense = auditPackageMetadata({
    name: "test",
    type: "module",
    license: "MIT",
    bin: { authscope: "./dist/cli.js" },
    engines: { node: ">=22" }
  });
  assert.equal(wrongLicense.valid, false);
  assert.ok(wrongLicense.errors.some(e => e.includes("license")));
});

test("cli source code has executable shebang", () => {
  const cliSource = readFileSync(new URL("../src/cli.ts", import.meta.url), "utf8");
  const shebangAudit = auditCliShebang(cliSource);

  assert.equal(shebangAudit.valid, true);
  assert.equal(shebangAudit.firstLine, "#!/usr/bin/env node");

  const invalidShebang = auditCliShebang("const x = 1;");
  assert.equal(invalidShebang.valid, false);
  assert.ok(invalidShebang.error);
});

test("manifest audit passes clean distribution manifests", () => {
  const cleanFiles = [
    "package.json",
    "README.md",
    "LICENSE",
    "dist/cli.js",
    "dist/core.js",
    "schemas/v1/snapshot.schema.json",
    "schemas/v1/comparison.schema.json"
  ];
  const audit = auditManifest(cleanFiles);
  assert.equal(audit.valid, true);
  assert.equal(audit.violations.length, 0);
  assert.equal(audit.auditedCount, cleanFiles.length);
});

test("manifest audit detects and excludes forbidden sensitive files", () => {
  const dirtyFiles = [
    ".env",
    ".env.local",
    "deploy/keys/server.key",
    "certificates/cert.pem",
    ".npmrc",
    "ssh/id_rsa",
    "tests/fixtures/captured-private.json",
    ".git/config",
    "valid/file.js"
  ];

  const audit = auditManifest(dirtyFiles);
  assert.equal(audit.valid, false);
  assert.equal(audit.violations.length, 8);

  const filenames = audit.violations.map(v => v.file);
  assert.ok(filenames.includes(".env"));
  assert.ok(filenames.includes(".env.local"));
  assert.ok(filenames.includes("deploy/keys/server.key"));
  assert.ok(filenames.includes("certificates/cert.pem"));
  assert.ok(filenames.includes(".npmrc"));
  assert.ok(filenames.includes("ssh/id_rsa"));
  assert.ok(filenames.includes("tests/fixtures/captured-private.json"));
  assert.ok(filenames.includes(".git/config"));
  assert.ok(!filenames.includes("valid/file.js"));
});

test("cli sandbox execution handles exit codes deterministically outside repo root", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "authscope-smoke-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  // Create throwaway test fixture outside repo root
  const validFixture = join(dir, "sim.json");
  writeFileSync(validFixture, JSON.stringify({ auth: [] }));

  const malformedFixture = join(dir, "malformed.json");
  writeFileSync(malformedFixture, "{ invalid json content");

  // Test with node executing CLI script file
  const cliSrc = join(process.cwd(), "src/cli.ts");
  const cliDist = join(process.cwd(), "dist/cli.js");

  // Verify behavior helper with mock/stub CLI runner
  const mockCli = join(dir, "mock-authscope.mjs");
  writeFileSync(
    mockCli,
    `#!/usr/bin/env node
import { readFileSync } from "node:fs";
const args = process.argv.slice(2);
if (args.includes("--help") || args.includes("--version")) {
  console.log("AuthScope CLI");
  process.exit(0);
}
if (args[0] === "inspect") {
  try {
    const data = JSON.parse(readFileSync(args[1], "utf8"));
    if (data.auth) {
      console.log("Authorization entries: 0");
      process.exit(0);
    }
  } catch {
    process.exit(2);
  }
}
if (args[0] === "diff") {
  process.exit(0);
}
process.exit(2);
`
  );

  const helpResult = executeCli(mockCli, ["--help"], { cwd: dir });
  assert.equal(helpResult.status, 0);
  assert.match(helpResult.stdout, /AuthScope CLI/);

  const versionResult = executeCli(mockCli, ["--version"], { cwd: dir });
  assert.equal(versionResult.status, 0);

  const inspectResult = executeCli(mockCli, ["inspect", validFixture], { cwd: dir });
  assert.equal(inspectResult.status, 0);

  const diffResult = executeCli(mockCli, ["diff", validFixture, validFixture], { cwd: dir });
  assert.equal(diffResult.status, 0);

  const malformedResult = executeCli(mockCli, ["inspect", malformedFixture], { cwd: dir });
  assert.equal(malformedResult.status, 2);
});
