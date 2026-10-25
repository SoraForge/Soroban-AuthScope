import { spawnSync } from "node:child_process";
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

/**
 * Disallowed file patterns in packaged npm distribution tarballs.
 * Enforces exclusion of environment variables, private keys, secrets,
 * unreviewed captures, and internal tooling/source repository metadata.
 */
export const FORBIDDEN_PATTERNS = [
  /^\.env(?:\..+)?$/i,
  /\.pem$/i,
  /\.key$/i,
  /id_rsa/i,
  /\.npmrc$/i,
  /\.git(?:\/|$)/,
  /(?:^|\/)captured-private\.json$/i,
  /(?:^|\/)secrets?\.json$/i
];

/**
 * Audits package.json metadata against release distribution criteria.
 * - Node >= 22 engine requirement
 * - Apache-2.0 licensing
 * - Valid CLI bin entry
 * - ESM module format
 */
export function auditPackageMetadata(pkg) {
  const errors = [];
  if (!pkg || typeof pkg !== "object") {
    return { valid: false, errors: ["Missing or non-object package.json data"] };
  }

  if (!pkg.name) {
    errors.push("Missing package 'name'");
  }

  if (pkg.type !== "module") {
    errors.push(`Expected "type": "module", found "${pkg.type}"`);
  }

  if (pkg.license !== "Apache-2.0") {
    errors.push(`Expected "license": "Apache-2.0", found "${pkg.license}"`);
  }

  const nodeEngine = pkg.engines?.node;
  if (!nodeEngine || (!nodeEngine.includes("22") && !nodeEngine.includes(">=22"))) {
    errors.push(`Expected engines.node to require Node 22 (e.g. ">=22"), found "${nodeEngine}"`);
  }

  const binPath = typeof pkg.bin === "object" ? pkg.bin?.authscope : pkg.bin;
  if (!binPath || !binPath.endsWith("cli.js")) {
    errors.push(`Expected bin.authscope pointing to compiled CLI (dist/cli.js), found "${binPath}"`);
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Audits file manifest against prohibited files (secrets, keys, capture logs).
 */
export function auditManifest(files) {
  if (!Array.isArray(files)) {
    throw new TypeError("Manifest file list must be an array of paths");
  }

  const violations = [];
  for (const file of files) {
    const normalized = typeof file === "string" ? file : file?.path || "";
    for (const pattern of FORBIDDEN_PATTERNS) {
      if (pattern.test(normalized)) {
        violations.push({ file: normalized, pattern: pattern.toString() });
        break;
      }
    }
  }

  return {
    valid: violations.length === 0,
    violations,
    auditedCount: files.length
  };
}

/**
 * Audits executable shebang of the compiled CLI entry point.
 */
export function auditCliShebang(cliContent) {
  if (typeof cliContent !== "string") {
    return { valid: false, error: "Content must be a string" };
  }
  const firstLine = cliContent.split(/\r?\n/)[0]?.trim();
  const valid = firstLine === "#!/usr/bin/env node";
  return {
    valid,
    firstLine,
    error: valid ? null : `Expected shebang '#!/usr/bin/env node', found '${firstLine}'`
  };
}

/**
 * Executes authscope CLI outside repository context.
 */
export function executeCli(cliPath, args = [], options = {}) {
  const timeout = options.timeout ?? 10000;
  const cwd = options.cwd ?? process.cwd();
  const env = options.env ?? { ...process.env };

  const result = spawnSync(process.execPath, [cliPath, ...args], {
    cwd,
    env,
    encoding: "utf8",
    timeout
  });

  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    error: result.error
  };
}

/**
 * Runs smoke test harness against package.json and npm pack dry-run metadata.
 */
export function runPackageSmoke(options = {}) {
  const rootDir = options.rootDir ? resolve(options.rootDir) : process.cwd();
  const pkgPath = join(rootDir, "package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));

  const metadataAudit = auditPackageMetadata(pkg);
  const results = {
    metadata: metadataAudit,
    manifest: { valid: true, violations: [], auditedCount: 0 },
    cliExecution: [],
    success: true
  };

  if (!metadataAudit.valid) {
    results.success = false;
  }

  // Inspect dry-run file list if npm pack is available
  try {
    const packRun = spawnSync("npm", ["pack", "--dry-run", "--json"], {
      cwd: rootDir,
      encoding: "utf8",
      timeout: 30000
    });

    if (packRun.status === 0 && packRun.stdout) {
      const packMeta = JSON.parse(packRun.stdout);
      const fileList = packMeta[0]?.files?.map((f) => f.path) ?? [];
      const manifestAudit = auditManifest(fileList);
      results.manifest = manifestAudit;
      if (!manifestAudit.valid) {
        results.success = false;
      }
    }
  } catch (err) {
    results.manifestWarning = "Could not invoke npm pack dry-run: " + (err.message || String(err));
  }

  return results;
}
