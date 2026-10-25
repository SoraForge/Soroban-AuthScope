#!/usr/bin/env node
import { runPackageSmoke, auditCliShebang } from "./index.mjs";
import { readFileSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";

const rootDir = resolve(process.cwd());
console.log("=== AuthScope Distribution Smoke Harness ===");

try {
  const smokeResults = runPackageSmoke({ rootDir });
  let hasFailures = false;

  console.log("\n[1/3] Package Metadata Audit:");
  if (smokeResults.metadata.valid) {
    console.log("  ✓ package.json metadata complies with distribution requirements (ESM, Node >=22, Apache-2.0, bin)");
  } else {
    console.error("  ✗ Package metadata failures:");
    for (const err of smokeResults.metadata.errors) {
      console.error(`    - ${err}`);
    }
    hasFailures = true;
  }

  console.log("\n[2/3] Package Tarball Manifest Audit:");
  if (smokeResults.manifest.valid) {
    console.log(`  ✓ Checked ${smokeResults.manifest.auditedCount} packaged paths: no forbidden keys, secrets, or capture files found.`);
  } else {
    console.error(`  ✗ Forbidden files discovered in pack manifest:`);
    for (const v of smokeResults.manifest.violations) {
      console.error(`    - ${v.file} matched prohibited pattern ${v.pattern}`);
    }
    hasFailures = true;
  }

  console.log("\n[3/3] CLI Executable Shebang Audit:");
  const cliSource = join(rootDir, "src/cli.ts");
  const cliDist = join(rootDir, "dist/cli.js");
  const targetCli = existsSync(cliDist) ? cliDist : existsSync(cliSource) ? cliSource : null;

  if (targetCli) {
    const shebangCheck = auditCliShebang(readFileSync(targetCli, "utf8"));
    if (shebangCheck.valid) {
      console.log(`  ✓ ${targetCli} begins with correct shebang (${shebangCheck.firstLine})`);
    } else {
      console.error(`  ✗ CLI missing valid shebang: ${shebangCheck.error}`);
      hasFailures = true;
    }
  } else {
    console.log("  ℹ Neither dist/cli.js nor src/cli.ts found to check shebang.");
  }

  if (hasFailures) {
    console.error("\nResult: FAIL. Package smoke harness detected errors.");
    process.exitCode = 1;
  } else {
    console.log("\nResult: PASS. Packaging smoke checks completed successfully.");
    process.exitCode = 0;
  }
} catch (error) {
  console.error("Fatal error running package smoke harness:", error);
  process.exitCode = 2;
}
