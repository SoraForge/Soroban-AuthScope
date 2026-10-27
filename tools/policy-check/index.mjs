#!/usr/bin/env node
/**
 * Offline CLI wrapper for AuthScope approval-policy evaluation.
 * Exit codes:
 *   0 = approved
 *   1 = review-required ("review")
 *   2 = invalid input, missing file, or malformed policy/comparison
 *   3 = policy-blocked ("blocked")
 */
import { evaluateScopePolicy } from "../../dist/features/scope-policy/index.js";
import { readBoundedJson, validateReport } from "../schema-check/index.mjs";
import { pathToFileURL } from "node:url";

export const EXIT_APPROVED = 0;
export const EXIT_REVIEW = 1;
export const EXIT_INVALID = 2;
export const EXIT_BLOCKED = 3;

function sanitizeText(value) {
  return String(value ?? "").replace(/[\x00-\x1f\x7f-\x9f]/g, " ").trim();
}

export function formatPolicyText(result) {
  const lines = [
    `Decision: ${sanitizeText(result.decision)}`,
    `Summary: ${sanitizeText(result.summary)}`
  ];
  for (const finding of result.findings) {
    lines.push(
      `- [${sanitizeText(finding.decision)}] ${sanitizeText(finding.id)}: ${sanitizeText(finding.message)}`
    );
  }
  return `${lines.join("\n")}\n`;
}

export function decisionToExitCode(decision) {
  if (decision === "approved") return EXIT_APPROVED;
  if (decision === "review") return EXIT_REVIEW;
  if (decision === "blocked") return EXIT_BLOCKED;
  return EXIT_INVALID;
}

function isSafeInputPath(filepath) {
  if (typeof filepath !== "string" || !filepath.length || filepath.length > 1024) return false;
  if (filepath.includes("\0")) return false;
  return true;
}

export async function main(args, io = { stdout: process.stdout, stderr: process.stderr }) {
  if (args.length === 1 && ["--help", "-h"].includes(args[0])) {
    io.stdout.write(
      "Usage: node tools/policy-check/index.mjs --diff <comparison.json> --policy <rules.json> [--json]\n"
    );
    return EXIT_APPROVED;
  }

  let diffPath = null;
  let policyPath = null;
  let jsonMode = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--diff") {
      if (i + 1 >= args.length || diffPath !== null) {
        io.stderr.write("Usage: policy-check --diff <comparison.json> --policy <rules.json> [--json]\n");
        return EXIT_INVALID;
      }
      diffPath = args[++i];
    } else if (arg === "--policy") {
      if (i + 1 >= args.length || policyPath !== null) {
        io.stderr.write("Usage: policy-check --diff <comparison.json> --policy <rules.json> [--json]\n");
        return EXIT_INVALID;
      }
      policyPath = args[++i];
    } else if (arg === "--json") {
      jsonMode = true;
    } else {
      io.stderr.write("Usage: policy-check --diff <comparison.json> --policy <rules.json> [--json]\n");
      return EXIT_INVALID;
    }
  }

  if (!isSafeInputPath(diffPath) || !isSafeInputPath(policyPath)) {
    io.stderr.write("Usage: policy-check --diff <comparison.json> --policy <rules.json> [--json]\n");
    return EXIT_INVALID;
  }

  try {
    const comparison = await readBoundedJson(diffPath);
    const reportCheck = validateReport(comparison, { type: "comparison" });
    if (!reportCheck.valid) {
      io.stderr.write("Invalid Comparison v1 report structure.\n");
      return EXIT_INVALID;
    }
    const policy = await readBoundedJson(policyPath);
    const result = evaluateScopePolicy(comparison, policy);
    if (jsonMode) {
      io.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      io.stdout.write(formatPolicyText(result));
    }
    return decisionToExitCode(result.decision);
  } catch {
    io.stderr.write("Invalid comparison report, malformed policy definition, or unreadable file.\n");
    return EXIT_INVALID;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
