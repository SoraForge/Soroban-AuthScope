#!/usr/bin/env node
/**
 * Offline converter from AuthScope v1 Comparison JSON to conservative SARIF 2.1.0.
 * Never fabricates source lines, never emits "error" level, and never claims exploitability.
 */
import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { readBoundedJson, validateReport } from "../schema-check/index.mjs";

export const SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json";
export const SARIF_VERSION = "2.1.0";
export const RULE_ADDED_ID = "AUTHSCOPE001";
export const RULE_REMOVED_ID = "AUTHSCOPE002";

const SARIF_RULES = Object.freeze([
  {
    id: RULE_ADDED_ID,
    name: "AuthorizationScopeAdded",
    shortDescription: {
      text: "Additional Soroban authorization scope detected between simulations."
    },
    fullDescription: {
      text: "An authorizer or contract sub-invocation was added compared to the baseline simulation. Scope additions require human review and do not prove a vulnerability."
    },
    defaultConfiguration: {
      level: "warning"
    },
    properties: {
      tags: ["soroban", "authorization-scope", "review-required"]
    }
  },
  {
    id: RULE_REMOVED_ID,
    name: "AuthorizationScopeRemoved",
    shortDescription: {
      text: "Previously present Soroban authorization scope was removed."
    },
    fullDescription: {
      text: "An authorizer or contract invocation present in the baseline simulation is absent in the target simulation. Scope removals require human review and do not establish safety or vulnerability."
    },
    defaultConfiguration: {
      level: "note"
    },
    properties: {
      tags: ["soroban", "authorization-scope", "review-required"]
    }
  }
]);

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

/**
 * Sanitizes untrusted strings for safe inclusion in SARIF text fields without control characters or HTML.
 */
export function sanitizeSarifText(value, maxLength = 256) {
  if (typeof value !== "string") return "[unknown]";
  const cleaned = value
    .replace(/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/g, " ")
    .replace(/[<>&"`]/g, ch => {
      switch (ch) {
        case "<": return "&lt;";
        case ">": return "&gt;";
        case "&": return "&amp;";
        case "\"": return "&quot;";
        default: return "&#96;";
      }
    })
    .trim();
  if (!cleaned.length) return "[empty]";
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength)}…` : cleaned;
}

/**
 * Validates an optional caller-supplied contract-to-relative-repo-path mapping.
 * Rejects absolute paths, parent traversal (..), URLs, backslashes, or query/fragment line syntax.
 */
export function validateSourceMap(input) {
  if (input === undefined) return new Map();
  if (!isPlainObject(input)) {
    throw new TypeError("sourceMap must be a plain object mapping contract IDs to relative paths");
  }
  const entries = Object.entries(input);
  if (entries.length > 256) {
    throw new TypeError("sourceMap exceeds maximum of 256 entries");
  }
  const map = new Map();
  for (const [contract, relPath] of entries) {
    if (typeof contract !== "string" || !/^C[A-Z2-7]{55}$/.test(contract)) {
      throw new TypeError("Invalid contract ID key in sourceMap");
    }
    if (
      typeof relPath !== "string" ||
      relPath.length < 1 ||
      relPath.length > 240 ||
      relPath.startsWith("/") ||
      relPath.startsWith(".") ||
      relPath.includes("..") ||
      relPath.includes("\\") ||
      relPath.includes(":") ||
      relPath.includes("#") ||
      relPath.includes("?") ||
      !/^[A-Za-z0-9._/-]+$/.test(relPath)
    ) {
      throw new TypeError("Invalid repository-relative path in sourceMap");
    }
    map.set(contract, relPath);
  }
  return map;
}

function parseIdentityTuple(rawAuthorizer) {
  try {
    const parsed = JSON.parse(rawAuthorizer);
    if (!Array.isArray(parsed) || parsed.length !== 3 ||
        typeof parsed[0] !== "string" || typeof parsed[1] !== "string" || !Array.isArray(parsed[2])) {
      return null;
    }
    const delegates = [];
    let visited = 0;
    function collect(node, depth) {
      if (++visited > 2000 || depth > 24) return false;
      if (typeof node === "string") {
        delegates.push(sanitizeSarifText(node, 128));
        return true;
      }
      if (!Array.isArray(node) || node.length !== 2 || typeof node[0] !== "string" || !Array.isArray(node[1])) {
        return false;
      }
      delegates.push(sanitizeSarifText(node[0], 128));
      return node[1].every(child => collect(child, depth + 1));
    }
    if (!parsed[2].every(item => collect(item, 0))) return null;
    return {
      credential: sanitizeSarifText(parsed[0], 64),
      authorizer: sanitizeSarifText(parsed[1], 128),
      delegates
    };
  } catch {
    return null;
  }
}

function parseSteps(rawPath) {
  if (typeof rawPath !== "string" || !rawPath.length || rawPath.length > 32768) return null;
  const steps = [];
  let offset = 0;
  try {
    while (offset < rawPath.length && steps.length <= 24) {
      if (rawPath[offset] !== "[") return null;
      let quoted = false, escaped = false, depth = 0, end = -1;
      for (let i = offset; i < rawPath.length; i++) {
        const ch = rawPath[i];
        if (quoted) {
          if (escaped) escaped = false;
          else if (ch === "\\") escaped = true;
          else if (ch === "\"") quoted = false;
        } else if (ch === "\"") quoted = true;
        else if (ch === "[") depth++;
        else if (ch === "]" && --depth === 0) { end = i + 1; break; }
      }
      if (end < 0) return null;
      const tuple = JSON.parse(rawPath.slice(offset, end));
      if (!Array.isArray(tuple) || tuple.length !== 4 || !tuple.every(x => typeof x === "string")) return null;
      steps.push({
        kind: sanitizeSarifText(tuple[0], 32),
        contract: sanitizeSarifText(tuple[1], 128),
        rawContract: tuple[1],
        method: sanitizeSarifText(tuple[2], 64),
        argumentsSha256: /^[a-f0-9]{64}$/.test(tuple[3]) ? tuple[3] : sanitizeSarifText(tuple[3], 64)
      });
      offset = end;
      if (offset < rawPath.length) {
        if (rawPath.slice(offset, offset + 3) !== " > ") return null;
        offset += 3;
      }
    }
    return offset === rawPath.length && steps.length > 0 && steps.length <= 25 ? steps : null;
  } catch {
    return null;
  }
}

/**
 * Converts a validated v1 Comparison object into a SARIF 2.1.0 log object.
 */
export function comparisonToSarif(comparison, options = {}) {
  const validation = validateReport(comparison, { type: "comparison" });
  if (!validation.valid) {
    throw new TypeError(`Invalid Comparison v1 report: ${validation.errors.join("; ")}`);
  }
  const sourceMap = validateSourceMap(options.sourceMap);
  const sortedChanges = [...comparison.changes].sort((a, b) =>
    JSON.stringify(a).localeCompare(JSON.stringify(b))
  );

  const results = sortedChanges.map((delta, index) => {
    const isAdded = delta.kind === "added";
    const ruleId = isAdded ? RULE_ADDED_ID : RULE_REMOVED_ID;
    const ruleIndex = isAdded ? 0 : 1;
    const level = isAdded ? "warning" : "note";

    const identity = parseIdentityTuple(delta.authorizer);
    const steps = parseSteps(delta.path);
    const depth = steps ? steps.length : 0;
    const isNested = depth > 1;
    const rootStep = steps ? steps[0] : null;
    const leafStep = steps ? steps[steps.length - 1] : null;

    const callChainText = steps
      ? steps.map(s => `${s.contract}.${s.method}`).join(" -> ")
      : "[unparsed-invocation-path]";
    const authorizerText = identity
      ? `${identity.authorizer} (${identity.credential})`
      : "[unparsed-authorizer]";
    const scopeKindText = isNested ? "nested sub-invocation" : "root authorization";

    const messageText = `${isAdded ? "Added" : "Removed"} ${scopeKindText} (count: ${delta.count}) on ${callChainText} under authorizer ${authorizerText}. Review required; authorization scope changes do not prove a security vulnerability.`;

    const locations = [];
    if (leafStep && sourceMap.has(leafStep.rawContract)) {
      locations.push({
        physicalLocation: {
          artifactLocation: {
            uri: sourceMap.get(leafStep.rawContract),
            uriBaseId: "%SRCROOT%"
          }
        }
      });
    }

    const fingerprint = createHash("sha256")
      .update(JSON.stringify([delta.kind, delta.authorizer, delta.path, delta.count, index]))
      .digest("hex");

    return {
      ruleId,
      ruleIndex,
      level,
      message: {
        text: messageText
      },
      locations,
      partialFingerprints: {
        authScopeDeltaSha256: fingerprint
      },
      properties: {
        assessment: "review-required",
        changeKind: delta.kind,
        scopeLevel: isNested ? "nested" : "root",
        isNested,
        invocationDepth: depth,
        count: delta.count,
        credential: identity ? identity.credential : "unknown",
        authorizer: identity ? identity.authorizer : "unknown",
        delegates: identity ? identity.delegates.slice(0, 32) : [],
        rootContract: rootStep ? rootStep.contract : "unknown",
        rootMethod: rootStep ? rootStep.method : "unknown",
        leafContract: leafStep ? leafStep.contract : "unknown",
        leafMethod: leafStep ? leafStep.method : "unknown",
        argumentsSha256: leafStep ? leafStep.argumentsSha256 : "unknown"
      }
    };
  });

  return {
    $schema: SARIF_SCHEMA_URI,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: "Soroban AuthScope",
            version: "0.1.0",
            informationUri: "https://github.com/SoraForge/Soroban-AuthScope",
            rules: SARIF_RULES
          }
        },
        invocations: [
          {
            executionSuccessful: true,
            properties: {
              schemaVersion: 1,
              status: comparison.changed ? "changed" : "unchanged",
              beforeCount: comparison.beforeCount,
              afterCount: comparison.afterCount,
              deltaCount: comparison.changes.length,
              disclaimer: "Authorization scope differences indicate review items, not validated vulnerabilities."
            }
          }
        ],
        results
      }
    ]
  };
}

/**
 * Structural validator checking required SARIF 2.1.0 fields and AuthScope conservative invariants.
 */
export function validateSarifLog(sarif) {
  const errors = [];
  if (!isPlainObject(sarif)) return { valid: false, errors: ["SARIF root must be an object"] };
  if (sarif.version !== "2.1.0") errors.push("version must be '2.1.0'");
  if (typeof sarif.$schema !== "string" || !sarif.$schema.includes("sarif-2.1.0")) {
    errors.push("$schema must reference SARIF 2.1.0");
  }
  if (!Array.isArray(sarif.runs) || sarif.runs.length !== 1) {
    errors.push("runs must be a single-element array");
    return { valid: false, errors };
  }
  const run = sarif.runs[0];
  if (!isPlainObject(run?.tool?.driver) || typeof run.tool.driver.name !== "string") {
    errors.push("runs[0].tool.driver.name is required");
  }
  if (!Array.isArray(run?.tool?.driver?.rules) || run.tool.driver.rules.length !== 2) {
    errors.push("runs[0].tool.driver.rules must contain AUTHSCOPE001 and AUTHSCOPE002");
  }
  if (!Array.isArray(run?.results)) {
    errors.push("runs[0].results must be an array");
    return { valid: false, errors };
  }
  for (let i = 0; i < run.results.length; i++) {
    const res = run.results[i];
    if (![RULE_ADDED_ID, RULE_REMOVED_ID].includes(res?.ruleId)) {
      errors.push(`results[${i}].ruleId is invalid`);
    }
    if (!["warning", "note"].includes(res?.level)) {
      errors.push(`results[${i}].level must be 'warning' or 'note' (never 'error')`);
    }
    if (typeof res?.message?.text !== "string" || !res.message.text.length) {
      errors.push(`results[${i}].message.text is required`);
    }
    if (!Array.isArray(res?.locations)) {
      errors.push(`results[${i}].locations must be an array`);
    } else {
      for (const loc of res.locations) {
        if (loc?.physicalLocation?.region !== undefined) {
          errors.push(`results[${i}] must not fabricate line regions`);
        }
      }
    }
  }
  return { valid: errors.length === 0, errors };
}

async function writeExclusiveFile(filepath, content) {
  const handle = await open(filepath, "wx", 0o600);
  try {
    await handle.writeFile(content, "utf-8");
  } finally {
    await handle.close();
  }
}

export async function main(args) {
  if (args.length === 1 && ["--help", "-h"].includes(args[0])) {
    console.log(
      "Usage: node tools/sarif-export/index.mjs <comparison.json> [--source-map <map.json>] [--output <out.sarif>]"
    );
    return 0;
  }

  let inputPath = null;
  let sourceMapPath = null;
  let outputPath = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--source-map") {
      if (i + 1 >= args.length || sourceMapPath !== null) {
        console.error("Invalid --source-map argument");
        return 2;
      }
      sourceMapPath = args[++i];
    } else if (arg === "--output") {
      if (i + 1 >= args.length || outputPath !== null) {
        console.error("Invalid --output argument");
        return 2;
      }
      outputPath = args[++i];
    } else if (!arg.startsWith("-") && inputPath === null) {
      inputPath = arg;
    } else {
      console.error("Usage: sarif-export <comparison.json> [--source-map <map.json>] [--output <out.sarif>]");
      return 2;
    }
  }

  if (!inputPath) {
    console.error("Usage: sarif-export <comparison.json> [--source-map <map.json>] [--output <out.sarif>]");
    return 2;
  }

  try {
    const comparison = await readBoundedJson(inputPath);
    const sourceMap = sourceMapPath ? await readBoundedJson(sourceMapPath) : undefined;
    const sarif = comparisonToSarif(comparison, { sourceMap });
    const serialized = `${JSON.stringify(sarif, null, 2)}\n`;
    if (outputPath) {
      await writeExclusiveFile(outputPath, serialized);
    } else {
      process.stdout.write(serialized);
    }
    return comparison.changed ? 1 : 0;
  } catch {
    console.error("Invalid comparison input, invalid source map, or output file already exists.");
    return 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
