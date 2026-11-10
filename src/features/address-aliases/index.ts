import { StrKey } from "@stellar/stellar-sdk";
import type {
  Authorization,
  Comparison,
  DelegateSigner,
  Invocation,
  ScopeDelta,
  Snapshot
} from "../../core.js";
import { parseCallPath } from "../scope-explainer/index.js";

export const MAX_ALIAS_ENTRIES = 256;
export const MAX_ALIAS_LABEL_LENGTH = 64;

export interface AliasManifest {
  schemaVersion: 1;
  aliases: Record<string, string>;
}

export interface AliasedDelegateSigner {
  address: string;
  alias: string | null;
  display: string;
  children: AliasedDelegateSigner[];
}

export interface AliasedInvocation {
  kind: "contract" | "createContract" | "createContractV2";
  contract: string;
  contractAlias: string | null;
  contractDisplay: string;
  method: string;
  argumentsSha256: string;
  children: AliasedInvocation[];
}

export interface AliasedAuthorization {
  credential: string;
  authorizer: string;
  authorizerAlias: string | null;
  authorizerDisplay: string;
  delegates: string[];
  delegateAliases: Array<{ address: string; alias: string | null; display: string }>;
  delegateTree?: AliasedDelegateSigner[];
  root: AliasedInvocation;
}

export interface AliasedSnapshot {
  schemaVersion: 1;
  authorizationCount: number;
  entries: AliasedAuthorization[];
  appliedAliases: Array<{ address: string; alias: string }>;
}

export interface AliasedCallStep {
  kind: string;
  contract: string;
  contractAlias: string | null;
  contractDisplay: string;
  method: string;
  fingerprint: string;
}

export interface AliasedScopeDelta extends ScopeDelta {
  authorizerPrincipal: string | null;
  authorizerAlias: string | null;
  authorizerDisplay: string;
  steps: AliasedCallStep[] | null;
}

export interface AliasedComparison {
  schemaVersion: 1;
  changed: boolean;
  beforeCount: number;
  afterCount: number;
  changes: AliasedScopeDelta[];
  appliedAliases: Array<{ address: string; alias: string }>;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

/**
 * Validates that a string is a canonical Stellar StrKey contract ID (C...) or public authorizer (G.../M...).
 * Rejects secret seeds (S...) and arbitrary strings.
 */
export function isValidAliasTargetAddress(address: unknown): address is string {
  if (typeof address !== "string" || address.trim() !== address) return false;
  return (
    StrKey.isValidContract(address) ||
    StrKey.isValidEd25519PublicKey(address) ||
    StrKey.isValidMed25519PublicKey(address)
  );
}

/**
 * Validates a human-readable alias label:
 * - 1..64 characters, trimmed
 * - No ASCII/Unicode control characters, angle brackets (<, >), backticks, or bidi overrides
 * - Must not itself look like a Stellar StrKey or secret seed to prevent spoofing
 */
export function isValidAliasLabel(label: unknown): label is string {
  if (typeof label !== "string") return false;
  if (label.length < 1 || label.length > MAX_ALIAS_LABEL_LENGTH) return false;
  if (label.trim() !== label) return false;
  if (/[\x00-\x1f\x7f-\x9f<>`\\$\u202a-\u202e\u2066-\u2069]/.test(label)) return false;
  if (/^[CGMS][A-Z2-7]{55}$/.test(label)) return false;
  return true;
}

/**
 * Validates and normalizes a caller-provided alias map or `{ schemaVersion: 1, aliases }` manifest
 * into a deterministic sorted `Map<string, string>`.
 */
export function validateAliases(input: unknown): Map<string, string> {
  if (!isPlainObject(input)) {
    throw new TypeError("Alias mapping must be a plain JSON object");
  }

  let rawMap: Record<string, unknown>;
  if ("schemaVersion" in input || "aliases" in input) {
    const keys = Object.keys(input).sort().join(",");
    if (keys !== "aliases,schemaVersion" || input.schemaVersion !== 1 || !isPlainObject(input.aliases)) {
      throw new TypeError("Invalid alias manifest; expected schemaVersion 1 and aliases object");
    }
    rawMap = input.aliases;
  } else {
    rawMap = input;
  }

  const entries = Object.entries(rawMap);
  if (entries.length > MAX_ALIAS_ENTRIES) {
    throw new TypeError(`Alias mapping exceeds maximum of ${MAX_ALIAS_ENTRIES} entries`);
  }

  const sortedEntries = [...entries].sort(([a], [b]) => a.localeCompare(b));
  const validated = new Map<string, string>();
  const usedLabelsLower = new Set<string>();

  for (const [address, label] of sortedEntries) {
    if (!isValidAliasTargetAddress(address)) {
      throw new TypeError("Invalid Stellar contract or public authorizer StrKey in alias map");
    }
    if (!isValidAliasLabel(label)) {
      throw new TypeError("Invalid alias label; must be 1..64 safe printable characters without HTML or control codes");
    }
    const normalizedLabel = label.toLowerCase();
    if (usedLabelsLower.has(normalizedLabel)) {
      throw new TypeError("Duplicate or conflicting alias label assigned to multiple addresses");
    }
    usedLabelsLower.add(normalizedLabel);
    validated.set(address, label);
  }

  return validated;
}

/**
 * Formats an address alongside its optional local alias without ever replacing the canonical ID.
 */
export function formatAliasedAddress(address: string, aliases: Map<string, string>): string {
  const alias = aliases.get(address);
  return alias ? `${alias} (${address})` : address;
}

function resolveDelegateTree(
  nodes: readonly DelegateSigner[],
  aliases: Map<string, string>,
  used: Set<string>,
  depth = 0,
  counter = { n: 0 }
): AliasedDelegateSigner[] {
  if (depth > 24) throw new Error("Delegate tree exceeds safety limits");
  return nodes.map(node => {
    if (++counter.n > 2000) throw new Error("Delegate tree exceeds safety limits");
    const alias = aliases.get(node.address) ?? null;
    if (alias !== null) used.add(node.address);
    return {
      address: node.address,
      alias,
      display: formatAliasedAddress(node.address, aliases),
      children: resolveDelegateTree(node.children, aliases, used, depth + 1, counter)
    };
  });
}

function resolveInvocation(
  node: Invocation,
  aliases: Map<string, string>,
  used: Set<string>,
  depth = 0,
  counter = { n: 0 }
): AliasedInvocation {
  if (depth > 24 || ++counter.n > 2000) {
    throw new Error("Authorization tree exceeds safety limits");
  }
  const contractAlias = aliases.get(node.contract) ?? null;
  if (contractAlias !== null) used.add(node.contract);
  return {
    kind: node.kind,
    contract: node.contract,
    contractAlias,
    contractDisplay: formatAliasedAddress(node.contract, aliases),
    method: node.method,
    argumentsSha256: node.argumentsSha256,
    children: node.children.map(child => resolveInvocation(child, aliases, used, depth + 1, counter))
  };
}

/**
 * Pure, view-only resolver that annotates a v1 Snapshot with caller-supplied local aliases
 * while preserving all original canonical contract IDs and authorizer addresses.
 */
export function resolveSnapshotAliases(snapshot: Snapshot, aliasInput: unknown): AliasedSnapshot {
  if (!snapshot || typeof snapshot !== "object" || snapshot.schemaVersion !== 1 || !Array.isArray(snapshot.entries)) {
    throw new TypeError("Expected valid Snapshot schemaVersion 1");
  }
  const aliases = aliasInput instanceof Map ? validateAliases(Object.fromEntries(aliasInput)) : validateAliases(aliasInput);
  const used = new Set<string>();

  const entries: AliasedAuthorization[] = snapshot.entries.map(entry => {
    const authorizerAlias = aliases.get(entry.authorizer) ?? null;
    if (authorizerAlias !== null) used.add(entry.authorizer);
    const delegateAliases = entry.delegates.map(addr => {
      const alias = aliases.get(addr) ?? null;
      if (alias !== null) used.add(addr);
      return {
        address: addr,
        alias,
        display: formatAliasedAddress(addr, aliases)
      };
    });
    const resolved: AliasedAuthorization = {
      credential: entry.credential,
      authorizer: entry.authorizer,
      authorizerAlias,
      authorizerDisplay: formatAliasedAddress(entry.authorizer, aliases),
      delegates: [...entry.delegates],
      delegateAliases,
      root: resolveInvocation(entry.root, aliases, used)
    };
    if (entry.delegateTree !== undefined) {
      resolved.delegateTree = resolveDelegateTree(entry.delegateTree, aliases, used);
    }
    return resolved;
  });

  const appliedAliases = [...used]
    .sort((a, b) => a.localeCompare(b))
    .map(address => ({ address, alias: aliases.get(address)! }));

  return {
    schemaVersion: 1,
    authorizationCount: snapshot.authorizationCount,
    entries,
    appliedAliases
  };
}

function parsePrincipalFromIdentityTuple(rawAuthorizer: string): string | null {
  try {
    const parsed: unknown = JSON.parse(rawAuthorizer);
    if (!Array.isArray(parsed) || parsed.length !== 3 || typeof parsed[1] !== "string") {
      return null;
    }
    return parsed[1];
  } catch {
    return null;
  }
}

/**
 * Pure, view-only resolver that annotates a v1 Comparison with caller-supplied local aliases
 * while retaining canonical `authorizer` and `path` strings untouched for verification.
 */
export function resolveComparisonAliases(comparison: Comparison, aliasInput: unknown): AliasedComparison {
  if (!comparison || typeof comparison !== "object" || comparison.schemaVersion !== 1 || !Array.isArray(comparison.changes)) {
    throw new TypeError("Expected valid Comparison schemaVersion 1");
  }
  const aliases = aliasInput instanceof Map ? validateAliases(Object.fromEntries(aliasInput)) : validateAliases(aliasInput);
  const used = new Set<string>();

  const changes: AliasedScopeDelta[] = comparison.changes.map(delta => {
    const principal = parsePrincipalFromIdentityTuple(delta.authorizer);
    const authorizerAlias = principal ? (aliases.get(principal) ?? null) : null;
    if (principal && authorizerAlias !== null) {
      used.add(principal);
    }
    const authorizerDisplay = principal
      ? formatAliasedAddress(principal, aliases)
      : delta.authorizer;

    const rawSteps = parseCallPath(delta.path);
    const steps: AliasedCallStep[] | null = rawSteps
      ? rawSteps.map(step => {
          const contractAlias = aliases.get(step.contract) ?? null;
          if (contractAlias !== null) used.add(step.contract);
          return {
            kind: step.kind,
            contract: step.contract,
            contractAlias,
            contractDisplay: formatAliasedAddress(step.contract, aliases),
            method: step.method,
            fingerprint: step.fingerprint
          };
        })
      : null;

    return {
      kind: delta.kind,
      authorizer: delta.authorizer,
      path: delta.path,
      count: delta.count,
      authorizerPrincipal: principal,
      authorizerAlias,
      authorizerDisplay,
      steps
    };
  });

  const appliedAliases = [...used]
    .sort((a, b) => a.localeCompare(b))
    .map(address => ({ address, alias: aliases.get(address)! }));

  return {
    schemaVersion: 1,
    changed: comparison.changed,
    beforeCount: comparison.beforeCount,
    afterCount: comparison.afterCount,
    changes,
    appliedAliases
  };
}
