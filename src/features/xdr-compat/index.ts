import { xdr } from "@stellar/stellar-sdk";

/**
 * Offline XDR compatibility diagnostics, not an authorization or signature verifier.
 * Never returns raw XDR, arguments, signatures, nonces, or ledger metadata.
 */
export const MAX_AUTHORIZATION_XDR_BYTES = 128 * 1024;
const MAX_DEPTH = 24;
const MAX_NODES = 2000;
const CREDENTIAL_TYPES: Readonly<Record<number, string>> = Object.freeze({
  0: "sorobanCredentialsSourceAccount",
  1: "sorobanCredentialsAddress",
  2: "sorobanCredentialsAddressV2",
  3: "sorobanCredentialsAddressWithDelegates"
});
const FUNCTION_TYPES = new Set([
  "sorobanAuthorizedFunctionTypeContractFn",
  "sorobanAuthorizedFunctionTypeCreateContractHostFn",
  "sorobanAuthorizedFunctionTypeCreateContractV2HostFn"
]);

export type XdrCompatibilityResult =
  | {
      status: "supported";
      reviewRequired: false;
      credential: string;
      invocationKinds: string[];
      invocationCount: number;
      maximumDepth: number;
      byteLength: number;
    }
  | {
      status: "unsupported";
      reviewRequired: true;
      reason: "unknown-credential-arm" | "unknown-function-arm" | "unsupported-sdk-arm";
    }
  | {
      status: "malformed";
      reviewRequired: true;
      reason: "invalid-base64" | "oversized-entry" | "invalid-xdr" |
        "noncanonical-xdr" | "tree-limit-exceeded";
    };

function malformed(reason: Extract<XdrCompatibilityResult, { status: "malformed" }>["reason"]): XdrCompatibilityResult {
  return { status: "malformed", reviewRequired: true, reason };
}
function unsupported(reason: Extract<XdrCompatibilityResult, { status: "unsupported" }>["reason"]): XdrCompatibilityResult {
  return { status: "unsupported", reviewRequired: true, reason };
}

/**
 * Validate one canonical, bounded SorobanAuthorizationEntry base64 XDR string.
 * Unknown union discriminants return review-required, never supported.
 * Corrupt known variants return malformed. Neither outcome discloses input.
 */
export function checkAuthorizationXdr(base64: unknown): XdrCompatibilityResult {
  if (typeof base64 !== "string" || base64.length === 0) return malformed("invalid-base64");
  if (base64.length > Math.ceil(MAX_AUTHORIZATION_XDR_BYTES / 3) * 4 + 8) {
    return malformed("oversized-entry");
  }
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64)) {
    return malformed("invalid-base64");
  }
  const bytes = Buffer.from(base64, "base64");
  if (bytes.length === 0 || bytes.toString("base64") !== base64) return malformed("invalid-base64");
  if (bytes.length > MAX_AUTHORIZATION_XDR_BYTES) return malformed("oversized-entry");
  if (bytes.length < 8) return malformed("invalid-xdr");

  // These discriminants are pinned to the v17.2.1 SDK's supported Stellar XDR.
  // Inspect only tags: do not attempt to decode or display unknown payloads.
  const credentialTag = bytes.readInt32BE(0);
  if (!Object.hasOwn(CREDENTIAL_TYPES, credentialTag)) return unsupported("unknown-credential-arm");
  // Source-account credentials have a void payload; the root function tag starts at byte 4.
  if (credentialTag === 0 && ![0, 1, 2].includes(bytes.readInt32BE(4))) {
    return unsupported("unknown-function-arm");
  }

  let entry: xdr.SorobanAuthorizationEntry;
  try {
    entry = xdr.SorobanAuthorizationEntry.fromXdr(bytes);
  } catch {
    // For non-source credentials the next discriminant is not at a fixed offset.
    // Unknown future arms can be indistinguishable from corrupt bytes here: fail closed.
    return malformed("invalid-xdr");
  }

  let encoded: Buffer;
  try {
    encoded = Buffer.from(entry.toXdr());
  } catch {
    return malformed("invalid-xdr");
  }
  if (!encoded.equals(bytes)) return malformed("noncanonical-xdr");

  const credential = entry.credentials.type;
  if (!Object.values(CREDENTIAL_TYPES).includes(credential)) {
    return unsupported("unsupported-sdk-arm");
  }

  const kinds = new Set<string>();
  let nodes = 0;
  let maximumDepth = 0;
  let reason: "unsupported" | "limit" | null = null;
  function walk(node: xdr.SorobanAuthorizedInvocation, depth: number): void {
    if (reason !== null) return;
    nodes++;
    if (nodes > MAX_NODES || depth > MAX_DEPTH || node.subInvocations.length > MAX_NODES) {
      reason = "limit";
      return;
    }
    if (!FUNCTION_TYPES.has(node.function.type)) {
      reason = "unsupported";
      return;
    }
    kinds.add(node.function.type);
    maximumDepth = Math.max(maximumDepth, depth);
    for (const child of node.subInvocations) walk(child, depth + 1);
  }
  walk(entry.rootInvocation, 0);
  if (reason === "limit") return malformed("tree-limit-exceeded");
  if (reason === "unsupported") return unsupported("unsupported-sdk-arm");

  return {
    status: "supported",
    reviewRequired: false,
    credential,
    invocationKinds: [...kinds].sort(),
    invocationCount: nodes,
    maximumDepth,
    byteLength: bytes.length
  };
}
