import { createHash } from "node:crypto";
import { normalizeClientValue } from "./normalize";

/** A safe diagnostic without response secrets. */
export type Difference = { readonly path: string; readonly reason: string };
/** Explicit fixture origins and scenario clocks used to compare runtime output. */
export type ComparisonContext = {
  readonly leftBaseURL: string;
  readonly rightBaseURL: string;
  readonly leftOAuthURL?: string | undefined;
  readonly rightOAuthURL?: string | undefined;
  readonly leftStartedAt: number;
  readonly rightStartedAt: number;
};

const entityKeys = new Set([
  "id", "accountId", "userId", "sessionId", "organizationId", "memberId", "invitationId",
  "inviterId", "activeOrganizationId", "activeTeamId", "teamId", "impersonatedBy", "referenceId",
]);
const opaqueKeys = new Set(["token", "sessionToken", "state", "challenge", "code_challenge", "device_code", "user_code", "access_token", "refresh_token"]);
const opaqueAliases: Readonly<Record<string, string>> = { "set-ott": "token" };
const urlKeys = new Set(["url", "location", "path", "verification_uri", "verification_uri_complete"]);

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** A bijection preserves identity, repeated references, and token rotation across a run. */
export function compareValues(left: unknown, right: unknown, context: ComparisonContext): Difference[] {
  const differences: Difference[] = [];
  const identities = new Map<string, string>();
  const reverseIdentities = new Map<string, string>();
  const fail = (path: string, reason: string) => { differences.push({ path, reason }); };

  const normalizedLeft=normalizeClientValue(left),normalizedRight=normalizeClientValue(right);

  function sessions(value:unknown,result=new Map<string,number>()):Map<string,number> {
    if (Array.isArray(value)) for (const child of value) sessions(child,result);
    else if (record(value)) {
      if (typeof value.token==="string" && typeof value.expiresAt==="string" && Number.isFinite(Date.parse(value.expiresAt))) result.set(value.token,Date.parse(value.expiresAt));
      for (const child of Object.values(value)) sessions(child,result);
    }
    return result;
  }
  const leftSessions = sessions(normalizedLeft), rightSessions = sessions(normalizedRight);

  function issuedTokens(value: unknown, result = new Set<string>()): Set<string> {
    if (Array.isArray(value)) for (const child of value) issuedTokens(child, result);
    else if (record(value)) for (const [key, child] of Object.entries(value)) {
      if ((key === "token" || key === "set-ott") && typeof child === "string") result.add(child);
      issuedTokens(child, result);
    }
    return result;
  }
  const leftTokens = issuedTokens(normalizedLeft), rightTokens = issuedTokens(normalizedRight);

  function oneTimeIdentifier(value: string, tokens: ReadonlySet<string>): { token: string; mode: "plain" | "hashed" } | undefined {
    const prefix = "one-time-token:";
    if (!value.startsWith(prefix)) return;
    const stored = value.slice(prefix.length);
    for (const token of tokens) {
      if (stored === token) return { token, mode: "plain" };
      if (stored === createHash("sha256").update(token).digest("base64url")) return { token, mode: "hashed" };
    }
  }

  function identity(a: string, b: string, path: string, namespace: string) {
    if (!a.trim() || !b.trim()) { fail(path, "empty identity or token"); return; }
    const source = `${namespace}:${a}`;
    const target = `${namespace}:${b}`;
    if ((identities.has(source) && identities.get(source) !== target)
      || (reverseIdentities.has(target) && reverseIdentities.get(target) !== source)) {
      fail(path, "identity relationship or token rotation differs");
    } else {
      identities.set(source, target);
      reverseIdentities.set(target, source);
    }
  }

  function urlParts(value: string, base: string, oauthBase?: string): Record<string, unknown> | undefined {
    try {
      const url = new URL(value, base);
      const own = new URL(base);
      // Only these two explicitly configured loopback addresses name the test server.
      const isOwn = url.protocol === own.protocol && url.port === own.port && [own.hostname, "127.0.0.1"].includes(url.hostname);
      const resetToken = url.pathname.match(/^(.*\/reset-password\/)([^/]+)$/);
      const pathname = resetToken ? resetToken[1] : url.pathname;
      return {
        origin: oauthBase && url.origin === new URL(oauthBase).origin && url.pathname.startsWith("/oauth/") ? "<oauth-server>" : isOwn ? "<server>" : url.origin,
        pathname,
        ...(resetToken ? { token: decodeURIComponent(resetToken[2] ?? "") } : {}),
        hash: url.hash,
        query: Object.fromEntries([...new Set(url.searchParams.keys())].sort().map(key => [key, url.searchParams.getAll(key)])),
      };
    } catch { return undefined; }
  }

  function visit(a: unknown, b: unknown, path: string, key: string) {
    if (typeof a === "string" && typeof b === "string" && !path.includes("BodyShape")) {
      if (entityKeys.has(key) && !path.endsWith(".rp.id")) { identity(a, b, path, "entity"); return; }
      if (key === "identifier" && (a.startsWith("one-time-token:") || b.startsWith("one-time-token:"))) {
        const leftIdentifier = oneTimeIdentifier(a, leftTokens), rightIdentifier = oneTimeIdentifier(b, rightTokens);
        if (leftIdentifier || rightIdentifier) {
          if (!leftIdentifier || !rightIdentifier || leftIdentifier.mode !== rightIdentifier.mode) fail(path, "one-time-token storage derivation differs");
          else identity(leftIdentifier.token, rightIdentifier.token, path, "token");
          return;
        }
      }
      const opaqueKey = opaqueAliases[key] ?? key;
      if (opaqueKeys.has(opaqueKey)) { identity(a, b, path, opaqueKey); return; }
      if (key.endsWith("At") || key === "lastRequest" || key === "banExpires") {
        const at = Date.parse(a), bt = Date.parse(b);
        if (!/^\d{4}-\d\d-\d\dT/.test(a) || !/^\d{4}-\d\d-\d\dT/.test(b) || !Number.isFinite(at) || !Number.isFinite(bt)) {
          fail(path, "invalid timestamp");
        } else if (at !== bt && Math.abs((at - context.leftStartedAt) - (bt - context.rightStartedAt)) > 1500) {
          fail(path, `timestamp or lifetime differs: ${a} vs ${b}`);
        }
        return;
      }
      if (urlKeys.has(key) || key.endsWith("URL") || key.endsWith("Url") || key === "redirect_uri") {
        const ap = urlParts(a, context.leftBaseURL, context.leftOAuthURL), bp = urlParts(b, context.rightBaseURL, context.rightOAuthURL);
        if (!ap || !bp) { fail(path, "invalid URL"); return; }
        visit(ap, bp, path, ""); return;
      }
    }
    if (Array.isArray(a) && Array.isArray(b)) {
      if (a.length !== b.length) fail(path, "array length differs");
      a.forEach((child, index) => visit(child, b[index], `${path ? `${path}.` : ""}${index}`, key));
      return;
    }
    if (record(a) && record(b)) {
      const oneTimeRow = typeof a.identifier === "string" && typeof b.identifier === "string"
        && a.identifier.startsWith("one-time-token:") && b.identifier.startsWith("one-time-token:")
        && ["id", "expiresAt", "createdAt", "updatedAt"].every(field => Object.hasOwn(a, field) && Object.hasOwn(b, field));
      for (const childKey of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) {
        const childPath = path ? `${path}.${childKey}` : childKey;
        if (!Object.hasOwn(a, childKey) || !Object.hasOwn(b, childKey)) fail(childPath, "field presence differs");
        else if (oneTimeRow && childKey === "value" && typeof a.value === "string" && typeof b.value === "string") {
          if (!leftSessions.has(a.value) || !rightSessions.has(b.value)) fail(childPath, "one-time-token value is not an observed persisted session token");
          else identity(a.value, b.value, childPath, "token");
        }
        else visit(a[childKey], b[childKey], childPath, childKey === "accountId" && typeof a.providerId === "string" && a.providerId !== "credential" && !("accessToken" in a) && !("refreshToken" in a) ? "providerAccount" : childKey);
      }
      return;
    }
    if (!Object.is(a, b)) fail(path, "value or type differs");
  }
  visit(normalizedLeft, normalizedRight, "", "");
  return differences;
}
