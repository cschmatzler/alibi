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
  "inviterId", "activeOrganizationId", "activeTeamId", "teamId", "roleId", "impersonatedBy", "referenceId",
]);
const opaqueKeys = new Set(["token", "sessionToken", "state", "challenge", "code_challenge", "device_code", "user_code", "access_token", "refresh_token"]);
const urlKeys = new Set(["url", "location", "path", "verification_uri", "verification_uri_complete"]);

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function traceShape(path: string): boolean {
  return /^\.?traces\.\d+\.(?:request|response)BodyShape(?:\.|$)/.test(path);
}

/** A bijection preserves identity, repeated references, and token rotation across a run. */
export function compareValues(left: unknown, right: unknown, context: ComparisonContext): Difference[] {
  const differences: Difference[] = [];
  const identities = new Map<string, string>();
  const reverseIdentities = new Map<string, string>();
  const fail = (path: string, reason: string) => { differences.push({ path, reason }); };
  const normalizedLeft = normalizeClientValue(left), normalizedRight = normalizeClientValue(right);

  function apiKeyRow(value: Record<string, unknown>): boolean {
    return typeof value.configId === "string" && typeof value.enabled === "boolean"
      && (value.remaining === null || typeof value.remaining === "number");
  }

  function issuedApiKeys(value: unknown, path = "", result = new Map<string, string>()): Map<string, string> {
    if (Array.isArray(value)) value.forEach((child, index) => issuedApiKeys(child, `${path}.${index}`, result));
    else if (record(value) && !/(?:^|\.)(?:metadata|additionalFields)(?:\.|$)/.test(path) && !traceShape(path)) {
      if (apiKeyRow(value) && typeof value.id === "string" && typeof value.key === "string") {
        const previous = result.get(value.id);
        if (previous !== undefined && previous !== value.key) fail(path, "API key changed for a persisted row");
        result.set(value.id, value.key);
      }
      for (const [key, child] of Object.entries(value)) issuedApiKeys(child, `${path}.${key}`, result);
    }
    return result;
  }
  const leftApiKeys = issuedApiKeys(normalizedLeft), rightApiKeys = issuedApiKeys(normalizedRight);

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

  function visit(a: unknown, b: unknown, path: string, key: string, applicationData = false) {
    if (typeof a === "string" && typeof b === "string" && !traceShape(path) && !applicationData) {
      if (key === "teamId" && (a.includes(",") || b.includes(","))) {
        const leftTeams = a.split(","), rightTeams = b.split(",");
        if (leftTeams.length !== rightTeams.length) fail(path, "team selection length differs");
        leftTeams.forEach((team, index) => {
          const other = rightTeams[index];
          if (other === undefined) return;
          identity(team, other, `${path}.${index}`, "entity");
        });
        return;
      }
      if (entityKeys.has(key) && !path.endsWith(".rp.id")) { identity(a, b, path, "entity"); return; }
      if (opaqueKeys.has(key)) { identity(a, b, path, key); return; }
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
      a.forEach((child, index) => visit(child, b[index], `${path ? `${path}.` : ""}${index}`, key, applicationData));
      return;
    }
    if (record(a) && record(b)) {
      const inApplicationData = applicationData || key === "metadata" || key === "additionalFields";
      const apiKey = !inApplicationData && !traceShape(path) && apiKeyRow(a) && apiKeyRow(b);
      const issuedLeft = typeof a.key === "string" ? a.key : typeof a.id === "string" ? leftApiKeys.get(a.id) : undefined;
      const issuedRight = typeof b.key === "string" ? b.key : typeof b.id === "string" ? rightApiKeys.get(b.id) : undefined;
      for (const childKey of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) {
        const childPath = path ? `${path}.${childKey}` : childKey;
        if (!Object.hasOwn(a, childKey) || !Object.hasOwn(b, childKey)) fail(childPath, "field presence differs");
        else if (apiKey && childKey === "key" && typeof a.key === "string" && typeof b.key === "string") {
          if (a.key.length !== b.key.length) fail(childPath, "API key length differs");
          for (const row of [a, b]) {
            if (typeof row.prefix === "string" && typeof row.key === "string" && !row.key.startsWith(row.prefix)) fail(childPath, "API key prefix relationship differs");
          }
          identity(a.key, b.key, childPath, "api-key");
        }
        else if (apiKey && childKey === "start" && typeof a.start === "string" && typeof b.start === "string" && (issuedLeft !== undefined || issuedRight !== undefined)) {
          if (a.start.length !== b.start.length) fail(childPath, "API key stored-prefix length differs");
          if (issuedLeft === undefined || issuedRight === undefined) fail(childPath, "API key stored-prefix lacks observed issuance");
          else {
            if (!issuedLeft.startsWith(a.start) || !issuedRight.startsWith(b.start)) fail(childPath, "API key stored-prefix relationship differs");
            identity(issuedLeft, issuedRight, childPath, "api-key");
          }
        }
        else visit(a[childKey], b[childKey], childPath, childKey === "accountId" && typeof a.providerId === "string" && a.providerId !== "credential" && !("accessToken" in a) && !("refreshToken" in a) ? "providerAccount" : childKey, inApplicationData);
      }
      return;
    }
    if (!Object.is(a, b)) fail(path, "value or type differs");
  }
  visit(normalizedLeft, normalizedRight, "", "");
  return differences;
}
