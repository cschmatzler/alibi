import { sessionSchema, userSchema } from "@better-auth/core/db";
import { safeJSONParse } from "@better-auth/core/utils/json";
import { z } from "zod";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { normalizeClientValue } from "./normalize";

/** A safe diagnostic without response secrets. */
export type Difference = { readonly path: string; readonly reason: string };
/** Explicit fixture origins and scenario clocks used to compare runtime output. */
export type ComparisonContext = {
  readonly compactSessionCacheSecret?: string;
  readonly leftBaseURL: string;
  readonly rightBaseURL: string;
  readonly leftOAuthURL?: string | undefined;
  readonly rightOAuthURL?: string | undefined;
  readonly leftStartedAt: number;
  readonly rightStartedAt: number;
  readonly leftFinishedAt?: number;
  readonly rightFinishedAt?: number;
};

const entityKeys = new Set([
  "id", "accountId", "userId", "sessionId", "organizationId", "memberId", "invitationId",
  "roleId", "inviterId", "activeOrganizationId", "activeTeamId", "teamId", "impersonatedBy", "referenceId",
]);
const opaqueKeys = new Set(["token", "sessionToken", "state", "challenge", "code_challenge", "device_code", "user_code", "access_token", "refresh_token"]);
const opaqueAliases: Readonly<Record<string, string>> = { deviceCode: "device_code", userCode: "user_code", "set-ott": "token" };
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

  function deviceSessions(value: unknown, path = "", result = new Map<string, number>()): Map<string, number> {
    if (Array.isArray(value)) value.forEach((child, index) => deviceSessions(child, `${path}.${index}`, result));
    else if (record(value) && !/(?:^|\.)(?:metadata|additionalFields)(?:\.|$)/.test(path) && !traceShape(path)) {
      if (typeof value.id === "string" && typeof value.userId === "string" && typeof value.token === "string" && typeof value.expiresAt === "string" && Number.isFinite(Date.parse(value.expiresAt))) result.set(value.token, Date.parse(value.expiresAt));
      if (!("exp" in value && "iss" in value && "aud" in value)) for (const [key, child] of Object.entries(value)) deviceSessions(child, `${path}.${key}`, result);
    }
    return result;
  }
  const leftDeviceSessions = deviceSessions(normalizedLeft), rightDeviceSessions = deviceSessions(normalizedRight);


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

  function entityValues(value:unknown,result=new Set<string>()):Set<string> {
    if (Array.isArray(value)) for (const child of value) entityValues(child,result);
    else if (record(value)) for (const [key,child] of Object.entries(value)) {
      if (entityKeys.has(key) && typeof child==="string") result.add(child);
      entityValues(child,result);
    }
    return result;
  }
  const leftEntities=entityValues(normalizedLeft),rightEntities=entityValues(normalizedRight);

  function compactPart(value: string, whitespace: boolean): Buffer | undefined {
    const encoded = whitespace ? value.replace(/[ \t\n\r\f]/g, "") : value;
    if (!/^[A-Za-z0-9_-]+={0,2}$/.test(encoded)) return;
    const unpadded = encoded.replace(/=+$/, "");
    const padding = encoded.length - unpadded.length;
    if (unpadded.length % 4 === 1 || (padding > 0 && (encoded.length % 4 !== 0 || unpadded.length % 4 === 0))) return;
    return Buffer.from(unpadded, "base64url");
  }
  function jwt(value: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signature: Buffer } | undefined {
    const parts = value.split(".");
    if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) return;
    const headerBytes = compactPart(parts[0], false), payloadBytes = compactPart(parts[1], true), signature = compactPart(parts[2], true);
    if (!headerBytes || !payloadBytes || !signature) return;
    try {
      const header: unknown = JSON.parse(headerBytes.toString());
      const payload: unknown = JSON.parse(payloadBytes.toString());
      if (record(header) && typeof header.alg === "string" && record(payload)) return { header, payload, signature };
    } catch { return; }
  }
  // Only fixture observations authenticated by the published decoder use this
  // envelope. Application JSON and unrelated JWT-shaped objects stay literal.
  function encryptedAccountCookie(value: Record<string, unknown>): boolean {
    if (Object.keys(value).sort().join(",") !== "header,payload,token"
      || typeof value.token !== "string" || !record(value.header) || !record(value.payload)) return false;
    const parts = value.token.split(".");
    if (parts.length !== 5 || parts[1] !== "") return false;
    const header = compactPart(parts[0] ?? "", false), iv = compactPart(parts[2] ?? "", false);
    const ciphertext = compactPart(parts[3] ?? "", false), tag = compactPart(parts[4] ?? "", false);
    if (!header || iv?.length !== 16 || !ciphertext?.length || ciphertext.length % 16 !== 0 || tag?.length !== 32) return false;
    try {
      const decoded: unknown = JSON.parse(header.toString());
      return record(decoded) && decoded.alg === "dir" && decoded.enc === "A256CBC-HS512"
        && stableJSON(decoded) === stableJSON(value.header);
    } catch { return false; }
  }
  function stableJSON(value: unknown): string {
    if (Array.isArray(value)) return `[${value.map(stableJSON).join(",")}]`;
    if (record(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableJSON(value[key])}`).join(",")}}`;
    return JSON.stringify(value) ?? "undefined";
  }
  const cachePayloadSchema = z.looseObject({session: sessionSchema.loose(), user: userSchema.loose(), updatedAt: z.number(), version: z.string().optional()});
  function authenticatedCompactCache(value: Record<string, unknown>, start: number, finish: number | undefined): boolean {
    if (!context.compactSessionCacheSecret || Object.keys(value).sort().join(",") !== "decoded,effectiveMaxAgeSeconds,envelope,observedAt,token"
      || typeof value.effectiveMaxAgeSeconds !== "number" || !value.effectiveMaxAgeSeconds
      || typeof value.token !== "string" || !/^[A-Za-z0-9_-]+$/.test(value.token)
      || !record(value.envelope) || Object.keys(value.envelope).sort().join(",") !== "expiresAt,session,signature"
      || typeof value.observedAt !== "number" || !Number.isFinite(value.observedAt)
      || value.observedAt < start || value.observedAt > (finish ?? start)) return false;
    try {
      const bytes = Buffer.from(value.token, "base64url");
      if (bytes.toString("base64url") !== value.token) return false;
      const text = new TextDecoder("utf-8", {fatal:true}).decode(bytes);
      if (JSON.stringify(JSON.parse(text)) !== text || JSON.stringify(value.envelope) !== text) return false;
      const raw = value.envelope;
      if (!record(raw.session) || typeof raw.session.updatedAt !== "number" || !Number.isFinite(raw.session.updatedAt)
        || raw.session.updatedAt > value.observedAt || typeof raw.signature !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(raw.signature)) return false;
      const signature = Buffer.from(raw.signature, "base64url");
      const mac = (payload:Record<string,unknown>,expiresAt:unknown) => createHmac("sha256",context.compactSessionCacheSecret!)
        .update(JSON.stringify({...payload,expiresAt})).digest();
      const expected = mac(raw.session,raw.expiresAt);
      if (signature.toString("base64url") !== raw.signature || signature.length !== expected.length || !timingSafeEqual(signature,expected)) return false;
      const clip = (value:number) => Number.isFinite(value) && Math.abs(value)<=8.64e15 ? Math.trunc(value) : NaN;
      const age = value.effectiveMaxAgeSeconds;
      const earliest = clip(raw.session.updatedAt+age*1000), latest = clip(value.observedAt+age*1000);
      if (Number.isNaN(earliest) || Number.isNaN(latest)) {
        if (raw.expiresAt !== null) return false;
      } else if (typeof raw.expiresAt !== "number" || !Number.isInteger(raw.expiresAt) || raw.expiresAt < earliest || raw.expiresAt > latest) return false;
      // Independent Source decoder contract: Date revival precedes its HMAC
      // and loose payload schema; complete passthrough fields remain observable.
      const revived = safeJSONParse(text);
      if (!record(revived) || !record(revived.session)) return false;
      const parsed = cachePayloadSchema.safeParse(revived.session);
      const valid = typeof revived.expiresAt === "number" && Number.isFinite(revived.expiresAt)
        && timingSafeEqual(signature,mac(revived.session,revived.expiresAt))
        && parsed.success && revived.expiresAt >= value.observedAt
        && parsed.data.session.expiresAt.getTime() >= value.observedAt;
      return valid ? stableJSON(normalizeClientValue(parsed.data)) === stableJSON(value.decoded) : value.decoded === null;
    } catch { return false; }
  }
  function cacheClock(a: number, b: number, path: string) {
    if (a !== b && Math.abs((a-context.leftStartedAt)-(b-context.rightStartedAt)) > 1500) fail(path,"compact cache timestamp differs");
  }
  const leftEncryptedClaims = new Map<string, string>(), rightEncryptedClaims = new Map<string, string>();
  function rememberEncryptedClaims(value: Record<string, unknown>, seen: Map<string, string>, path: string) {
    const token = String(value.token), claims = stableJSON(value.payload), previous = seen.get(token);
    if (previous !== undefined && previous !== claims) fail(path, "the same encrypted cookie has different decoded claims");
    seen.set(token, claims);
  }
  function clock(a:number,b:number,path:string) {
    if (a!==b && Math.abs((a-context.leftStartedAt/1000)-(b-context.rightStartedAt/1000))>1.5) fail(path,"JWT timestamp differs");
  }
  function sessionLifetime(a:Record<string,unknown>,b:Record<string,unknown>,path:string):boolean {
    if (a.token_type!=="Bearer" || b.token_type!=="Bearer" || typeof a.access_token!=="string" || typeof b.access_token!=="string" || typeof a.expires_in!=="number" || typeof b.expires_in!=="number") return false;
    const leftExpiry=leftDeviceSessions.get(a.access_token),rightExpiry=rightDeviceSessions.get(b.access_token);
    if (leftExpiry===undefined || rightExpiry===undefined) return false;
    // The reference floors (absolute persisted expiry - response time) to seconds.
    // Only this proven session relationship gets the one-second floor allowance.
    for (const [ttl,expiry,start,end] of [
      [a.expires_in,leftExpiry,context.leftStartedAt,context.leftFinishedAt],
      [b.expires_in,rightExpiry,context.rightStartedAt,context.rightFinishedAt],
    ]) {
      if (typeof ttl!=="number" || typeof expiry!=="number" || typeof start!=="number" || typeof end!=="number") return false;
      if (!Number.isInteger(ttl) || ttl<Math.floor((expiry-end)/1000) || ttl>Math.floor((expiry-start)/1000)) fail(path,"session TTL disagrees with persisted expiry and execution interval");
    }
    if (Math.abs(a.expires_in-b.expires_in)>1) fail(path,"session TTL differs beyond floor boundary");
    if (Math.abs((leftExpiry-context.leftStartedAt)-(rightExpiry-context.rightStartedAt))>1500) fail(path,"persisted session lifetime differs");
    return true;
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

  function visit(a: unknown, b: unknown, path: string, key: string, jwtPayload = false, applicationData = false, jwtHeader = false, encryptedClaims = false, urlQueryContext: "url" | "query" | undefined = undefined, adminFilterUrl = false, compactCache = false) {
    if (compactCache && typeof a === "number" && typeof b === "number" && /\.compactSessionCache\.(?:envelope\.expiresAt|(?:envelope\.session|decoded)\.updatedAt)$/.test(`.${path}`)) {
      cacheClock(a,b,path); return;
    }
    if (typeof a === "string" && typeof b === "string" && !traceShape(path)
      && !/(?:^|\.)(?:metadata|additionalFields)(?:\.|$)/.test(path)) {
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
      const leftJwt=jwt(a),rightJwt=jwt(b);
      if (leftJwt || rightJwt) {
        if (!leftJwt || !rightJwt) {fail(path,"JWT structure differs");return;}
        identity(a,b,path,"jwt");
        visit(leftJwt.header,rightJwt.header,`${path}.header`,"",false,false,true);
        visit(leftJwt.payload,rightJwt.payload,`${path}.payload`,"",true);
        if (leftJwt.signature.length!==rightJwt.signature.length) fail(path,"JWT signature length differs");
        return;
      }
      if (entityKeys.has(key) && !path.endsWith(".rp.id")) {
        if (urlQueryContext === "query" && !a.trim() && !b.trim()) {
          if (a !== b) fail(path, "literal empty URL selector differs");
        } else identity(a, b, path, "entity");
        return;
      }
      if (key === "identifier" && (a.startsWith("one-time-token:") || b.startsWith("one-time-token:"))) {
        const leftIdentifier = oneTimeIdentifier(a, leftTokens), rightIdentifier = oneTimeIdentifier(b, rightTokens);
        if (leftIdentifier || rightIdentifier) {
          if (!leftIdentifier || !rightIdentifier || leftIdentifier.mode !== rightIdentifier.mode) fail(path, "one-time-token storage derivation differs");
          else identity(leftIdentifier.token, rightIdentifier.token, path, "token");
          return;
        }
      }
      const opaqueKey = (key === "deviceCode" || key === "userCode") && (applicationData || jwtPayload) ? key : opaqueAliases[key] ?? key;
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
        const adminPath = /^\/(?:api\/auth|__test\/profiles\/[^/]+\/api\/auth)\/admin\/list-users$/;
        const observedAdminUrl = ap.origin === "<server>" && bp.origin === "<server>"
          && typeof ap.pathname === "string" && typeof bp.pathname === "string"
          && adminPath.test(ap.pathname) && adminPath.test(bp.pathname);
        visit(ap, bp, path, "", false, false, false, false, "url", observedAdminUrl); return;
      }
    }
    if (Array.isArray(a) && Array.isArray(b)) {
      if (a.length !== b.length) fail(path, "array length differs");
      a.forEach((child, index) => visit(child, b[index], `${path ? `${path}.` : ""}${index}`, key, false, applicationData || jwtPayload, false, false, urlQueryContext, adminFilterUrl, compactCache));
      return;
    }
    if (record(a) && record(b)) {
      if (key === "compactSessionCache") {
        if (applicationData || traceShape(path) || /(?:^|\.)applicationData(?:\.|$)/.test(path)) {
          if (stableJSON(a) !== stableJSON(b)) fail(path,"application compact-cache-shaped data differs literally");
          return;
        }
        if (!authenticatedCompactCache(a,context.leftStartedAt,context.leftFinishedAt)
          || !authenticatedCompactCache(b,context.rightStartedAt,context.rightFinishedAt)) {
          if (stableJSON(a) !== stableJSON(b)) fail(path,"unverified compact cache observation differs literally");
          return;
        }
        const leftEnvelope = a.envelope as Record<string,unknown>, rightEnvelope = b.envelope as Record<string,unknown>;
        const leftPayload = leftEnvelope.session as Record<string,unknown>, rightPayload = rightEnvelope.session as Record<string,unknown>;
        if (!Object.is(a.effectiveMaxAgeSeconds,b.effectiveMaxAgeSeconds)) fail(path,"compact cache effective lifetime differs");
        identity(String(a.token),String(b.token),`${path}.token`,"token");
        cacheClock(Number(a.observedAt),Number(b.observedAt),`${path}.observedAt`);
        visit(leftEnvelope.expiresAt,rightEnvelope.expiresAt,`${path}.envelope.expiresAt`,"expiresAt",false,false,false,false,undefined,false,true);
        visit(leftPayload,rightPayload,`${path}.envelope.session`,"",false,false,false,false,undefined,false,true);
        visit(a.decoded,b.decoded,`${path}.decoded`,"",false,false,false,false,undefined,false,true);
        return;
      }
      if (key === "accountCookie" && !applicationData && !traceShape(path)) {
        if (!encryptedAccountCookie(a) || !encryptedAccountCookie(b)) {
          fail(path, "authenticated encrypted account-cookie envelope differs");
          return;
        }
        rememberEncryptedClaims(a, leftEncryptedClaims, path);
        rememberEncryptedClaims(b, rightEncryptedClaims, path);
        identity(String(a.token), String(b.token), `${path}.token`, "token");
        // The same configured secret gives the same key thumbprint. Protected
        // encryption headers retain their complete literal values and presence.
        if (stableJSON(a.header) !== stableJSON(b.header)) fail(`${path}.header`, "protected encrypted cookie header differs");
        visit(a.payload, b.payload, `${path}.payload`, "", true, false, false, true);
        return;
      }
      const oneTimeRow = typeof a.identifier === "string" && typeof b.identifier === "string"
        && a.identifier.startsWith("one-time-token:") && b.identifier.startsWith("one-time-token:")
        && ["id", "expiresAt", "createdAt", "updatedAt"].every(field => Object.hasOwn(a, field) && Object.hasOwn(b, field));
      const jwtClaims=!applicationData && typeof a.exp==="number" && typeof b.exp==="number" && (jwtPayload || ("iss" in a && "iss" in b && "aud" in a && "aud" in b));
      const inApplicationData=applicationData || jwtPayload || jwtClaims || key === "metadata" || key === "additionalFields";
      const computedLifetime = !inApplicationData && !traceShape(path) && sessionLifetime(a,b,path);
      const apiKey = !inApplicationData && !traceShape(path) && apiKeyRow(a) && apiKeyRow(b);
      const issuedLeft = typeof a.key === "string" ? a.key : typeof a.id === "string" ? leftApiKeys.get(a.id) : undefined;
      const issuedRight = typeof b.key === "string" ? b.key : typeof b.id === "string" ? rightApiKeys.get(b.id) : undefined;
      // User claims retain literal key-shaped content; only public key material carries key entropy.
      const jwk=!inApplicationData && typeof a.kty==="string" && typeof b.kty==="string" && ["EC","OKP","RSA"].includes(a.kty) && ["EC","OKP","RSA"].includes(b.kty);
      const inClock=(date:unknown,start:number,end:number|undefined)=>typeof date==="number" && Number.isInteger(date) && date>=Math.floor(start/1000)-1 && date<=Math.ceil((end ?? start)/1000)+1;
      const runtimeDates=jwtClaims && (
        (inClock(a.iat,context.leftStartedAt,context.leftFinishedAt) && inClock(b.iat,context.rightStartedAt,context.rightFinishedAt))
        // The trusted server API omits iat when signing default expiry claims.
        || (!("iat" in a) && !("iat" in b) && [60,900].some(lifetime=>typeof a.exp==="number" && typeof b.exp==="number" && inClock(a.exp-lifetime,context.leftStartedAt,context.leftFinishedAt) && inClock(b.exp-lifetime,context.rightStartedAt,context.rightFinishedAt)))
      );
      if (jwtClaims && typeof a.exp==="number" && typeof b.exp==="number" && typeof a.iat==="number" && typeof b.iat==="number" && a.exp-a.iat!==b.exp-b.iat) fail(path,"JWT lifetime differs");
      for (const childKey of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) {
        const childPath = path ? `${path}.${childKey}` : childKey;
        if (!Object.hasOwn(a, childKey) || !Object.hasOwn(b, childKey)) fail(childPath, "field presence differs");
        else if (computedLifetime && childKey === "expires_in") continue;
        else if (computedLifetime && childKey === "access_token" && typeof a.access_token === "string" && typeof b.access_token === "string") identity(a.access_token,b.access_token,childPath,"token");
        else if (oneTimeRow && childKey === "value" && typeof a.value === "string" && typeof b.value === "string") {
          if (!leftSessions.has(a.value) || !rightSessions.has(b.value)) fail(childPath, "one-time-token value is not an observed persisted session token");
          else identity(a.value, b.value, childPath, "token");
        }
        else if (childKey==="kid" && !inApplicationData && (jwk || (typeof a.alg==="string" && typeof b.alg==="string")) && typeof a.kid==="string" && typeof b.kid==="string") {
          // A provider may use the literal empty selector in a protected header.
          // Public key IDs and every nonempty selector still use the bijection.
          if (jwtHeader && !jwk && (a.kid === "" || b.kid === "")) visit(a.kid,b.kid,childPath,childKey);
          else identity(a.kid,b.kid,childPath,"entity");
        }
        else if (childKey === "jti" && encryptedClaims) {
          const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
          if (typeof a.jti !== "string" || typeof b.jti !== "string" || !uuid.test(a.jti) || !uuid.test(b.jti)) fail(childPath, "encrypted JWT identifier is not a generated UUID");
          else identity(a.jti, b.jti, childPath, "encrypted-jwt-id");
        }
        else if (childKey==="sub" && jwtClaims && typeof a.sub==="string" && typeof b.sub==="string" && (leftEntities.has(a.sub)||rightEntities.has(b.sub))) identity(a.sub,b.sub,childPath,"entity");
        else if (runtimeDates && ["iat","exp"].includes(childKey) && typeof a[childKey]==="number" && typeof b[childKey]==="number") clock(a[childKey],b[childKey],childPath);
        else if (jwtClaims && ["iss","aud"].includes(childKey)) visit(a[childKey],b[childKey],childPath,childKey==="iss" ? "issuerURL" : "audienceURL");
        else if (jwk && ["x","y","n"].includes(childKey) && typeof a[childKey]==="string" && typeof b[childKey]==="string") {
          const leftMaterial=a[childKey],rightMaterial=b[childKey];
          if (!/^[A-Za-z0-9_-]+$/.test(leftMaterial) || !/^[A-Za-z0-9_-]+$/.test(rightMaterial) || Buffer.from(leftMaterial,"base64url").length!==Buffer.from(rightMaterial,"base64url").length) fail(childPath,"JWK key encoding or size differs");
          identity(leftMaterial,rightMaterial,childPath,`jwk:${childKey}`);
        }
        else if (apiKey && childKey === "key" && typeof a.key === "string" && typeof b.key === "string") {
          if (a.key.length !== b.key.length) fail(childPath, "API key length differs");
          // Application generators own the full key and need not prepend prefix.
          // Retain the relationship observed in the source, including its absence.
          if (typeof a.prefix !== typeof b.prefix || (typeof a.prefix === "string" && typeof b.prefix === "string" && a.key.startsWith(a.prefix) !== b.key.startsWith(b.prefix))) fail(childPath, "API key prefix relationship differs");
          identity(a.key,b.key,childPath,"api-key");
        }
        else if (apiKey && childKey === "start" && typeof a.start === "string" && typeof b.start === "string" && (issuedLeft !== undefined || issuedRight !== undefined)) {
          if (a.start.length !== b.start.length) fail(childPath, "API key stored-prefix length differs");
          if (issuedLeft === undefined || issuedRight === undefined) fail(childPath, "API key stored-prefix lacks observed issuance");
          else {
            if (!issuedLeft.startsWith(a.start) || !issuedRight.startsWith(b.start)) fail(childPath, "API key stored-prefix relationship differs");
            identity(issuedLeft, issuedRight, childPath, "api-key");
          }
        }
        else if (adminFilterUrl && urlQueryContext === "query" && childKey === "filterValue"
          && Array.isArray(a.filterField) && a.filterField.length === 1 && a.filterField[0] === "id"
          && Array.isArray(b.filterField) && b.filterField.length === 1 && b.filterField[0] === "id"
          && Array.isArray(a.filterValue) && a.filterValue.every(value => typeof value === "string" && leftEntities.has(value))
          && Array.isArray(b.filterValue) && b.filterValue.every(value => typeof value === "string" && rightEntities.has(value))) {
          // Only complete independently observed IDs in this real ID selector
          // use the existing graph. Arity, order, duplicates and URL fields stay.
          visit(a.filterValue, b.filterValue, childPath, "id", false, false, false, false, "query");
        }
        else visit(a[childKey], b[childKey], childPath, childKey === "accountId" && typeof a.providerId === "string" && a.providerId !== "credential" && !("accessToken" in a) && !("refreshToken" in a) ? "providerAccount" : childKey, false, inApplicationData, false, false, urlQueryContext === "query" || (urlQueryContext === "url" && childKey === "query") ? "query" : undefined, adminFilterUrl, compactCache);
      }
      return;
    }
    if (!Object.is(a, b)) fail(path, "value or type differs");
  }
  visit(normalizedLeft, normalizedRight, "", "");
  return differences;
}
