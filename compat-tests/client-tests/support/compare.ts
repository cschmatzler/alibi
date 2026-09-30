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
  readonly leftFinishedAt?: number;
  readonly rightFinishedAt?: number;
};

const entityKeys = new Set([
  "id", "accountId", "userId", "sessionId", "organizationId", "memberId", "invitationId",
  "inviterId", "activeOrganizationId", "activeTeamId", "teamId", "impersonatedBy", "referenceId",
]);
const opaqueKeys = new Set(["token", "sessionToken", "state", "challenge", "code_challenge", "device_code", "user_code", "access_token", "refresh_token"]);
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
  function clock(a:number,b:number,path:string) {
    if (a!==b && Math.abs((a-context.leftStartedAt/1000)-(b-context.rightStartedAt/1000))>1.5) fail(path,"JWT timestamp differs");
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

  function visit(a: unknown, b: unknown, path: string, key: string, jwtPayload = false) {
    if (typeof a === "string" && typeof b === "string" && !path.includes("BodyShape")) {
      const leftJwt=jwt(a),rightJwt=jwt(b);
      if (leftJwt || rightJwt) {
        if (!leftJwt || !rightJwt) {fail(path,"JWT structure differs");return;}
        identity(a,b,path,"jwt");
        visit(leftJwt.header,rightJwt.header,`${path}.header`,"");
        visit(leftJwt.payload,rightJwt.payload,`${path}.payload`,"",true);
        if (leftJwt.signature.length!==rightJwt.signature.length) fail(path,"JWT signature length differs");
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
      a.forEach((child, index) => visit(child, b[index], `${path ? `${path}.` : ""}${index}`, key));
      return;
    }
    if (record(a) && record(b)) {
      const jwk=typeof a.kty==="string" && typeof b.kty==="string" && ["EC","OKP","RSA"].includes(a.kty) && ["EC","OKP","RSA"].includes(b.kty);
      const jwtClaims=typeof a.exp==="number" && typeof b.exp==="number" && (jwtPayload || ("iss" in a && "iss" in b && "aud" in a && "aud" in b));
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
        else if (childKey==="kid" && (jwk || (typeof a.alg==="string" && typeof b.alg==="string")) && typeof a.kid==="string" && typeof b.kid==="string") identity(a.kid,b.kid,childPath,"entity");
        else if (childKey==="sub" && jwtClaims && typeof a.sub==="string" && typeof b.sub==="string" && (leftEntities.has(a.sub)||rightEntities.has(b.sub))) identity(a.sub,b.sub,childPath,"entity");
        else if (runtimeDates && ["iat","exp"].includes(childKey) && typeof a[childKey]==="number" && typeof b[childKey]==="number") clock(a[childKey],b[childKey],childPath);
        else if (jwtClaims && ["iss","aud"].includes(childKey)) visit(a[childKey],b[childKey],childPath,childKey==="iss" ? "issuerURL" : "audienceURL");
        else if (jwk && ["x","y","n"].includes(childKey) && typeof a[childKey]==="string" && typeof b[childKey]==="string") {
          const leftMaterial=a[childKey],rightMaterial=b[childKey];
          if (!/^[A-Za-z0-9_-]+$/.test(leftMaterial) || !/^[A-Za-z0-9_-]+$/.test(rightMaterial) || Buffer.from(leftMaterial,"base64url").length!==Buffer.from(rightMaterial,"base64url").length) fail(childPath,"JWK key encoding or size differs");
          identity(leftMaterial,rightMaterial,childPath,`jwk:${childKey}`);
        }
        else if (!/^traces\.\d+\.(?:request|response)BodyShape(?:\.|$)/.test(path) && childKey === "key" && typeof a.key === "string" && typeof b.key === "string" && typeof a.configId === "string" && typeof b.configId === "string" && "enabled" in a && "enabled" in b && "remaining" in a && "remaining" in b) {
          if (a.key.length !== b.key.length) fail(childPath, "API key length differs");
          for (const item of [a,b]) {
            if (typeof item.prefix === "string" && typeof item.key === "string" && !item.key.startsWith(item.prefix)) fail(childPath, "API key prefix relationship differs");
            if (typeof item.start === "string" && typeof item.key === "string" && !item.key.startsWith(item.start)) fail(childPath, "API key stored-prefix relationship differs");
          }
          identity(a.key,b.key,childPath,"api-key");
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
