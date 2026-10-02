import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sessionSchema, userSchema } from "@better-auth/core/db";
import { safeJSONParse } from "@better-auth/core/utils/json";
import { z } from "zod";
import { Cookie } from "tough-cookie";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { normalizeClientValue } from "./normalize";
import type { RequestWindow } from "./trace";
import { verificationPublicationPairs, samePublication } from "./verification-publication";

/** A safe diagnostic without response secrets. */
export type Difference = { readonly path: string; readonly reason: string };
/** Original complete responses from the existing read-only physical controls. */
export type PhysicalObservation = {
  readonly kind: "session" | "verification";
  readonly owner: string;
  readonly body: unknown;
  readonly digest: string;
};
/** Explicit fixture origins and scenario clocks used to compare runtime output. */
export type ComparisonContext = {
  readonly leftPhysicalObservations?: readonly PhysicalObservation[];
  readonly rightPhysicalObservations?: readonly PhysicalObservation[];
  readonly sessionCookieSecret?: string;
  readonly compactSessionCacheSecret?: string;
  readonly oauthProxyProfileSecret?: string;
  readonly leftBaseURL: string;
  readonly rightBaseURL: string;
  readonly leftOAuthURL?: string | undefined;
  readonly rightOAuthURL?: string | undefined;
  readonly leftStartedAt: number;
  readonly rightStartedAt: number;
  readonly leftFinishedAt?: number;
  readonly rightFinishedAt?: number;
  readonly leftRequestWindows?: readonly (RequestWindow | undefined)[];
  readonly rightRequestWindows?: readonly (RequestWindow | undefined)[];
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
  // Decoded payload copies cannot authorize their own generated identities.
  // Keep independently observed user/session fields available for default JWTs.
  const payloads: Record<string, unknown>[] = [];
  function collectPayloads(value: unknown) {
    if (typeof value === "string") {
      const token = jwt(value);
      if (token) payloads.push(token.payload);
    } else if (Array.isArray(value)) value.forEach(collectPayloads);
    else if (record(value)) Object.values(value).forEach(collectPayloads);
  }
  collectPayloads(normalizedLeft);
  collectPayloads(normalizedRight);
  const claimObject = (value: Record<string, unknown>) =>
    (typeof value.exp === "number" && ("iss" in value || "aud" in value || "sub" in value))
    || payloads.some(payload => samePublication(payload, value));
  const applicationField = (key: string) => ["metadata", "custom", "additionalFields", "applicationData"].includes(key);
  const claimNamespace = (key: string) => entityKeys.has(key) ? "entity"
    : key === "sessionToken" ? "token" : opaqueAliases[key] ?? key;
  const claimEvidence = new Set<string>();
  const claimPair = (key: string, a: string, b: string) => JSON.stringify([claimNamespace(key), a, b]);
  function collectClaimEvidence(a: unknown, b: unknown) {
    if (Array.isArray(a) && Array.isArray(b)) {
      a.forEach((child, index) => collectClaimEvidence(child, b[index]));
    } else if (record(a) && record(b) && !claimObject(a) && !claimObject(b)) {
      for (const [key, value] of Object.entries(a)) {
        if (applicationField(key) || ["requestBodyShape", "responseBodyShape", "accountCookie"].includes(key)) continue;
        const other = b[key];
        if (typeof value === "string" && typeof other === "string") claimEvidence.add(claimPair(key, value, other));
        else collectClaimEvidence(value, other);
      }
    }
  }
  collectClaimEvidence(normalizedLeft, normalizedRight);
  const pairedDates = new Set<string>();
  const invalidLifetimes = new Set<string>();
  const invalidPhysicalDates = new Set<string>();
  const dateKey = (owner: string, field: string, a: string, b: string) => JSON.stringify([owner, field, Date.parse(a), Date.parse(b)]);
  const physicalOwners = new WeakMap<object, WeakMap<object, string>>();
  let nextPhysicalOwner = 0;
  function physicalOwner(a: Record<string, unknown>, b: Record<string, unknown>): string {
    let rights = physicalOwners.get(a);
    if (!rights) { rights = new WeakMap(); physicalOwners.set(a, rights); }
    let owner = rights.get(b);
    if (!owner) { owner = `physical:${nextPhysicalOwner++}`; rights.set(b, owner); }
    return owner;
  }
  const dateOwners = (a: Record<string, unknown>, b: Record<string, unknown>) => [...["id", "token"].flatMap(key => typeof a[key] === "string" && typeof b[key] === "string" ? [JSON.stringify([key, a[key], b[key]])] : []), physicalOwner(a, b)];
  const approvedDate = (owners: readonly string[], field: string, a: string, b: string) => owners.some(owner => pairedDates.has(dateKey(owner, field, a, b)));
  const approveDate = (owners: readonly string[], field: string, a: string, b: string) => { for (const owner of owners) pairedDates.add(dateKey(owner, field, a, b)); };
  const isDate = (value: unknown): value is string => typeof value === "string" && /^\d{4}-\d\d-\d\dT/.test(value) && Number.isFinite(Date.parse(value));
  type ClockReceipt = { left: RequestWindow; right: RequestWindow; leftUser: string; rightUser: string; authPath: string };
  const issuances = new Map<string, ClockReceipt>(), cookieOwners = new Map<string, ClockReceipt>();
  const signedCookieIssuances = new Set<string>();
  const emailOwners = new Map<string, {leftUser: string; rightUser: string}>();
  const challenges = new Map<string, ClockReceipt & {lifetime: number}>();
  const sessionCookieName = /^(?:__Secure-)?better-auth\.session_token$/;
  function signedCookie(value: string): { token: string; error?: never } | { error: string; token?: never } {
    try {
      const decoded = decodeURIComponent(value), separator = decoded.lastIndexOf(".");
      if (separator < 1 || encodeURIComponent(decoded) !== value)
        return { error: "signed session cookie encoding is not canonical" };
      const token = decoded.slice(0, separator), encodedSignature = decoded.slice(separator + 1);
      const signature = Buffer.from(encodedSignature, "base64");
      const expected = createHmac("sha256", context.sessionCookieSecret!).update(token).digest();
      if (signature.toString("base64") !== encodedSignature || signature.length !== expected.length
        || !timingSafeEqual(signature, expected))
        return { error: "signed session cookie signature is invalid" };
      return { token };
    } catch { return { error: "signed session cookie encoding is not canonical" }; }
  }
  function issuedCookie(value: string | undefined, token: string): boolean {
    if (!value) return false;
    const separator = value.indexOf("=");
    if (separator < 1 || !sessionCookieName.test(value.slice(0, separator))) return false;
    return signedCookie(value.slice(separator + 1)).token === token;
  }
  const updates = new Map<string, ClockReceipt[]>();
  const inWindows = (a: number, b: number, left: RequestWindow, right: RequestWindow) => a >= left.startedAt - 5 && a <= left.finishedAt && b >= right.startedAt - 5 && b <= right.finishedAt;
  function collectResponseDates(a: unknown, b: unknown, left: RequestWindow, right: RequestWindow) {
    if (Array.isArray(a) && Array.isArray(b)) { a.forEach((value, index) => collectResponseDates(value, b[index], left, right)); return; }
    if (!record(a) || !record(b) || claimObject(a) || claimObject(b)) return;
    const owners = dateOwners(a, b);
    const issuance = typeof a.token === "string" && typeof b.token === "string" ? issuances.get(JSON.stringify([a.token, b.token])) : undefined;
    const issuedSession = issuance && issuance.leftUser === a.userId && issuance.rightUser === b.userId ? issuance : undefined;
    for (const key of Object.keys(a)) {
      if (["metadata", "custom", "additionalFields", "applicationData"].includes(key)) continue;
      const av = a[key], bv = b[key];
      if (["createdAt", "updatedAt"].includes(key) && isDate(av) && isDate(bv)) {
        const at = Date.parse(av), bt = Date.parse(bv);
        const updateReceipts = key === "updatedAt" && typeof a.id === "string" && typeof b.id === "string" ? updates.get(JSON.stringify([a.id, b.id])) ?? [] : [];
        if (inWindows(at, bt, left, right) || (issuedSession && inWindows(at, bt, issuedSession.left, issuedSession.right)) || updateReceipts.some(receipt => inWindows(at, bt, receipt.left, receipt.right))) approveDate(owners, key, av, bv);
      } else collectResponseDates(av, bv, left, right);
    }
    // A session's expiry remains tied to its observed creation/update clock.
    if (typeof a.token === "string" && typeof b.token === "string" && typeof a.userId === "string" && typeof b.userId === "string" && isDate(a.expiresAt) && isDate(b.expiresAt)) {
      for (const anchor of ["createdAt", "updatedAt"]) {
        const av = a[anchor], bv = b[anchor];
        if (isDate(av) && isDate(bv) && approvedDate(owners, anchor, av, bv)) {
          if (Math.abs((Date.parse(a.expiresAt) - Date.parse(av)) - (Date.parse(b.expiresAt) - Date.parse(bv))) <= 1500) approveDate(owners, "expiresAt", a.expiresAt, b.expiresAt);
          else for (const owner of owners) invalidLifetimes.add(dateKey(owner, "expiresAt", a.expiresAt, b.expiresAt));
        }
      }
    }
  }
  if (record(normalizedLeft) && record(normalizedRight) && Array.isArray(normalizedLeft.traces) && Array.isArray(normalizedRight.traces)) {
    const rightTraces = normalizedRight.traces;
    normalizedLeft.traces.forEach((trace, index) => {
      const other = rightTraces[index], left = context.leftRequestWindows?.[index], right = context.rightRequestWindows?.[index];
      if (!record(trace) || !record(other) || !left || !right || trace.method !== other.method) return;
      if (trace.path === other.path && typeof trace.path === "string" && trace.method === "POST" && trace.responseStatus === 200 && other.responseStatus === 200) {
        const issuancePath = /^(\/(?:api\/auth|__test\/profiles\/[^/]+\/api\/auth))\/sign-(?:in|up)\/email$/.exec(trace.path);
        const a = trace.responseBody, b = other.responseBody;
        if (issuancePath && record(a) && record(b) && typeof a.token === "string" && typeof b.token === "string" && record(a.user) && record(b.user) && typeof a.user.id === "string" && typeof b.user.id === "string") {
          const receipt = { left, right, leftUser: a.user.id, rightUser: b.user.id, authPath: issuancePath[1]! };
          issuances.set(JSON.stringify([a.token, b.token]), receipt);
          if (context.sessionCookieSecret && issuedCookie(left.issuedSessionCookie, a.token)
            && issuedCookie(right.issuedSessionCookie, b.token)) {
            signedCookieIssuances.add(JSON.stringify([a.token, b.token]));
            if (typeof a.user.email === "string" && typeof b.user.email === "string") emailOwners.set(JSON.stringify([receipt.authPath, a.user.email, b.user.email]), {leftUser: a.user.id, rightUser: b.user.id});
            identity(a.token, b.token, `traces.${index}.responseBody.token`, "token");
          }
          const containsToken = (cookie: string | undefined, token: string) => { try { return !!cookie && decodeURIComponent(cookie.slice(cookie.indexOf("=") + 1)).startsWith(`${token}.`); } catch { return false; } };
          if (containsToken(left.issuedSessionCookie, a.token) && containsToken(right.issuedSessionCookie, b.token)) cookieOwners.set(JSON.stringify([left.issuedSessionCookie, right.issuedSessionCookie]), receipt);
        }
        if (issuancePath && record(a) && record(b) && a.twoFactorRedirect === true && b.twoFactorRedirect === true
          && context.sessionCookieSecret && left.issuedTwoFactorCookie && right.issuedTwoFactorCookie) {
          const owner = emailOwners.get(JSON.stringify([issuancePath[1], left.signInEmail, right.signInEmail]));
          const decode = (cookie: string) => /^(?:__Secure-)?better-auth\.two_factor=/.test(cookie) ? signedCookie(cookie.slice(cookie.indexOf("=") + 1)).token : undefined;
          const at = decode(left.issuedTwoFactorCookie), bt = decode(right.issuedTwoFactorCookie);
          const profile = /^\/__test\/profiles\/(two-factor-(?:skip-verification|trust-(?:fractional|zero-challenge|negative-challenge|zero|negative|cleanup-disabled)))\/api\/auth$/.exec(issuancePath[1]!);
          if (owner && at && bt && /^2fa-(?:[a-zA-Z0-9_-]{20}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/.test(at) && /^2fa-(?:[a-zA-Z0-9_-]{20}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/.test(bt) && profile) {
            const lifetime = profile[1]!.endsWith("zero-challenge") ? 0 : profile[1]!.endsWith("negative-challenge") ? -250 : profile[1]!.startsWith("two-factor-trust-") ? 600750 : 600000;
            challenges.set(JSON.stringify([at, bt]), {...owner, left, right, authPath: issuancePath[1]!, lifetime});
            identity(at, bt, `traces.${index}.responseBody.twoFactorRedirect`, "token");
          }
        }
        const owner = left.sessionCookie && right.sessionCookie ? cookieOwners.get(JSON.stringify([left.sessionCookie, right.sessionCookie])) : undefined;
        if (owner && trace.path === `${owner.authPath}/update-user`) {
          const key = JSON.stringify([owner.leftUser, owner.rightUser]);
          updates.set(key, [...updates.get(key) ?? [], { ...owner, left, right }]);
        }
      }
      for (const [key, a] of Object.entries(left.inputDates)) {
        const b = right.inputDates[key];
        if (b && left.inputOwner && right.inputOwner && left.inputOwner.field === right.inputOwner.field && Math.abs((Date.parse(a) - left.startedAt) - (Date.parse(b) - right.startedAt)) <= 1500) approveDate([JSON.stringify([left.inputOwner.field, left.inputOwner.value, right.inputOwner.value])], key.split(".").at(-1)!, a, b);
      }
      collectResponseDates(trace.responseBody, other.responseBody, left, right);
    });
  }

  const tracePairs = record(normalizedLeft) && record(normalizedRight) && Array.isArray(normalizedLeft.traces) && Array.isArray(normalizedRight.traces)
    ? normalizedLeft.traces.flatMap((a, index) => {
      const b = (normalizedRight.traces as unknown[])[index], left = context.leftRequestWindows?.[index], right = context.rightRequestWindows?.[index];
      if (!record(a) || !record(b) || !left || !right || a.method !== b.method || typeof a.path !== "string" || typeof b.path !== "string" || a.path.split("?")[0] !== b.path.split("?")[0]) return [];
      return [{a, b, left, right, path: a.path.split("?")[0]!}];
    }) : [];
  function controlBody(window: RequestWindow, kind: "member-addition" | "social-provider") {
    const observation = window.controlObservation;
    return observation?.kind === kind && record(observation.body)
      && observation.digest === createHash("sha256").update(JSON.stringify(observation.body)).digest("hex") ? observation.body : undefined;
  }
  for (const [index, observer] of tracePairs.entries()) {
    if (observer.a.method !== "GET" || observer.a.responseStatus !== 200 || observer.b.responseStatus !== 200) continue;
    const previous = tracePairs.slice(0, index).reverse();
    if (observer.path === "/__test/organization-member-addition/state") {
      const a = controlBody(observer.left, "member-addition"), b = controlBody(observer.right, "member-addition");
      if (!a || !b || !Array.isArray(a.receipts) || !Array.isArray(b.receipts) || !record(a.snapshot) || !record(b.snapshot)
        || !Array.isArray(a.snapshot.members) || !Array.isArray(b.snapshot.members)) continue;
      const leftMembers = a.snapshot.members, rightMembers = b.snapshot.members;
      a.receipts.forEach((receipt, receiptIndex) => {
        const other = (b.receipts as unknown[])[receiptIndex];
        if (!record(receipt) || !record(other) || receipt.phase !== "after-add" || other.phase !== "after-add" || !record(receipt.member) || !record(other.member)) return;
        const am = receipt.member, bm = other.member;
        const backed = (member: Record<string, unknown>, rows: unknown[], note: Record<string, unknown>) => typeof member.id === "string"
          && record(note.user) && note.user.id === member.userId && record(note.organization) && note.organization.id === member.organizationId
          && rows.some(row => record(row) && ["id", "organizationId", "userId", "role"].every(field => row[field] === member[field]));
        if (!backed(am, leftMembers, receipt) || !backed(bm, rightMembers, other)) return;
        const producer = previous.find(pair => pair.path === "/__test/organization-member-addition/server" && pair.a.method === "POST"
          && pair.left.memberAdditionOwner?.organizationId === am.organizationId && pair.right.memberAdditionOwner?.organizationId === bm.organizationId
          && pair.left.memberAdditionOwner?.userId === am.userId && pair.right.memberAdditionOwner?.userId === bm.userId);
        if (producer && isDate(am.createdAt) && isDate(bm.createdAt) && inWindows(Date.parse(am.createdAt), Date.parse(bm.createdAt), producer.left, producer.right))
          approveDate(dateOwners(am, bm), "createdAt", am.createdAt, bm.createdAt);
      });
    }
    if (observer.path === "/__test/social-provider/state" && context.sessionCookieSecret) {
      const a = controlBody(observer.left, "social-provider"), b = controlBody(observer.right, "social-provider");
      if (!a || !b || !Array.isArray(a.sessions) || !Array.isArray(b.sessions) || !Array.isArray(a.users) || !Array.isArray(b.users) || !Array.isArray(a.accounts) || !Array.isArray(b.accounts)) continue;
      for (const producer of previous) {
        // The local GitLab fixture issues a one-hour provider token and the
        // default seven-day session. Its actual signed redirect owns these rows.
        if (!/^\/__test\/profiles\/social-gitlab-(?:issuer|issuer-slashes)\/api\/auth\/callback\/gitlab$/.test(producer.path)
          || producer.a.method !== "GET" || producer.a.responseStatus !== 302 || producer.b.responseStatus !== 302) continue;
        const token = (window: RequestWindow) => {
          const cookie = window.issuedSessionCookie;
          return cookie && sessionCookieName.test(cookie.slice(0, cookie.indexOf("="))) ? signedCookie(cookie.slice(cookie.indexOf("=") + 1)).token : undefined;
        };
        const at = token(producer.left), bt = token(producer.right);
        if (!at || !bt) continue;
        const session = (body: Record<string, unknown>, token: string) => (body.sessions as unknown[]).find(row => record(row) && row.token === token);
        const am = session(a, at), bm = session(b, bt);
        if (!record(am) || !record(bm) || typeof am.userId !== "string" || typeof bm.userId !== "string") continue;
        const user = (body: Record<string, unknown>, id: string) => (body.users as unknown[]).find(row => record(row) && row.id === id);
        const account = (body: Record<string, unknown>, id: string) => (body.accounts as unknown[]).find(row => record(row) && row.userId === id && row.providerId === "gitlab");
        const au = user(a, am.userId), bu = user(b, bm.userId), aa = account(a, am.userId), ba = account(b, bm.userId);
        if (!record(au) || !record(bu) || !record(aa) || !record(ba)) continue;
        collectResponseDates({session: am, user: au, account: aa}, {session: bm, user: bu, account: ba}, producer.left, producer.right);
        for (const [left, right, field, lifetime] of [[am, bm, "expiresAt", 604800000], [aa, ba, "accessTokenExpiresAt", 3600000]] as const) {
          if (isDate(left[field]) && isDate(right[field]) && inWindows(Date.parse(left[field]) - lifetime, Date.parse(right[field]) - lifetime, producer.left, producer.right))
            approveDate(dateOwners(left, right), field, left[field], right[field]);
        }
      }
    }
  }
  // API-key middleware constructs a new virtual session on every request. Bind
  // signed snapshot dates to the signing request, actual key issuance and a
  // separately returned virtual session with the same owner and lifetime.
  for (const producer of tracePairs) {
    if (producer.a.method !== "GET" || !producer.path.endsWith("/api/auth/token") || producer.a.responseStatus !== 200 || producer.b.responseStatus !== 200) continue;
    const a = record(producer.a.responseBody) && typeof producer.a.responseBody.token === "string" ? jwt(producer.a.responseBody.token)?.payload : undefined;
    const b = record(producer.b.responseBody) && typeof producer.b.responseBody.token === "string" ? jwt(producer.b.responseBody.token)?.payload : undefined;
    if (!a || !b || !record(a.snapshot) || !record(b.snapshot) || !record(a.snapshot.session) || !record(b.snapshot.session)) continue;
    const leftSession = a.snapshot.session, rightSession = b.snapshot.session, base = producer.path.slice(0, -6);
    const sameOwner = (row: Record<string, unknown>, session: Record<string, unknown>) => row.id === session.id && row.token === session.token && row.userId === session.userId;
    const issued = tracePairs.some(pair => pair.path === `${base}/api-key/create` && pair.a.method === "POST" && pair.a.responseStatus === 200 && pair.b.responseStatus === 200
      && record(pair.a.responseBody) && record(pair.b.responseBody)
      && [pair.a.responseBody, pair.b.responseBody].every((key, index) => {
        const session = index === 0 ? leftSession : rightSession;
        return typeof key.id === "string" && typeof key.key === "string" && typeof key.referenceId === "string"
          && key.id === session.id && key.key === session.token && key.referenceId === session.userId && key.expiresAt === null;
      }));
    if (!issued) continue;
    const independent = tracePairs.find(pair => pair.path === `${base}/get-session` && pair.a.method === "GET" && pair.a.responseStatus === 200 && pair.b.responseStatus === 200
      && record(pair.a.responseBody) && record(pair.b.responseBody) && record(pair.a.responseBody.session) && record(pair.b.responseBody.session)
      && sameOwner(pair.a.responseBody.session, leftSession) && sameOwner(pair.b.responseBody.session, rightSession));
    if (!independent) continue;
    const leftObserved = (independent.a.responseBody as {session: Record<string, unknown>}).session, rightObserved = (independent.b.responseBody as {session: Record<string, unknown>}).session;
    if (![leftObserved, rightObserved, leftSession, rightSession].every(row => ["createdAt", "updatedAt", "expiresAt"].every(field => isDate(row[field])))) continue;
    const lifetime = (row: Record<string, unknown>) => Date.parse(String(row.expiresAt)) - Date.parse(String(row.createdAt));
    if (Math.abs(lifetime(leftObserved) - lifetime(rightObserved)) > 5 || !approvedDate(dateOwners(leftObserved, rightObserved), "createdAt", String(leftObserved.createdAt), String(rightObserved.createdAt))) continue;
    const valid = ["createdAt", "updatedAt"].every(field => inWindows(Date.parse(String(leftSession[field])), Date.parse(String(rightSession[field])), producer.left, producer.right))
      && inWindows(Date.parse(String(leftSession.expiresAt)) - lifetime(leftObserved), Date.parse(String(rightSession.expiresAt)) - lifetime(rightObserved), producer.left, producer.right);
    if (valid) for (const field of ["createdAt", "updatedAt", "expiresAt"]) approveDate(dateOwners(leftSession, rightSession), field, String(leftSession[field]), String(rightSession[field]));
  }

  function observedPhysical(value: Record<string, unknown>, observations: readonly PhysicalObservation[] | undefined, kind: PhysicalObservation["kind"]): boolean {
    const raw = {...value};
    if (kind === "verification") {
      if (record(raw.identifier) && Object.keys(raw.identifier).join() === "token") raw.identifier = raw.identifier.token;
      if (record(raw.value) && Object.keys(raw.value).join() === "userId") raw.value = raw.value.userId;
    }
    return !!observations?.some(observation => {
      if (observation.kind !== kind || observation.digest !== createHash("sha256").update(JSON.stringify(observation.body)).digest("hex")) return false;
      if (kind === "verification") return raw.identifier === observation.owner && Array.isArray(observation.body) && observation.body.some(row => samePublication(raw, row));
      return raw.userId === observation.owner && record(observation.body) && record(observation.body.user) && observation.body.user.id === observation.owner
        && Array.isArray(observation.body.sessions) && observation.body.sessions.some(row => samePublication(raw, row));
    });
  }
  function physicalShape(a: Record<string, unknown>, b: Record<string, unknown>) {
    for (const field of ["createdAt", "updatedAt", "expiresAt"]) {
      const av = a[field], bv = b[field];
      if (isDate(av) && isDate(bv) && (new Date(Date.parse(av)).toISOString() !== av || new Date(Date.parse(bv)).toISOString() !== bv)) invalidPhysicalDates.add(dateKey(physicalOwner(a, b), field, av, bv));
    }
  }
  // Physical observer rows need their producer's clock, not the scenario clock.
  // Only a verified issued cookie and its exact token/user pair may supply it.
  function physicalSessions(a: unknown, b: unknown) {
    if (Array.isArray(a) && Array.isArray(b)) { a.forEach((child, i) => physicalSessions(child, b[i])); return; }
    if (!record(a) || !record(b)) return;
    if (typeof a.id === "string" && typeof b.id === "string" && typeof a.token === "string" && typeof b.token === "string"
      && typeof a.userId === "string" && typeof b.userId === "string" && isDate(a.expiresAt) && isDate(b.expiresAt)) {
      const pair = JSON.stringify([a.token, b.token]), receipt = issuances.get(pair);
      const observedLeft = observedPhysical(a, context.leftPhysicalObservations, "session"), observedRight = observedPhysical(b, context.rightPhysicalObservations, "session");
      if (receipt && signedCookieIssuances.has(pair) && (observedLeft || observedRight) && !(observedLeft && observedRight && a.userId === receipt.leftUser && b.userId === receipt.rightUser)) {
        for (const field of ["createdAt", "updatedAt", "expiresAt"]) if (isDate(a[field]) && isDate(b[field])) invalidPhysicalDates.add(dateKey(physicalOwner(a, b), field, a[field], b[field]));
      }
      if (receipt && signedCookieIssuances.has(pair) && a.userId === receipt.leftUser && b.userId === receipt.rightUser
        && observedLeft && observedRight) {
        physicalShape(a, b);
        const owners = [physicalOwner(a, b)];
        for (const field of ["createdAt", "updatedAt"]) {
          const av = a[field], bv = b[field];
          if (isDate(av) && isDate(bv) && inWindows(Date.parse(av), Date.parse(bv), receipt.left, receipt.right)) approveDate(owners, field, av, bv);
        }
        // This fixture uses the real default seven-day session policy. Its
        // narrow observer omits creation dates; subtract the configured lifetime
        // and require the independent issuance windows on both runtimes.
        if (receipt.authPath === "/__test/profiles/org-member-addition/api/auth") {
          if (inWindows(Date.parse(a.expiresAt) - 604800000, Date.parse(b.expiresAt) - 604800000, receipt.left, receipt.right)) approveDate(owners, "expiresAt", a.expiresAt, b.expiresAt);
          else for (const owner of owners) invalidLifetimes.add(dateKey(owner, "expiresAt", a.expiresAt, b.expiresAt));
        } else if (isDate(a.createdAt) && isDate(b.createdAt) && approvedDate(owners, "createdAt", a.createdAt, b.createdAt)) {
          if (Math.abs((Date.parse(a.expiresAt) - Date.parse(a.createdAt)) - (Date.parse(b.expiresAt) - Date.parse(b.createdAt))) <= 5) approveDate(owners, "expiresAt", a.expiresAt, b.expiresAt);
          else for (const owner of owners) invalidLifetimes.add(dateKey(owner, "expiresAt", a.expiresAt, b.expiresAt));
        }
      }
    }
    for (const [key, child] of Object.entries(a)) {
      if (!["metadata", "custom", "additionalFields", "applicationData", "requestBodyShape", "responseBodyShape", "compactSessionCache", "traces"].includes(key)) physicalSessions(child, b[key]);
    }
  }
  physicalSessions(normalizedLeft, normalizedRight);

  // Challenge and counter rows are physical records projected through the
  // existing identity wrappers. The cookie authenticates the identifier; the
  // observed signup and exact sign-in email authenticate its original owner.
  const challengeRows = new Map<string, {a: Record<string, unknown>; b: Record<string, unknown>; receipt: ClockReceipt & {lifetime: number}}>();
  const verificationRows: {a: Record<string, unknown>; b: Record<string, unknown>}[] = [];
  function collectVerificationRows(a: unknown, b: unknown) {
    if (Array.isArray(a) && Array.isArray(b)) { a.forEach((child, i) => collectVerificationRows(child, b[i])); return; }
    if (!record(a) || !record(b)) return;
    if (typeof a.id === "string" && typeof b.id === "string" && record(a.identifier) && record(b.identifier)
      && typeof a.identifier.token === "string" && typeof b.identifier.token === "string") {
      if (observedPhysical(a, context.leftPhysicalObservations, "verification") && observedPhysical(b, context.rightPhysicalObservations, "verification")) verificationRows.push({a, b});
      const receipt = challenges.get(JSON.stringify([a.identifier.token, b.identifier.token]));
      if (receipt && observedPhysical(a, context.leftPhysicalObservations, "verification") && observedPhysical(b, context.rightPhysicalObservations, "verification") && record(a.value) && record(b.value) && a.value.userId === receipt.leftUser && b.value.userId === receipt.rightUser) challengeRows.set(JSON.stringify([a.identifier.token, b.identifier.token]), {a, b, receipt});
    }
    for (const [key, child] of Object.entries(a)) if (!["metadata", "custom", "additionalFields", "applicationData", "requestBodyShape", "responseBodyShape"].includes(key)) collectVerificationRows(child, b[key]);
  }
  collectVerificationRows(normalizedLeft, normalizedRight);
  for (const {a, b} of verificationRows) {
    const at = (a.identifier as {token: string}).token, bt = (b.identifier as {token: string}).token;
    const attempt = at.startsWith("2fa-attempts-") && bt.startsWith("2fa-attempts-");
    const challenge = challengeRows.get(JSON.stringify(attempt ? [at.slice(13), bt.slice(13)] : [at, bt]));
    if (!challenge || (attempt ? a.value !== "0" || b.value !== "0" || a.expiresAt !== challenge.a.expiresAt || b.expiresAt !== challenge.b.expiresAt : a !== challenge.a || b !== challenge.b)) continue;
    physicalShape(a, b);
    const {receipt} = challenge, owners = [physicalOwner(a, b)];
    for (const field of ["createdAt", "updatedAt"]) {
      const av = a[field], bv = b[field];
      if (isDate(av) && isDate(bv) && inWindows(Date.parse(av), Date.parse(bv), receipt.left, receipt.right)) approveDate(owners, field, av, bv);
    }
    if (isDate(a.expiresAt) && isDate(b.expiresAt)) {
      if (inWindows(Date.parse(a.expiresAt) - receipt.lifetime, Date.parse(b.expiresAt) - receipt.lifetime, receipt.left, receipt.right)) approveDate(owners, "expiresAt", a.expiresAt, b.expiresAt);
      else for (const owner of owners) invalidLifetimes.add(dateKey(owner, "expiresAt", a.expiresAt, b.expiresAt));
    }
  }

  const verificationPublications = verificationPublicationPairs(normalizedLeft, normalizedRight,
    context.leftRequestWindows, context.rightRequestWindows, (a, b, leftCookie, rightCookie) => {
      if (!context.sessionCookieSecret || !signedCookieIssuances.has(JSON.stringify([a, b]))) return false;
      return signedCookie(leftCookie.slice(leftCookie.indexOf("=") + 1)).token === a
        && signedCookie(rightCookie.slice(rightCookie.indexOf("=") + 1)).token === b;
    }, (state, cookie) => !!context.sessionCookieSecret && /^(?:__Secure-)?better-auth\.state=/.test(cookie)
      && signedCookie(cookie.slice(cookie.indexOf("=") + 1)).token === state);

  function traceEndpoint(root: unknown, path: string): string | undefined {
    const index = /^traces\.(\d+)\.responseBody(?:\.|$)/.exec(path)?.[1];
    if (index === undefined || !record(root) || !Array.isArray(root.traces)) return;
    const trace = root.traces[Number(index)];
    return record(trace) && typeof trace.path === "string" ? trace.path.split("?")[0] : undefined;
  }


  function sessions(value:unknown,result=new Map<string,number>()):Map<string,number> {
    if (Array.isArray(value)) for (const child of value) sessions(child,result);
    else if (record(value) && !claimObject(value)) {
      if (typeof value.token==="string" && typeof value.expiresAt==="string" && Number.isFinite(Date.parse(value.expiresAt))) result.set(value.token,Date.parse(value.expiresAt));
      for (const child of Object.values(value)) sessions(child,result);
    }
    return result;
  }
  const leftSessions = sessions(normalizedLeft), rightSessions = sessions(normalizedRight);

  function deviceSessions(value: unknown, path = "", result = new Map<string, number>()): Map<string, number> {
    if (Array.isArray(value)) value.forEach((child, index) => deviceSessions(child, path ? `${path}.${index}` : `${index}`, result));
    else if (record(value) && !claimObject(value) && !/(?:^|\.)(?:metadata|additionalFields|custom|applicationData)(?:\.|$)/.test(path) && !traceShape(path)) {
      if (typeof value.id === "string" && typeof value.userId === "string" && typeof value.token === "string" && typeof value.expiresAt === "string" && Number.isFinite(Date.parse(value.expiresAt))) result.set(value.token, Date.parse(value.expiresAt));
      for (const [key, child] of Object.entries(value)) deviceSessions(child, path ? `${path}.${key}` : key, result);
    }
    return result;
  }
  const leftDeviceSessions = deviceSessions(normalizedLeft), rightDeviceSessions = deviceSessions(normalizedRight);


  function issuedTokens(value: unknown, result = new Set<string>()): Set<string> {
    if (Array.isArray(value)) for (const child of value) issuedTokens(child, result);
    else if (record(value) && !claimObject(value)) for (const [key, child] of Object.entries(value)) {
      if (applicationField(key)) continue;
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

  // These are observations from the actual SQLite expressions, not another
  // plaintext issuance. Every such candidate is independently validated below;
  // adding these fields never grants an unchecked identity exception.
  function sqliteApiKeyReceipt(value: Record<string, unknown>): boolean {
    return apiKeyRow(value) && (Object.hasOwn(value, "startHex") || Object.hasOwn(value, "startType"));
  }

  function issuedApiKeys(value: unknown, path = "", result = new Map<string, string>()): Map<string, string> {
    if (Array.isArray(value)) value.forEach((child, index) => issuedApiKeys(child, path ? `${path}.${index}` : `${index}`, result));
    else if (record(value) && !claimObject(value) && !/(?:^|\.)(?:metadata|additionalFields|custom|applicationData)(?:\.|$)/.test(path) && !traceShape(path)) {
      if (apiKeyRow(value) && !sqliteApiKeyReceipt(value) && typeof value.id === "string" && typeof value.key === "string") {
        const previous = result.get(value.id);
        if (previous !== undefined && previous !== value.key) fail(path, "API key changed for a persisted row");
        result.set(value.id, value.key);
      }
      for (const [key, child] of Object.entries(value)) issuedApiKeys(child, path ? `${path}.${key}` : key, result);
    }
    return result;
  }
  const leftApiKeys = issuedApiKeys(normalizedLeft), rightApiKeys = issuedApiKeys(normalizedRight);

  function codeUnitBytes(unit: number): number[] {
    if (unit <= 0x7f) return [unit];
    if (unit <= 0x7ff) return [0xc0 | (unit >> 6), 0x80 | (unit & 0x3f)];
    return [0xe0 | (unit >> 12), 0x80 | ((unit >> 6) & 0x3f), 0x80 | (unit & 0x3f)];
  }
  // Find an actual UTF-16 prefix whose WTF-8 encoding equals the persisted
  // bytes. A cut between a surrogate pair encodes its high code unit as three
  // bytes; a complete pair uses ordinary UTF-8. No replacement text is accepted
  // without this derivation and the exact database readback.
  function utf16PrefixUnits(key: string, bytes: Buffer): number | undefined {
    if (!bytes.length) return 0;
    const prefix: number[] = [];
    for (let index = 0; index < key.length; index++) {
      const unit = key.charCodeAt(index), next = key.charCodeAt(index + 1);
      if (unit >= 0xd800 && unit <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) {
        if (prefix.length + 3 === bytes.length && Buffer.from([...prefix, ...codeUnitBytes(unit)]).equals(bytes)) return index + 1;
        prefix.push(...Buffer.from(key.substring(index, index + 2)));
        index++;
      } else prefix.push(...codeUnitBytes(unit));
      if (prefix.length === bytes.length && Buffer.from(prefix).equals(bytes)) return index + 1;
      if (prefix.length > bytes.length) return;
    }
  }
  type SqliteApiKey = { key: string; mode: "plain" | "hashed"; start: string | null; units: number | null };
  function sqliteApiKeys(value: unknown, issued: ReadonlyMap<string, string>, path = "", result = new Map<string, SqliteApiKey[]>()): Map<string, SqliteApiKey[]> {
    if (Array.isArray(value)) value.forEach((child, index) => sqliteApiKeys(child, issued, path ? `${path}.${index}` : `${index}`, result));
    else if (record(value) && !/(?:^|\.)(?:metadata|additionalFields|custom|applicationData)(?:\.|$)/.test(path) && !traceShape(path)) {
      if (sqliteApiKeyReceipt(value)) {
        const plaintext = typeof value.id === "string" ? issued.get(value.id) : undefined;
        const mode = plaintext !== undefined && value.key === plaintext ? "plain"
          : plaintext !== undefined && value.key === createHash("sha256").update(plaintext).digest("base64url") ? "hashed" : undefined;
        if (mode === undefined) fail(`${path}.key`, "SQLite API-key storage is not derived from its observed issuance");
        let units: number | null | undefined;
        if (value.startType !== "text" && value.startType !== "null") fail(`${path}.startType`, "SQLite API-key storage type is neither text nor null");
        if (value.startType === "null" && value.start === null && value.startHex === "") units = null;
        else if (value.startType === "text" && typeof value.start === "string" && typeof value.startHex === "string" && /^(?:[0-9A-Fa-f]{2})*$/.test(value.startHex)) {
          const bytes = Buffer.from(value.startHex, "hex");
          if (bytes.toString("utf8") !== value.start) fail(`${path}.start`, "SQLite API-key text readback disagrees with its actual bytes");
          else if (plaintext !== undefined) units = utf16PrefixUnits(plaintext, bytes);
        }
        if (units === undefined) fail(`${path}.startHex`, "SQLite API-key bytes are not an actual UTF-16 credential prefix");
        if (mode !== undefined && units !== undefined && typeof value.id === "string" && typeof value.key === "string" && (typeof value.start === "string" || value.start === null)) {
          const receipts = result.get(value.id) ?? [];
          receipts.push({ key: value.key, mode, start: value.start, units }); result.set(value.id, receipts);
        }
      }
      for (const [key, child] of Object.entries(value)) sqliteApiKeys(child, issued, path ? `${path}.${key}` : key, result);
    }
    return result;
  }
  const leftSqliteApiKeys = sqliteApiKeys(normalizedLeft, leftApiKeys), rightSqliteApiKeys = sqliteApiKeys(normalizedRight, rightApiKeys);
  function sqliteStorage(value: Record<string, unknown>, receipts: ReadonlyMap<string, SqliteApiKey[]>): SqliteApiKey | undefined {
    return typeof value.id === "string" ? receipts.get(value.id)?.find(row => row.key === value.key && row.start === value.start) : undefined;
  }
  function observedPrefixUnits(value: Record<string, unknown>, plaintext: string, receipts: ReadonlyMap<string, SqliteApiKey[]>): number | undefined {
    if (typeof value.start !== "string") return;
    if (typeof value.id === "string") {
      const receipt = receipts.get(value.id)?.find(row => row.start === value.start);
      if (receipt && receipt.units !== null) return receipt.units;
    }
    return plaintext.startsWith(value.start) ? value.start.length : undefined;
  }

  function entityValues(value:unknown,result=new Set<string>()):Set<string> {
    if (Array.isArray(value)) for (const child of value) entityValues(child,result);
    else if (record(value) && !claimObject(value)) for (const [key,child] of Object.entries(value)) {
      if (applicationField(key)) continue;
      if (entityKeys.has(key) && typeof child==="string") result.add(child);
      entityValues(child,result);
    }
    return result;
  }
  const leftEntities=entityValues(normalizedLeft),rightEntities=entityValues(normalizedRight);

  const leftMemberIds = new Set<string>(), rightMemberIds = new Set<string>();
  const leftKeyIds = new Set<string>(), rightKeyIds = new Set<string>();
  const memberReceipt = (value: Record<string, unknown>) => typeof value.id === "string"
    && typeof value.organizationId === "string" && typeof value.userId === "string"
    && typeof value.role === "string" && isDate(value.createdAt);
  function observedSelectors(a: unknown, b: unknown, path = "", applicationData = false) {
    if (applicationData || traceShape(path)) return;
    if (Array.isArray(a) && Array.isArray(b)) {
      a.forEach((child, index) => observedSelectors(child, b[index], path ? `${path}.${index}` : `${index}`));
    } else if (record(a) && record(b)) {
      if (claimObject(a) || claimObject(b)) return;
      const leftMember = memberReceipt(a), rightMember = memberReceipt(b);
      if (leftMember) leftMemberIds.add(String(a.id));
      if (rightMember) rightMemberIds.add(String(b.id));
      if (leftMember && rightMember) {
        identity(String(a.id), String(b.id), `${path}.id`, "entity");
      }
      const leftKey = sqliteApiKeyReceipt(a) && sqliteStorage(a, leftSqliteApiKeys);
      const rightKey = sqliteApiKeyReceipt(b) && sqliteStorage(b, rightSqliteApiKeys);
      if (leftKey) leftKeyIds.add(String(a.id));
      if (rightKey) rightKeyIds.add(String(b.id));
      if (leftKey && rightKey) {
        identity(String(a.id), String(b.id), `${path}.id`, "entity");
      }
      for (const [key, child] of Object.entries(a)) observedSelectors(child, b[key], path ? `${path}.${key}` : key,
        ["metadata", "additionalFields", "custom", "applicationData"].includes(key));
    }
  }
  observedSelectors(normalizedLeft, normalizedRight);

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
  function exactCacheCopy(a: unknown, b: unknown): boolean {
    if (Array.isArray(a)) return Array.isArray(b) && a.length === b.length && a.every((child,index) => exactCacheCopy(child,b[index]));
    if (record(a)) return record(b) && Object.keys(a).length === Object.keys(b).length
      && Object.entries(a).every(([key,child]) => Object.hasOwn(b,key) && exactCacheCopy(child,b[key]));
    return Object.is(a,b);
  }
  const cachePayloadSchema = z.looseObject({session: sessionSchema.loose(), user: userSchema.loose(), updatedAt: z.number(), version: z.string().optional()});
  function compactCookieHeaders(value: Record<string,unknown>): {name:string;attributes:string;tombstone:boolean}[] | undefined {
    if (!Object.hasOwn(value,"rawCookies")) return [];
    if (!Array.isArray(value.rawCookies) || !value.rawCookies.length || typeof value.token!=="string") return;
    const result: {name:string;attributes:string;tombstone:boolean}[]=[];
    const live: {name:string;value:string;attributes:string;raw:string}[]=[];
    for (const raw of value.rawCookies) {
      if (typeof raw!=="string") return;
      const cookie=Cookie.parse(raw);
      if (!cookie || !/^better-auth\.session_data(?:\.(?:0|[1-9]\d*))?$/.test(cookie.key)) return;
      const separator=raw.indexOf(";"),pair=separator<0?raw:raw.slice(0,separator),attributes=separator<0?"":raw.slice(separator);
      let decoded:string;try{decoded=decodeURIComponent(cookie.value);}catch{return;}
      if (pair!==`${cookie.key}=${encodeURIComponent(decoded)}`) return;
      const tombstone=decoded==="" && cookie.maxAge===0;
      if (decoded==="" && !tombstone) return;
      result.push({name:cookie.key,attributes,tombstone});
      if (!tombstone) live.push({name:cookie.key,value:decoded,attributes,raw});
    }
    if (!live.length || live.length>100 || live.map(part=>part.value).join("")!==value.token) return;
    const attributes=live[0]!.attributes,capacity=4050-(`better-auth.session_data.99=${attributes}`).length;
    if (capacity<=0) return;
    for (let index=0;index<live.length;index++) {
      const part=live[index]!;
      const name=live.length===1?"better-auth.session_data":`better-auth.session_data.${index}`;
      if (part.name!==name || part.attributes!==attributes || Buffer.byteLength(part.raw)>4050
        || part.value.length!==Math.min(capacity,value.token.length-index*capacity)) return;
    }
    if (live.length!==Math.ceil(value.token.length/capacity)) return;
    return result;
  }
  function authenticatedCompactCache(value: Record<string, unknown>, start: number, finish: number | undefined): boolean {
    if (!context.compactSessionCacheSecret || Object.keys(value).sort().join(",") !== (Object.hasOwn(value,"rawCookies") ? "decoded,effectiveMaxAgeSeconds,envelope,observedAt,rawCookies,token" : "decoded,effectiveMaxAgeSeconds,envelope,observedAt,token")
      || compactCookieHeaders(value)===undefined
      || typeof value.effectiveMaxAgeSeconds !== "number" || !value.effectiveMaxAgeSeconds
      || typeof value.token !== "string" || !/^[A-Za-z0-9_-]+$/.test(value.token)
      || !record(value.envelope) || Object.keys(value.envelope).sort().join(",") !== "expiresAt,session,signature"
      || typeof value.observedAt !== "number" || !Number.isFinite(value.observedAt)
      || value.observedAt < start || value.observedAt > (finish ?? start)) return false;
    try {
      const bytes = Buffer.from(value.token, "base64url");
      if (bytes.toString("base64url") !== value.token) return false;
      const text = new TextDecoder("utf-8", {fatal:true}).decode(bytes);
      const parsedEnvelope: unknown = JSON.parse(text);
      if (JSON.stringify(parsedEnvelope) !== text || JSON.stringify(value.envelope) !== text || !exactCacheCopy(parsedEnvelope,value.envelope)) return false;
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
      return valid ? exactCacheCopy(normalizeClientValue(parsed.data),value.decoded) : value.decoded === null;
    } catch { return false; }
  }
  const compactHeaderIssuances = new Map<string, readonly [string, string]>();
  function observedCompactHeaders(a: unknown, b: unknown, path = "", applicationData = false) {
    if (applicationData || traceShape(path)) return;
    if (Array.isArray(a) && Array.isArray(b)) {
      a.forEach((child,index) => observedCompactHeaders(child,b[index],`${path}.${index}`));
    } else if (record(a) && record(b)) {
      if (claimObject(a) || claimObject(b)) return;
      for (const [key,child] of Object.entries(a)) {
        if (key === "compactSessionCache" && record(child) && record(b[key])) {
          const other = b[key];
          if (!authenticatedCompactCache(child,context.leftStartedAt,context.leftFinishedAt)
            || !authenticatedCompactCache(other,context.rightStartedAt,context.rightFinishedAt)) continue;
          const leftCookies=compactCookieHeaders(child),rightCookies=compactCookieHeaders(other);
          const left=child.decoded,right=other.decoded;
          if (leftCookies?.length!==1 || rightCookies?.length!==1
            || leftCookies[0]?.name!=="better-auth.session_data" || rightCookies[0]?.name!=="better-auth.session_data"
            || leftCookies[0].tombstone || rightCookies[0].tombstone
            || !record(left) || !record(right) || !record(left.user) || !record(right.user)
            || !record(left.session) || !record(right.session)) continue;
          const pair=JSON.stringify([left.session.token,right.session.token]),issuance=issuances.get(pair);
          if (!issuance || !signedCookieIssuances.has(pair)
            || left.user.id!==left.session.userId || right.user.id!==right.session.userId
            || issuance.leftUser!==left.user.id || issuance.rightUser!==right.user.id) continue;
          compactHeaderIssuances.set(JSON.stringify([child.token,other.token]),[String(left.session.token),String(right.session.token)]);
        } else observedCompactHeaders(child,b[key],`${path}.${key}`,
          ["metadata","additionalFields","custom","applicationData"].includes(key));
      }
    }
  }
  observedCompactHeaders(normalizedLeft,normalizedRight);
  function cacheClock(a: number, b: number, path: string) {
    if (a !== b && Math.abs((a-context.leftStartedAt)-(b-context.rightStartedAt)) > 1500) fail(path,"compact cache timestamp differs");
  }
  function authenticatedProxyProfile(value: Record<string, unknown>): boolean {
    if (!context.oauthProxyProfileSecret || Object.keys(value).sort().join(",") !== "payload,token"
      || typeof value.token !== "string" || !/^(?:[0-9a-f]{2}){40,}$/.test(value.token) || !record(value.payload)) return false;
    try {
      const bytes = Buffer.from(value.token, "hex"), key = createHash("sha256").update(context.oauthProxyProfileSecret).digest();
      const plaintext = xchacha20poly1305(key, bytes.subarray(0, 24)).decrypt(bytes.subarray(24));
      const text = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
      const parsed: unknown = JSON.parse(text);
      const exactCopy = (a: unknown, b: unknown): boolean => {
        if (Array.isArray(a)) return Array.isArray(b) && a.length === b.length && a.every((child,index) => exactCopy(child,b[index]));
        if (record(a)) return record(b) && Object.keys(a).length === Object.keys(b).length
          && Object.entries(a).every(([key,child]) => Object.hasOwn(b,key) && exactCopy(child,b[key]));
        return Object.is(a,b);
      };
      if (JSON.stringify(parsed) !== text || JSON.stringify(value.payload) !== text || !exactCopy(parsed,value.payload)) return false;
      // Authentication proves the complete submitted JSON, including schema-invalid
      // or expired input. Endpoint admission remains the primary owner's proof.
      return true;
    } catch { return false; }
  }
  function proxyProfiles(value: unknown, path = "", applicationData = false, result = new Map<string, Record<string, unknown>>()): Map<string, Record<string, unknown>> {
    if (Array.isArray(value)) value.forEach((child, index) => proxyProfiles(child, path ? `${path}.${index}` : `${index}`, applicationData, result));
    else if (record(value) && !applicationData && !traceShape(path)) for (const [key, child] of Object.entries(value)) {
      const childPath = path ? `${path}.${key}` : key;
      if (key === "oauthProxyProfile" && record(child) && authenticatedProxyProfile(child)) result.set(String(child.token),child.payload as Record<string,unknown>);
      else proxyProfiles(child,childPath,["metadata","additionalFields","applicationData","userInfo","profile"].includes(key),result);
    }
    return result;
  }
  const leftProxyProfiles = proxyProfiles(normalizedLeft);
  const rightProxyProfiles = proxyProfiles(normalizedRight);
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

  function sessionHeader(a: string, b: string, path: string, setCookie: boolean): boolean {
    if (!context.sessionCookieSecret) return false;
    // Preserve the complete raw header around its credential: name, spacing,
    // order, every other cookie and all Set-Cookie attributes remain literal.
    const pattern = setCookie
      ? /(?:^|,\s*)((?:__Secure-)?better-auth\.session_token)=([^;,\s]*)/g
      : /(?:^|;\s*)((?:__Secure-)?better-auth\.session_token)=([^;\s]*)/g;
    const left = [...a.matchAll(pattern)], right = [...b.matchAll(pattern)];
    if (!left.length && !right.length) return false;
    if (left.length !== 1 || right.length !== 1 || left[0]![1] !== right[0]![1]) {
      fail(path, "signed session cookie presence or name differs"); return true;
    }
    const av = left[0]![2]!, bv = right[0]![2]!;
    const ac = signedCookie(av), bc = signedCookie(bv);
    if (ac.error || bc.error) { fail(path, ac.error ?? bc.error!); return true; }
    if (!signedCookieIssuances.has(JSON.stringify([ac.token, bc.token]))) {
      fail(path, "signed session cookie does not match corresponding observed issuance"); return true;
    }
    const cachePattern=setCookie?/(?:^|,\s*)(better-auth\.session_data)=([^;,\s]*)/g
      :/(?:^|;\s*)(better-auth\.session_data)=([^;\s]*)/g;
    const leftCache=[...a.matchAll(cachePattern)],rightCache=[...b.matchAll(cachePattern)];
    if (leftCache.length || rightCache.length) {
      const pair=leftCache.length===1 && rightCache.length===1
        ? compactHeaderIssuances.get(JSON.stringify([leftCache[0]![2],rightCache[0]![2]])) : undefined;
      if (!pair || pair[0]!==ac.token || pair[1]!==bc.token) {
        fail(path,"compact cookie does not match authenticated corresponding session issuance");return true;
      }
    }
    const scaffold = (raw: string, matches: readonly RegExpMatchArray[]) => {
      for (const match of [...matches].sort((a,b)=>b.index!-a.index!)) {
        const value=match[2]!,start=match.index!+match[0].length-value.length;
        raw=`${raw.slice(0,start)}<verified-${match[1]}>${raw.slice(start+value.length)}`;
      }
      return raw;
    };
    if (scaffold(a,[left[0]!,...leftCache]) !== scaffold(b,[right[0]!,...rightCache]))
      fail(path, "signed session cookie header bytes or attributes differ");
    identity(ac.token!, bc.token!, path, "token");
    return true;
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
        username: url.username,
        password: url.password,
        pathname,
        ...(resetToken ? { token: decodeURIComponent(resetToken[2] ?? "") } : {}),
        hash: url.hash,
        query: Object.fromEntries([...new Set(url.searchParams.keys())].sort().map(key => [key, url.searchParams.getAll(key)])),
      };
    } catch { return undefined; }
  }

  function visit(a: unknown, b: unknown, path: string, key: string, jwtPayload = false, applicationData = false, jwtHeader = false, encryptedClaims = false, urlQueryContext: "url" | "query" | undefined = undefined, adminFilterUrl = false, compactCache = false, proxyProviders: readonly [string | undefined, string | undefined] | undefined = undefined, proxyPayload = false, owners: readonly string[] = [], literalClaims = false) {
    if (!applicationData && !jwtPayload && !traceShape(path)
      && !/(?:^|\.)(?:metadata|custom|additionalFields|applicationData)(?:\.|$)/.test(path)
      && record(a) && record(b)) {
      const complete = record(a.request) && record(a.before) && record(a.snapshot) && record(a.set)
        && record(b.request) && record(b.before) && record(b.snapshot) && record(b.set);
      const cacheSet = a.operation === "set" && b.operation === "set" && typeof a.key === "string" && a.key.startsWith("verification:")
        && typeof b.key === "string" && b.key.startsWith("verification:") && "rawValue" in a && "rawValue" in b;
      const otpDelivery = verificationPublications.find(pair => pair.kind === "otp" && pair.valid
        && samePublication(a, pair.left.delivery) && samePublication(b, pair.right.delivery));
      if (otpDelivery) {
        for (const field of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) {
          const child = `${path}.${field}`;
          if (!Object.hasOwn(a, field) || !Object.hasOwn(b, field)) fail(child, "field presence differs");
          else if (field === "otp") identity(String(a.otp), String(b.otp), child, "token");
          else visit(a[field], b[field], child, field);
        }
        return;
      }
      const observed = (complete || cacheSet) && verificationPublications.some(pair => samePublication(a, complete ? pair.left : pair.left.set)
        || samePublication(b, complete ? pair.right : pair.right.set));
      if (observed) {
        const receipt = verificationPublications.find(pair => samePublication(a, complete ? pair.left : pair.left.set)
          && samePublication(b, complete ? pair.right : pair.right.set));
        if (!receipt?.valid) fail(`${path}.${complete ? "set." : ""}ttl`, "verification TTL lacks its exact issuing-request publication proof");
        else {
          const snapshot = (left: Record<string, unknown>, right: Record<string, unknown>, target: string) => {
            for (const field of [...new Set([...Object.keys(left), ...Object.keys(right)])].sort()) {
              const child = `${target}.${field}`;
              if (!Object.hasOwn(left, field) || !Object.hasOwn(right, field)) fail(child, "field presence differs");
              else if (field === "identifier" && receipt.kind === "oauth") identity(String(left.identifier), String(right.identifier), child, "verification-identifier");
              else if (field === "value" && receipt.kind === "otp") {
                const [leftCode, leftCounter] = String(left.value).split(":"), [rightCode, rightCounter] = String(right.value).split(":");
                identity(leftCode!, rightCode!, `${child}.otp`, "token");
                visit(leftCounter, rightCounter, `${child}.counter`, "counter");
              }
              else if (field === "value" && receipt.kind === "transfer") identity(String(left.value), String(right.value), child, "token");
              else if (field === "value" && receipt.kind === "oauth") {
                const a = JSON.parse(String(left.value)), b = JSON.parse(String(right.value));
                for (const key of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) {
                  const target = `${child}.${key}`;
                  if (!Object.hasOwn(a, key) || !Object.hasOwn(b, key)) fail(target, "field presence differs");
                  else if (key === "expiresAt") continue; // Each exact 600s deadline was independently admitted.
                  else if (key === "codeVerifier") identity(a[key], b[key], target, "code-verifier");
                  else if (key === "oauthState") identity(a[key], b[key], target, "state");
                  else visit(a[key], b[key], target, key);
                }
              }
              else visit(left[field], right[field], child, field, false, false, false, false, undefined, false, false, undefined, false, dateOwners(left, right));
            }
          };
          const set = (left: Record<string, unknown>, right: Record<string, unknown>, target: string) => {
            for (const field of [...new Set([...Object.keys(left), ...Object.keys(right)])].sort()) {
              const child = `${target}.${field}`;
              if (!Object.hasOwn(left, field) || !Object.hasOwn(right, field)) { fail(child, "field presence differs"); continue; }
              if (["ttl", "executedAt", "storedAt", "storageExpiresAt"].includes(field)) continue;
              if (field === "key" && receipt.kind === "oauth") identity(String(left.key).slice("verification:".length), String(right.key).slice("verification:".length), child, "verification-identifier");
              else if (field === "rawValue") snapshot(JSON.parse(String(left.rawValue)), JSON.parse(String(right.rawValue)), child);
              else if (field === "value") snapshot(left.value as Record<string, unknown>, right.value as Record<string, unknown>, child);
              else visit(left[field], right[field], child, field);
            }
          };
          if (cacheSet) set(a, b, path);
          else for (const field of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) {
            const child = `${path}.${field}`;
            if (!Object.hasOwn(a, field) || !Object.hasOwn(b, field)) { fail(child, "field presence differs"); continue; }
            const av = a[field] as Record<string, unknown>, bv = b[field] as Record<string, unknown>;
            if (field === "set") set(av, bv, child);
            else if (field === "snapshot") snapshot(av, bv, child);
            else if (field === "before") for (const key of [...new Set([...Object.keys(av), ...Object.keys(bv)])].sort()) {
              if (!Object.hasOwn(av, key) || !Object.hasOwn(bv, key)) { fail(`${child}.${key}`, "field presence differs"); continue; }
              if (key === "executedAt") continue;
              if (key === "snapshot") snapshot(av.snapshot as Record<string, unknown>, bv.snapshot as Record<string, unknown>, `${child}.snapshot`);
              else visit(av[key], bv[key], `${child}.${key}`, key);
            }
            else if (field === "request") for (const key of [...new Set([...Object.keys(av), ...Object.keys(bv)])].sort()) {
              if (!Object.hasOwn(av, key) || !Object.hasOwn(bv, key)) { fail(`${child}.${key}`, "field presence differs"); continue; }
              if (["startedAt", "finishedAt"].includes(key)) continue;
              if (key === "cookie" && typeof av.cookie === "string" && typeof bv.cookie === "string")
                visit({headers:{cookie:av.cookie}}, {headers:{cookie:bv.cookie}}, child, "");
              else visit(av[key], bv[key], `${child}.${key}`, key, false, key === "body");
            }
            else visit(a[field], b[field], child, field);
          }
          return;
        }
      }
    }
    if (literalClaims && typeof a === "string" && typeof b === "string"
      && !claimEvidence.has(claimPair(key, a, b)) && !(isDate(a) && isDate(b) && approvedDate(owners, key, a, b))) {
      if (a !== b) fail(path, "value or type differs");
      return;
    }
    const leftEndpoint = traceEndpoint(normalizedLeft, path), rightEndpoint = traceEndpoint(normalizedRight, path);
    if (leftEndpoint && leftEndpoint === rightEndpoint && typeof a === "string" && typeof b === "string") {
      if (key === "totpURI" && /^traces\.\d+\.responseBody\.totpURI$/.test(path) && /\/two-factor\/(?:enable|get-totp-uri)$/.test(leftEndpoint)) {
        try {
          const leftURI = new URL(a), rightURI = new URL(b), leftSecret = leftURI.searchParams.get("secret"), rightSecret = rightURI.searchParams.get("secret");
          if (leftURI.searchParams.getAll("secret").length !== 1 || rightURI.searchParams.getAll("secret").length !== 1) { fail(path, "TOTP URI must contain exactly one secret"); return; }
          if (leftURI.protocol !== "otpauth:" || rightURI.protocol !== "otpauth:" || leftURI.hostname !== "totp" || rightURI.hostname !== "totp" || !leftSecret || !rightSecret || !/^[A-Z2-7]+=*$/.test(leftSecret) || !/^[A-Z2-7]+=*$/.test(rightSecret) || leftSecret.length !== rightSecret.length) { fail(path, "TOTP secret encoding or URI protocol differs"); return; }
          identity(leftSecret, rightSecret, `${path}.secret`, "totp-secret");
          leftURI.searchParams.set("secret", "<generated>"); rightURI.searchParams.set("secret", "<generated>");
          if (leftURI.href !== rightURI.href) fail(path, "TOTP URI configuration differs");
        } catch { fail(path, "invalid TOTP URI"); }
        return;
      }
      if (key === "backupCodes" && /^traces\.\d+\.responseBody\.backupCodes\.\d+$/.test(path) && /\/two-factor\/(?:enable|generate-backup-codes)$/.test(leftEndpoint) && !leftEndpoint.includes("two-factor-backup-custom")) {
        if (!/^[a-zA-Z0-9-]+$/.test(a) || !/^[a-zA-Z0-9-]+$/.test(b) || a.replace(/[a-zA-Z0-9]/g, "x") !== b.replace(/[a-zA-Z0-9]/g, "x")) fail(path, "backup-code format differs");
        identity(a, b, path, "backup-code"); return;
      }
      if (key === "responseBody" && /\/(?:reference|docs)$/.test(leftEndpoint)) {
        const embedded = /<script\s+id="api-reference"\s+type="application\/json">\s*([^]*?)\s*<\/script>/;
        const am = embedded.exec(a), bm = embedded.exec(b);
        if (am?.[1] && bm?.[1]) {
          try { visit({ frame: a.replace(am[1], "<document>"), document: JSON.parse(am[1]) }, { frame: b.replace(bm[1], "<document>"), document: JSON.parse(bm[1]) }, path, ""); return; }
          catch { fail(path, "invalid embedded OpenAPI document"); return; }
        }
      }
    }
    if (proxyPayload && key === "timestamp" && typeof a === "number" && typeof b === "number") {
      if (a !== b && Math.abs((a-context.leftStartedAt)-(b-context.rightStartedAt)) > 1500) fail(path,"OAuth proxy profile timestamp differs");
      return;
    }
    if (compactCache && typeof a === "number" && typeof b === "number" && /\.compactSessionCache\.(?:envelope\.expiresAt|(?:envelope\.session|decoded)\.updatedAt)$/.test(`.${path}`)) {
      cacheClock(a,b,path); return;
    }
    if (typeof a === "string" && typeof b === "string" && !traceShape(path)
      && !/(?:^|\.)(?:metadata|additionalFields|custom|applicationData)(?:\.|$)/.test(path)) {
      if (!applicationData && !jwtPayload && /\.headers\.(?:cookie|set-cookie)$/.test(path)
        && sessionHeader(a, b, path, key === "set-cookie")) return;
      if (!applicationData && !jwtPayload && (key === "keyId" || (key === "memberIdOrEmail" && !a.includes("@") && !b.includes("@")))) {
        const leftKnown = key === "keyId" ? leftKeyIds : leftMemberIds;
        const rightKnown = key === "keyId" ? rightKeyIds : rightMemberIds;
        if (leftKnown.has(a) || rightKnown.has(b)) {
          if (!leftKnown.has(a) || !rightKnown.has(b)) fail(path, "server selector lacks its observed entity on both sides");
          else identity(a, b, path, "entity");
          return;
        }
      }
      if (key === "profile" && urlQueryContext === "query" && proxyProviders) {
        const leftPayload = leftProxyProfiles.get(a), rightPayload = rightProxyProfiles.get(b);
        if (!leftPayload || !rightPayload) {
          if (a !== b) fail(path,"unverified OAuth proxy URL profile differs literally");
        } else {
          const provider = (payload: Record<string,unknown>) => record(payload.account) && typeof payload.account.providerId === "string" ? payload.account.providerId : undefined;
          const leftProvider = provider(leftPayload), rightProvider = provider(rightPayload);
          if (leftProvider !== undefined && rightProvider !== undefined && proxyProviders[0] !== undefined && proxyProviders[1] !== undefined
            && (leftProvider === proxyProviders[0]) !== (rightProvider === proxyProviders[1])) fail(path,"OAuth proxy provider-route relationship differs");
          identity(a,b,path,"token");
        }
        return;
      }
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
        visit(leftJwt.payload,rightJwt.payload,`${path}.payload`,"",true,false,false,false,undefined,false,false,undefined,false,[],true);
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
        if (owners.some(owner => invalidPhysicalDates.has(dateKey(owner, key, a, b)))) { fail(path, "physical row timestamp shape or provenance differs"); return; }
        if (approvedDate(owners, key, a, b)) return;
        if (owners.some(owner => invalidLifetimes.has(dateKey(owner, key, a, b)))) { fail(path, "session lifetime differs from its observed issuance clock"); return; }
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
        const proxyPath = /^\/(?:api\/auth|__test\/profiles\/[^/]+\/api\/auth)\/callback\/([^/]+)\/oauth-proxy$/;
        const leftProvider = ap.origin === "<server>" && typeof ap.pathname === "string" ? proxyPath.exec(ap.pathname)?.[1] : undefined;
        const rightProvider = bp.origin === "<server>" && typeof bp.pathname === "string" ? proxyPath.exec(bp.pathname)?.[1] : undefined;
        const legacyPath = /^\/(?:api\/auth|__test\/profiles\/[^/]+\/api\/auth)\/oauth-proxy-callback$/;
        const leftLegacy = ap.origin === "<server>" && typeof ap.pathname === "string" && legacyPath.test(ap.pathname);
        const rightLegacy = bp.origin === "<server>" && typeof bp.pathname === "string" && legacyPath.test(bp.pathname);
        const providers = (leftProvider || leftLegacy) && (rightProvider || rightLegacy) ? [leftProvider,rightProvider] as const : undefined;
        visit(ap, bp, path, "", false, false, false, false, "url", observedAdminUrl, false, providers); return;
      }
    }
    if (Array.isArray(a) && Array.isArray(b)) {
      if (a.length !== b.length) fail(path, "array length differs");
      a.forEach((child, index) => visit(child, b[index], `${path ? `${path}.` : ""}${index}`, key, false, applicationData || jwtPayload, false, false, urlQueryContext, adminFilterUrl, compactCache, proxyProviders, false, [], literalClaims));
      return;
    }
    if (record(a) && record(b)) {
      if (key === "oauthProxyProfile") {
        if (applicationData || traceShape(path) || /(?:^|\.)applicationData(?:\.|$)/.test(path)
          || !authenticatedProxyProfile(a)
          || !authenticatedProxyProfile(b)) {
          if (stableJSON(a) !== stableJSON(b)) fail(path,"unverified or application OAuth proxy profile differs literally");
          return;
        }
        const providerAccountMatches = (payload: unknown) => record(payload) && record(payload.account) && record(payload.userInfo)
          && typeof payload.account.accountId === "string" && typeof payload.userInfo.id === "string" ? payload.account.accountId === payload.userInfo.id : undefined;
        if (providerAccountMatches(a.payload) !== providerAccountMatches(b.payload)) fail(path,"OAuth proxy provider account identity relationship differs");
        identity(String(a.token),String(b.token),`${path}.token`,"token");
        visit(a.payload,b.payload,`${path}.payload`,"",false,false,false,false,undefined,false,false,undefined,true);
        return;
      }
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
        if (Object.hasOwn(a,"rawCookies")!==Object.hasOwn(b,"rawCookies")) fail(`${path}.rawCookies`,"raw compact cookie presence differs");
        visit(compactCookieHeaders(a),compactCookieHeaders(b),`${path}.rawCookies`,"",false,false,false,false,undefined,false,false);
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
      const childClaims = literalClaims || (!encryptedClaims && (jwtPayload || jwtClaims || claimObject(a) || claimObject(b)));
      const computedLifetime = !inApplicationData && !traceShape(path) && sessionLifetime(a,b,path);
      const apiKey = !inApplicationData && !traceShape(path) && apiKeyRow(a) && apiKeyRow(b);
      const sqliteApiKey = apiKey && (sqliteApiKeyReceipt(a) || sqliteApiKeyReceipt(b));
      const issuedLeft = !sqliteApiKey && typeof a.key === "string" ? a.key : typeof a.id === "string" ? leftApiKeys.get(a.id) : undefined;
      const issuedRight = !sqliteApiKey && typeof b.key === "string" ? b.key : typeof b.id === "string" ? rightApiKeys.get(b.id) : undefined;
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
        else if (proxyPayload && ["userInfo","profile"].includes(childKey)) {
          if (stableJSON(a[childKey]) !== stableJSON(b[childKey])) fail(childPath,"OAuth proxy provider JSON differs literally");
        }
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
        else if (sqliteApiKey && childKey === "key") {
          const leftStorage = sqliteStorage(a, leftSqliteApiKeys), rightStorage = sqliteStorage(b, rightSqliteApiKeys);
          if (!leftStorage || !rightStorage || issuedLeft === undefined || issuedRight === undefined) fail(childPath, "SQLite API-key lacks independently validated issuance and storage");
          else {
            if (leftStorage.mode !== rightStorage.mode) fail(childPath, "SQLite API-key plaintext-versus-hashed storage differs");
            identity(issuedLeft, issuedRight, childPath, "api-key");
          }
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
            const leftUnits = observedPrefixUnits(a, issuedLeft, leftSqliteApiKeys), rightUnits = observedPrefixUnits(b, issuedRight, rightSqliteApiKeys);
            if (leftUnits === undefined || rightUnits === undefined || leftUnits !== rightUnits) fail(childPath, "API key stored-prefix relationship differs");
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
        else visit(a[childKey], b[childKey], childPath, childKey === "accountId" && typeof a.providerId === "string" && a.providerId !== "credential" && !("accessToken" in a) && !("refreshToken" in a) ? "providerAccount" : childKey, false, inApplicationData, false, false, urlQueryContext === "query" || (urlQueryContext === "url" && childKey === "query") ? "query" : undefined, adminFilterUrl, compactCache, proxyProviders, proxyPayload && childKey === "timestamp", dateOwners(a, b), childClaims);
      }
      return;
    }
    if (!Object.is(a, b)) fail(path, "value or type differs");
  }
  visit(normalizedLeft, normalizedRight, "", "");
  return differences;
}
