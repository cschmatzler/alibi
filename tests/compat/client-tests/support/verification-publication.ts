import { createHash } from "node:crypto";
import type { RequestWindow } from "./trace";

export const verificationPublicationObserver = "/__test/verification-publications";
type Row = Record<string, unknown>;
const row = (value: unknown): value is Row => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (a: unknown, b: unknown): boolean => {
  if (Array.isArray(a)) return Array.isArray(b) && a.length === b.length && a.every((v, i) => exact(v, b[i]));
  if (row(a)) return row(b) && Object.keys(a).length === Object.keys(b).length && Object.entries(a).every(([k, v]) => Object.hasOwn(b, k) && exact(v, b[k]));
  return Object.is(a, b);
};
const time = (value: unknown): number | undefined => {
  if (typeof value !== "string") return;
  const parsed = Date.parse(value);
  if (Number.isFinite(parsed) && new Date(parsed).toISOString() === value) return parsed;
};
const hash = (value: string) => createHash("sha256").update(value).digest("base64url");
const cookie = (value: unknown): string | undefined => typeof value === "string"
  ? value.split(";").map(v => v.trim()).find(v => /^(?:__Secure-)?better-auth\.session_token=/.test(v)) : undefined;

export type PublicationPair = {
  readonly left: Row;
  readonly right: Row;
  readonly producerIndex: number;
  readonly kind: "otp" | "magic" | "transfer";
  readonly valid: boolean;
};

/** Receipts are admitted only from the complete, exact HTTP observer response. */
export function verificationPublicationPairs(
  left: unknown,
  right: unknown,
  leftWindows: readonly (RequestWindow | undefined)[] | undefined,
  rightWindows: readonly (RequestWindow | undefined)[] | undefined,
  sessionPair: (leftToken: string, rightToken: string, leftCookie: string, rightCookie: string) => boolean,
): PublicationPair[] {
  if (!row(left) || !row(right) || !Array.isArray(left.traces) || !Array.isArray(right.traces)) return [];
  const lt = left.traces, rt = right.traces;
  const result: PublicationPair[] = [];
  function admission(value: Row, traces: unknown[], windows: readonly (RequestWindow | undefined)[] | undefined) {
    if (!row(value.request) || !row(value.before) || !row(value.before.snapshot) || !row(value.snapshot) || !row(value.set)) return;
    const req = value.request, before = value.before, candidate = value.before.snapshot, snapshot = value.snapshot, set = value.set;
    const requestStart = time(req.startedAt), requestEnd = time(req.finishedAt), hookAt = time(before.executedAt), setAt = time(set.executedAt), expiry = time(snapshot.expiresAt);
    const storedAt = time(set.storedAt), storageExpiresAt = time(set.storageExpiresAt);
    if ([requestStart, requestEnd, hookAt, setAt, expiry, storedAt, storageExpiresAt].some(v => v === undefined)) return;
    if (!(requestStart! <= hookAt! && hookAt! <= setAt! && setAt! <= storedAt! && storedAt! <= requestEnd!)) return;
    if (set.operation !== "set" || typeof set.key !== "string" || set.key !== `verification:${candidate.identifier}`
      || typeof set.rawValue !== "string" || !row(set.value) || set.rawValue !== JSON.stringify(set.value)
      || !exact(set.value, snapshot) || !Object.entries(candidate).every(([k, v]) => exact(v, snapshot[k]))) return;
    if (typeof set.ttl !== "number" || !Number.isInteger(set.ttl) || set.ttl <= 0 || storageExpiresAt !== storedAt! + set.ttl * 1000
      || set.ttl < Math.max(Math.floor((expiry! - setAt!) / 1000), 0)
      || set.ttl > Math.max(Math.floor((expiry! - hookAt!) / 1000), 0)) return;
    const suffix = /^(\/__test\/profiles\/verification-storage-(?:cache|mixed)-default\/api\/auth)\/(email-otp\/send-verification-otp|sign-in\/magic-link|one-time-token\/generate)$/.exec(String(req.path));
    if (!suffix) return;
    const kind: PublicationPair["kind"] = suffix[2] === "email-otp/send-verification-otp" ? "otp" : suffix[2] === "sign-in/magic-link" ? "magic" : "transfer";
    const lifetime = kind === "transfer" ? 180000 : 300000;
    if (expiry! < requestStart! + lifetime || expiry! > requestEnd! + lifetime) return;
    const matching = traces.flatMap((trace, index) => {
      const window = windows?.[index];
      if (!row(trace) || !window || trace.responseStatus !== 200 || trace.method !== req.method || trace.path !== req.path
        || window.startedAt > requestStart! || window.finishedAt < requestEnd!
        || !Object.hasOwn(window, "verificationInput") || !exact(window.verificationInput, req.body)) return [];
      if (kind === "transfer" && (!window.sessionCookie || window.sessionCookie !== cookie(req.cookie))) return [];
      return [index];
    });
    if (matching.length !== 1 || typeof snapshot.identifier !== "string") return;
    let logical: string;
    if (kind === "otp") {
      if (req.method !== "POST" || !row(req.body) || req.body.type !== "sign-in" || typeof req.body.email !== "string"
        || !row(value.delivery) || value.delivery.email !== req.body.email || value.delivery.type !== "sign-in"
        || typeof value.delivery.otp !== "string" || !/^\d{6}$/.test(value.delivery.otp) || snapshot.value !== `${value.delivery.otp}:0`) return;
      logical = `sign-in-otp-${req.body.email}`;
    } else if (kind === "magic") {
      if (req.method !== "POST" || !row(req.body) || typeof req.body.email !== "string" || !row(value.delivery)
        || value.delivery.email !== req.body.email || typeof value.delivery.token !== "string"
        || snapshot.value !== JSON.stringify({email: req.body.email, name: req.body.name})) return;
      logical = value.delivery.token;
    } else {
      const trace = traces[matching[0]!] as Row;
      if (req.method !== "GET" || !row(trace.responseBody) || typeof trace.responseBody.token !== "string" || typeof snapshot.value !== "string") return;
      logical = `one-time-token:${trace.responseBody.token}`;
    }
    if (snapshot.identifier !== hash(logical)) return;
    return {index: matching[0]!, kind, cookie: cookie(req.cookie)};
  }
  lt.forEach((trace, index) => {
    const other = rt[index];
    if (!row(trace) || !row(other) || trace.method !== "GET" || other.method !== "GET"
      || trace.path !== verificationPublicationObserver || other.path !== verificationPublicationObserver
      || trace.responseStatus !== 200 || other.responseStatus !== 200 || trace.actor !== other.actor
      || !row(trace.responseBody) || !row(other.responseBody)
      || !Array.isArray(trace.responseBody.publications) || !Array.isArray(other.responseBody.publications)) return;
    const others = other.responseBody.publications;
    trace.responseBody.publications.forEach((a, publicationIndex) => {
      const b = others[publicationIndex];
      if (!row(a) || !row(b)) return;
      const pa = admission(a, lt, leftWindows), pb = admission(b, rt, rightWindows);
      const sameProducer = pa && pb && pa.index === pb.index && pa.kind === pb.kind
        && row(lt[pa.index]) && row(rt[pb.index]) && lt[pa.index].actor === rt[pb.index].actor;
      const transfer = sameProducer && pa.kind === "transfer";
      const valid = !!sameProducer && (!transfer || (!!pa.cookie && !!pb.cookie
        && row(a.snapshot) && row(b.snapshot) && typeof a.snapshot.value === "string" && typeof b.snapshot.value === "string"
        && sessionPair(a.snapshot.value, b.snapshot.value, pa.cookie, pb.cookie)));
      result.push({left: a, right: b, producerIndex: pa?.index ?? -1, kind: pa?.kind ?? "otp", valid});
    });
  });
  return result;
}

export function samePublication(a: unknown, b: unknown): boolean { return exact(a, b); }
