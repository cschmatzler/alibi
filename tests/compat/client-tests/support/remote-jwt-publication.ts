import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import type { RequestWindow } from "./trace";
import { samePublication } from "./verification-publication";

type Row = Record<string, unknown>;
const row = (value: unknown): value is Row =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const digest = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");

/** Authenticate the actual raw-profile default-expiry producer and its complete copies.
 * The installed signJWT uses its 15m default only for nullish exp/iat; the raw
 * fixture has no expiration override. No caller-supplied expiry is admitted.
 */
export function remoteJwtDefaultPublication(
  value: unknown,
  windows: readonly (RequestWindow | undefined)[] | undefined,
  secret: string,
): Row | undefined {
  if (!row(value) || !row(value.observation)) return;
  const observation = value.observation;
  if (!row(observation.response) || !row(observation.response.body) || !row(observation.verified)) {
    return;
  }
  const response = observation.response.body;
  const verified = observation.verified;
  if (
    observation.response.status !== 200 ||
    typeof response.token !== "string" ||
    verified.token !== response.token
  ) {
    return;
  }
  const issued = windows?.find((window) => {
    const publication = window?.remoteJwtSigning;
    return (
      publication &&
      samePublication(publication.response, response) &&
      publication.digest === digest([publication.input, publication.response])
    );
  });
  const input = issued?.remoteJwtSigning?.input;
  if (
    !issued ||
    !row(input) ||
    input.operation !== "sign" ||
    input.profile !== "jwt-remote-raw" ||
    !row(input.payload) ||
    input.payload.exp !== null ||
    input.payload.iat !== null ||
    !Array.isArray(input.nanFields) ||
    input.nanFields.length !== 0 ||
    !samePublication(input.header, { typ: "application+jwt", custom: "retained" }) ||
    input.signingKeyId !== "application-selected-key" ||
    input.signingAlgorithm !== "ES256"
  ) {
    return;
  }
  try {
    const parts = response.token.split(".");
    if (parts.length !== 3) return;
    const signature = Buffer.from(parts[2]!, "base64url");
    const expected = createHmac("sha256", secret).update(`${parts[0]}.${parts[1]}`).digest();
    if (
      signature.toString("base64url") !== parts[2] ||
      signature.length !== expected.length ||
      !timingSafeEqual(signature, expected)
    ) {
      return;
    }
    const header: unknown = JSON.parse(Buffer.from(parts[0]!, "base64url").toString());
    const payload: unknown = JSON.parse(Buffer.from(parts[1]!, "base64url").toString());
    if (
      !row(payload) ||
      !samePublication(header, {
        ...(input.header as Row),
        alg: "HS256",
        kid: "application-remote-key",
      }) ||
      !samePublication(verified.header, header) ||
      !samePublication(verified.payload, payload)
    ) {
      return;
    }
    const expiry = payload.exp;
    if (
      typeof expiry !== "number" ||
      !Number.isInteger(expiry) ||
      !Number.isFinite(issued.startedAt) ||
      !Number.isFinite(issued.finishedAt) ||
      issued.finishedAt < issued.startedAt ||
      expiry < Math.floor(issued.startedAt / 1000) + 900 ||
      expiry > Math.floor(issued.finishedAt / 1000) + 900
    ) {
      return;
    }
    const expectedPayload = {
      ...input.payload,
      iat: null,
      exp: expiry,
      nbf: input.payload.nbf,
      iss: input.payload.iss ?? "remote-application-issuer",
      aud: input.payload.aud ?? "remote-application-audience",
    };
    if (!samePublication(payload, expectedPayload)) return;
    const observer = windows?.find(
      (window) =>
        window?.remoteJwtObserver &&
        window.startedAt >= issued.finishedAt &&
        window.remoteJwtObserver.digest === digest(window.remoteJwtObserver.body) &&
        samePublication(window.remoteJwtObserver.body, observation.captured),
    );
    const captured = observation.captured;
    if (
      !observer ||
      !row(captured) ||
      !Array.isArray(captured.events) ||
      captured.events.length !== 1 ||
      !row(captured.events[0])
    ) {
      return;
    }
    const event = captured.events[0];
    if (
      !samePublication(event.payload, payload) ||
      !samePublication(event.ownKeys, Object.keys(expectedPayload)) ||
      !samePublication(event.header, input.header) ||
      !samePublication(event.options, {
        signingKeyId: input.signingKeyId,
        signingAlgorithm: input.signingAlgorithm,
      })
    ) {
      return;
    }
    return payload;
  } catch {
    return;
  }
}

/** Only the four producer-bound owner observations can share this default clock. */
export function remoteJwtDefaultCopy(
  value: Row,
  published: Row | undefined,
  path: string,
): boolean {
  return (
    published !== undefined &&
    /^observation\.(?:captured\.events\.0\.payload|response\.body\.token\.payload|verified\.payload|verified\.token\.payload)$/.test(
      path,
    ) &&
    samePublication(value, published)
  );
}
