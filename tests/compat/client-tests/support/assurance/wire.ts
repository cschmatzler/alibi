import { readFileSync } from "node:fs";
import { z } from "zod";
import { digest } from "./common";
import { assuranceEvent, assurancePhase } from "./evidence";

export const wireMutationSchema = z
  .object({
    id: z.string().regex(/^wire:[0-9a-f]{24}$/),
    kind: z.literal("wire"),
    route: z.string(),
    method: z.string(),
    operator: z.enum([
      "drop-field",
      "change-value",
      "drop-header",
      "drop-cookie",
      "drop-http-only",
      "change-status",
    ]),
    pointer: z.array(z.string()),
    scenario: z.string(),
  })
  .strict()
  .refine(
    (value) =>
      value.id ===
      `wire:${digest(JSON.stringify([value.method, value.route, value.operator, value.pointer])).slice(0, 24)}`,
    "Wire mutation identity does not match its target",
  );
export type WireMutation = z.infer<typeof wireMutationSchema>;
const configuredPath = process.env.COMPAT_ASSURANCE_WIRE_MUTATION;
const configured = configuredPath
  ? wireMutationSchema.parse(JSON.parse(readFileSync(configuredPath, "utf8")))
  : undefined;
const discovered = new Set<string>();
const routes = (
  JSON.parse(
    readFileSync(
      new URL("../../../capabilities.json", import.meta.url),
      "utf8",
    ),
  ) as { capabilities: { route: string }[] }
).capabilities.map((entry) => entry.route);

function routeFor(request: Request): string | undefined {
  const path = new URL(request.url).pathname;
  const prefix = path.match(
    /^(?:\/__test\/profiles\/[a-z0-9-]+)?\/api\/auth(?=\/)/,
  )?.[0];
  if (!prefix) return;
  const endpoint = path.slice(prefix.length);
  const pattern =
    routes
      .find((route) => {
        const [method, pathname] = route.split(" ");
        return (
          method === request.method &&
          pathname?.split("/").length === endpoint.split("/").length &&
          pathname
            .split("/")
            .every(
              (part, index) =>
                part === "{}" || part === endpoint.split("/")[index],
            )
        );
      })
      ?.split(" ")[1] ?? endpoint;
  return prefix + pattern;
}
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}
const transportHeaders = new Set([
  "date",
  "server",
  "connection",
  "keep-alive",
  "content-length",
  "transfer-encoding",
  "set-cookie",
]);

/** Discover mutation targets from actual oracle responses, never from assertions. */
export async function mutateTransport(
  request: Request,
  response: Response,
): Promise<Response> {
  const phase = assurancePhase(),
    route = routeFor(request);
  if (
    !phase ||
    !route ||
    (!configured && process.env.COMPAT_ASSURANCE_DISCOVER_WIRE !== "1")
  )
    return response;
  const isDiscovery =
    process.env.COMPAT_ASSURANCE_DISCOVER_WIRE === "1" && phase.label === "TS";
  const active =
    configured &&
    phase.label === "Rust" &&
    configured.route === route &&
    configured.method === request.method;
  if (!isDiscovery && !active) return response;
  const text = await response.clone().text();
  let body: unknown;
  let json = true;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
    json = false;
  }
  function discover(operator: WireMutation["operator"], pointer: string[]) {
    const id = `wire:${digest(JSON.stringify([request.method, route, operator, pointer])).slice(0, 24)}`;
    if (discovered.has(id)) return;
    discovered.add(id);
    const candidate: WireMutation = {
      id,
      kind: "wire",
      route: route!,
      method: request.method,
      operator,
      pointer,
      scenario: phase!.name,
    };
    assuranceEvent({ event: "wire-candidate", candidate });
  }
  if (isDiscovery) {
    discover("change-status", []);
    for (const name of response.headers.keys())
      if (!transportHeaders.has(name)) discover("drop-header", [name]);
    for (const raw of response.headers.getSetCookie()) {
      const name = raw.split("=", 1)[0]!;
      discover("drop-cookie", [name]);
      if (/;\s*httponly(?:;|$)/i.test(raw)) discover("drop-http-only", [name]);
    }
    function walk(value: unknown, path: string[]) {
      if (record(value)) {
        for (const key of Object.keys(value)) {
          discover("drop-field", [...path, key]);
          walk(value[key], [...path, key]);
        }
      } else discover("change-value", path);
    }
    if (json) walk(body, []);
    else if (text) discover("change-value", []);
  }
  if (!active || !configured) return response;
  const headers = new Headers(response.headers);
  let changed = false,
    status = response.status,
    output = text;
  if (configured.operator === "change-status") {
    status = response.status === 200 ? 400 : 200;
    changed = true;
  } else if (configured.operator === "drop-header") {
    changed = headers.has(configured.pointer[0]!);
    headers.delete(configured.pointer[0]!);
  } else if (
    configured.operator === "drop-cookie" ||
    configured.operator === "drop-http-only"
  ) {
    const cookies = headers.getSetCookie();
    headers.delete("set-cookie");
    for (const cookie of cookies) {
      if (cookie.startsWith(`${configured.pointer[0]}=`)) {
        if (configured.operator === "drop-cookie") {
          changed = true;
          continue;
        }
        const next = cookie.replace(/;\s*httponly(?=;|$)/gi, "");
        changed ||= next !== cookie;
        headers.append("set-cookie", next);
      } else headers.append("set-cookie", cookie);
    }
  } else if (
    !json &&
    configured.operator === "change-value" &&
    configured.pointer.length === 0
  ) {
    output = `${text}__assurance_mutation`;
    changed = true;
  } else if (json) {
    const pointer = configured.pointer;
    let parent = body;
    for (const key of pointer.slice(0, -1))
      parent =
        record(parent) && Object.hasOwn(parent, key) ? parent[key] : undefined;
    const last = pointer.at(-1);
    const exists =
      pointer.length === 0 ||
      (last !== undefined && record(parent) && Object.hasOwn(parent, last));
    if (exists) {
      if (
        configured.operator === "drop-field" &&
        last !== undefined &&
        record(parent)
      ) {
        if (Array.isArray(parent)) parent.splice(Number(last), 1);
        else delete parent[last];
        changed = true;
      } else if (configured.operator === "change-value") {
        const old =
          pointer.length === 0
            ? body
            : (parent as Record<string, unknown>)[last!];
        if (!record(old)) {
          const value =
            typeof old === "boolean"
              ? !old
              : typeof old === "number"
                ? old + 86400
                : typeof old === "string"
                  ? `${old}__assurance_mutation`
                  : "__assurance_mutation";
          if (pointer.length === 0) body = value;
          else (parent as Record<string, unknown>)[last!] = value;
          changed = !Object.is(old, value);
        }
      }
      if (changed) output = JSON.stringify(body);
    }
  }
  assuranceEvent({
    event: "wire-receipt",
    id: configured.id,
    scenario: phase.name,
    route,
    operator: configured.operator,
    pointer: configured.pointer,
    changed,
  });
  if (!changed) return response;
  headers.delete("content-length");
  headers.delete("transfer-encoding");
  const replacement = new Response(
    [204, 205, 304].includes(status) ? null : output,
    {
      status,
      headers,
      ...(status === response.status
        ? { statusText: response.statusText }
        : {}),
    },
  );
  for (const name of ["url", "redirected", "type"] as const)
    Object.defineProperty(replacement, name, {
      value: response[name],
      configurable: true,
    });
  const clone = replacement.clone.bind(replacement);
  replacement.clone = () => {
    const copy = clone();
    for (const name of ["url", "redirected", "type"] as const)
      Object.defineProperty(copy, name, {
        value: response[name],
        configurable: true,
      });
    return copy;
  };
  return replacement;
}
