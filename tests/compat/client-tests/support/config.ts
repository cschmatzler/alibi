import { z } from "zod";
export const TS_BASE_URL = process.env.AUTH_BASE_URL_TS || "http://localhost:3100";
export const RUST_BASE_URL = process.env.AUTH_BASE_URL_RUST || "http://localhost:3200";
export const LOCAL_NO_PROXY = "localhost,127.0.0.1";

/** The committed oracle release; `capabilities.json` is the single source of truth. */
export const UPSTREAM_VERSION: string = z
  .object({ upstreamVersion: z.string().regex(/^\d+\.\d+\.\d+$/) })
  .parse(await Bun.file(new URL("../../capabilities.json", import.meta.url)).json()).upstreamVersion;

const healthSchema = z.object({
  ok: z.literal(true),
  oauthBaseURL: z.string().url().optional(),
  // Every fixture server must state which better-auth release it reproduces.
  upstreamVersion: z.literal(UPSTREAM_VERSION),
});

export async function requireHealthy(baseURL: string, label: string) {
  const response = await fetch(`${baseURL}/__health`, {
    headers: {
      connection: "close",
    },
    signal: AbortSignal.timeout(5000),
  }).catch(() => null);

  if (!response?.ok) {
    throw new Error(`${label} server is not reachable at ${baseURL}`);
  }
  const parsed = healthSchema.safeParse(await response.json());
  if (!parsed.success) {
    throw new Error(`${label} server at ${baseURL} does not declare the pinned better-auth ${UPSTREAM_VERSION}: ${parsed.error.message}`);
  }
  return parsed.data;
}
