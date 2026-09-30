import { z } from "zod";
export const TS_BASE_URL = process.env.AUTH_BASE_URL_TS || "http://localhost:3100";
export const RUST_BASE_URL = process.env.AUTH_BASE_URL_RUST || "http://localhost:3200";
export const LOCAL_NO_PROXY = "localhost,127.0.0.1";

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
  return z.object({ ok: z.literal(true), oauthBaseURL: z.string().url().optional() }).parse(await response.json());
}
