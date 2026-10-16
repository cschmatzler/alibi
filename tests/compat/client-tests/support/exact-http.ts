import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

export async function exactHttpFetch(input: Request): Promise<Response> {
  const bytes = input.body === null ? undefined : new Uint8Array(await input.arrayBuffer());
  const send = new URL(input.url).protocol === "https:" ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    const outgoing = send(
      input.url,
      {
        method: input.method,
        headers: Object.fromEntries(input.headers),
        signal: input.signal,
      },
      (incoming) => {
        const chunks: Buffer[] = [];
        incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
        incoming.once("error", reject);
        incoming.once("end", () => {
          const headers = new Headers();
          for (let i = 0; i < incoming.rawHeaders.length; i += 2) {
            headers.append(incoming.rawHeaders[i]!, incoming.rawHeaders[i + 1]!);
          }
          const status = incoming.statusCode!;
          const empty = input.method === "HEAD" || [204, 205, 304].includes(status);
          const response = new Response(empty ? null : Buffer.concat(chunks), {
            status,
            statusText: incoming.statusMessage,
            headers,
          });
          Object.defineProperty(response, "url", { value: input.url });
          resolve(response);
        });
      },
    );
    outgoing.once("error", reject);
    outgoing.end(bytes);
  });
}
