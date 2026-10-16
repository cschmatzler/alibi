import { once } from "node:events";
import { createServer } from "node:http";

import { expect, test } from "vitest";

import { createTracingFetch, type TraceEntry } from "../support/trace";

test("streamed request bodies retain bytes and media headers with the unmodified Node Request", async () => {
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        body: Buffer.concat(chunks).toString("utf8"),
        contentType: request.headers["content-type"],
      }),
    );
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Expected TCP fixture address");
    const traces: TraceEntry[] = [];
    const traced = createTracingFetch(`http://127.0.0.1:${address.port}`, "stream", traces);
    const response = await traced("/api/auth/echo", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"literal":'));
          controller.enqueue(new TextEncoder().encode('"value"}'));
          controller.close();
        },
      }),
    });
    expect(await response.json()).toEqual({
      body: '{"literal":"value"}',
      contentType: "application/json",
    });
    expect(traces).toHaveLength(1);
    expect(traces[0]!.responseStatus).toBe(200);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
});
