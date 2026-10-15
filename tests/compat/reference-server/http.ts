import { createServer as createHTTPServer } from "node:http";
import { createServer as createHTTPSServer, type ServerOptions } from "node:https";
import type { AddressInfo } from "node:net";

import { getRequestListener } from "@hono/node-server";

type RequestScope = (handler: () => Response | Promise<Response>) => Response | Promise<Response>;
let requestScope: RequestScope = (handler) => handler();

/** Attribute asynchronous fixture work to the originating assurance window. */
export function setRequestScope(scope: RequestScope) {
  requestScope = scope;
}

/** Web Request/Response transport shared by the oracle and local HTTP providers. */
export async function serveFixture(options: {
  hostname?: string;
  port?: number;
  idleTimeout?: number;
  tls?: ServerOptions;
  fetch(request: Request): Response | Promise<Response>;
}) {
  const listener = getRequestListener((request) => requestScope(() => options.fetch(request)));
  const server = options.tls
    ? createHTTPSServer(options.tls, listener)
    : createHTTPServer(listener);
  server.timeout = (options.idleTimeout ?? 60) * 1000;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, options.hostname ?? "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const port = (server.address() as AddressInfo).port;
  const url = new URL(`${options.tls ? "https" : "http"}://localhost:${port}/`);
  return {
    port,
    url,
    unref() {
      server.unref();
    },
    async stop(force = false) {
      const stopped = new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
      if (force) server.closeAllConnections();
      await stopped;
    },
  };
}
