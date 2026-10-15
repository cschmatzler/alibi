import { readFile } from "node:fs/promises";

import type { Database } from "better-sqlite3";

/** Read actual credential/session rows and control trusted fixture clock/counter state. */
export function passkeyFixture(database: Database) {
  return async (request: Request): Promise<Response | null> => {
    const url = new URL(request.url);

    if (url.pathname === "/__test/passkey-crl") {
      return new Response(
        await readFile(new URL("../../fixtures/passkey-attestation/revoked.der", import.meta.url)),
      );
    }

    if (url.pathname === "/__test/passkey-state") {
      const userId = url.searchParams.get("userId") ?? "";
      return Response.json({
        passkeys: database.prepare('SELECT "userId", counter, name FROM passkey ORDER BY id').all(),
        sessions: database
          .prepare('SELECT COUNT(*) AS count FROM session WHERE "userId" = ?')
          .get(userId),
        challenges: database.prepare("SELECT COUNT(*) AS count FROM verification").get(),
      });
    }

    if (url.pathname === "/__test/passkey-current-counter" && request.method === "POST") {
      const body = (await request.json()) as { credentialId: string; counter: number };
      const result = database
        .prepare('UPDATE passkey SET counter = ? WHERE "credentialID" = ?')
        .run(body.counter, body.credentialId);
      return Response.json({ updated: result.changes });
    }

    if (url.pathname === "/__test/passkey-public-key" && request.method === "POST") {
      const body = (await request.json()) as { credentialId: string; publicKey: string };
      const result = database
        .prepare('UPDATE passkey SET "publicKey" = ? WHERE "credentialID" = ?')
        .run(body.publicKey, body.credentialId);
      return Response.json({ updated: result.changes });
    }

    if (url.pathname === "/__test/passkey-challenge-clock" && request.method === "POST") {
      const body = (await request.json()) as { expiresAt: string };
      database
        .prepare('UPDATE verification SET "expiresAt" = ?')
        .run(new Date(body.expiresAt).getTime());
      return Response.json({ updated: true });
    }

    return null;
  };
}
