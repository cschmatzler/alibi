import type { Database } from "bun:sqlite";

/** Read actual credential/session rows and control trusted fixture clock/counter state. */
export function passkeyFixture(database: Database) {
  return async (request: Request): Promise<Response | null> => {
    const url = new URL(request.url);

    if (url.pathname === "/__test/passkey-state") {
      const userId = url.searchParams.get("userId") ?? "";
      return Response.json({
        passkeys: database.query('SELECT "userId", counter, name FROM passkey ORDER BY id').all(),
        sessions: database
          .query('SELECT COUNT(*) AS count FROM session WHERE "userId" = ?')
          .get(userId),
        challenges: database.query("SELECT COUNT(*) AS count FROM verification").get(),
      });
    }

    if (url.pathname === "/__test/passkey-current-counter" && request.method === "POST") {
      const body = (await request.json()) as { credentialId: string; counter: number };
      const result = database
        .query('UPDATE passkey SET counter = ? WHERE "credentialID" = ?')
        .run(body.counter, body.credentialId);
      return Response.json({ updated: result.changes });
    }

    if (url.pathname === "/__test/passkey-challenge-clock" && request.method === "POST") {
      const body = (await request.json()) as { expiresAt: string };
      database
        .query('UPDATE verification SET "expiresAt" = ?')
        .run(new Date(body.expiresAt).getTime());
      return Response.json({ updated: true });
    }

    return null;
  };
}
