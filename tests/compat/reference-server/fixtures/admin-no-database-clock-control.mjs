import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { betterAuth } from "better-auth";
import { admin } from "better-auth/plugins/admin";
// Explicit fixture clock; published files are untouched. Both constructor and
// Date.now return the exact same instant; monotonic runtime clocks stay real.
const RealDate = Date;
const clockMs = 1893456000000;
class ProofDate extends RealDate {
  constructor(...args) {
    super(...(args.length ? args : [clockMs]));
  }
  static now() {
    return clockMs;
  }
}
globalThis.Date = ProofDate;
assert.equal(new Date().getTime(), Date.now());
const secret = "numeric-admin-identity-secret-at-least-32";
const options = {
  secret,
  baseURL: "http://localhost:31984",
  plugins: [admin()],
  emailAndPassword: { enabled: true },
};
const auth = betterAuth(options);
const ctx = await auth.$context;
const actor = await ctx.internalAdapter.createUser({
  name: "Actor",
  email: "actor@no-db.fixture.test",
  role: "admin",
  emailVerified: false,
});
const target = await ctx.internalAdapter.createUser({
  name: "Target",
  email: "target@no-db.fixture.test",
  role: "user",
  emailVerified: false,
});
await ctx.internalAdapter.createAccount({
  userId: target.id,
  accountId: target.id,
  providerId: "credential",
  password: await ctx.password.hash("Password123!"),
});
const original = await ctx.internalAdapter.createSession(actor.id);
const snapshot = async () =>
  Object.fromEntries(
    await Promise.all(
      ["user", "account", "session"].map(async (model) => [
        model,
        await ctx.adapter.findMany({ model }),
      ]),
    ),
  );
const signed = encodeURIComponent(
  original.token +
    "." +
    createHmac("sha256", secret).update(original.token).digest("base64"),
);
for (const path of ["/admin/impersonate-user", "/sign-in/email"]) {
  for (const [delta, status] of [
    [0, 403],
    [1, 403],
    [-1, 200],
  ]) {
    await ctx.internalAdapter.updateUser(target.id, {
      banned: true,
      banReason: "boundary",
      banExpires: new Date(clockMs + delta),
    });
    const before = await snapshot();
    const response = await auth.handler(
      new Request(options.baseURL + "/api/auth" + path, {
        method: "POST",
        headers: {
          origin: options.baseURL,
          "content-type": "application/json",
          cookie: `better-auth.session_token=${signed}`,
        },
        body: JSON.stringify(
          path === "/sign-in/email"
            ? { email: target.email, password: "Password123!" }
            : { userId: target.id },
        ),
      }),
    );
    const body = await response.text();
    const after = await snapshot();
    console.log(
      JSON.stringify({
        path,
        delta,
        clockMs,
        status: response.status,
        body,
        before,
        after,
        actor: actor.id,
        target: target.id,
      }),
    );
    assert.equal(response.status, status);
    assert.deepEqual(after.account, before.account);
    for (const u of before.user.filter((u) => u.id !== target.id)) {
      assert.deepEqual(
        after.user.find((v) => v.id === u.id),
        u,
      );
    }
    for (const row of before.session) {
      assert.deepEqual(
        after.session.find((s) => s.id === row.id),
        row,
      );
    }
    if (status === 403) assert.deepEqual(after, before);
    else {
      assert.equal(JSON.parse(body).user.id, target.id);
      assert.equal(
        (await ctx.internalAdapter.findUserById(target.id)).banned,
        false,
      );
    }
  }
}
