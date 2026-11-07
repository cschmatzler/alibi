import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { wechat } from "../reference-server/node_modules/@better-auth/core/dist/social-providers/index.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/core/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");
const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
const requests = [];
const fetch = globalThis.fetch;
const cases = [];
try {
  globalThis.fetch = async url => {
    requests.push(String(url));
    return new Response(JSON.stringify({
      access_token: "access", refresh_token: "refresh", openid: "token-open",
      scope: "snsapi_login", expires_in: 7200,
    }), { status: 200, headers: { "content-type": "application/json" } });
  };
  for (const ids of [[], ["single"], ["first", "second"], ["client: +", "second/&"]]) {
    const provider = wechat({ clientId: ids, clientSecret: "secret" });
    const start = requests.length;
    await provider.validateAuthorizationCode({ code: "code", redirectURI: "https://app.example/callback" });
    await provider.refreshAccessToken("refresh");
    const sent = requests.slice(start).map(url => ({ url, appid: new URL(url).searchParams.getAll("appid") }));
    assert.equal(sent.length, 2);
    for (const { appid } of sent) assert.deepEqual(appid, ids);
    cases.push({ ids, sent });
  }
} finally {
  globalThis.fetch = fetch;
}
console.log(JSON.stringify({ version: pkg.version, revision: pin.commit, node: process.version, cases }, null, 2));
