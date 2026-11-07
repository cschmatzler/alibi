import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { socialProviders } from "../reference-server/node_modules/@better-auth/core/dist/social-providers/index.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/core/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");
const names = ["roblox", "salesforce", "slack", "spotify", "twitch", "twitter", "vercel", "vk", "zoom"];
const modes = ["missing", "null", "false", "empty", "utf16", "mapped"];
const cases = [];
const fetch = globalThis.fetch;
try {
  for (const name of names) {
    for (const mode of modes) {
      const profile = {
        roblox: { sub: "subject" },
        salesforce: { user_id: "subject" },
        slack: { "https://slack.com/user_id": "subject" },
        spotify: { id: "subject", images: [] },
        twitch: { sub: "subject" },
        twitter: { data: { id: "subject" } },
        vercel: { sub: "subject" },
        vk: { user: { user_id: "subject", email: "vk@fixture.test" } },
        zoom: { id: "subject" },
      }[name];
      if (mode !== "missing" && mode !== "mapped") {
        const value = { null: null, false: false, empty: "", utf16: "\ud800" }[mode];
        const fields = {
          roblox: ["nickname", "preferred_username", "picture"],
          salesforce: ["name", "email", "email_verified"],
          slack: ["name", "email", "email_verified", "picture", "https://slack.com/user_image_512"],
          spotify: ["display_name", "email"],
          twitch: ["preferred_username", "email", "picture", "email_verified"],
          twitter: ["name", "email", "profile_image_url"],
          vercel: ["name", "preferred_username", "email", "picture", "email_verified"],
          vk: ["first_name", "last_name", "birthday", "sex", "avatar"],
          zoom: ["display_name", "email", "pic_url", "verified"],
        }[name];
        const receiver = name === "vk" ? profile.user : name === "twitter" ? profile.data : profile;
        for (const field of fields) receiver[field] = value;
        if (name === "salesforce") profile.photos = { picture: value, thumbnail: value };
        if (name === "spotify") profile.images = [{ url: value }];
      }
      const mapping = mode === "mapped"
        ? { id: "mapped", name: "\udfff", email: "mapped@fixture.test", extra: { text: "\ud800" } }
        : null;
      const mappingUndefined = mode === "mapped" ? ["image", "extraUndefined"] : [];
      let mapCalls = 0;
      globalThis.fetch = async input => {
        const url = String(input instanceof Request ? input.url : input);
        const body = url.includes("user.fields=confirmed_email") ? { data: {} } : profile;
        return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
      };
      const provider = socialProviders[name]({
        clientId: "client", clientSecret: "secret",
        ...(mapping ? { mapProfileToUser: async observed => {
          ++mapCalls;
          assert.deepEqual(observed, profile);
          return { ...mapping, ...Object.fromEntries(mappingUndefined.map(key => [key, undefined])) };
        } } : {}),
      });
      const idToken = `h.${Buffer.from(JSON.stringify(profile)).toString("base64url")}.s`;
      const response = await provider.getUserInfo({ accessToken: "access", idToken });
      assert.ok(response, `${name}/${mode}`);
      assert.equal(mapCalls, mapping ? 1 : 0);
      assert.deepEqual(response.data, profile);
      cases.push({
        provider: name, mode, profile, mapping, mapping_undefined: mappingUndefined,
        expected: response.user,
        keys: Object.keys(response.user),
        undefined: Object.keys(response.user).filter(key => response.user[key] === undefined),
      });
    }
  }
} finally {
  globalThis.fetch = fetch;
}
assert.equal(cases.length, 54);
await writeFile(new URL("../../../crates/plugins/src/oauth/providers/remaining_profile_own_fields_cases.json", import.meta.url),
  JSON.stringify({ better_auth: pkg.version, cases }).replaceAll('},{"provider":', '},\n{"provider":') + "\n");
console.log(`${cases.length} provider own-field cases from Better Auth ${pkg.version}`);
