import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { getBody } from "../reference-server/node_modules/better-call/dist/utils.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/better-call/package.json", import.meta.url)));
const auth = JSON.parse(await readFile(new URL("../reference-server/node_modules/better-auth/package.json", import.meta.url)));
assert.equal(auth.version, "1.7.18");
assert.equal(pkg.version, "1.4.5");
const inputs = [
  ["json-utf16", "application/json", Buffer.from('{"\\ud800":"\\udfff","name":"\\ud800"}')],
  ["json-prototype-key", "application/json", Buffer.from('{"__proto__":"kept","constructor":"kept"}')],
  ["json-bom-invalid-utf8", "application/json; charset=iso-8859-1", Buffer.from([239,187,191,123,34,120,34,58,34,255,34,125])],
  ["form-repeat", "application/x-www-form-urlencoded", Buffer.from("name=Ada+Lovelace&tag=first&tag=second&literal=%2B")],
  ["form-bom", "application/x-www-form-urlencoded", Buffer.concat([Buffer.from([239,187,191]), Buffer.from("name=Ada")])],
  ["form-utf8", "application/x-www-form-urlencoded", Buffer.from("%ED%A0%80=%F0%90%80%80&value=%ED%BF%BF")],
  ["form-prototype-key", "application/x-www-form-urlencoded", Buffer.from("__proto__=ignored&constructor=kept&prototype=kept&toString=kept")],
  ["form-percent-bom", "application/x-www-form-urlencoded", Buffer.from("%EF%BB%BFname=%EF%BB%BFAda")],
  ["form-nul", "application/x-www-form-urlencoded", Buffer.from("%00=%00")],
  ["text-bom", "text/plain; charset=iso-8859-1", Buffer.from([239,187,191,104,105,239,187,191])],
  ["text-invalid-utf8", "text/plain", Buffer.from([104,255,105])],
  ["multipart-text", "multipart/form-data; boundary=canonical", Buffer.from("--canonical\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nAda\r\n--canonical--\r\n")],
  ["multipart-prototype-key", "multipart/form-data; boundary=canonical", Buffer.from("--canonical\r\nContent-Disposition: form-data; name=\"__proto__\"\r\n\r\nignored\r\n--canonical\r\nContent-Disposition: form-data; name=\"constructor\"\r\n\r\nkept\r\n--canonical--\r\n")],
];
for (const [mode, encoding, value, filename] of [
  ["multipart-base64-text", "base64", "aGVsbG8="],
  ["multipart-base64-unpadded", "base64", "aGVsbG8"],
  ["multipart-base64-forgiving", "base64", "aG V\ts\nbG8$!===ignored"],
  ["multipart-base64-one-sextet", "base64", "a"],
  ["multipart-base64-two-sextets", "base64", "ab"],
  ["multipart-base64-three-sextets", "base64", "abc"],
  ["multipart-base64-url-alphabet", "base64", "_w"],
  ["multipart-base64-early-padding", "base64", "a=b"],
  ["multipart-base64-unicode", "base64", "ŁŇŖųŬŇŸĽ"],
  ["multipart-base64-case-sensitive", "BASE64", "aGVsbG8="],
  ["multipart-base64-header-whitespace", " base64\t ", "aGVsbG8="],
  ["multipart-base64-file", "base64", "AAH+/w==", "binary.dat"],
]) {
  inputs.push([mode, "multipart/form-data; boundary=canonical", Buffer.from(
    '--canonical\r\nContent-Disposition: form-data; name="value"' +
    (filename === undefined ? "" : `; filename="${filename}"`) +
    "\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: " + encoding +
    "\r\n\r\n" + value + "\r\n--canonical--\r\n"
  )]);
}
const cases = [];
for (const [mode, type] of [
  ["multipart-file-default-type", undefined],
  ["multipart-file-empty-type", ""],
  ["multipart-file-mixed-case-type", "Application/JSON; Charset=UTF-8"],
  ["multipart-file-non-mime-type", "not a mime type"],
  ["multipart-file-non-ascii-type", "text/é"],
  ["multipart-file-tab-type", "text/\tplain"],
]) {
  inputs.push([mode, "multipart/form-data; boundary=canonical", Buffer.from(
    '--canonical\r\nContent-Disposition: form-data; name="value"; filename="file.txt"\r\n' +
    (type === undefined ? "" : `Content-Type: ${type}\r\n`) +
    "\r\nhello\r\n--canonical--\r\n"
  )]);
}
for (const [mode, content_type, bytes] of inputs) {
  const request = new Request("https://body.test", { method: "POST", headers: { "content-type": content_type }, body: bytes });
  const expected = await getBody(request);
  const files = {};
  for (const [name, value] of Object.entries(expected)) {
    if (value instanceof File) {
      files[name] = { filename: value.name, content_type: value.type, bytes: [...new Uint8Array(await value.arrayBuffer())] };
    }
  }
  cases.push({ mode, content_type, bytes: [...bytes], expected, wire: JSON.stringify(expected), files });
}
assert.equal(cases.length, 31);
await writeFile(new URL("../../../src/runtime/body_canonical_cases.json", import.meta.url),
  JSON.stringify({ better_auth: auth.version, better_call: pkg.version, cases }) + "\n");
console.log(cases.length + " actual Better Call" + pkg.version + " body cases under Better Auth" + auth.version);
