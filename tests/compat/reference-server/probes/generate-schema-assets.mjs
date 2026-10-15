import { spawnSync } from "node:child_process";
import { readFile as readFixtureFile } from "node:fs/promises";

import { writeArtifact } from "../../support/files.ts";
// Refresh the SQL and independent database snapshots from the pinned packages.
// Requires BETTER_AUTH_TEST_POSTGRES_URL pointing to a disposable PostgreSQL database.
import { snapshot } from "./schema-parity.mjs";

const root = new URL("../../../../", import.meta.url);
const packageJson = JSON.parse(
  await readFixtureFile(
    new URL("../node_modules/better-auth/package.json", import.meta.url),
    "utf8",
  ),
);
if (packageJson.version !== snapshot.version) {
  throw new Error(`Expected Better Auth ${snapshot.version}, got ${packageJson.version}`);
}

function probe(dialect, inspect = false) {
  const result = spawnSync(
    "nub",
    [
      new URL("./compile-schema.mjs", import.meta.url).pathname,
      dialect,
      ...(inspect ? ["inspect"] : []),
    ],
    { env: process.env },
  );
  if (result.status !== 0) throw new Error(result.stderr.toString());
  return result.stdout.toString();
}

const oauthTables = new Set(
  Object.entries(snapshot.tables)
    .filter(([name]) => name.startsWith("oauth"))
    .map(([, table]) => table.modelName),
);
for (const dialect of ["sqlite", "postgres"]) {
  const groups = { auth: [], oauth: [], rate: [], sso: [] };
  for (const statement of probe(dialect)
    .split(";")
    .map((sql) => sql.trim())
    .filter(Boolean)) {
    const match = statement.match(
      /^create table "([^"]+)"|^create(?: unique)? index .*? on "([^"]+)"/i,
    );
    if (!match) throw new Error(`Unexpected upstream migration statement: ${statement}`);
    const table = match[1] ?? match[2];
    groups[
      table === "ssoProvider"
        ? "sso"
        : table === "rateLimit"
          ? "rate"
          : oauthTables.has(table)
            ? "oauth"
            : "auth"
    ].push(`${statement};`);
  }
  for (const [group, suffix] of [
    ["auth", ""],
    ["oauth", "_oauth_clients"],
    ["rate", "_rate_limit"],
    ["sso", "_sso"],
  ]) {
    await writeArtifact(
      new URL(`crates/schema-registry/schema/${dialect}${suffix}.sql`, root),
      `-- Generated from Better Auth ${snapshot.version} by the schema parity probe.\n\n${groups[group].join("\n\n")}\n`,
    );
  }
  const oracle = JSON.parse(probe(dialect, true));
  if (oracle.length !== 25) throw new Error(`Expected 25 ${dialect} tables`);
  await writeArtifact(
    new URL(`tests/fixtures/schema/${dialect}-${snapshot.version}.json`, root),
    `${JSON.stringify(oracle, null, 2)}\n`,
  );
}
await writeArtifact(
  new URL(`crates/schema-registry/schema/better-auth-${snapshot.version}.json`, root),
  `${JSON.stringify(snapshot, null, 2)}\n`,
);
