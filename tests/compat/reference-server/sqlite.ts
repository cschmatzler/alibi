import Database from "better-sqlite3";

function binding(value: unknown): unknown {
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  if (Array.isArray(value)) return value.map(binding);
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(Object.entries(value).map(([key, value]) => [key, binding(value)]));
  }
  return value;
}

/** All fixtures share the same explicit persistence policy as the Rust pair. */
export function createDatabase(filename = ":memory:") {
  const database = new Database(filename);
  database.pragma("foreign_keys = OFF");
  // Node SQLite drivers bind every Number as REAL. Preserve the fixture's
  // integer binding contract, including SQLite's observable TEXT coercion.
  database.prepare = new Proxy(database.prepare, {
    apply(prepare, database, parameters) {
      const statement: Database.Statement = Reflect.apply(prepare, database, parameters);
      return new Proxy(statement, {
        get(statement, key) {
          const value = Reflect.get(statement, key, statement);
          if (
            typeof value === "function" &&
            ["run", "get", "all", "iterate", "bind"].includes(String(key))
          ) {
            return (...parameters: unknown[]) =>
              Reflect.apply(value, statement, parameters.map(binding));
          }
          return value;
        },
      });
    },
  });
  return database;
}
