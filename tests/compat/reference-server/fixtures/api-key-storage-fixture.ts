import type { Database } from "bun:sqlite";

import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { organization, username } from "better-auth/plugins";

type Entry = { value: string; expiresAt: number | null };

/** Real application stores; controls never implement API-key admission or index maintenance. */
export async function apiKeyStorageFixture(
  database: Database,
  options: Parameters<typeof betterAuth>[0],
) {
  const maps = new Map<string, Map<string, Entry>>([
    ["secondary", new Map()],
    ["custom", new Map()],
    ["isolated", new Map()],
  ]);
  for (let group = 0; group < 32; group++) maps.set(`group-${group}`, new Map());
  let generated = 0;
  let failure = "";
  let failStore = "";
  let holdStore = "";
  let hashReads = 0;
  let holdAt = -1;
  let captureBeforeWait = false;
  let holdOperation = "";
  let activeStorage = 0;
  let entered = 0;
  const blocked = new Set<() => void>();
  const listeners = new Set<() => void>();
  const completions = new Set<Promise<unknown>>();
  function notify() {
    for (const listener of listeners) listener();
  }
  function release() {
    holdAt = -1;
    holdOperation = "";
    for (const sender of blocked) sender();
    blocked.clear();
  }
  async function hold(operation: string, name: string) {
    if (holdOperation === operation && holdStore === name) {
      const wait = new Promise<void>((resolve) => blocked.add(resolve));
      entered++;
      notify();
      await wait;
    }
  }
  const storage = (name: string) => ({
    async get(key: string) {
      activeStorage++;
      try {
        const map = maps.get(name)!;
        const read = () => {
          const entry = map.get(key);
          if (
            entry?.expiresAt !== null &&
            entry?.expiresAt !== undefined &&
            entry.expiresAt <= Date.now()
          ) {
            map.delete(key);
            return null;
          }
          return entry?.value ?? null;
        };
        const captured = captureBeforeWait ? read() : null;
        if (key.startsWith("api-key:") && !key.startsWith("api-key:by-") && name !== "isolated") {
          hashReads++;
          if (holdAt === 0 || holdAt === hashReads) {
            const wait = new Promise<void>((resolve) => blocked.add(resolve));
            entered++;
            notify();
            await wait;
          }
        }
        if (key.startsWith("api-key:")) {
          await hold(
            `get-${key.startsWith("api-key:by-ref:") ? "reference" : key.startsWith("api-key:by-id:") ? "id" : "hash"}`,
            name,
          );
        }
        if (key.startsWith("api-key:") && failure === "get" && failStore === name) {
          throw new Error("application storage veto");
        }
        return captureBeforeWait ? captured : read();
      } finally {
        activeStorage--;
        notify();
      }
    },
    async set(key: string, value: string, ttl?: number) {
      activeStorage++;
      try {
        const kind = key.startsWith("api-key:by-id:")
          ? "id"
          : key.startsWith("api-key:by-ref:")
            ? "reference"
            : "hash";
        if (key.startsWith("api-key:")) await hold(`set-${kind}`, name);
        if (key.startsWith("api-key:") && failure === `set-${kind}` && failStore === name) {
          failure = "";
          throw new Error("application storage veto");
        }
        maps
          .get(name)!
          .set(key, { value, expiresAt: ttl === undefined ? null : Date.now() + ttl * 1000 });
      } finally {
        activeStorage--;
        notify();
      }
    },
    async delete(key: string) {
      activeStorage++;
      try {
        const kind = key.startsWith("api-key:by-id:")
          ? "id"
          : key.startsWith("api-key:by-ref:")
            ? "reference"
            : "hash";
        if (key.startsWith("api-key:")) await hold(`delete-${kind}`, name);
        if (key.startsWith("api-key:") && failure === `delete-${kind}` && failStore === name) {
          failure = "";
          throw new Error("application storage veto");
        }
        maps.get(name)!.delete(key);
      } finally {
        activeStorage--;
        notify();
      }
    },
    async getAndDelete(key: string) {
      const entry = maps.get(name)!.get(key);
      maps.get(name)!.delete(key);
      return entry && (entry.expiresAt === null || entry.expiresAt > Date.now())
        ? entry.value
        : null;
    },
    async increment(key: string, ttl: number) {
      const map = maps.get(name)!;
      const entry = map.get(key);
      const live =
        entry && (entry.expiresAt === null || entry.expiresAt > Date.now()) ? entry : undefined;
      const value = Number(live?.value ?? 0) + 1;
      map.set(key, { value: String(value), expiresAt: live?.expiresAt ?? Date.now() + ttl * 1000 });
      return value;
    },
  });
  async function buildProfile(name: string, custom: boolean, fallback: boolean, deferred: boolean) {
    const path = `/__test/profiles/${name}/api/auth`;
    const settings = {
      storage: "secondary-storage" as const,
      fallbackToDatabase: fallback,
      deferUpdates: deferred,
      enableMetadata: true,
      enableSessionForAPIKeys: true,
      rateLimit: { enabled: false },
      keyExpiration: { minExpiresIn: 0 },
      customKeyGenerator() {
        return `public-application-storage-credential-${String(++generated).padStart(8, "0")}`;
      },
      ...(custom ? { customStorage: storage("custom") } : {}),
    };
    const auth = betterAuth({
      ...options,
      basePath: path,
      secondaryStorage: storage("secondary"),
      session: { ...options.session, storeSessionInDatabase: true },
      advanced: {
        ...options.advanced,
        backgroundTasks: {
          handler(completion) {
            completions.add(completion);
            void completion.then(
              () => completions.delete(completion),
              () => completions.delete(completion),
            );
          },
        },
      },
      plugins: [
        username(),
        organization(),
        apiKey(
          name === "api-key-storage-many-groups"
            ? Array.from({ length: 32 }, (_, group) => ({
                ...settings,
                configId: `group-${group}`,
                customStorage: storage(`group-${group}`),
              }))
            : [
                { ...settings, configId: "default" },
                { ...settings, configId: "other" },
                { ...settings, configId: "organization", references: "organization" },
                { ...settings, configId: "isolated", customStorage: storage("isolated") },
              ],
        ),
      ],
    });
    await auth.$context;
    return [path, auth] as const;
  }
  const profiles = new Map<string, Awaited<ReturnType<typeof buildProfile>>[1]>();
  for (const [name, custom, fallback, deferred] of [
    ["api-key-storage-secondary", false, false, false],
    ["api-key-storage-custom", true, false, false],
    ["api-key-storage-fallback", false, true, false],
    ["api-key-storage-custom-fallback", true, true, false],
    ["api-key-storage-deferred", true, false, true],
    ["api-key-storage-fallback-deferred", true, true, true],
    ["api-key-storage-many-groups", false, false, false],
  ] as const) {
    const [path, auth] = await buildProfile(name, custom, fallback, deferred);
    profiles.set(path, auth);
  }
  function snapshot() {
    return [...maps].map(([store, map]) => ({
      store,
      entries: [...map]
        .filter(([index]) => index.startsWith("api-key:"))
        .map(([index, entry]) => {
          const value = JSON.parse(entry.value);
          if (index.startsWith("api-key:by-ref:")) {
            return {
              namespace: "reference",
              lookup: { referenceId: index.slice(15) },
              value: value.map((id: string) => ({ id })),
              expiresAt: entry.expiresAt === null ? null : new Date(entry.expiresAt).toISOString(),
            };
          }
          return {
            namespace: index.startsWith("api-key:by-id:") ? "id" : "hash",
            lookup: index.startsWith("api-key:by-id:")
              ? { id: index.slice(14) }
              : { key: index.slice(8) },
            value,
            expiresAt: entry.expiresAt === null ? null : new Date(entry.expiresAt).toISOString(),
          };
        })
        .sort((a, b) => {
          const order = (entry: any) =>
            `${entry.namespace}:${entry.value.name ?? database.query<{ email: string }, [string]>("SELECT email FROM user WHERE id=?").get(entry.lookup.referenceId)?.email ?? database.query<{ slug: string }, [string]>("SELECT slug FROM organization WHERE id=?").get(entry.lookup.referenceId)?.slug ?? entry.lookup.referenceId}`;
          return order(a).localeCompare(order(b));
        }),
    }));
  }
  async function drain() {
    await Promise.allSettled(completions);
    await new Promise<void>((resolve) => {
      const listener = () => {
        if (activeStorage === 0) {
          listeners.delete(listener);
          resolve();
        }
      };
      listeners.add(listener);
      listener();
    });
  }
  async function reset() {
    release();
    await drain();
    for (const map of maps.values()) map.clear();
    generated = 0;
    failure = "";
    failStore = "";
    hashReads = 0;
    entered = 0;
    captureBeforeWait = false;
  }
  return {
    profiles,
    reset,
    async control(request: Request): Promise<Response | null> {
      const url = new URL(request.url);
      if (url.pathname === "/__test/api-key-storage/database") {
        return Response.json(
          database
            .query(
              "SELECT *,hex(CAST(start AS BLOB)) AS startHex,typeof(start) AS startType FROM apikey ORDER BY name",
            )
            .all()
            .map((row: any) => ({
              ...row,
              enabled: !!row.enabled,
              rateLimitEnabled: !!row.rateLimitEnabled,
              metadata: row.metadata === null ? null : JSON.parse(row.metadata),
            })),
        );
      }
      if (url.pathname === "/__test/api-key-storage/state") return Response.json(snapshot());
      if (url.pathname === "/__test/api-key-storage/verify") {
        const auth = profiles.get(`/__test/profiles/${url.searchParams.get("profile")}/api/auth`)!;
        return Response.json(await auth.api.verifyApiKey({ body: await request.json() }));
      }
      if (url.pathname !== "/__test/api-key-storage/control") return null;
      const input = await request.json();
      switch (input.action) {
        case "reset":
          await reset();
          break;
        case "configure":
          failure = input.failure ?? "";
          failStore = input.store ?? "custom";
          holdStore = input.holdStore ?? failStore;
          holdAt = input.holdAt ?? -1;
          holdOperation = input.holdOperation ?? "";
          captureBeforeWait = !!input.captureBeforeWait;
          hashReads = 0;
          entered = 0;
          break;
        case "wait":
          await new Promise<void>((resolve) => {
            const listener = () => {
              if (entered >= input.count) {
                listeners.delete(listener);
                resolve();
              }
            };
            listeners.add(listener);
            listener();
          });
          break;
        case "release":
          release();
          break;
        case "drain":
          await drain();
          break;
        case "clear":
          for (const map of maps.values()) {
            for (const index of map.keys()) if (index.startsWith("api-key:")) map.delete(index);
          }
          break;
        case "expire-cache":
          for (const map of maps.values()) {
            for (const [index, entry] of map) {
              if (
                index.startsWith("api-key:") &&
                !index.startsWith("api-key:by-ref:") &&
                JSON.parse(entry.value).id === input.keyId
              ) {
                entry.expiresAt = 0;
              }
            }
          }
          break;
        case "patch":
          if (input.cache !== false) {
            for (const map of maps.values()) {
              for (const [index, entry] of map) {
                if (!index.startsWith("api-key:") || index.startsWith("api-key:by-ref:")) continue;
                const row = JSON.parse(entry.value);
                if (row.id === input.keyId) {
                  entry.value = JSON.stringify({ ...row, ...input.patch });
                }
              }
            }
          }
          if (input.database) {
            for (const [field, value] of Object.entries(input.patch)) {
              if (
                ![
                  "remaining",
                  "expiresAt",
                  "lastRefillAt",
                  "refillAmount",
                  "refillInterval",
                  "name",
                ].includes(field)
              ) {
                throw new Error("supported application column required");
              }
              database
                .query(`UPDATE apikey SET ${field}=? WHERE id=?`)
                .run(value as any, input.keyId);
            }
          }
          break;
        case "misindex": {
          const map = maps.get(input.store)!;
          map.set(`api-key:by-ref:${input.referenceId}`, {
            value: JSON.stringify([input.keyId]),
            expiresAt: null,
          });
          break;
        }
        default:
          throw new Error("unknown storage control");
      }
      return Response.json({ entered, pending: blocked.size });
    },
  };
}
