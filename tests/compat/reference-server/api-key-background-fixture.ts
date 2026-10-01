import type { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { username } from "better-auth/plugins";
import { apiKey } from "@better-auth/api-key";

/** Application integration; all auth operations use the unchanged pinned runtime. */
export async function apiKeyBackgroundFixture(
  database: Database,
  options: Parameters<typeof betterAuth>[0],
) {
  let events: Record<string, unknown>[] = [], serial = 0, generated = 0;
  let hold = false, observer = "", generator = "", lastAdmission: number | null = null;
  let observeUsage = false;
  const blocked = new Map<number, () => void>();
  const listeners = new Set<() => void>();
  const inflight = new Set<Promise<unknown>>(), observed = new Set<Promise<unknown>>();
  function event(value: Record<string, unknown>) {
    events.push(value);
    for (const listener of listeners) listener();
  }
  async function wait(kind: string, count: number) {
    if (events.filter(value => value.kind === kind).length >= count) return;
    await new Promise<void>(resolve => {
      const listener = () => {
        if (events.filter(value => value.kind === kind).length >= count) {
          listeners.delete(listener); resolve();
        }
      };
      listeners.add(listener); listener();
    });
  }
  const createAuth = (path: string, deferUpdates: boolean, rateEnabled: boolean) => betterAuth({
      ...options, basePath: path,
      advanced: {
        ...options.advanced,
        backgroundTasks: {
          handler(completion) {
            event({ kind: "background-register" });
            if (observer === "api") throw new APIError("FORBIDDEN", { code: "BACKGROUND_TASK_DENIED", message: "Application background observer denied" });
            if (observer === "throw") throw new Error("application background observer rejected");
            if (observer === "ignore") return;
            const observation = completion.then(
              () => event({ kind: "background-complete", fulfilled: true }),
              () => event({ kind: "background-complete", fulfilled: false }),
            );
            observed.add(observation);
            void observation.finally(() => observed.delete(observation));
          },
        },
      },
      plugins: [username(), apiKey({
        deferUpdates, enableSessionForAPIKeys: true,
        rateLimit: { enabled: rateEnabled },
        customKeyGenerator({ length, prefix }) {
          event({ kind: "generator", length, prefix: prefix ?? null });
          if (generator === "throw") throw new Error("application generator rejected");
          return `public-fixture-automatic-cleanup-credential-${String(++generated).padStart(16,"0")}-stable-fixture-key`;
        },
      })],
    });
  const profiles = new Map<string, ReturnType<typeof createAuth>>();
  for (const [name, deferUpdates, rateEnabled] of [
    ["api-key-automatic", false, false],
    ["api-key-automatic-deferred", true, false],
    ["api-key-automatic-other", true, false],
    ["api-key-usage-rate", false, true],
    ["api-key-usage-rate-deferred", true, true],
  ] as const) {
    const path = `/__test/profiles/${name}/api/auth`;
    const auth = createAuth(path, deferUpdates, rateEnabled);
    const context = await auth.$context;
    const incrementOne = context.adapter.incrementOne.bind(context.adapter);
    context.adapter.incrementOne = <T>(input: Parameters<typeof incrementOne>[0]): Promise<T | null> => {
      if (!observeUsage || input.model !== "apikey" || !("remaining" in input.increment || "remaining" in (input.set ?? {}))) return incrementOne<T>(input);
      const id = ++serial, keyId = input.where?.find(value => value.field === "id")?.value;
      let release: (() => void) | undefined;
      const gate = hold ? new Promise<void>(resolve => { release = resolve; }) : null;
      if (release) blocked.set(id, release);
      event({kind:"usage-enter",profile:name,serial:id,key:{id:keyId}});
      const work = (async () => {
        if (gate) await gate;
        try {const result = await incrementOne<T>(input);event({kind:"usage-complete",serial:id,success:true});return result;}
        catch(error){event({kind:"usage-complete",serial:id,success:false});throw error;}
      })();
      inflight.add(work);
      void work.then(() => inflight.delete(work), () => inflight.delete(work));
      return work;
    };
    const deleteMany = context.adapter.deleteMany.bind(context.adapter);
    context.adapter.deleteMany = input => {
      if (input.model !== "apikey") return deleteMany(input);
      const id = ++serial;
      lastAdmission = Date.now();
      let release: (() => void) | undefined;
      const gate = hold ? new Promise<void>(resolve => { release = resolve; }) : null;
      if (release) blocked.set(id, release);
      event({ kind: "cleanup-enter", profile: name, serial: id, createdAt: new Date().toISOString() });
      const work = (async () => {
        if (gate) await gate;
        try {
          const result = await deleteMany(input);
          event({ kind: "cleanup-complete", serial: id, success: true });
          return result;
        } catch (error) {
          event({ kind: "cleanup-complete", serial: id, success: false });
          throw error;
        }
      })();
      inflight.add(work);
      void work.then(() => inflight.delete(work), () => inflight.delete(work));
      return work;
    };
    const deleteOne = context.adapter.delete.bind(context.adapter);
    context.adapter.delete = input => {
      if (input.model !== "apikey") return deleteOne(input);
      const id = ++serial;
      const keyId = input.where?.find(value => value.field === "id")?.value;
      let release: (() => void) | undefined;
      const gate = hold ? new Promise<void>(resolve => { release = resolve; }) : null;
      if (release) blocked.set(id, release);
      event({kind:"row-delete-enter",profile:name,serial:id,key:{id:keyId}});
      const work = (async () => {
        if (gate) await gate;
        try {const result = await deleteOne(input);event({kind:"row-delete-complete",serial:id,success:true});return result;}
        catch(error){event({kind:"row-delete-complete",serial:id,success:false});throw error;}
      })();
      inflight.add(work);
      void work.then(() => inflight.delete(work), () => inflight.delete(work));
      return work;
    };
    profiles.set(path, auth);
  }
  function release(selected?: number) {
    if (selected !== undefined) {const sender=blocked.get(selected);blocked.delete(selected);sender?.();return;}
    const senders = [...blocked.values()]; blocked.clear();
    for (const sender of senders) sender();
  }
  return {
    profiles,
    async control(request: Request): Promise<Response | null> {
      const url = new URL(request.url);
      if (url.pathname === "/__test/api-key-background/state") {
        const usage = url.searchParams.get('usage') === 'true';
        const rows = database.query(`SELECT id,name,referenceId,configId,key,remaining,requestCount,expiresAt,createdAt,updatedAt,lastRequest,lastRefillAt${usage ? ',refillAmount,refillInterval,rateLimitEnabled,rateLimitTimeWindow,rateLimitMax' : ''} FROM apikey ORDER BY name`).all();
        if(url.searchParams.get("rawDates")==="true")return Response.json(rows);
        return Response.json(rows.map((row: any) => ({
          ...row,
          ...(usage ? {rateLimitEnabled: !!row.rateLimitEnabled} : {}),
          ...Object.fromEntries(["expiresAt", "createdAt", "updatedAt", "lastRequest", "lastRefillAt"].map(key => [key, row[key] === null ? null : new Date(row[key]).toISOString()])),
        })));
      }
      if (url.pathname === "/__test/api-key-background/control" && request.method === "POST") {
        const input = await request.json();
        switch (input.action) {
          case "reset":
            release();
            await Promise.allSettled([...inflight, ...observed]);
            events = []; serial = 0; generated = 0; lastAdmission = null;
            hold = false; observer = ""; generator = ""; observeUsage = false;
            break;
          case "configure": hold = !!input.hold; observer = input.observer ?? ""; generator = input.generator ?? ""; observeUsage = !!input.observeUsage; break;
          case "release": release(input.serial); break;
          case "wait": await wait(input.kind, input.count); break;
          case "window":
            if (lastAdmission === null) throw new Error("actual cleanup receipt required");
            await Bun.sleep(Math.max(0, lastAdmission + 10020 - Date.now()));
            break;
          case "remaining": database.query('UPDATE apikey SET remaining=11 WHERE id=?').run(input.keyId); break;
          case "quota": database.query('UPDATE apikey SET remaining=? WHERE id=?').run(input.remaining, input.keyId); break;
          case "refill": database.query('UPDATE apikey SET remaining=0,refillAmount=3,refillInterval=60000,lastRefillAt=? WHERE id=?').run(new Date(0).toISOString(), input.keyId); break;
          case "timestamps": {
            if (!database.query('SELECT id FROM apikey WHERE id=?').get(input.keyId)) throw new Error("actual API key required");
            const values=["createdAt","updatedAt","lastRequest","lastRefillAt","expiresAt"].map(field=>input.dates[field]);
            if(values.some(value=>typeof value!=="string"||!Number.isFinite(Date.parse(value))))throw new Error("valid stored dates required");
            database.query('UPDATE apikey SET createdAt=?,updatedAt=?,lastRequest=?,lastRefillAt=?,expiresAt=? WHERE id=?').run(...values,input.keyId);
            break;
          }
          case "phase-refill": database.query('UPDATE apikey SET remaining=0,refillAmount=3,refillInterval=60000,lastRefillAt=?,lastRequest=NULL,requestCount=0,rateLimitEnabled=1,rateLimitMax=3,rateLimitTimeWindow=60000 WHERE id=?').run(new Date(0).toISOString(),input.keyId);break;
          case "usage-veto": {
            const condition=input.phase==='rate' ? 'NEW.requestCount<>OLD.requestCount' : input.phase==='final' ? 'NEW.remaining IS OLD.remaining AND NEW.requestCount IS OLD.requestCount AND NEW.lastRequest IS OLD.lastRequest AND NEW.lastRefillAt IS OLD.lastRefillAt' : null;
            if(!condition)throw new Error('actual phase required');
            database.exec(`CREATE TRIGGER usage_phase_veto BEFORE UPDATE ON apikey WHEN OLD.name='phase-target' AND (${condition}) BEGIN SELECT RAISE(ABORT,'actual phase storage veto'); END`);break;
          }
          case "usage-restore": database.exec('DROP TRIGGER IF EXISTS usage_phase_veto');database.exec('DROP TRIGGER IF EXISTS usage_current_read');break;
          case "usage-current-read": database.exec("CREATE TRIGGER usage_current_read AFTER UPDATE ON apikey WHEN OLD.name='phase-target' AND NEW.lastRequest IS NOT OLD.lastRequest AND NEW.updatedAt IS OLD.updatedAt BEGIN UPDATE apikey SET remaining=77,name='current-row' WHERE id=NEW.id; END");break;
          case "expire": database.query('UPDATE apikey SET expiresAt=? WHERE id=?').run(new Date(0).toISOString(), input.keyId); break;
          case "veto": database.exec("CREATE TRIGGER automatic_cleanup_veto BEFORE DELETE ON apikey BEGIN SELECT RAISE(ABORT,'actual cleanup storage veto'); END"); break;
          case "restore": database.exec("DROP TRIGGER IF EXISTS automatic_cleanup_veto"); break;
          default: throw new Error("unknown application control");
        }
        return Response.json(events);
      }
      const selected = profiles.get(`/__test/profiles/${url.searchParams.get("profile")}/api/auth`);
      if (url.pathname === "/__test/api-key-background/cleanup" && request.method === "POST") {
        if (!selected) throw new Error("actual profile required");
        return Response.json(await selected.api.deleteAllExpiredApiKeys());
      }
      if (url.pathname === "/__test/api-key-background/verify" && request.method === "POST") {
        if (!selected) throw new Error("actual profile required");
        return Response.json(await selected.api.verifyApiKey({ body: await request.json() }));
      }
      return null;
    },
  };
}
