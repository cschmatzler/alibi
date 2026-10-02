import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

const fixture = fileURLToPath(new URL("../../reference-server/runtime-boundaries.mjs", import.meta.url));

test("actual pinned initialization captures telemetry gates, provider side effects and privileged test helpers", async () => {
  for (const mode of ["default", "disabled", "enabled", "environment", "test", "no-endpoint", "debug", "failure", "init-failure"]) {
    const child = Bun.spawn([process.execPath, fixture, mode], {
      stdout: "pipe", stderr: "pipe",
      env: { ...process.env, NODE_ENV: "production", BUN_ENV: "production", VITEST: "", TEST: "false", BETTER_AUTH_TELEMETRY: "false", BETTER_AUTH_TELEMETRY_ENDPOINT: "", BETTER_AUTH_TELEMETRY_DEBUG: "false" },
    });
    const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect({ mode, code, stderr }).toEqual({ mode, code: 0, stderr: "" });
    const receipt = JSON.parse(stdout.trim().split("\n").at(-1)!);
    if (mode === "init-failure") {
      expect(receipt.initError).toBe("synthetic initialization rejection");
      expect(receipt.providerCalls).toBe(2);
      expect(receipt.events.length).toBe(1);
      expect(receipt.events[0].type).toBe("init");
      expect(receipt.events[0].payload.config.plugins).toEqual(["organization", "email-otp", "test-utils", "reject-init"]);
      continue;
    }
    const active = ["enabled", "environment", "debug", "failure"].includes(mode);
    expect(receipt.providerCalls).toBe(active ? 2 : 1);
    expect(receipt.events.length).toBe(["enabled", "environment", "failure"].includes(mode) ? 2 : 0);
    if (receipt.events.length) {
      const init = receipt.events.find((event: any) => event.type === "init");
      const ready = receipt.events.find((event: any) => event.type === "application-ready");
      expect(init.payload.config.adapter).toBe("memory");
      expect(init.payload.config.database).toBe("adapter");
      expect(init.payload.config.emailAndPassword.enabled).toBe(true);
      expect(init.payload.config.plugins).toEqual(["organization", "email-otp", "test-utils"]);
      expect(init.payload.config.socialProviders[0].id).toBe("github");
      expect(init.payload.runtime.name).toBe("bun");
      expect(init.payload.systemInfo.systemPlatform).toBe(process.platform);
      expect(ready.payload).toEqual({ ready: true });
      expect(ready.anonymousId).toBe(init.anonymousId);
      expect(JSON.stringify(receipt.events)).not.toContain("synthetic-provider-secret");
      expect(JSON.stringify(receipt.events)).not.toContain("synthetic-boundaries-secret");
    }
    const h = receipt.helpers;
    expect(h.factoryWrites).toBe(0);
    expect(h.missingLogin.error).toBe("User not found: nonexistent-user");
    expect(h.missingLogin.after).toEqual(h.missingLogin.before);
    expect(h.read.user.id).toBe(h.user.id);
    expect(h.read.session.id).toBe(h.login.session.id);
    expect(h.sessionRows.length).toBe(3);
    expect(h.sessionRows.every((row: any) => row.userId === h.user.id)).toBe(true);
    expect(h.member.organizationId).toBe(h.org.id);
    expect(h.member.role).toBe("member");
    expect(h.capturedOTP).toMatch(/^\d{6}$/);
    expect(h.isolatedOTP).toBeNull();
    expect(h.clearedOTP).toBeNull();
    expect(h.rows.user).toEqual([]);
    expect(h.rows.session).toEqual([]);
    expect(h.rows.organization).toEqual([]);
    expect(h.rows.member).toEqual([]);
    expect(h.permissions).toEqual([
      { success: true }, { success: false, error: 'unauthorized to access resource "document"' },
      { success: false, error: "You are not allowed to access resource: missing" },
      { success: false, error: 'unauthorized to access resource "document"' },
      { success: true }, { success: true },
    ]);
  }
}, 30000);
