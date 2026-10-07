import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { deviceAuthorizationClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "device deviceCodeLength custom length reaches persisted grants and approval redemption",
  async (ctx) => {
    const profile = "device-length-506" as const;
    const make = (name: string) =>
      createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
        plugins: [deviceAuthorizationClient()],
        fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
      });
    const device = make("length-device");
    const owner = make("length-owner");
    const signup = await owner.signUp.email({
      email: ctx.uniqueEmail("length-owner"),
      name: "Length owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const issued = await device.device.code({ client_id: "compat-device-client", scope: "read" });
    const other = await device.device.code({ client_id: "compat-device-client", scope: "other" });
    expect(issued.error).toBeNull();
    expect(other.error).toBeNull();
    expect(issued.data!.device_code).toHaveLength(16);
    expect(issued.data!.user_code).toHaveLength(8);
    expect(issued.data!.device_code).not.toBe(other.data!.device_code);
    expect(issued.data!.user_code).not.toBe(other.data!.user_code);
    const stored = z
      .object({
        deviceCode: z.string(),
        userCode: z.string(),
        status: z.string(),
        userId: z.string().nullable(),
      })
      .parse(await ctx.readDeviceState({ deviceCode: issued.data!.device_code }));
    expect(stored).toEqual({
      deviceCode: issued.data!.device_code,
      userCode: issued.data!.user_code,
      status: "pending",
      userId: null,
    });
    const foreignBefore = await ctx.readDeviceState({ deviceCode: other.data!.device_code });
    const claimed = await owner.device({ query: { user_code: issued.data!.user_code } });
    expect(claimed.error).toBeNull();
    const approved = await owner.device.approve({ userCode: issued.data!.user_code });
    expect(approved.data).toEqual({ success: true });
    expect(await ctx.readDeviceState({ deviceCode: other.data!.device_code })).toEqual(
      foreignBefore,
    );
    const redeemed = await device.device.token({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: issued.data!.device_code,
      client_id: "compat-device-client",
    });
    expect(redeemed.error).toBeNull();
    expect(redeemed.data?.token_type).toBe("Bearer");
    expect(redeemed.data?.scope).toBe("read");
    const consumed = await ctx.readDeviceState({ deviceCode: issued.data!.device_code });
    expect(consumed).toBeNull();
    return ctx.snapshot({
      signup,
      issued,
      other,
      stored,
      foreignBefore,
      claimed,
      approved,
      redeemed,
      consumed,
    });
  },
  ["POST /device/code", "POST /device/approve", "POST /device/token"],
);
