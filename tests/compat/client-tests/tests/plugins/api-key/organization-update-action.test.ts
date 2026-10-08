import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { organizationActions } from "./organization-actions";
compatScenario(
  "organization key update requires the custom update action and preserves reference ownership",
  async (ctx) => {
    const s = await organizationActions(ctx, "org-update");
    const reader = await s.member("member");
    const updater = await s.member("updater");
    const key = await s.create("Original key");
    const query = { id: key.data!.id, configId: "organization" };
    const before = await s.owner.apiKey.get({ query });
    expect(before.error).toBeNull();
    const denied = await reader.actor.apiKey.update({
      configId: "organization",
      keyId: key.data!.id,
      name: "must-not-commit",
    });
    expect(denied.error).toMatchObject({ status: 403, code: "INSUFFICIENT_API_KEY_PERMISSIONS" });
    expect(await s.owner.apiKey.get({ query })).toEqual(before);
    const checked = await s.verify(key.data!.key);
    expect(checked.valid).toBe(true);
    expect(checked.key).toMatchObject({
      id: key.data!.id,
      name: "Original key",
      referenceId: s.organizationId,
      configId: "organization",
    });
    const updated = await updater.actor.apiKey.update({
      configId: "organization",
      keyId: key.data!.id,
      name: "Granted update",
    });
    expect(updated.error).toBeNull();
    const after = await s.owner.apiKey.get({ query });
    expect(after.error).toBeNull();
    expect(after.data).toMatchObject({
      id: key.data!.id,
      name: "Granted update",
      referenceId: s.organizationId,
      configId: "organization",
    });
    expect((await s.verify(key.data!.key)).valid).toBe(true);
    return ctx.snapshot({
      org: s.org,
      key,
      reader: reader.accepted,
      updater: updater.accepted,
      before,
      denied,
      checked,
      updated,
      after,
    });
  },
  ["POST /api-key/update", "GET /api-key/get"],
);
