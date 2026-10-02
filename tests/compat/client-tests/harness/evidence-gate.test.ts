import { expect, test } from "bun:test";
import { copyFile, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Run the actual CLI against isolated inventory and observed evidence files.
test("capability gate requires every committed scenario and regeneration preserves requirements", async () => {
  const root = await mkdtemp(join(tmpdir(), "auth-evidence-gate-"));
  try {
    const client = join(root, "tests/compat/client-tests");
    const support = join(client, "support");
    const artifacts = join(client, "artifacts/evidence");
    await Promise.all([
      mkdir(support, { recursive: true }),
      mkdir(artifacts, { recursive: true }),
      mkdir(join(root, "coverage"), { recursive: true }),
      mkdir(join(root, "tests/compat/reference-server"), { recursive: true }),
    ]);

    for (const name of ["coverage.ts", "check-coverage.ts"]) {
      await copyFile(new URL(`../support/${name}`, import.meta.url), join(support, name));
    }

    for (const project of ["client-tests", "reference-server"]) {
      await symlink(
        new URL(`../../${project}/node_modules`, import.meta.url).pathname,
        join(root, `tests/compat/${project}/node_modules`),
      );
    }

    const inventoryPath = join(root, "tests/compat/capabilities.json");
    const inventory = {
      upstreamVersion: "1.7.6",
      capabilities: [
        {
          route: "GET /token",
          implemented: true,
          upstream: true,
          evidence: {
            success: ["session refresh", "API key principal"],
            rejection: "expired session",
            authorization: { notApplicable: "public route" },
            state: { knownGap: "not yet observed" },
          },
        },
      ],
    };
    await Bun.write(inventoryPath, JSON.stringify(inventory));

    for (const name of ["upstream-routes", "runtime-routes"]) {
      await Bun.write(join(root, `coverage/${name}.json`), JSON.stringify(["GET /token"]));
    }

    const observed = join(artifacts, "scenario.json");
    await Bun.write(
      observed,
      JSON.stringify({
        "GET /token": {
          success: ["session refresh", "unrelated success"],
          rejection: ["expired session"],
        },
      }),
    );
    const run = async (update = false) => {
      const child = Bun.spawn([process.execPath, join(support, "check-coverage.ts")], {
        env: { ...process.env, BETTER_AUTH_UPDATE_CAPABILITIES: update ? "1" : "0" },
        stdout: "pipe",
        stderr: "pipe",
      });
      const [code, output] = await Promise.all([child.exited, new Response(child.stderr).text()]);
      return { code, output };
    };
    const missing = await run();
    expect(missing.code).not.toBe(0);
    expect(missing.output).toContain("missing success (API key principal)");

    const regeneration = await run(true);
    expect(regeneration.code).not.toBe(0);
    expect(regeneration.output).toContain("missing success (API key principal)");
    expect(await Bun.file(inventoryPath).json()).toEqual(inventory);

    await Bun.write(
      observed,
      JSON.stringify({
        "GET /token": {
          success: ["session refresh", "API key principal", "earlier alphabetic scenario"],
          rejection: ["expired session"],
          state: ["persisted refresh"],
        },
      }),
    );
    expect((await run()).code).toBe(0);
    expect((await run(true)).code).toBe(0);

    const updated = await Bun.file(inventoryPath).json();
    expect(updated.capabilities[0].evidence.success).toEqual(
      inventory.capabilities[0]!.evidence.success,
    );
    expect(updated.capabilities[0].evidence.rejection).toBe("expired session");
    expect(updated.capabilities[0].evidence.state).toBe("persisted refresh");
    expect(updated.capabilities[0].evidence.authorization).toEqual({
      notApplicable: "public route",
    });

    // A category must name evidence or explain its absence; it cannot be empty.
    const silent = {
      ...updated,
      capabilities: [
        {
          ...updated.capabilities[0],
          evidence: { ...updated.capabilities[0].evidence, state: null },
        },
      ],
    };
    await Bun.write(inventoryPath, JSON.stringify(silent));
    for (const update of [false, true]) {
      const result = await run(update);
      expect(result.code).not.toBe(0);
      expect(result.output).toContain('"state"');
      expect(await Bun.file(inventoryPath).json()).toEqual(silent);
    }

    // A misspelled or separate requirement field must never be silently stripped.
    const unknownRequirements = {
      ...updated,
      capabilities: [
        { ...updated.capabilities[0], requiredEvidence: { success: "unobserved lifecycle" } },
      ],
    };
    await Bun.write(inventoryPath, JSON.stringify(unknownRequirements));

    for (const update of [false, true]) {
      const unknown = await run(update);
      expect(unknown.code).not.toBe(0);
      expect(unknown.output).toContain("requiredEvidence");
      expect(await Bun.file(inventoryPath).json()).toEqual(unknownRequirements);
    }

    await Bun.write(inventoryPath, JSON.stringify(updated));
    const duplicated = {
      ...updated,
      capabilities: [
        ...updated.capabilities,
        {
          ...updated.capabilities[0],
          evidence: { ...updated.capabilities[0].evidence, success: "earlier alphabetic scenario" },
        },
      ],
    };
    await Bun.write(inventoryPath, JSON.stringify(duplicated));
    const duplicateResult = await run(true);
    expect(duplicateResult.code).not.toBe(0);
    expect(duplicateResult.output).toContain("Duplicate committed capability routes");
    expect(await Bun.file(inventoryPath).json()).toEqual(duplicated);

    await Bun.write(inventoryPath, JSON.stringify(updated));

    // Updating route discovery cannot silently discard a committed route either.
    for (const name of ["upstream-routes", "runtime-routes"]) {
      await Bun.write(join(root, `coverage/${name}.json`), "[]");
    }

    const removed = await run(true);
    expect(removed.code).not.toBe(0);
    expect(removed.output).toContain("Committed capability route disappeared: GET /token");
    expect(await Bun.file(inventoryPath).json()).toEqual(updated);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
