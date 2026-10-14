import { Database } from "bun:sqlite";

import { scim } from "@better-auth/scim";
import { type BetterAuthOptions, betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
export async function scimFixture(base: BetterAuthOptions) {
  const options = {
    ...base,
    database: new Database(":memory:"),
    basePath: "/__test/profiles/scim/api/auth",
    plugins: [
      scim({
        connections: [],
        authentication: { verifyBearerToken: async () => null },
        managedConnections: {
          credentialHashSecret: "managed-scim-credential-hmac-secret-32-chars",
          maxActiveCredentials: 2,
        },
      }),
    ],
  };
  await (await getMigrations(options)).runMigrations();
  let auth = betterAuth(options);
  const projectionStates: unknown[] = [];
  let projectionFails = false;
  return async (request: Request): Promise<Response | undefined> => {
    const path = new URL(request.url).pathname;
    if (path.startsWith("/__test/profiles/scim/api/auth/")) return auth.handler(request);
    if (path === "/__test/server-api/scim") {
      const query = new URL(request.url).searchParams;
      if (query.get("operation") === "configure-projection") {
        options.plugins = [
          scim({
            connections: [],
            authentication: { verifyBearerToken: async () => null },
            managedConnections: {
              credentialHashSecret: "managed-scim-credential-hmac-secret-32-chars",
              maxActiveCredentials: 2,
            },
            projection: {
              reconcileUser: async (input, context) => {
                await context.database.update({
                  model: "user",
                  where: [{ field: "id", value: input.userId }],
                  update: {
                    name: projectionFails
                      ? "Should roll back"
                      : input.active
                        ? "Projected active"
                        : "Projected inactive",
                  },
                });
                projectionStates.push(input);
                if (projectionFails) throw new Error("application rejected projection");
              },
            },
          }),
        ];
        auth = betterAuth(options);
        return new Response(JSON.stringify({ configured: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "seed-projection") {
        const signed = await auth.api.signUpEmail({
          body: {
            email: "projection-owner@example.com",
            password: "a-native-password-123",
            name: "Native owner",
          },
        });
        const uid = signed.user.id;
        options.database
          .query(
            "INSERT INTO scimSubject (id,userId,revision,createdAt,updatedAt) VALUES ('projection-subject',?,0,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",
          )
          .run(uid);
        for (const [id, cid, domain, active] of [
          ["scim-alias-a", "conn-a", "tenant-a", 1],
          ["scim-alias-b", "conn-b", "tenant-a", 0],
          ["scim-alias-c", "conn-c", "tenant-b", 1],
        ] as const) {
          options.database
            .query(
              "INSERT INTO scimUser (id,connectionId,provisioningDomainId,userId,connectionUserKey,userName,userNameKey,primaryEmail,workEmailValueIndex,emailValueIndex,displayName,formattedName,serializedEmails,active,orderKey,createdAt,updatedAt) VALUES (?,?,?,?,?,'projection-owner@example.com',?,'projection-owner@example.com','[]','[]','Owner','Owner','[]',?,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",
            )
            .run(id, cid, domain, uid, id, id, active, id);
        }
        options.database
          .query(
            "INSERT INTO scimProjectionGrant (id,connectionId,provisioningDomainId,scimUserId,userId,sourceKind,sourceId,role,grantKey,createdAt,updatedAt) VALUES ('legacy-grant','conn-a','tenant-a','scim-alias-a',?,'group','retired-group','legacy-role','legacy-grant','2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",
          )
          .run(uid);
        return new Response(JSON.stringify({ userId: uid }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "projection-fails") {
        const owner = options.database
          .query("SELECT id FROM user WHERE email='projection-owner@example.com'")
          .get() as any;
        options.database
          .query(
            "INSERT INTO scimProjectionGrant (id,connectionId,provisioningDomainId,scimUserId,userId,sourceKind,sourceId,role,grantKey,createdAt,updatedAt) VALUES ('failure-grant','conn-a','tenant-a','scim-alias-a',?,'group','retired-group','legacy-role','failure-grant','2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",
          )
          .run(owner.id);
        projectionFails = true;
        return new Response(JSON.stringify({ failing: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "projection-states") {
        return new Response(JSON.stringify(projectionStates), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "projection-storage") {
        return new Response(
          JSON.stringify({
            users: options.database
              .query("SELECT id,name FROM user WHERE email='projection-owner@example.com'")
              .all(),
            subjects: options.database.query("SELECT * FROM scimSubject").all(),
            scimUsers: options.database
              .query("SELECT id,connectionId,provisioningDomainId,userId,active FROM scimUser")
              .all(),
            grants: options.database.query("SELECT * FROM scimProjectionGrant").all(),
          }),
          { headers: { "content-type": "application/json" } },
        );
      }
      if (query.get("operation") === "restart-managed") {
        auth = betterAuth(options);
        return new Response(JSON.stringify({ restarted: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "age-connection") {
        const input = (await request.json()) as any;
        options.database
          .query("UPDATE scimManagedConnection SET createdAt=? WHERE connectionId=?")
          .run("2000-01-01T00:00:00.000Z", input.connectionId);
        return new Response(JSON.stringify({ aged: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "credential-state") {
        const input = (await request.json()) as any;
        if (input.policy !== undefined) {
          options.database
            .query("UPDATE scimManagedCredential SET serializedScopes=? WHERE credentialId=?")
            .run(input.policy, input.credentialId);
        } else {
          options.database
            .query("UPDATE scimManagedCredential SET expiresAt=? WHERE credentialId=?")
            .run("2000-01-01T00:00:00.000Z", input.credentialId);
        }
        return new Response(JSON.stringify({ changed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "reject-rotation-event") {
        options.database.exec(
          "CREATE TRIGGER reject_scim_rotation_event BEFORE INSERT ON scimManagedConnectionEvent WHEN NEW.actorId='rollback-operator' AND NEW.type='credential.rotated' BEGIN SELECT RAISE(ABORT,'fixture rejected rotation event'); END",
        );
        return new Response(JSON.stringify({ installed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "rotation-failure") {
        const input = (await request.json()) as any;
        input.body.expiresAt = new Date(input.body.expiresAt);
        try {
          await auth.api.rotateSCIMManagedCredential({ body: input.body });
          return new Response(JSON.stringify({ failed: false }), {
            headers: { "content-type": "application/json" },
          });
        } catch (error) {
          return new Response(
            JSON.stringify({
              failed: true,
              rejectedEvent: String(error).includes("fixture rejected rotation event"),
            }),
            { headers: { "content-type": "application/json" } },
          );
        }
      }
      if (query.get("operation") === "reject-revocation-event") {
        options.database.exec(
          "CREATE TRIGGER reject_scim_revocation_event BEFORE INSERT ON scimManagedConnectionEvent WHEN NEW.actorId='rollback-operator' AND NEW.type='credential.revoked' BEGIN SELECT RAISE(ABORT,'fixture rejected revocation event'); END",
        );
        return new Response(JSON.stringify({ installed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "revocation-failure") {
        const input = (await request.json()) as any;
        try {
          await auth.api.revokeSCIMManagedCredential({ body: input.body });
          return new Response(JSON.stringify({ failed: false }), {
            headers: { "content-type": "application/json" },
          });
        } catch (error) {
          return new Response(
            JSON.stringify({
              failed: true,
              rejectedEvent: String(error).includes("fixture rejected revocation event"),
            }),
            { headers: { "content-type": "application/json" } },
          );
        }
      }
      if (query.get("operation") === "revokeSCIMManagedCredential") {
        const input = (await request.json()) as any;
        return auth.api.revokeSCIMManagedCredential({ body: input.body, asResponse: true });
      }
      if (query.get("operation") === "rotateSCIMManagedCredential") {
        const input = (await request.json()) as any;
        input.body.expiresAt = new Date(input.body.expiresAt);
        return auth.api.rotateSCIMManagedCredential({ body: input.body, asResponse: true });
      }
      if (query.get("operation") === "listSCIMManagedConnectionEvents") {
        const input = (await request.json()) as any;
        return auth.api.listSCIMManagedConnectionEvents({ body: input.body, asResponse: true });
      }
      if (query.get("operation") === "binding-lease") {
        const input = (await request.json()) as any;
        options.database
          .query(
            "UPDATE scimConnectionBinding SET decommissionStatus='reconciling',decommissionLeaseId='other-worker',decommissionCompletedAt=NULL,decommissionReconciledUserCount=7,decommissionBatchCount=2,decommissionLeaseExpiresAt=? WHERE connectionId=?",
          )
          .run("2035-02-03T04:05:06.789Z", input.connectionId);
        return new Response(JSON.stringify({ leased: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "expire-binding-lease") {
        const input = (await request.json()) as any;
        options.database
          .query(
            "UPDATE scimConnectionBinding SET decommissionLeaseExpiresAt=? WHERE connectionId=?",
          )
          .run("2000-01-01T00:00:00.000Z", input.connectionId);
        return new Response(JSON.stringify({ expired: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "reject-binding-completion") {
        const input = (await request.json()) as any;
        options.database
          .query(
            "UPDATE scimConnectionBinding SET decommissionStatus='reconciling',decommissionLeaseId='failed-worker',decommissionCompletedAt=NULL,decommissionLeaseExpiresAt=? WHERE connectionId=?",
          )
          .run("2000-01-01T00:00:00.000Z", input.connectionId);
        options.database.exec(
          "CREATE TRIGGER reject_scim_binding_completion BEFORE UPDATE ON scimConnectionBinding WHEN NEW.decommissionStatus='complete' AND OLD.decommissionStatus='reconciling' BEGIN SELECT RAISE(ABORT,'fixture rejected binding completion'); END",
        );
        return new Response(JSON.stringify({ installed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "accept-binding-completion") {
        options.database.exec("DROP TRIGGER reject_scim_binding_completion");
        return new Response(JSON.stringify({ removed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "binding-completion-failure") {
        const input = (await request.json()) as any;
        try {
          await auth.api.decommissionSCIMConnection({ body: input.body });
          return new Response(JSON.stringify({ failed: false }), {
            headers: { "content-type": "application/json" },
          });
        } catch (error) {
          return new Response(
            JSON.stringify({
              failed: true,
              rejectedCompletion: String(error).includes("fixture rejected binding completion"),
            }),
            { headers: { "content-type": "application/json" } },
          );
        }
      }
      if (query.get("operation") === "binding-storage") {
        return new Response(
          JSON.stringify(options.database.query("SELECT * FROM scimConnectionBinding").all()),
          { headers: { "content-type": "application/json" } },
        );
      }
      if (query.get("operation") === "reject-decommission-events") {
        options.database.exec(
          "CREATE TRIGGER reject_scim_decommission_event BEFORE INSERT ON scimManagedConnectionEvent WHEN (NEW.actorId='reject-begin' AND NEW.type='connection.decommissioning') OR (NEW.actorId='reject-complete' AND NEW.type='connection.decommissioned') BEGIN SELECT RAISE(ABORT,'fixture rejected decommission event'); END",
        );
        return new Response(JSON.stringify({ installed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "decommission-failure") {
        const input = (await request.json()) as any;
        try {
          await auth.api.decommissionSCIMManagedConnection({ body: input.body });
          return new Response(JSON.stringify({ failed: false }), {
            headers: { "content-type": "application/json" },
          });
        } catch (error) {
          return new Response(
            JSON.stringify({
              failed: true,
              rejectedEvent: String(error).includes("fixture rejected decommission event"),
            }),
            { headers: { "content-type": "application/json" } },
          );
        }
      }
      if (query.get("operation") === "decommissionSCIMManagedConnection") {
        const input = (await request.json()) as any;
        return auth.api.decommissionSCIMManagedConnection({ body: input.body, asResponse: true });
      }
      if (query.get("operation") === "reconcileSCIMProjection") {
        const input = (await request.json()) as any;
        try {
          return await auth.api.reconcileSCIMProjection({ body: input.body, asResponse: true });
        } catch (error: any) {
          return new Response(
            JSON.stringify({ failed: true, message: error.body?.message ?? error.message }),
            {
              headers: { "content-type": "application/json" },
            },
          );
        }
      }
      if (query.get("operation") === "decommissionSCIMConnection") {
        const input = (await request.json()) as any;
        return auth.api.decommissionSCIMConnection({ body: input.body, asResponse: true });
      }
      if (query.get("operation") === "getSCIMManagedConnection") {
        const input = (await request.json()) as any;
        return auth.api.getSCIMManagedConnection({ body: input.body, asResponse: true });
      }
      if (query.get("operation") === "listSCIMManagedConnections") {
        const input = (await request.json()) as any;
        return auth.api.listSCIMManagedConnections({ body: input.body, asResponse: true });
      }
      if (query.get("operation") === "reject-late-event") {
        options.database.exec(
          "CREATE TRIGGER reject_scim_late_event BEFORE INSERT ON scimManagedConnectionEvent WHEN NEW.actorId='rollback-operator' AND NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'fixture rejected late event'); END",
        );
        return new Response(JSON.stringify({ installed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "managed-failure") {
        const input = (await request.json()) as any;
        input.body.expiresAt = new Date(input.body.expiresAt);
        try {
          await auth.api.createSCIMManagedConnection({ body: input.body });
          return new Response(JSON.stringify({ failed: false }), {
            headers: { "content-type": "application/json" },
          });
        } catch (error) {
          return new Response(
            JSON.stringify({
              failed: true,
              rejectedLateEvent: String(error).includes("fixture rejected late event"),
            }),
            { headers: { "content-type": "application/json" } },
          );
        }
      }
      if (query.get("operation") === "managed-storage") {
        const result = {
          connections: options.database.query("SELECT * FROM scimManagedConnection").all(),
          credentials: options.database.query("SELECT * FROM scimManagedCredential").all(),
          events: options.database
            .query("SELECT * FROM scimManagedConnectionEvent ORDER BY sequence")
            .all(),
        };
        return new Response(JSON.stringify(result), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "createSCIMManagedConnection") {
        const input = (await request.json()) as any;
        if (input.sdkDate) input.body.expiresAt = new Date(input.body.expiresAt);
        return auth.api.createSCIMManagedConnection({ body: input.body, asResponse: true });
      }

      if (query.get("operation") === "getSCIMSchemas") {
        return new Response(JSON.stringify(await auth.api.getSCIMSchemas()), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "getSCIMSchema") {
        try {
          const value = await auth.api.getSCIMSchema({
            params: { schemaId: query.get("id") ?? "" },
          });
          return new Response(JSON.stringify(value), {
            headers: { "content-type": "application/json" },
          });
        } catch (error: any) {
          return new Response(JSON.stringify(error.body), {
            status: error.statusCode,
            headers: { "content-type": "application/json" },
          });
        }
      }
      if (query.get("operation") === "getSCIMResourceType") {
        try {
          const value = await auth.api.getSCIMResourceType({
            params: { resourceTypeId: query.get("id") ?? "" },
          });
          return new Response(JSON.stringify(value), {
            headers: { "content-type": "application/json" },
          });
        } catch (error: any) {
          return new Response(JSON.stringify(error.body), {
            status: error.statusCode,
            headers: { "content-type": "application/json" },
          });
        }
      }
      return new Response(
        JSON.stringify(
          new URL(request.url).searchParams.get("operation") === "getSCIMResourceTypes"
            ? await auth.api.getSCIMResourceTypes()
            : await auth.api.getSCIMServiceProviderConfig(),
        ),
        {
          headers: { "content-type": "application/json" },
        },
      );
    }
  };
}
