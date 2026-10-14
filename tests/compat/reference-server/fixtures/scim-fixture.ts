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
        connections: [
          {
            id: "conn-a",
            provisioningDomainId: "tenant-a",
            credentials: [
              { id: "reader", token: "group-reader" },
              { id: "limited", token: "users-reader", scopes: ["scim.users.read"] },
              {
                id: "expired",
                token: "expired-reader",
                expiresAt: new Date("2000-01-01T00:00:00Z"),
              },
            ],
          },
          {
            id: "conn-b",
            provisioningDomainId: "tenant-a",
            credentials: [{ id: "reader", token: "other-reader" }],
          },
        ],
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
  const identityStates: unknown[] = [];
  let identityFails = false;
  const roleMapped: unknown[] = [];
  const roleChecked: unknown[] = [];
  let roleStage = 0;
  const verifierInputs: unknown[] = [];
  let verifierClaims: any = undefined;
  let userReadAttributes = "";
  return async (request: Request): Promise<Response | undefined> => {
    const path = new URL(request.url).pathname;
    if (path.startsWith("/__test/profiles/scim/api/auth/")) return auth.handler(request);
    if (path === "/__test/server-api/scim") {
      const query = new URL(request.url).searchParams;
      if (
        ["configure-projection", "configure-role-projection"].includes(query.get("operation") ?? "")
      ) {
        options.plugins = [
          scim({
            connections: [],
            authentication: { verifyBearerToken: async () => null },
            managedConnections: {
              credentialHashSecret: "managed-scim-credential-hmac-secret-32-chars",
              maxActiveCredentials: 2,
            },
            projection: {
              ...(query.get("operation") === "configure-role-projection"
                ? {
                    roles: {
                      map: async (input: any, context: any) => {
                        roleMapped.push(input);
                        if (roleStage === 1) {
                          await context.database.update({
                            model: "user",
                            where: [{ field: "id", value: input.userId }],
                            update: { name: "Should roll back mapping" },
                          });
                          throw new Error("application rejected mapping");
                        }
                        return [" admin ", "", "admin", "missing"];
                      },
                      exists: async (input: any) => {
                        roleChecked.push(input);
                        if (roleStage === 2) throw new Error("application rejected validation");
                        return input.role === "admin";
                      },
                    },
                  }
                : {}),
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
      if (query.get("operation") === "user-read-attributes") {
        const input = (await request.json()) as any;
        options.database
          .query("UPDATE scimUser SET serializedAttributes=? WHERE id='rich'")
          .run(input.restore ? userReadAttributes : input.serializedAttributes);
        return new Response(JSON.stringify({ changed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "getSCIMUser") {
        const input = (await request.json()) as any;
        return auth.api.getSCIMUser({
          params: input.params,
          query: input.query,
          headers:
            input.token === undefined ? undefined : { authorization: `Bearer ${input.token}` },
          asResponse: true,
        });
      }
      if (query.get("operation") === "seed-user-read") {
        const owner = await auth.api.signUpEmail({
          body: {
            email: "user-read-owner@example.com",
            password: "a-native-password-123",
            name: "User owner",
          },
        });
        const attributes = {
          schemas: [
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
            "urn:ietf:params:scim:schemas:core:2.0:User",
          ],
          name: { formatted: " Alice Example ", givenName: " Alice ", ignored: "drop" },
          emails: [{ value: "Alice@example.com", primary: true, type: "WORK", ignored: "drop" }],
          title: " Principal ",
          phoneNumbers: [{ value: " +1 555 ", type: "WORK", primary: true }],
          addresses: [{ streetAddress: " 1 Road ", type: "WORK", primary: true }],
          roles: [{ value: " admin ", display: " Admin ", type: "CUSTOM", primary: true }],
          enterprise: {
            employeeNumber: [" 42 "],
            organization: " Example ",
            manager: { value: " manager ", displayName: "drop" },
          },
          userName: "spoof",
          active: true,
        };
        for (const [id, cid, domain] of [
          ["rich", "conn-a", "tenant-a"],
          ["legacy", "conn-a", "tenant-a"],
          ["corrupt", "conn-a", "tenant-a"],
          ["foreign", "conn-b", "tenant-a"],
          ["drift", "conn-a", "tenant-b"],
        ]) {
          options.database
            .query(
              "INSERT INTO scimUser (id,connectionId,provisioningDomainId,userId,connectionUserKey,userName,userNameKey,primaryEmail,workEmailValueIndex,emailValueIndex,displayName,formattedName,givenName,serializedEmails,active,orderKey,createdAt,updatedAt) VALUES (?,?,?,?,?,'alice',?,'Alice@example.com','[]','[]','Alice from row',' Legacy Name ',' Legacy ',?,0,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",
            )
            .run(
              id,
              cid,
              domain,
              owner.user.id,
              id,
              id,
              JSON.stringify([{ value: "legacy@example.com", primary: true }]),
              id,
            );
        }
        options.database
          .query(
            "UPDATE scimUser SET serializedAttributes=?,externalId='external-alice' WHERE id='rich'",
          )
          .run((userReadAttributes = JSON.stringify(attributes)));
        options.database.exec(
          "UPDATE scimUser SET serializedAttributes='not-json' WHERE id='corrupt'",
        );
        return new Response(JSON.stringify({ seeded: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "configure-verifier") {
        options.plugins = [
          scim({
            connections: [
              {
                id: "declared",
                provisioningDomainId: "tenant-declared",
                credentials: [{ id: "static", token: "static-token" }],
              },
            ],
            authentication: {
              verifyBearerToken: async (input, context) => {
                verifierInputs.push({
                  token: input.token,
                  method: input.method,
                  path: input.path,
                  headers: Object.fromEntries(input.headers),
                });
                const owner = await context.database.findOne<any>({
                  model: "user",
                  where: [{ field: "email", value: "verifier-owner@example.com" }],
                });
                await context.database.update({
                  model: "user",
                  where: [{ field: "id", value: owner.id }],
                  update: { name: "Verified remote" },
                });
                if (verifierClaims !== undefined) return verifierClaims;
                return input.token === "oauth-dynamic"
                  ? {
                      connection: { id: "dynamic", provisioningDomainId: "tenant-dynamic" },
                      credentialId: "remote",
                      scopes: ["scim.groups.read"],
                    }
                  : {
                      connectionId: "declared",
                      credentialId: "remote",
                      scopes: ["scim.groups.read"],
                    };
              },
            },
          }),
        ];
        auth = betterAuth(options);
        return new Response(JSON.stringify({ configured: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "verifier-claims") {
        const input = (await request.json()) as any;
        verifierClaims = input.claims;
        if (input.sdkDate && verifierClaims && "expiresAt" in verifierClaims) {
          verifierClaims.expiresAt = new Date(verifierClaims.expiresAt);
        }
        return new Response(JSON.stringify({ changed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "verifier-inputs") {
        return new Response(JSON.stringify(verifierInputs), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "seed-verifier-groups") {
        await auth.api.signUpEmail({
          body: {
            email: "verifier-owner@example.com",
            password: "a-native-password-123",
            name: "Verifier owner",
          },
        });
        for (const [id, domain] of [
          ["declared", "tenant-declared"],
          ["dynamic", "tenant-dynamic"],
        ]) {
          options.database
            .query(
              "INSERT INTO scimGroup (id,connectionId,provisioningDomainId,revision,displayName,displayNameKey,orderKey,createdAt,updatedAt) VALUES (?,?,?,0,'Verified Group',?,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",
            )
            .run(id, id, domain, id, id);
        }
        return new Response(JSON.stringify({ seeded: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "verifier-user") {
        return new Response(
          JSON.stringify(
            options.database
              .query("SELECT name FROM user WHERE email='verifier-owner@example.com'")
              .get(),
          ),
          { headers: { "content-type": "application/json" } },
        );
      }
      if (query.get("operation") === "reject-managed-usage") {
        options.database.exec(
          "CREATE TRIGGER reject_scim_usage BEFORE UPDATE ON scimManagedCredential WHEN NEW.lastUsedAt IS NOT NULL BEGIN SELECT RAISE(ABORT,'fixture rejected usage'); END",
        );
        return new Response(JSON.stringify({ installed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "accept-managed-usage") {
        options.database.exec("DROP TRIGGER reject_scim_usage");
        return new Response(JSON.stringify({ removed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "seed-managed-group") {
        const input = (await request.json()) as any;
        options.database
          .query(
            "INSERT INTO scimGroup (id,connectionId,provisioningDomainId,revision,displayName,displayNameKey,orderKey,createdAt,updatedAt) VALUES ('managed-group',?,'tenant-managed',0,'Managed Staff','managed-group','managed-group','2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",
          )
          .run(input.connectionId);
        return new Response(JSON.stringify({ seeded: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "managed-bearer-policy") {
        const input = (await request.json()) as any;
        for (const field of [
          "serializedScopes",
          "hashVersion",
          "status",
          "expiresAt",
          "lastUsedAt",
        ] as const) {
          if (field in input) {
            options.database
              .query(`UPDATE scimManagedCredential SET ${field}=? WHERE credentialId=?`)
              .run(input[field], input.credentialId);
          }
        }
        if ("connectionStatus" in input) {
          options.database
            .query("UPDATE scimManagedConnection SET status=? WHERE connectionId=?")
            .run(input.connectionStatus, input.connectionId);
        }
        return new Response(JSON.stringify({ changed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "oversize-group-read") {
        options.database.exec(
          "WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<1001) INSERT INTO scimGroupMember (id,connectionId,groupId,scimUserId,membershipKey,createdAt) SELECT 'cap-'||CAST(n AS TEXT),'conn-a','staff','member-a','cap-'||CAST(n AS TEXT),'2026-01-02T03:04:05.000Z' FROM seq",
        );
        return new Response(JSON.stringify({ oversized: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "drift-read-binding") {
        options.database.exec(
          "UPDATE scimConnectionBinding SET provisioningDomainId='drifted-domain' WHERE connectionId='conn-a'",
        );
        return new Response(JSON.stringify({ changed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "retire-read-binding") {
        options.database.exec(
          "UPDATE scimConnectionBinding SET provisioningDomainId='tenant-a',decommissionStatus='complete' WHERE connectionId='conn-a'",
        );
        return new Response(JSON.stringify({ retired: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "getSCIMGroup") {
        const input = (await request.json()) as any;
        return auth.api.getSCIMGroup({
          params: input.params,
          query: input.query,
          headers:
            input.token === undefined ? undefined : { authorization: `Bearer ${input.token}` },
          asResponse: true,
        });
      }
      if (query.get("operation") === "seed-group-read") {
        const owner = await auth.api.signUpEmail({
          body: {
            email: "group-read-owner@example.com",
            password: "a-native-password-123",
            name: "Group owner",
          },
        });
        for (const [id, cid, domain, display] of [
          ["member-a", "conn-a", "tenant-a", "Inactive member"],
          ["member-b", "conn-b", "tenant-a", "Foreign member"],
          ["member-c", "conn-a", "tenant-b", "Other domain member"],
        ]) {
          options.database
            .query(
              "INSERT INTO scimUser (id,connectionId,provisioningDomainId,userId,connectionUserKey,userName,userNameKey,primaryEmail,workEmailValueIndex,emailValueIndex,displayName,formattedName,serializedEmails,active,orderKey,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,'group-read-owner@example.com','[]','[]',?,?,'[]',0,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",
            )
            .run(id, cid, domain, owner.user.id, id, id, id, display, display, id);
        }
        for (const [id, cid, domain] of [
          ["staff", "conn-a", "tenant-a"],
          ["other", "conn-b", "tenant-a"],
          ["drift", "conn-a", "tenant-b"],
        ]) {
          options.database
            .query(
              "INSERT INTO scimGroup (id,connectionId,provisioningDomainId,revision,displayName,displayNameKey,externalId,orderKey,createdAt,updatedAt) VALUES (?,?,?,0,'Staff',?,'external-staff',?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",
            )
            .run(id, cid, domain, id, id);
        }
        for (const [id, time] of [
          ["member-a", "2026-01-02T03:04:05.001Z"],
          ["member-b", "2026-01-02T03:04:05.002Z"],
          ["member-c", "2026-01-02T03:04:05.003Z"],
        ]) {
          options.database
            .query(
              "INSERT INTO scimGroupMember (id,connectionId,groupId,scimUserId,membershipKey,createdAt) VALUES (?,'conn-a','staff',?,?,?)",
            )
            .run(id, id, id, time);
        }
        return new Response(JSON.stringify({ seeded: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "seed-role-groups") {
        for (const [id, cid, domain, display, external] of [
          ["group-a", "conn-a", "tenant-a", "Admins", "administrators"],
          ["group-b", "conn-a", "tenant-a", "Admin backups", "administrators-b"],
          ["group-e", "conn-a", "tenant-a", "Editors", "editors"],
          ["group-g", "conn-a", "tenant-a", "Guests", "guests"],
          ["group-c", "conn-a", "tenant-b", "Foreign domain", "foreign-domain"],
          ["group-d", "conn-other", "tenant-a", "Foreign connection", "foreign-connection"],
        ] as const) {
          options.database
            .query(
              "INSERT INTO scimGroup (id,connectionId,provisioningDomainId,revision,displayName,displayNameKey,externalId,externalIdKey,orderKey,createdAt,updatedAt) VALUES (?,?,?,0,?,?,?,?,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",
            )
            .run(id, cid, domain, display, id, external, id, id);
          options.database
            .query(
              "INSERT INTO scimGroupMember (id,connectionId,groupId,scimUserId,membershipKey,createdAt) VALUES (?,'conn-a',?,'scim-alias-a',?,'2026-01-02T03:04:05.000Z')",
            )
            .run(id, id, id);
        }
        return new Response(JSON.stringify({ seeded: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "role-observations") {
        return new Response(JSON.stringify({ mapped: roleMapped, checked: roleChecked }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "rename-role-source") {
        options.database.exec(
          "UPDATE scimGroup SET externalId='administrators-renamed' WHERE id='group-a'",
        );
        return new Response(JSON.stringify({ renamed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "role-failure-stage") {
        const input = (await request.json()) as any;
        roleStage = input.stage;
        return new Response(JSON.stringify({ stage: roleStage }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "prepare-active-bindings") {
        for (const [connectionId, provisioningDomainId] of [
          ["conn-a", "tenant-a"],
          ["conn-c", "tenant-b"],
        ]) {
          await auth.api.decommissionSCIMConnection({
            body: { connectionId, provisioningDomainId },
          });
          options.database
            .query(
              "UPDATE scimConnectionBinding SET decommissionStatus='active',decommissionedAt=NULL,decommissionCompletedAt=NULL WHERE connectionId=?",
            )
            .run(connectionId);
        }
        return new Response(JSON.stringify({ prepared: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "projection-toggle-failure") {
        const input = (await request.json()) as any;
        projectionFails = input.fail;
        return new Response(JSON.stringify({ failing: projectionFails }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "configure-identity") {
        options.plugins = [
          scim({
            connections: [],
            authentication: { verifyBearerToken: async () => null },
            managedConnections: {
              credentialHashSecret: "managed-scim-credential-hmac-secret-32-chars",
              maxActiveCredentials: 2,
            },
            identity: {
              reconcileUser: async (input, context) => {
                await context.database.update({
                  model: "user",
                  where: [{ field: "id", value: input.userId }],
                  update: {
                    name: identityFails
                      ? "Should roll back identity"
                      : input.active
                        ? "Identity active"
                        : "Identity inactive",
                  },
                });
                identityStates.push(input);
                if (identityFails) throw new Error("application rejected identity");
              },
            },
          }),
        ];
        auth = betterAuth(options);
        return new Response(JSON.stringify({ configured: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "identity-states") {
        return new Response(JSON.stringify(identityStates), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "identity-toggle-failure") {
        const input = (await request.json()) as any;
        identityFails = input.fail;
        return new Response(JSON.stringify({ failing: identityFails }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "claim-profile-source") {
        options.database.exec("UPDATE scimSubject SET profileSourceId='scim-alias-a'");
        return new Response(JSON.stringify({ claimed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "seed-projection") {
        const input = (await request.json()) as { sourceIds?: string[] };
        const [aliasA = "scim-alias-a", aliasB = "scim-alias-b", aliasC = "scim-alias-c"] =
          input.sourceIds ?? [];
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
          [aliasA, "conn-a", "tenant-a", 1],
          [aliasB, "conn-b", "tenant-a", 0],
          [aliasC, "conn-c", "tenant-b", 1],
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
            sessions: options.database
              .query(
                "SELECT id,userId FROM session WHERE userId IN (SELECT id FROM user WHERE email='projection-owner@example.com')",
              )
              .all(),
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
