/** Private configurations and persistence observations; authentication uses pinned Better Auth. */
import {betterAuth} from "better-auth";
import {APIError} from "better-auth/api";
import {organization} from "better-auth/plugins";
import {createAccessControl} from "better-auth/plugins/access";
import {defaultStatements} from "better-auth/plugins/organization/access";
import type {Database} from "bun:sqlite";

export const CREATION_PROFILES = [
  "org-creation-denied", "org-creation-limit", "org-creation-negative",
  "org-creation-infinity", "org-creation-nan", "org-creation-callback",
  "org-creation-founder", "org-creation-empty-role",
] as const;

type CallbackUser = {id:string; email:string; name:string};
type Receipt = {operation:string; userId:string; email:string; name:string};

export function createOrganizationCreationFixture(
  database:Database,
  shared:Parameters<typeof betterAuth>[0],
  origin:string,
) {
  const receipts:Receipt[] = [];
  const ac = createAccessControl(defaultStatements);
  const profiles = new Map(CREATION_PROFILES.map(name => {
    const opts = name === "org-creation-denied" ? {allowUserToCreateOrganization:false}
      : name === "org-creation-limit" ? {organizationLimit:1.5}
      : name === "org-creation-negative" ? {organizationLimit:-0.5}
      : name === "org-creation-infinity" ? {organizationLimit:Infinity}
      : name === "org-creation-nan" ? {organizationLimit:NaN}
      : name === "org-creation-empty-role" ? {creatorRole:""}
      : name === "org-creation-founder" ? {
        creatorRole:"founder", ac,
        roles:{
          founder:ac.newRole({invitation:["create"]}),
          editor:ac.newRole({organization:["update"]}),
        },
      } : {
        allowUserToCreateOrganization:async(user:CallbackUser) => {
          receipts.push({operation:"allow", userId:user.id, email:user.email, name:user.name});
          if (user.name === "Reject Allow") {
            throw new APIError("FORBIDDEN", {
              code:"CREATION_ALLOW_REJECTED", message:"Creation allow callback rejected",
            });
          }
          return user.name.startsWith("Paid");
        },
        organizationLimit:async(user:CallbackUser) => {
          receipts.push({operation:"limit", userId:user.id, email:user.email, name:user.name});
          if (user.name === "Paid Reject Limit") {
            throw new APIError("FORBIDDEN", {
              code:"CREATION_LIMIT_REJECTED", message:"Creation limit callback rejected",
            });
          }
          const row = database.query('SELECT COUNT(*) AS count FROM member WHERE userId=?')
            .get(user.id) as {count:number};
          return row.count >= 1;
        },
      };
    return [name, betterAuth({
      ...shared, database, baseURL:origin,
      basePath:`/__test/profiles/${name}/api/auth`, plugins:[organization(opts)],
    })] as const;
  }));
  return {
    profiles,
    state(email:string, includeMetadata=false) {
      const user = database.query('SELECT id FROM user WHERE email=?').get(email) as {id:string}|null;
      return {
        organizations:user ? database.query(
          `SELECT o.id,o.name,o.slug,${includeMetadata ? 'o.metadata,' : ''}m.id AS memberId,m.userId,m.role FROM organization o JOIN member m ON m.organizationId=o.id WHERE m.userId=? ORDER BY o.createdAt,o.id`,
        ).all(user.id) : [],
        sessions:user ? database.query(
          'SELECT id,token,userId,activeOrganizationId FROM session WHERE userId=? ORDER BY createdAt,id',
        ).all(user.id) : [],
        orphanOrganizations:database.query(
          'SELECT o.id,o.name,o.slug FROM organization o LEFT JOIN member m ON m.organizationId=o.id WHERE m.id IS NULL ORDER BY o.createdAt,o.id',
        ).all(),
        receipts:receipts.filter(receipt => receipt.email === email),
      };
    },
    async server(body:Record<string,unknown>) {
      const profile = profiles.get(body.profile as typeof CREATION_PROFILES[number]);
      if (!profile) return Response.json({message:"Unknown fixture profile"}, {status:400});
      try {
        return Response.json(await profile.api.createOrganization({body:{
          name:String(body.name), slug:String(body.slug), userId:String(body.userId),
          ...(body.metadata === undefined ? {} : {metadata:body.metadata as Record<string,unknown>}),
          ...(body.keepCurrentActiveOrganization === undefined ? {} : {
            keepCurrentActiveOrganization:body.keepCurrentActiveOrganization === true,
          }),
        }}));
      } catch (error) {
        const result = error as {statusCode?:number; body?:unknown};
        return Response.json(result.body ?? null, {status:result.statusCode ?? 500});
      }
    },
  };
}
