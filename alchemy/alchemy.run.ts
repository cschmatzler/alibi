import { Query } from "@distilled.cloud/core/query";
import { Railway as RailwayApi } from "@distilled.cloud/railway";
import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";
import * as Namespace from "alchemy/Namespace";
import * as Output from "alchemy/Output";
import * as Railway from "alchemy/Railway";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";

const domainDns = Query.fn((id: string, projectId: string) =>
  RailwayApi.customDomain({ id, projectId }).status.dnsRecords.pipe(
    Query.map((record) => ({
      type: record.recordType,
      zone: record.zone,
      content: record.requiredValue,
    })),
  ),
);

export const Docs = Effect.gen(function* () {
  const domain = yield* Config.String("DOCS_DOMAIN").pipe(Config.withDefault(""));
  // Keep the project in the website's resource namespace.
  const project = yield* Railway.Project("Project", {
    name: "better-auth-rs",
  }).pipe(Namespace.push("Docs"));

  const docs = yield* Railway.Website.Astro("Docs", {
    project,
    rootDir: "./docs",
    serviceName: "docs",
    astro: {
      output: "static",
      site: domain ? `https://${domain}` : undefined,
    },
    assets: { notFoundHandling: "404-page" },
  });

  if (domain && docs.service) {
    // Keep the existing Docs/Domain resource identity when moving it out
    // of the website helper so its DNS outputs can drive Cloudflare.
    const customDomain = yield* Railway.CustomDomain("Domain", {
      service: docs.service,
      environment: project,
      domain,
      targetPort: 3000,
    }).pipe(Namespace.push("Docs"));
    const zoneId = yield* Config.String("DOCS_DNS_ZONE_ID");
    const records = Output.all(customDomain.customDomainId, project.projectId).pipe(
      Output.mapEffect(([id, projectId]) => domainDns(id, projectId).pipe(Effect.orDie)),
    );
    yield* Cloudflare.DNS.Record("DocsCNAME", {
      zoneId,
      type: "CNAME",
      name: domain,
      content: records.pipe(Output.map((records) => {
        const record = records.find((record) => record.type === "DNS_RECORD_TYPE_CNAME");
        if (!record?.content) {
          throw new Error(`Railway did not return a CNAME target for ${domain}`);
        }
        return record.content;
      })),
      proxied: false,
    });
    yield* Cloudflare.DNS.Record("DocsTXT", {
      zoneId,
      type: "TXT",
      name: `_railway-verify.${domain}`,
      content: customDomain.verificationToken.pipe(Output.map((token) => {
        if (!token) throw new Error(`Railway did not return a verification token for ${domain}`);
        return token;
      })),
    });
  }

  return { ...docs, url: domain ? `https://${domain}` : docs.url };
});

export default Alchemy.Stack(
  "BetterAuthDocs",
  {
    providers: Cloudflare.providers().pipe(Layer.provideMerge(Railway.providers())),
    state: Cloudflare.state(),
  },
  Effect.gen(function* () {
    const docs = yield* Docs;
    return { url: docs.url };
  }),
);
