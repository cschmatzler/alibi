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
      content: record.requiredValue,
    })),
  ),
);

export const Docs = Effect.gen(function* () {
  const domain = yield* Config.String("DOCS_DOMAIN");
  const zoneId = yield* Config.String("DOCS_DNS_ZONE_ID");

  const project = yield* Railway.Project("Project", {
    name: "alibi",
  }).pipe(Namespace.push("Docs"));

  const docs = yield* Railway.Website.Astro("Docs", {
    project,
    rootDir: "./docs",
    serviceName: "docs",
    astro: {
      output: "static",
      site: `https://${domain}`,
    },
    assets: { notFoundHandling: "404-page" },
  });

  const service =
    docs.service ?? (yield* Effect.die(new Error("Missing Railway service")));

  const customDomain = yield* Railway.CustomDomain("Domain", {
    service,
    environment: project,
    domain,
    targetPort: 3000,
  }).pipe(Namespace.push("Docs"));

  const records = Output.mapEffect(
    (resource: Railway.CustomDomain["Attributes"]) =>
      domainDns(resource.customDomainId, resource.projectId).pipe(Effect.orDie),
  )(Output.of(customDomain));

  yield* Cloudflare.DNS.Record("DocsCNAME", {
    zoneId,
    type: "CNAME",
    name: domain,
    content: Output.map(records, (records) => {
      const record = records.find(
        (record) => record.type === "DNS_RECORD_TYPE_CNAME",
      );

      if (!record?.content) {
        throw new Error(`Railway did not return a CNAME target for ${domain}`);
      }

      return record.content;
    }),
    proxied: false,
  });

  yield* Cloudflare.DNS.Record("DocsTXT", {
    zoneId,
    type: "TXT",
    name: `_railway-verify.${domain}`,
    content: customDomain.verificationToken.pipe(
      Output.map((token) => {
        if (!token) {
          throw new Error(`Railway did not return a verification token for ${domain}`);
        }

        return token;
      }),
    ),
  });

  return { url: `https://${domain}` };
});

export default Alchemy.Stack(
  "BetterAuthDocs",
  {
    providers: Cloudflare.providers().pipe(Layer.provideMerge(Railway.providers())),
    state: Cloudflare.state(),
  },
  Docs,
);
