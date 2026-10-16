import {
  adminClient,
  multiSessionClient,
  organizationClient,
  twoFactorClient,
  usernameClient,
} from "better-auth/client/plugins";
import { createAuthClient } from "better-auth/react";
import { createElement } from "react";
import { createRoot } from "react-dom/client";

export type FetchInput = {
  url: string;
  method: string;
  headers: [string, string][];
  body?: string;
};
type FetchOutput = { status: number; headers: [string, string][]; body: string };

const redirects: { twoFactorMethods?: string[] }[] = [];
const client = createAuthClient({
  baseURL: location.origin,
  plugins: [
    usernameClient(),
    organizationClient(),
    multiSessionClient(),
    adminClient(),
    twoFactorClient({
      onTwoFactorRedirect: async (context) => {
        redirects.push(context);
      },
    }),
  ],
  sessionOptions: { refetchOnWindowFocus: false },
  fetchOptions: {
    ...(new URLSearchParams(location.search).has("jsonContentType")
      ? { headers: { "content-type": "application/json" } }
      : {}),
    customFetchImpl: async (input, init) => {
      const request = new Request(input, init);
      const result = await window.reactFetch({
        url: request.url,
        method: request.method,
        headers: [...request.headers],
        ...(request.body === null ? {} : { body: await request.text() }),
      });
      if (new URL(request.url).pathname.endsWith("/get-session")) window.reactSessionReads += 1;
      return new Response(result.body, { status: result.status, headers: result.headers });
    },
  },
});
declare global {
  interface Window {
    reactFetch(input: FetchInput): Promise<FetchOutput>;
    reactClient: typeof client;
    reactRedirects: typeof redirects;
    reactSessionReads: number;
  }
}
function value(store: {
  data: unknown;
  error: unknown;
  isPending: boolean;
  isRefetching: boolean;
}) {
  return {
    data: store.data,
    error: store.error,
    isPending: store.isPending,
    isRefetching: store.isRefetching,
  };
}
function Organizations() {
  const list = client.useListOrganizations();
  const active = client.useActiveOrganization();
  const member = client.useActiveMember();
  const role = client.useActiveMemberRole();
  return createElement(
    "pre",
    { id: "organizations" },
    JSON.stringify({
      list: value(list),
      active: value(active),
      member: value(member),
      role: value(role),
    }),
  );
}
const showOrganizations = new URLSearchParams(location.search).get("organizations") !== "false";
function App() {
  const session = client.useSession();
  return createElement(
    "main",
    null,
    createElement("pre", { id: "session" }, JSON.stringify(value(session))),
    createElement("button", { id: "refetch", onClick: () => session.refetch() }, "Refetch session"),
    session.data && showOrganizations ? createElement(Organizations) : null,
  );
}
window.reactClient = client;
window.reactRedirects = redirects;
window.reactSessionReads = 0;
const root = document.createElement("div");
document.body.append(root);
createRoot(root).render(createElement(App));
