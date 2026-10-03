import { createAuthClient } from "better-auth/client";
import { oauthPopupClient } from "better-auth/client/plugins";
const client = createAuthClient({
  baseURL: `${new URLSearchParams(location.search).get("authOrigin") || location.origin}/__test/profiles/oauth-popup/api/auth`,
  plugins: [oauthPopupClient()],
});
Object.assign(window, { popupClient: client });
