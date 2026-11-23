/** Sliding windows configured by the OAuth provider quota fixture. */
export function oauthProtocolQuotaSeconds(mode: string, path: string): number | undefined {
  switch (mode) {
    case "rate-default":
      return path === "/oauth2/token-extra" ? 120 : 60;
    case "rate-override":
      if (path === "/oauth2/token") return 120;
      if (path === "/oauth2/authorize") return 60;
      return;
    case "rate-false":
      return 120;
    case "rate-application":
      return path === "/oauth2/token" ? undefined : 180;
  }
}
