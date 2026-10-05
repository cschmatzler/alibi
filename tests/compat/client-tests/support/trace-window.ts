export const requestWindow = Symbol("compat-request-window");

export type RequestWindow = {
  startedAt: number;
  finishedAt: number;
  inputDates: Record<string, string>;
  inputOwner?: { field: "id" | "token"; value: string };
  sessionCookie?: string;
  issuedSessionCookie?: string;
  /** Exact account JWE observed from the real issuing response. */
  issuedAccountCookie?: string;
  /** Complete multi-session Set-Cookie headers observed from the real response. */
  issuedMultiSessionCookies?: string[];
  /** Exact email and signed challenge returned by the real password sign-in. */
  signInEmail?: string;
  issuedTwoFactorCookie?: string;
  /** Actual outer-signed, user-bound trust proof returned by factor verification. */
  issuedTrustCookie?: string;
  /** Actual signed database-state cookie from the default OAuth issuing response. */
  issuedVerificationStateCookie?: string;
  /** Exact input of verification producers, provider profile and explicit expiry controls. */
  verificationInput?: unknown;
  /** Integrity of the original complete parsed observer response, separate from compared output. */
  verificationObserverDigest?: string;
  /** Original remote signer input and signed response, before any client projection. */
  remoteJwtSigning?: { input: unknown; response: unknown; digest: string };
  /** Complete callback receipt from the real signer observer. */
  remoteJwtObserver?: { body: unknown; digest: string };
  /** Original narrow physical controls; their values are not transport output. */
  controlObservation?: {
    kind:
      | "member-addition"
      | "social-provider"
      | "user-validation"
      | "managed-secrets"
      | "jwt-keyring";
    body: unknown;
    digest: string;
  };
  memberAdditionOwner?: { organizationId: string; userId: string };
  jwtKeyringInput?: { profile: string; operation: string };
  /** Exact application error destination supplied to an actual OAuth grant. */
  oauthErrorCallbackURL?: string;
};
