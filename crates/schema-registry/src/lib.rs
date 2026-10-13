//! Authoritative field registry for Alibi entity schemas.
//!
//! Shared by the `AuthEntity` proc macro (for compile-time validation)
//! and the CLI (for code generation). This is the single source of truth
//! for which fields belong to core vs which are plugin-provided.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntityRole {
    User,
    Session,
    Account,
    Verification,
}

#[derive(Clone, Copy, Debug)]
pub struct FieldDef {
    pub name: &'static str,
    /// Rust type as it appears in a `SeaORM` `Model` struct,
    /// e.g. `"Option<String>"`, `"bool"`, `"DateTimeUtc"`, `"Json"`.
    pub ty: &'static str,
    pub is_primary_key: bool,
    pub column_name: Option<&'static str>,
    /// Database string default, rendered as a literal by each backend.
    pub default_value: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub struct PluginSchema {
    pub name: &'static str,
    pub user_fields: &'static [FieldDef],
    pub session_fields: &'static [FieldDef],
    pub extra_entities: &'static [ExtraEntitySchema],
}

#[derive(Clone, Copy, Debug)]
pub struct ExtraEntitySchema {
    pub mod_name: &'static str,
    pub table_name: &'static str,
    pub role: Option<EntityRole>,
    pub fields: &'static [FieldDef],
}

macro_rules! f {
    ($name:expr, $ty:expr, $default:expr) => {
        FieldDef {
            default_value: Some($default),
            ..f!($name, $ty)
        }
    };
    ($name:expr, $ty:expr) => {
        FieldDef {
            name: $name,
            ty: $ty,
            is_primary_key: false,
            column_name: None,
            default_value: None,
        }
    };
}

macro_rules! pk {
    ($name:expr, $ty:expr) => {
        FieldDef {
            is_primary_key: true,
            ..f!($name, $ty)
        }
    };
}

macro_rules! f_col {
    ($name:expr, $ty:expr, $column_name:expr) => {
        FieldDef {
            column_name: Some($column_name),
            ..f!($name, $ty)
        }
    };
}

static USER_CORE: &[FieldDef] = &[
    pk!("id", "String"),
    f!("name", "String"),
    f!("email", "String"),
    f_col!("email_verified", "bool", "emailVerified"),
    f!("image", "Option<String>"),
    f_col!("created_at", "DateTimeUtc", "createdAt"),
    f_col!("updated_at", "DateTimeUtc", "updatedAt"),
];

static SESSION_CORE: &[FieldDef] = &[
    pk!("id", "String"),
    f_col!("expires_at", "DateTimeUtc", "expiresAt"),
    f!("token", "String"),
    f_col!("created_at", "DateTimeUtc", "createdAt"),
    f_col!("updated_at", "DateTimeUtc", "updatedAt"),
    f_col!("ip_address", "Option<String>", "ipAddress"),
    f_col!("user_agent", "Option<String>", "userAgent"),
    f_col!("user_id", "String", "userId"),
];

static ACCOUNT_CORE: &[FieldDef] = &[
    pk!("id", "String"),
    f_col!("account_id", "String", "accountId"),
    f_col!("provider_id", "String", "providerId"),
    f_col!("user_id", "String", "userId"),
    f_col!("access_token", "Option<String>", "accessToken"),
    f_col!("refresh_token", "Option<String>", "refreshToken"),
    f_col!("id_token", "Option<String>", "idToken"),
    f_col!(
        "access_token_expires_at",
        "Option<DateTimeUtc>",
        "accessTokenExpiresAt"
    ),
    f_col!(
        "refresh_token_expires_at",
        "Option<DateTimeUtc>",
        "refreshTokenExpiresAt"
    ),
    f!("scope", "Option<String>"),
    f!("password", "Option<String>"),
    f_col!("created_at", "DateTimeUtc", "createdAt"),
    f_col!("updated_at", "DateTimeUtc", "updatedAt"),
];

static VERIFICATION_CORE: &[FieldDef] = &[
    pk!("id", "String"),
    f!("identifier", "String"),
    f!("value", "String"),
    f_col!("expires_at", "DateTimeUtc", "expiresAt"),
    f_col!("created_at", "DateTimeUtc", "createdAt"),
    f_col!("updated_at", "DateTimeUtc", "updatedAt"),
];

static PLUGINS: &[PluginSchema] = &[
    PluginSchema {
        name: "siwe",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "wallet_address",
            table_name: "walletAddress",
            role: None,
            fields: &[
                pk!("id", "String"),
                f_col!("user_id", "String", "userId"),
                f!("address", "String"),
                f_col!("chain_id", "f64", "chainId"),
                f_col!("is_primary", "bool", "isPrimary"),
                f_col!("created_at", "DateTimeUtc", "createdAt"),
            ],
        }],
    },
    PluginSchema {
        name: "jwt",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "jwk",
            table_name: "jwks",
            role: None,
            fields: &[
                pk!("id", "String"),
                f_col!("public_key", "String", "publicKey"),
                f_col!("private_key", "String", "privateKey"),
                f_col!("created_at", "DateTimeUtc", "createdAt"),
                f_col!("expires_at", "Option<DateTimeUtc>", "expiresAt"),
                f!("alg", "Option<String>"),
                f!("crv", "Option<String>"),
            ],
        }],
    },
    PluginSchema {
        name: "anonymous",
        user_fields: &[f_col!("is_anonymous", "Option<bool>", "isAnonymous")],
        session_fields: &[],
        extra_entities: &[],
    },
    PluginSchema {
        name: "phone-number",
        user_fields: &[
            f_col!("phone_number", "Option<String>", "phoneNumber"),
            f_col!(
                "phone_number_verified",
                "Option<bool>",
                "phoneNumberVerified"
            ),
        ],
        session_fields: &[],
        extra_entities: &[],
    },
    PluginSchema {
        name: "last-login-method",
        user_fields: &[f_col!(
            "last_login_method",
            "Option<String>",
            "lastLoginMethod"
        )],
        session_fields: &[],
        extra_entities: &[],
    },
    PluginSchema {
        name: "organization-teams",
        user_fields: &[],
        session_fields: &[f_col!("active_team_id", "Option<String>", "activeTeamId")],
        extra_entities: &[
            ExtraEntitySchema {
                mod_name: "team",
                table_name: "team",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f!("name", "String"),
                    f_col!("organization_id", "String", "organizationId"),
                    f_col!("member_count", "i64", "memberCount"),
                    f_col!("created_at", "DateTimeUtc", "createdAt"),
                    f_col!("updated_at", "Option<DateTimeUtc>", "updatedAt"),
                ],
            },
            ExtraEntitySchema {
                mod_name: "team_member",
                table_name: "teamMember",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f_col!("team_id", "String", "teamId"),
                    f_col!("user_id", "String", "userId"),
                    f_col!("membership_key", "Option<String>", "membershipKey"),
                    f_col!("created_at", "Option<DateTimeUtc>", "createdAt"),
                ],
            },
        ],
    },
    PluginSchema {
        name: "organization-dynamic-roles",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "organization_role",
            table_name: "organizationRole",
            role: None,
            fields: &[
                pk!("id", "String"),
                f_col!("organization_id", "String", "organizationId"),
                f!("role", "String"),
                f!("permission", "String"),
                f_col!("created_at", "DateTimeUtc", "createdAt"),
                f_col!("updated_at", "Option<DateTimeUtc>", "updatedAt"),
            ],
        }],
    },
    PluginSchema {
        name: "username",
        user_fields: &[
            f!("username", "Option<String>"),
            f_col!("display_username", "Option<String>", "displayUsername"),
        ],
        session_fields: &[],
        extra_entities: &[],
    },
    PluginSchema {
        name: "two-factor",
        user_fields: &[f_col!(
            "two_factor_enabled",
            "Option<bool>",
            "twoFactorEnabled"
        )],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "two_factor",
            table_name: "twoFactor",
            role: None,
            fields: &[
                pk!("id", "String"),
                f!("secret", "String"),
                f_col!("backup_codes", "String", "backupCodes"),
                f_col!("user_id", "String", "userId"),
                f!("verified", "Option<bool>"),
                f_col!(
                    "failed_verification_count",
                    "Option<f64>",
                    "failedVerificationCount"
                ),
                f_col!("locked_until", "Option<DateTimeUtc>", "lockedUntil"),
            ],
        }],
    },
    PluginSchema {
        name: "device-authorization",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "device_code",
            table_name: "deviceCode",
            role: None,
            fields: &[
                pk!("id", "String"),
                f_col!("device_code", "String", "deviceCode"),
                f_col!("user_code", "String", "userCode"),
                f_col!("user_id", "Option<String>", "userId"),
                f_col!("expires_at", "DateTimeUtc", "expiresAt"),
                f!("status", "String"),
                f_col!("last_polled_at", "Option<DateTimeUtc>", "lastPolledAt"),
                f_col!("polling_interval", "Option<i64>", "pollingInterval"),
                f_col!("client_id", "Option<String>", "clientId"),
                f!("scope", "Option<String>"),
            ],
        }],
    },
    PluginSchema {
        name: "admin",
        user_fields: &[
            f!("role", "Option<String>"),
            f!("banned", "Option<bool>"),
            f_col!("ban_reason", "Option<String>", "banReason"),
            f_col!("ban_expires", "Option<DateTimeUtc>", "banExpires"),
        ],
        session_fields: &[f_col!(
            "impersonated_by",
            "Option<String>",
            "impersonatedBy"
        )],
        extra_entities: &[],
    },
    PluginSchema {
        name: "organization",
        user_fields: &[],
        session_fields: &[f_col!(
            "active_organization_id",
            "Option<String>",
            "activeOrganizationId"
        )],
        extra_entities: &[
            ExtraEntitySchema {
                mod_name: "organization",
                table_name: "organization",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f!("name", "String"),
                    f!("slug", "String"),
                    f!("logo", "Option<String>"),
                    f!("metadata", "Option<Json>"),
                    f_col!("created_at", "DateTimeUtc", "createdAt"),
                ],
            },
            ExtraEntitySchema {
                mod_name: "member",
                table_name: "member",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f_col!("organization_id", "String", "organizationId"),
                    f_col!("user_id", "String", "userId"),
                    f!("role", "String"),
                    f_col!("created_at", "DateTimeUtc", "createdAt"),
                ],
            },
            ExtraEntitySchema {
                mod_name: "invitation",
                table_name: "invitation",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f_col!("organization_id", "String", "organizationId"),
                    f!("email", "String"),
                    f!("role", "Option<String>"),
                    f_col!("team_id", "Option<String>", "teamId"),
                    f!("status", "String"),
                    f_col!("inviter_id", "String", "inviterId"),
                    f_col!("expires_at", "DateTimeUtc", "expiresAt"),
                    f_col!("created_at", "DateTimeUtc", "createdAt"),
                ],
            },
        ],
    },
    PluginSchema {
        name: "api-key",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "api_key",
            table_name: "apikey",
            role: None,
            fields: &[
                pk!("id", "String"),
                f!("name", "Option<String>"),
                f!("start", "Option<String>"),
                f!("prefix", "Option<String>"),
                f_col!("key_hash", "String", "key"),
                f_col!("reference_id", "String", "referenceId"),
                f_col!("config_id", "String", "configId"),
                f_col!("refill_interval", "Option<f64>", "refillInterval"),
                f_col!("refill_amount", "Option<f64>", "refillAmount"),
                f_col!("last_refill_at", "Option<DateTimeUtc>", "lastRefillAt"),
                f!("enabled", "Option<bool>"),
                f_col!("rate_limit_enabled", "Option<bool>", "rateLimitEnabled"),
                f_col!(
                    "rate_limit_time_window",
                    "Option<f64>",
                    "rateLimitTimeWindow"
                ),
                f_col!("rate_limit_max", "Option<f64>", "rateLimitMax"),
                f_col!("request_count", "Option<f64>", "requestCount"),
                f!("remaining", "Option<f64>"),
                f_col!("last_request", "Option<DateTimeUtc>", "lastRequest"),
                f_col!("expires_at", "Option<DateTimeUtc>", "expiresAt"),
                f_col!("created_at", "DateTimeUtc", "createdAt"),
                f_col!("updated_at", "DateTimeUtc", "updatedAt"),
                f!("permissions", "Option<String>"),
                f!("metadata", "Option<String>"),
            ],
        }],
    },
    PluginSchema {
        name: "passkey",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "passkey",
            table_name: "passkey",
            role: None,
            fields: &[
                pk!("id", "String"),
                f!("name", "Option<String>"),
                f_col!("public_key", "String", "publicKey"),
                f_col!("user_id", "String", "userId"),
                f_col!("credential_id", "String", "credentialID"),
                f!("counter", "i64"),
                f_col!("device_type", "String", "deviceType"),
                f_col!("backed_up", "bool", "backedUp"),
                f!("transports", "Option<String>"),
                f!("aaguid", "Option<String>"),
                f_col!("created_at", "Option<DateTimeUtc>", "createdAt"),
            ],
        }],
    },
    PluginSchema {
        name: "oauth-provider",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[
            ExtraEntitySchema {
                mod_name: "oauth_client",
                table_name: "oauthClient",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f_col!("client_id", "String", "clientId"),
                    f_col!("client_secret", "Option<String>", "clientSecret"),
                    f_col!("client_discovery_id", "Option<String>", "clientDiscoveryId"),
                    f_col!("disabled", "Option<bool>", "disabled"),
                    f_col!("skip_consent", "Option<bool>", "skipConsent"),
                    f_col!("enable_end_session", "Option<bool>", "enableEndSession"),
                    f_col!("subject_type", "Option<String>", "subjectType"),
                    f_col!("scopes", "Option<Json>", "scopes"),
                    f_col!(
                        "client_credentials_scopes",
                        "Option<Json>",
                        "clientCredentialsScopes"
                    ),
                    f_col!("user_id", "Option<String>", "userId"),
                    f_col!("created_at", "Option<DateTimeUtc>", "createdAt"),
                    f_col!("updated_at", "Option<DateTimeUtc>", "updatedAt"),
                    f_col!("name", "Option<String>", "name"),
                    f_col!("uri", "Option<String>", "uri"),
                    f_col!("icon", "Option<String>", "icon"),
                    f_col!("contacts", "Option<Json>", "contacts"),
                    f_col!("tos", "Option<String>", "tos"),
                    f_col!("policy", "Option<String>", "policy"),
                    f_col!("software_id", "Option<String>", "softwareId"),
                    f_col!("software_version", "Option<String>", "softwareVersion"),
                    f_col!("software_statement", "Option<String>", "softwareStatement"),
                    f_col!("redirect_uris", "Json", "redirectUris"),
                    f_col!(
                        "post_logout_redirect_uris",
                        "Option<Json>",
                        "postLogoutRedirectUris"
                    ),
                    f_col!(
                        "backchannel_logout_uri",
                        "Option<String>",
                        "backchannelLogoutUri"
                    ),
                    f_col!(
                        "backchannel_logout_session_required",
                        "Option<bool>",
                        "backchannelLogoutSessionRequired"
                    ),
                    f_col!(
                        "token_endpoint_auth_method",
                        "Option<String>",
                        "tokenEndpointAuthMethod"
                    ),
                    f_col!("application_type", "Option<String>", "applicationType"),
                    f_col!("jwks", "Option<String>", "jwks"),
                    f_col!("jwks_uri", "Option<String>", "jwksUri"),
                    f_col!("grant_types", "Option<Json>", "grantTypes"),
                    f_col!("response_types", "Option<Json>", "responseTypes"),
                    f_col!("require_pkce", "Option<bool>", "requirePKCE"),
                    f_col!(
                        "dpop_bound_access_tokens",
                        "Option<bool>",
                        "dpopBoundAccessTokens"
                    ),
                    f_col!("reference_id", "Option<String>", "referenceId"),
                    f_col!("metadata", "Option<Json>", "metadata"),
                ],
            },
            ExtraEntitySchema {
                mod_name: "oauth_resource",
                table_name: "oauthResource",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f_col!("identifier", "String", "identifier"),
                    f_col!("name", "String", "name"),
                    f_col!("access_token_ttl", "Option<i64>", "accessTokenTtl"),
                    f_col!("refresh_token_ttl", "Option<i64>", "refreshTokenTtl"),
                    f_col!("signing_algorithm", "Option<String>", "signingAlgorithm"),
                    f_col!("signing_key_id", "Option<String>", "signingKeyId"),
                    f_col!("allowed_scopes", "Option<Json>", "allowedScopes"),
                    f_col!("custom_claims", "Option<Json>", "customClaims"),
                    f_col!(
                        "dpop_bound_access_tokens_required",
                        "Option<bool>",
                        "dpopBoundAccessTokensRequired"
                    ),
                    f_col!("disabled", "Option<bool>", "disabled"),
                    f_col!("created_at", "Option<DateTimeUtc>", "createdAt"),
                    f_col!("updated_at", "Option<DateTimeUtc>", "updatedAt"),
                    f_col!("policy_version", "Option<i64>", "policyVersion"),
                    f_col!("metadata", "Option<Json>", "metadata"),
                ],
            },
            ExtraEntitySchema {
                mod_name: "oauth_client_resource",
                table_name: "oauthClientResource",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f_col!("client_id", "String", "clientId"),
                    f_col!("resource_id", "String", "resourceId"),
                    f_col!("metadata", "Option<Json>", "metadata"),
                    f_col!("created_at", "Option<DateTimeUtc>", "createdAt"),
                ],
            },
            ExtraEntitySchema {
                mod_name: "oauth_refresh_token",
                table_name: "oauthRefreshToken",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f_col!("token", "String", "token"),
                    f_col!("client_id", "String", "clientId"),
                    f_col!("session_id", "Option<String>", "sessionId"),
                    f_col!("user_id", "String", "userId"),
                    f_col!("reference_id", "Option<String>", "referenceId"),
                    f_col!(
                        "authorization_code_id",
                        "Option<String>",
                        "authorizationCodeId"
                    ),
                    f_col!("resources", "Option<Json>", "resources"),
                    f_col!(
                        "requested_user_info_claims",
                        "Option<Json>",
                        "requestedUserInfoClaims"
                    ),
                    f_col!("expires_at", "DateTimeUtc", "expiresAt"),
                    f_col!("created_at", "DateTimeUtc", "createdAt"),
                    f_col!("revoked", "Option<DateTimeUtc>", "revoked"),
                    f_col!("rotated_at", "Option<DateTimeUtc>", "rotatedAt"),
                    f_col!(
                        "rotation_replay_response",
                        "Option<String>",
                        "rotationReplayResponse"
                    ),
                    f_col!(
                        "rotation_replay_expires_at",
                        "Option<DateTimeUtc>",
                        "rotationReplayExpiresAt"
                    ),
                    f_col!("auth_time", "Option<DateTimeUtc>", "authTime"),
                    f_col!("confirmation", "Option<Json>", "confirmation"),
                    f_col!("scopes", "Json", "scopes"),
                ],
            },
            ExtraEntitySchema {
                mod_name: "oauth_access_token",
                table_name: "oauthAccessToken",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f_col!("token", "String", "token"),
                    f_col!("client_id", "String", "clientId"),
                    f_col!("session_id", "Option<String>", "sessionId"),
                    f_col!("user_id", "Option<String>", "userId"),
                    f_col!("reference_id", "Option<String>", "referenceId"),
                    f_col!(
                        "authorization_code_id",
                        "Option<String>",
                        "authorizationCodeId"
                    ),
                    f_col!("resources", "Option<Json>", "resources"),
                    f_col!(
                        "requested_user_info_claims",
                        "Option<Json>",
                        "requestedUserInfoClaims"
                    ),
                    f_col!("refresh_id", "Option<String>", "refreshId"),
                    f_col!("expires_at", "DateTimeUtc", "expiresAt"),
                    f_col!("created_at", "DateTimeUtc", "createdAt"),
                    f_col!("revoked", "Option<DateTimeUtc>", "revoked"),
                    f_col!("confirmation", "Option<Json>", "confirmation"),
                    f_col!("scopes", "Json", "scopes"),
                ],
            },
            ExtraEntitySchema {
                mod_name: "oauth_consent",
                table_name: "oauthConsent",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f_col!("client_id", "String", "clientId"),
                    f_col!("user_id", "Option<String>", "userId"),
                    f_col!("reference_id", "Option<String>", "referenceId"),
                    f_col!("resources", "Option<Json>", "resources"),
                    f_col!(
                        "requested_user_info_claims",
                        "Option<Json>",
                        "requestedUserInfoClaims"
                    ),
                    f_col!("scopes", "Json", "scopes"),
                    f_col!("created_at", "DateTimeUtc", "createdAt"),
                    f_col!("updated_at", "DateTimeUtc", "updatedAt"),
                ],
            },
            ExtraEntitySchema {
                mod_name: "oauth_client_assertion",
                table_name: "oauthClientAssertion",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f_col!("expires_at", "DateTimeUtc", "expiresAt"),
                ],
            },
        ],
    },
    PluginSchema {
        name: "sso",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "sso_provider",
            table_name: "ssoProvider",
            role: None,
            fields: &[
                pk!("id", "String"),
                f!("issuer", "String"),
                f!("domain", "String"),
                f_col!("provider_id", "String", "providerId"),
                f_col!("user_id", "String", "userId"),
                f_col!("organization_id", "Option<String>", "organizationId"),
                f_col!("oidc_config", "Option<String>", "oidcConfig"),
                f_col!("saml_config", "Option<String>", "samlConfig"),
                f_col!("domain_verified", "Option<bool>", "domainVerified"),
            ],
        }],
    },
    PluginSchema {
        name: "rate-limit",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "rate_limit",
            table_name: "rateLimit",
            role: None,
            fields: &[
                pk!("id", "String"),
                f!("key", "String"),
                f!("count", "i32"),
                f_col!("last_request", "i64", "lastRequest"),
            ],
        }],
    },
];

/// Core fields that are always required for a given entity role.
#[must_use]
pub fn core_fields(role: EntityRole) -> &'static [FieldDef] {
    match role {
        EntityRole::User => USER_CORE,
        EntityRole::Session => SESSION_CORE,
        EntityRole::Account => ACCOUNT_CORE,
        EntityRole::Verification => VERIFICATION_CORE,
    }
}

/// Plugin schemas — each plugin can add fields to user and/or session entities.
#[must_use]
pub fn plugin_schemas() -> &'static [PluginSchema] {
    PLUGINS
}

/// All plugin field names for a given role (convenience for the macro).
#[must_use]
pub fn plugin_field_names(role: EntityRole) -> Vec<&'static str> {
    plugin_schemas()
        .iter()
        .flat_map(|p| match role {
            EntityRole::User => p.user_fields.iter(),
            EntityRole::Session => p.session_fields.iter(),
            EntityRole::Account | EntityRole::Verification => [].iter(),
        })
        .map(|f| f.name)
        .collect()
}

/// Core field names only (convenience for the macro).
#[must_use]
pub fn core_field_names(role: EntityRole) -> Vec<&'static str> {
    core_fields(role).iter().map(|f| f.name).collect()
}

/// Exact bundled SQL compiled from the pinned Better Auth TypeScript schema.
pub const SQLITE_AUTH_SCHEMA: &str = include_str!("../schema/sqlite.sql");
pub const POSTGRES_AUTH_SCHEMA: &str = include_str!("../schema/postgres.sql");
pub const SQLITE_OAUTH_SCHEMA: &str = include_str!("../schema/sqlite_oauth_clients.sql");
pub const POSTGRES_OAUTH_SCHEMA: &str = include_str!("../schema/postgres_oauth_clients.sql");
pub const SQLITE_RATE_LIMIT_SCHEMA: &str = include_str!("../schema/sqlite_rate_limit.sql");
pub const POSTGRES_RATE_LIMIT_SCHEMA: &str = include_str!("../schema/postgres_rate_limit.sql");

pub const SQLITE_SSO_SCHEMA: &str = include_str!("../schema/sqlite_sso.sql");
pub const POSTGRES_SSO_SCHEMA: &str = include_str!("../schema/postgres_sso.sql");
