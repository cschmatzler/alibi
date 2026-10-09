//! Source-backed Better Auth 1.7.7 declarations.
//! Author-time port: tests/compat/reference-server/port-openapi-annotations.ts.
//! Conversion helpers SHA256: ecbb352aeae990043fa25e1a5c42413aa433f33f015110d85c2bfecff74d67c5.
//! No generated document or fixture response was captured.
use super::{OpenApiField, OpenApiModel};
use serde_json::json;

pub(super) fn models(plugin: &str) -> Option<Vec<OpenApiModel>> {
    Some(match plugin {
        "admin" => vec![
            OpenApiModel::new(
                "User",
                vec![
                    OpenApiField::new("role", json!({"type":"string"}), false).read_only(),
                    OpenApiField::new("banned", json!({"type":"boolean","default":false}), false)
                        .read_only(),
                    OpenApiField::new("banReason", json!({"type":"string"}), false).read_only(),
                    OpenApiField::new(
                        "banExpires",
                        json!({"type":"string","format":"date-time"}),
                        false,
                    )
                    .read_only(),
                ],
            ),
            OpenApiModel::new(
                "Session",
                vec![
                    OpenApiField::new("impersonatedBy", json!({"type":"string"}), false)
                        .read_only(),
                ],
            ),
        ],
        "multi-session" => vec![],
        "organization" => vec![
            OpenApiModel::new(
                "Organization",
                vec![
                    OpenApiField::new("name", json!({"type":"string"}), true),
                    OpenApiField::new("slug", json!({"type":"string"}), true),
                    OpenApiField::new("logo", json!({"type":"string"}), false),
                    OpenApiField::new(
                        "createdAt",
                        json!({"type":"string","format":"date-time"}),
                        true,
                    ),
                    OpenApiField::new("metadata", json!({"type":"string"}), false),
                ],
            ),
            OpenApiModel::new(
                "OrganizationRole",
                vec![
                    OpenApiField::new("organizationId", json!({"type":"string"}), true),
                    OpenApiField::new("role", json!({"type":"string"}), true),
                    OpenApiField::new("permission", json!({"type":"string"}), true),
                    OpenApiField::new(
                        "createdAt",
                        json!({"type":"string","format":"date-time"}),
                        true,
                    ),
                    OpenApiField::new(
                        "updatedAt",
                        json!({"type":"string","format":"date-time"}),
                        false,
                    ),
                ],
            ),
            OpenApiModel::new(
                "Team",
                vec![
                    OpenApiField::new("name", json!({"type":"string"}), true),
                    OpenApiField::new("memberCount", json!({"type":"number","default":0}), true)
                        .read_only()
                        .hidden(),
                    OpenApiField::new("organizationId", json!({"type":"string"}), true),
                    OpenApiField::new(
                        "createdAt",
                        json!({"type":"string","format":"date-time"}),
                        true,
                    ),
                    OpenApiField::new(
                        "updatedAt",
                        json!({"type":"string","format":"date-time"}),
                        false,
                    ),
                ],
            ),
            OpenApiModel::new(
                "TeamMember",
                vec![
                    OpenApiField::new("teamId", json!({"type":"string"}), true),
                    OpenApiField::new("userId", json!({"type":"string"}), true),
                    OpenApiField::new("membershipKey", json!({"type":"string"}), false)
                        .read_only()
                        .hidden(),
                    OpenApiField::new(
                        "createdAt",
                        json!({"type":"string","format":"date-time"}),
                        false,
                    ),
                ],
            ),
            OpenApiModel::new(
                "Member",
                vec![
                    OpenApiField::new("organizationId", json!({"type":"string"}), true),
                    OpenApiField::new("userId", json!({"type":"string"}), true),
                    OpenApiField::new("role", json!({"type":"string","default":"member"}), true),
                    OpenApiField::new(
                        "createdAt",
                        json!({"type":"string","format":"date-time"}),
                        true,
                    ),
                ],
            ),
            OpenApiModel::new(
                "Invitation",
                vec![
                    OpenApiField::new("organizationId", json!({"type":"string"}), true),
                    OpenApiField::new("email", json!({"type":"string"}), true),
                    OpenApiField::new("role", json!({"type":"string"}), false),
                    OpenApiField::new("teamId", json!({"type":"string"}), false),
                    OpenApiField::new("status", json!({"type":"string","default":"pending"}), true),
                    OpenApiField::new(
                        "expiresAt",
                        json!({"type":"string","format":"date-time"}),
                        true,
                    ),
                    OpenApiField::new(
                        "createdAt",
                        json!({"type":"string","format":"date-time"}),
                        true,
                    ),
                    OpenApiField::new("inviterId", json!({"type":"string"}), true),
                ],
            ),
            OpenApiModel::new(
                "Session",
                vec![
                    OpenApiField::new("activeOrganizationId", json!({"type":"string"}), false)
                        .read_only(),
                    OpenApiField::new("activeTeamId", json!({"type":"string"}), false).read_only(),
                ],
            ),
        ],
        "username" => vec![OpenApiModel::new(
            "User",
            vec![
                OpenApiField::new("username", json!({"type":"string"}), false),
                OpenApiField::new("displayUsername", json!({"type":"string"}), false),
            ],
        )],
        "two-factor" => vec![
            OpenApiModel::new(
                "User",
                vec![
                    OpenApiField::new(
                        "twoFactorEnabled",
                        json!({"type":"boolean","default":false}),
                        false,
                    )
                    .read_only(),
                ],
            ),
            OpenApiModel::new(
                "TwoFactor",
                vec![
                    OpenApiField::new("secret", json!({"type":"string"}), true).hidden(),
                    OpenApiField::new("backupCodes", json!({"type":"string"}), true).hidden(),
                    OpenApiField::new("userId", json!({"type":"string"}), true).hidden(),
                    OpenApiField::new("verified", json!({"type":"boolean","default":true}), false)
                        .read_only(),
                    OpenApiField::new(
                        "failedVerificationCount",
                        json!({"type":"number","default":0}),
                        false,
                    )
                    .read_only()
                    .hidden(),
                    OpenApiField::new(
                        "lockedUntil",
                        json!({"type":"string","format":"date-time"}),
                        false,
                    )
                    .read_only()
                    .hidden(),
                ],
            ),
        ],
        "anonymous" => vec![OpenApiModel::new(
            "User",
            vec![
                OpenApiField::new(
                    "isAnonymous",
                    json!({"type":"boolean","default":false}),
                    false,
                )
                .read_only(),
            ],
        )],
        "jwt" => vec![OpenApiModel::new(
            "Jwks",
            vec![
                OpenApiField::new("publicKey", json!({"type":"string"}), true),
                OpenApiField::new("privateKey", json!({"type":"string"}), true),
                OpenApiField::new(
                    "createdAt",
                    json!({"type":"string","format":"date-time"}),
                    true,
                ),
                OpenApiField::new(
                    "expiresAt",
                    json!({"type":"string","format":"date-time"}),
                    false,
                ),
                OpenApiField::new("alg", json!({"type":"string"}), false),
                OpenApiField::new("crv", json!({"type":"string"}), false),
            ],
        )],
        "one-time-token" => vec![],
        "one-tap" => vec![],
        "email-otp" => vec![],
        "magic-link" => vec![],
        "phone-number" => vec![OpenApiModel::new(
            "User",
            vec![
                OpenApiField::new("phoneNumber", json!({"type":"string"}), false),
                OpenApiField::new("phoneNumberVerified", json!({"type":"boolean"}), false)
                    .read_only(),
            ],
        )],
        "device-authorization" => vec![OpenApiModel::new(
            "DeviceCode",
            vec![
                OpenApiField::new("deviceCode", json!({"type":"string"}), true),
                OpenApiField::new("userCode", json!({"type":"string"}), true),
                OpenApiField::new("userId", json!({"type":"string"}), false),
                OpenApiField::new(
                    "expiresAt",
                    json!({"type":"string","format":"date-time"}),
                    true,
                ),
                OpenApiField::new("status", json!({"type":"string"}), true),
                OpenApiField::new(
                    "lastPolledAt",
                    json!({"type":"string","format":"date-time"}),
                    false,
                ),
                OpenApiField::new("pollingInterval", json!({"type":"number"}), false),
                OpenApiField::new("clientId", json!({"type":"string"}), false),
                OpenApiField::new("scope", json!({"type":"string"}), false),
            ],
        )],
        "generic-oauth" => vec![],
        "last-login-method" => vec![OpenApiModel::new(
            "User",
            vec![OpenApiField::new("lastLoginMethod", json!({"type":"string"}), false).read_only()],
        )],
        "siwe" => vec![OpenApiModel::new(
            "WalletAddress",
            vec![
                OpenApiField::new("userId", json!({"type":"string"}), true),
                OpenApiField::new("address", json!({"type":"string"}), true),
                OpenApiField::new("chainId", json!({"type":"number"}), true),
                OpenApiField::new(
                    "isPrimary",
                    json!({"type":"boolean","default":false}),
                    false,
                ),
                OpenApiField::new(
                    "createdAt",
                    json!({"type":"string","format":"date-time"}),
                    true,
                ),
            ],
        )],
        "api-key" => vec![OpenApiModel::new(
            "Apikey",
            vec![
                OpenApiField::new(
                    "configId",
                    json!({"type":"string","default":"default"}),
                    true,
                )
                .read_only(),
                OpenApiField::new("name", json!({"type":"string"}), false).read_only(),
                OpenApiField::new("start", json!({"type":"string"}), false).read_only(),
                OpenApiField::new("referenceId", json!({"type":"string"}), true).read_only(),
                OpenApiField::new("prefix", json!({"type":"string"}), false).read_only(),
                OpenApiField::new("key", json!({"type":"string"}), true).read_only(),
                OpenApiField::new("refillInterval", json!({"type":"number"}), false).read_only(),
                OpenApiField::new("refillAmount", json!({"type":"number"}), false).read_only(),
                OpenApiField::new(
                    "lastRefillAt",
                    json!({"type":"string","format":"date-time"}),
                    false,
                )
                .read_only(),
                OpenApiField::new("enabled", json!({"type":"boolean","default":true}), false)
                    .read_only(),
                OpenApiField::new(
                    "rateLimitEnabled",
                    json!({"type":"boolean","default":true}),
                    false,
                )
                .read_only(),
                OpenApiField::new(
                    "rateLimitTimeWindow",
                    json!({"type":"number","default":86400000}),
                    false,
                )
                .read_only(),
                OpenApiField::new("rateLimitMax", json!({"type":"number","default":10}), false)
                    .read_only(),
                OpenApiField::new("requestCount", json!({"type":"number","default":0}), false)
                    .read_only(),
                OpenApiField::new("remaining", json!({"type":"number"}), false).read_only(),
                OpenApiField::new(
                    "lastRequest",
                    json!({"type":"string","format":"date-time"}),
                    false,
                )
                .read_only(),
                OpenApiField::new(
                    "expiresAt",
                    json!({"type":"string","format":"date-time"}),
                    false,
                )
                .read_only(),
                OpenApiField::new(
                    "createdAt",
                    json!({"type":"string","format":"date-time"}),
                    true,
                )
                .read_only(),
                OpenApiField::new(
                    "updatedAt",
                    json!({"type":"string","format":"date-time"}),
                    true,
                )
                .read_only(),
                OpenApiField::new("permissions", json!({"type":"string"}), false).read_only(),
                OpenApiField::new("metadata", json!({"type":"string"}), false),
            ],
        )],
        "passkey" => vec![OpenApiModel::new(
            "Passkey",
            vec![
                OpenApiField::new("name", json!({"type":"string"}), false),
                OpenApiField::new("publicKey", json!({"type":"string"}), true),
                OpenApiField::new("userId", json!({"type":"string"}), true),
                OpenApiField::new("credentialID", json!({"type":"string"}), true),
                OpenApiField::new("counter", json!({"type":"number"}), true),
                OpenApiField::new("deviceType", json!({"type":"string"}), true),
                OpenApiField::new("backedUp", json!({"type":"boolean"}), true),
                OpenApiField::new("transports", json!({"type":"string"}), false),
                OpenApiField::new(
                    "createdAt",
                    json!({"type":"string","format":"date-time"}),
                    false,
                ),
                OpenApiField::new("aaguid", json!({"type":"string"}), false),
            ],
        )],
        _ => return None,
    })
}
