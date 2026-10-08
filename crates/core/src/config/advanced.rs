use super::*;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl std::fmt::Display for SameSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strict => f.write_str("Strict"),
            Self::Lax => f.write_str("Lax"),
            Self::None => f.write_str("None"),
        }
    }
}

// ── Advanced configuration ──────────────────────────────────────────────

/// Advanced configuration options (mirrors TS `advanced` block).
#[derive(Debug, Clone, Default)]
pub struct AdvancedConfig {
    /// Trust forwarded host/protocol for URL resolution. Enable only behind a
    /// proxy that replaces client-supplied forwarding headers. Defaults to false.
    pub trust_forwarded_host: bool,

    /// IP address extraction configuration.
    pub ip_address: IpAddressConfig,

    /// Explicit CSRF override. `None` preserves the pinned compatibility behavior
    /// where disabling all origin checks also disables first-login CSRF checks.
    pub disable_csrf_check: Option<bool>,

    /// If `true`, callback / redirect target origin validation is skipped.
    ///
    /// This mirrors Better Auth TS `advanced.disableOriginCheck`.
    /// Request-origin validation is also skipped. First-login Fetch Metadata
    /// checks remain enabled when `disable_csrf_check` is explicitly `Some(false)`.
    pub disable_origin_check: bool,

    /// Skip origin validation for a literal path and its descendants. This does
    /// not disable first-login cross-site navigation protection.
    pub disable_origin_check_paths: Vec<String>,

    /// Admit trailing slashes while resolving the original registered endpoint.
    pub skip_trailing_slashes: bool,

    /// Select the secure cookie name prefix and initial Secure attribute.
    /// None uses the configured base URL protocol. Attribute overrides do not
    /// change this choice; the serializer enforces Secure for reserved prefixes.
    pub use_secure_cookies: Option<bool>,

    /// Cross-subdomain cookie sharing configuration.
    pub cross_sub_domain_cookies: Option<CrossSubDomainConfig>,

    /// Per-cookie-name overrides (name, attributes, prefix).
    ///
    /// Keys are the *logical* cookie names (e.g. `"session_token"`,
    /// `"csrf_token"`). Values specify the attributes to override.
    pub cookies: HashMap<String, CookieOverride>,

    /// Default cookie attributes applied to *every* cookie the library sets
    /// (individual overrides in `cookies` take precedence).
    pub default_cookie_attributes: CookieAttributes,

    /// Optional prefix prepended to every cookie name (e.g. `"myapp"` →
    /// `"myapp.session_token"`).
    pub cookie_prefix: Option<String>,

    /// Database-related advanced options.
    pub database: AdvancedDatabaseConfig,

    /// List of header names the framework trusts for extracting the
    /// client's real IP when behind a proxy (e.g. `X-Forwarded-For`).
    pub trusted_proxy_headers: Vec<String>,
}

/// IP-address extraction configuration.
#[derive(Debug, Clone)]
pub struct IpAddressConfig {
    /// Ordered list of headers to check for the client IP.
    /// Defaults to `["x-forwarded-for"]`. Header names are case insensitive.
    pub headers: Vec<String>,

    /// IP addresses or CIDRs removed from the right of a forwarded chain.
    /// Invalid entries are ignored. Without valid entries, only a single
    /// address is admitted. Deployments must prevent clients bypassing the
    /// proxy and supplying their own trusted forwarding headers.
    pub trusted_proxies: Vec<String>,

    /// IPv6 grouping prefix; defaults to 64. Fractional values are floored,
    /// negative values become zero, and values at least 128 or NaN preserve
    /// the full address. IPv4-mapped addresses use IPv4 grouping.
    pub ipv6_subnet: f64,

    /// Fall back to localhost when no configured header resolves an address.
    /// Defaults to true for NODE_ENV dev/development/test or a truthy TEST
    /// environment flag. Applications may configure this explicitly.
    pub localhost_fallback: bool,

    /// If `true`, IP tracking is entirely disabled (no IP stored in sessions).
    pub disable_ip_tracking: bool,
}

/// Configuration for sharing cookies across sub-domains.
#[derive(Debug, Clone, Default)]
pub struct CrossSubDomainConfig {
    /// Explicit cookie domain (e.g. `".example.com"`). An empty value infers
    /// the hostname of the configured or request-resolved base URL, without a port.
    pub domain: String,
}

/// Overridable cookie attributes.
#[derive(Debug, Clone, Default)]
pub struct CookieAttributes {
    /// Override `Secure` flag.
    pub secure: Option<bool>,
    /// Override `HttpOnly` flag.
    pub http_only: Option<bool>,
    /// Override `SameSite` policy.
    pub same_site: Option<SameSite>,
    /// Override `Path`.
    pub path: Option<String>,
    /// Override `Max-Age` (seconds).
    pub max_age: Option<f64>,
    /// Explicit expiry, checked at emission against the published 400-day limit.
    pub expires: Option<chrono::DateTime<chrono::Utc>>,
    /// Emit the published `Partitioned` attribute after SameSite.
    pub partitioned: Option<bool>,
    /// Override cookie `Domain`.
    pub domain: Option<String>,
}

/// Per-cookie override entry.
#[derive(Debug, Clone, Default)]
pub struct CookieOverride {
    /// Custom name to use instead of the logical name.
    pub name: Option<String>,
    /// Attribute overrides for this cookie.
    pub attributes: CookieAttributes,
}

/// Physical storage policy for the bundled two-factor model.
#[derive(Debug, Clone)]
pub struct TwoFactorDatabaseConfig {
    pub table_name: String,
    /// Canonical snake_case column names mapped to application-owned columns.
    pub columns: std::collections::HashMap<String, String>,
}

/// Database-related advanced options.
#[derive(Debug, Clone)]
pub struct AdvancedDatabaseConfig {
    /// Default `LIMIT` for "find many" queries.
    pub default_find_many_limit: usize,

    /// PostgreSQL namespace for every auth relation; does not change search_path.
    pub schema_name: Option<String>,

    /// Optional physical table and column mapping for two-factor credentials.
    pub two_factor: Option<TwoFactorDatabaseConfig>,

    /// Declares that the database uses numeric IDs, as upstream's
    /// `useNumberId`. IDs are always generated as strings; this only makes
    /// invitation email verification required by default, because numeric
    /// invitation IDs are guessable.
    pub use_number_id: bool,
}

impl Default for IpAddressConfig {
    fn default() -> Self {
        Self {
            headers: vec!["x-forwarded-for".to_owned()],
            trusted_proxies: Vec::new(),
            ipv6_subnet: 64.0,
            localhost_fallback: matches!(
                std::env::var("NODE_ENV").as_deref(),
                Ok("dev" | "development" | "test")
            ) || std::env::var("TEST")
                .is_ok_and(|value| !matches!(value.as_str(), "" | "false")),
            disable_ip_tracking: false,
        }
    }
}

impl Default for AdvancedDatabaseConfig {
    fn default() -> Self {
        Self {
            default_find_many_limit: 100,
            schema_name: None,
            two_factor: None,
            use_number_id: false,
        }
    }
}

impl TwoFactorDatabaseConfig {
    /// DDL used to migrate the bundled factor model to its configured physical layout.
    pub fn migration_statements(&self) -> crate::AuthResult<Vec<String>> {
        const COLUMNS: &[&str] = &[
            "id",
            "secret",
            "backup_codes",
            "user_id",
            "verified",
            "failed_verification_count",
            "locked_until",
            "created_at",
            "updated_at",
        ];
        if self.table_name.is_empty()
            || self
                .columns
                .iter()
                .any(|(name, column)| !COLUMNS.contains(&name.as_str()) || column.is_empty())
        {
            return Err(AuthError::config("Invalid two-factor storage mapping"));
        }
        let quote = |name: &str| format!("\"{}\"", name.replace('"', "\"\""));
        let table = quote(&self.table_name);
        let mut sql = Vec::new();
        if self.table_name != "two_factor" {
            sql.push(format!("ALTER TABLE \"two_factor\" RENAME TO {table}"));
        }
        for name in COLUMNS {
            if let Some(column) = self
                .columns
                .get(*name)
                .filter(|column| column.as_str() != *name)
            {
                sql.push(format!(
                    "ALTER TABLE {table} RENAME COLUMN {} TO {}",
                    quote(name),
                    quote(column)
                ));
            }
        }
        Ok(sql)
    }
}
