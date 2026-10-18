//! Configured resource persistence, separate from resource administration and caching.
use super::OAuthProviderPlugin;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthStore};
use futures_util::{
    FutureExt as _,
    future::{BoxFuture, Shared},
};
use serde_json::{Value, json};

const FIELDS: &[&str] = &[
    "name",
    "accessTokenTtl",
    "refreshTokenTtl",
    "signingAlgorithm",
    "signingKeyId",
    "allowedScopes",
    "customClaims",
    "dpopBoundAccessTokensRequired",
    "disabled",
    "metadata",
];

/// Scoped to an initialized store/context, not a plugin clone shared across instances.
#[derive(Default)]
pub(super) struct SeedState(tokio::sync::Mutex<SeedLifecycle>);

type SeedFuture = Shared<BoxFuture<'static, Result<(), SeedFailure>>>;
#[derive(Default)]
struct SeedLifecycle {
    completed: bool,
    attempt: u64,
    pending: Option<SeedFuture>,
}

// Shared attempts must return the same public callback failure to all waiters.
// AuthError itself is not Clone (it can own database/serialization errors).
#[derive(Clone)]
enum SeedFailure {
    Api {
        status: u16,
        code: Option<String>,
        message: String,
    },
    RateLimited {
        retry_after: Option<f64>,
    },
    Private {
        message: String,
        empty: bool,
    },
}
impl SeedFailure {
    fn capture(error: &AuthError) -> Self {
        if let AuthError::RateLimited { retry_after } = error {
            return Self::RateLimited {
                retry_after: *retry_after,
            };
        }
        if alibi_core::endpoint::is_endpoint_api_error(error) {
            let (status, code, message) = error.error_payload();
            return Self::Api {
                status,
                code,
                message,
            };
        }
        Self::Private {
            empty: matches!(
                &error,
                AuthError::CallbackFailure(_) | AuthError::Encryption(_)
            ),
            message: error.to_string(),
        }
    }
    fn into_error(self) -> AuthError {
        match self {
            Self::Api {
                status,
                code,
                message,
            } => AuthError::Api {
                status,
                code,
                message,
            },
            Self::RateLimited { retry_after } => AuthError::RateLimited { retry_after },
            Self::Private { message, empty } => {
                let error = AuthError::internal(message);
                if empty {
                    AuthError::CallbackFailure(Box::new(error))
                } else {
                    error
                }
            }
        }
    }
}

fn missing_table(error: &AuthError) -> bool {
    static PATTERN: std::sync::LazyLock<Option<regex::Regex>> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)no such table|relation.*does not exist|table.*does(?: not|n[''’]?t) exist",
        )
        .ok()
    });
    PATTERN
        .as_ref()
        .is_some_and(|pattern| pattern.is_match(&error.to_string()))
}

fn seed_row(input: &serde_json::Map<String, Value>, identifier: &str) -> Value {
    let mut row = serde_json::Map::new();
    for &field in FIELDS {
        let default = match field {
            "name" => json!(identifier),
            "disabled" | "dpopBoundAccessTokensRequired" => json!(false),
            _ => Value::Null,
        };
        _ = row.insert(
            field.into(),
            input
                .get(field)
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or(default),
        );
    }
    _ = row.insert("policyVersion".into(), json!(1));
    Value::Object(row)
}

impl OAuthProviderPlugin {
    pub(super) async fn seed_resources<S: AuthSchema>(
        &self,
        store: &dyn AuthStore<S>,
    ) -> AuthResult<()> {
        for raw in &self.config.resources {
            let mut input = if let Some(identifier) = raw.as_str() {
                serde_json::Map::from_iter([("identifier".into(), json!(identifier))])
            } else {
                raw.as_object().cloned().ok_or_else(|| {
                    AuthError::config("Resource seed must be an identifier or policy object")
                })?
            };
            let identifier = input
                .get("identifier")
                .and_then(Value::as_str)
                .ok_or_else(|| AuthError::config("Resource seed requires an identifier"))?
                .to_owned();
            let valid = if let Some(validator) = &self.config.identifier_validator {
                validator.validate(&identifier).await?
            } else {
                url::Url::parse(&identifier)
                    .is_ok_and(|url| url.fragment().is_none_or(str::is_empty))
            };
            if !valid {
                tracing::warn!(%identifier, "Skipping invalid configured OAuth resource");
                continue;
            }
            if input.get("signingAlgorithm").is_some_and(|value| {
                !value.is_null()
                    && !value
                        .as_str()
                        .is_some_and(|algorithm| super::resources::ALGORITHMS.contains(&algorithm))
            }) {
                tracing::warn!(%identifier, "Dropping unsupported configured resource signingAlgorithm");
                _ = input.remove("signingAlgorithm");
            }
            let existing = match store.get_oauth_resource(&identifier).await {
                Ok(existing) => existing,
                Err(error) if missing_table(&error) => return Ok(()),
                Err(error) => return Err(error),
            };
            let now =
                chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
                    .ok_or_else(|| AuthError::internal("Invalid resource seed timestamp"))?;
            if let Some(existing) = existing {
                if self.config.resource_seed_mode == OAuthResourceSeedMode::InsertOnly {
                    continue;
                }
                let row = if self.config.resource_seed_mode == OAuthResourceSeedMode::Overwrite {
                    seed_row(&input, &identifier)
                } else {
                    let mut row =
                        existing.metadata.as_object().cloned().ok_or_else(|| {
                            AuthError::internal("Invalid persisted resource policy")
                        })?;
                    for &field in FIELDS {
                        if let Some(value) = input.get(field) {
                            _ = row.insert(field.into(), value.clone());
                        }
                    }
                    Value::Object(row)
                };
                _ = store.update_oauth_resource(&identifier, row, now).await?;
            } else if let Err(error) = store
                .create_oauth_resource(alibi_core::store::CreateOAuthResource {
                    identifier: identifier.clone(),
                    metadata: seed_row(&input, &identifier),
                    created_at: now,
                })
                .await
            {
                let message = error.to_string().to_lowercase();
                if message.contains("unique") || message.contains("duplicate") {
                    continue;
                }
                if missing_table(&error) {
                    return Ok(());
                }
                return Err(error);
            }
        }
        Ok(())
    }

    pub(super) async fn get_resource<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        identifier: &str,
    ) -> AuthResult<Option<alibi_core::store::OAuthResource>> {
        // Init deliberately does not complete this state. A real first lookup
        // re-applies merge/overwrite, including edits made since initialization.
        if let Some(state) = ctx.extensions.get::<SeedState>() {
            let work = {
                let mut lifecycle = state.0.lock().await;
                if lifecycle.completed {
                    None
                } else {
                    let future = lifecycle
                        .pending
                        .get_or_insert_with(|| {
                            let provider = self.clone();
                            let store = ctx.database.clone();
                            async move {
                                provider
                                    .seed_resources(store.as_ref())
                                    .await
                                    .map_err(|error| SeedFailure::capture(&error))
                            }
                            .boxed()
                            .shared()
                        })
                        .clone();
                    Some((lifecycle.attempt, future))
                }
            };
            if let Some((attempt, future)) = work {
                let result = future.await;
                let mut lifecycle = state.0.lock().await;
                if lifecycle.attempt == attempt {
                    lifecycle.pending = None;
                    lifecycle.completed = result.is_ok();
                    lifecycle.attempt = lifecycle.attempt.wrapping_add(1);
                }
                result.map_err(SeedFailure::into_error)?;
            }
        }
        super::resource_cache::get(
            ctx,
            identifier,
            self.config.cached_resources.contains(identifier),
        )
        .await
    }
}

/// Restart policy for configured resource rows. The pinned replacement mode is `overwrite`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum OAuthResourceSeedMode {
    #[default]
    InsertOnly,
    Merge,
    Overwrite,
}

/// Application identifier validation replaces the default absolute-URI/fragment check.
#[async_trait::async_trait]
pub trait OAuthResourceIdentifierValidator: Send + Sync + std::fmt::Debug {
    async fn validate(&self, identifier: &str) -> AuthResult<bool>;
}
