//! Capture dependants before FK clearing; retire and notify only after successful deletion.
use super::OAuthProviderPlugin;
use alibi_core::store::{OAuthTokenKind, SessionDeletionHook, SessionDeletionWork};
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthSession};
use async_trait::async_trait;
use rand::distr::{Alphanumeric, SampleString as _};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::Arc, time::Duration};

pub(super) struct TokenRetirementHook(pub(super) OAuthProviderPlugin);
#[derive(Clone)]
struct LogoutTarget {
    client_id: String,
    uri: String,
    subject: String,
}
#[derive(Clone)]
struct RetirementWork {
    tokens: Vec<(OAuthTokenKind, String)>,
    session_id: String,
    targets: Vec<LogoutTarget>,
    config: Arc<alibi_core::AuthConfig>,
    endpoint: Option<alibi_core::endpoint::EndpointCall>,
    request: Option<alibi_core::AuthRequest>,
}
#[async_trait]
impl<S: AuthSchema> SessionDeletionHook<S> for TokenRetirementHook {
    async fn prepare(
        &self,
        session: &S::Session,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<Box<dyn SessionDeletionWork<S>>>> {
        if session.user_id().as_ref().is_empty() {
            return Ok(None);
        }
        let mut selected = Vec::new();
        let mut client_ids = BTreeSet::new();
        for kind in [OAuthTokenKind::Access, OAuthTokenKind::Refresh] {
            let rows = match context
                .database
                .list_oauth_tokens_for_session(kind, session.id().as_ref())
                .await
            {
                Ok(rows) => rows,
                Err(error) => {
                    tracing::error!(%error,"Unable to prepare OAuth session token retirement");
                    return Ok(None);
                }
            };
            for row in rows {
                _ = client_ids.insert(row.client_id);
                let offline = row
                    .metadata
                    .get("scopes")
                    .and_then(Value::as_array)
                    .is_some_and(|scopes| {
                        scopes
                            .iter()
                            .any(|scope| scope.as_str() == Some("offline_access"))
                    });
                if row.metadata.get("revoked").is_none_or(Value::is_null)
                    && (matches!(kind, OAuthTokenKind::Access) || !offline)
                {
                    selected.push((kind, row.id));
                }
            }
        }
        if client_ids.is_empty() {
            return Ok(None);
        }
        let mut targets = Vec::new();
        if !self.0.config.disable_jwt_plugin {
            for client_id in client_ids {
                let client = match context.database.get_oauth_client(&client_id).await {
                    Ok(Some(client)) => client,
                    Ok(None) => continue,
                    Err(error) => {
                        tracing::error!(%error, "Unable to prepare OAuth back-channel logout");
                        return Ok(None);
                    }
                };
                if client.metadata.get("disabled") == Some(&Value::Bool(true)) {
                    continue;
                }
                let Some(uri) = client
                    .metadata
                    .get("backchannel_logout_uri")
                    .and_then(Value::as_str)
                    .filter(|uri| !uri.is_empty())
                else {
                    continue;
                };
                match self.0.resolve_subject(session.user_id().as_ref(), &client) {
                    Ok(subject) => targets.push(LogoutTarget {
                        client_id,
                        uri: uri.into(),
                        subject,
                    }),
                    Err(error) => {
                        tracing::warn!(%error, %client_id, "Unable to resolve back-channel logout subject");
                    }
                }
            }
        }
        // The store projection is initialized once. Dispatch owns the resolved
        // request policy; retain it and the actual callback frame before the
        // deletion work can leave that endpoint's task-local scope.
        let endpoint = alibi_core::endpoint::current_endpoint_call_context();
        let config = endpoint
            .as_ref()
            .and_then(|call| call.extensions().get::<alibi_core::AuthConfig>())
            .unwrap_or_else(|| Arc::clone(&context.config));
        let request = endpoint
            .as_ref()
            .and_then(|call| call.request().cloned())
            .or_else(|| alibi_core::hooks::current_request_hook_context().map(|hook| hook.request));
        Ok(Some(Box::new(RetirementWork {
            tokens: selected,
            session_id: session.id().as_ref().into(),
            targets,
            config,
            endpoint,
            request,
        })))
    }
}
#[async_trait]
impl<S: AuthSchema> SessionDeletionWork<S> for RetirementWork {
    async fn complete(&self, context: &AuthContext<S>) -> AuthResult<()> {
        let work = self.clone();
        let mut owned_context = context.clone();
        owned_context.config = Arc::clone(&self.config);
        crate::authentication_helpers::run_owned_notification(
            context,
            async move {
                if let Some(endpoint) = work.endpoint.clone() {
                    alibi_core::endpoint::with_endpoint_call_context(
                        endpoint,
                        work.apply(&owned_context),
                    ).await
                } else {
                    work.apply(&owned_context).await
                }
            },
            alibi_core::AwaitedNotificationErrorPolicy::LogAndContinue,
        )
        .await
    }
}

impl RetirementWork {
    async fn apply(&self, context: &AuthContext<impl AuthSchema>) -> AuthResult<()> {
        let at = chrono::Utc::now();
        for (kind, id) in &self.tokens {
            if let Err(error) = context
                .database
                .mark_oauth_token_revoked(*kind, id, at)
                .await
            {
                tracing::error!(%error,"Unable to retire OAuth token after session deletion");
            }
        }
        if self.targets.is_empty() {
            return Ok(());
        }
        let jwt = context
            .extensions
            .get::<crate::jwt::JwtPlugin>()
            .ok_or_else(|| AuthError::config("jwt_config"))?;
        let mut options = crate::jwt::JwtSignOptions {
            header: Some(serde_json::Map::from_iter([(
                "typ".into(),
                json!("logout+jwt"),
            )])),
            ..Default::default()
        };
        options.resolved_key = jwt
            .resolve_signing_key(&options, self.request.as_ref(), context)
            .await?
            .map(Arc::new);
        let base = format!(
            "{}{}",
            context.config.base_url.trim_end_matches('/'),
            context.config.base_path
        );
        let discovery = context.extensions.get::<crate::jwt::JwtDiscoveryOptions>();
        let issuer = discovery
            .as_ref()
            .and_then(|options| options.issuer.as_deref())
            .unwrap_or(&base);
        let issued = chrono::Utc::now().timestamp();
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|error| AuthError::internal(error.to_string()))?;
        // One attempt per distinct RP. Neither transport nor signing failures may
        // prevent other recipients from receiving their notification.
        _ = futures_util::future::join_all(self.targets.iter().map(|target| {
            let http = &http;
            let jwt = &jwt;
            let options = &options;
            async move {
                let delivered = async {
                    let identifier = Alphanumeric.sample_string(&mut rand::rng(), 32);
                    let payload = json!({
                        "iss": issuer, "aud": target.client_id, "sub": target.subject,
                        "sid": self.session_id, "iat": issued, "exp": issued + 120,
                        "jti": identifier,
                        "events": {"http://schemas.openid.net/event/backchannel-logout": {}}
                    }).as_object().cloned().ok_or_else(|| AuthError::internal("Invalid logout token claims"))?;
                    let token = jwt.sign_jwt(payload, options, self.request.as_ref(), context).await?;
                    let response = http.post(&target.uri)
                        .header(reqwest::header::ACCEPT, "application/json")
                        .form(&[("logout_token", token)])
                        .send().await.map_err(|error| AuthError::internal(error.to_string()))?;
                    if !matches!(response.status().as_u16(), 200 | 204) {
                        tracing::warn!(client_id = %target.client_id, status = %response.status(), "Back-channel logout returned an unexpected status");
                    }
                    AuthResult::Ok(())
                }.await;
                if let Err(error) = delivered {
                    tracing::warn!(%error, client_id = %target.client_id, "Back-channel logout delivery failed");
                }
            }
        })).await;
        Ok(())
    }
}
