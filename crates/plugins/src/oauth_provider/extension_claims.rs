use super::{OAuthProviderConfig, OAuthProviderPlugin, OAuthTokenIssueParams};
use alibi_core::session::SessionRequest;
use alibi_core::store::OAuthClient;
use alibi_core::wire::UserView;
use alibi_core::{AuthContext, AuthResult, AuthSchema, CallbackContext};
use async_trait::async_trait;
use serde_json::{Map, Value};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct OAuthExtensionClaims {
    pub access_token: Option<Arc<dyn OAuthTokenClaimsContributor>>,
    pub id_token: Option<Arc<dyn OAuthTokenClaimsContributor>>,
    pub user_info: Option<Arc<dyn OAuthUserInfoClaimsContributor>>,
}

pub struct OAuthTokenClaimsInput<'a> {
    pub context: CallbackContext,
    pub options: &'a OAuthProviderConfig,
    pub params: &'a OAuthTokenIssueParams,
    /// The issuance grant, or `None` when re-deriving opaque access claims.
    pub grant_type: Option<&'a str>,
    pub metadata: Option<Value>,
}

#[derive(Clone)]
pub struct OAuthUserInfoClaimsInput<'a> {
    pub context: CallbackContext,
    pub options: &'a OAuthProviderConfig,
    pub user: &'a UserView,
    pub client: Option<&'a OAuthClient>,
    pub scopes: &'a [String],
    pub payload: &'a Value,
    pub requested_claims: &'a [String],
}

#[async_trait]
pub trait OAuthTokenClaimsContributor: Send + Sync + std::fmt::Debug {
    async fn contribute(&self, input: OAuthTokenClaimsInput<'_>) -> AuthResult<Map<String, Value>>;
}

#[async_trait]
pub trait OAuthUserInfoClaimsContributor: Send + Sync + std::fmt::Debug {
    async fn contribute(
        &self,
        input: OAuthUserInfoClaimsInput<'_>,
    ) -> AuthResult<Map<String, Value>>;
}

pub(super) enum TokenClaimKind {
    Access,
    Id,
}

pub(super) fn merge_additive(base: &mut Map<String, Value>, claims: Map<String, Value>) {
    for (key, value) in claims {
        if !matches!(
            key.as_str(),
            "__proto__"
                | "constructor"
                | "toString"
                | "toLocaleString"
                | "valueOf"
                | "hasOwnProperty"
                | "isPrototypeOf"
                | "propertyIsEnumerable"
                | "__defineGetter__"
                | "__defineSetter__"
                | "__lookupGetter__"
                | "__lookupSetter__"
        ) {
            _ = base.entry(key).or_insert(value);
        }
    }
}

/// Resource policy wins over extension/per-issuance claims, but no source may
/// supply authority owned by the authorization server. Shared by JWT minting
/// and live opaque validation (including reserved claims absent from the token).
pub(super) fn compose_access_claims(
    mut claims: Map<String, Value>,
    resource_claims: Map<String, Value>,
) -> Map<String, Value> {
    claims.extend(resource_claims);
    for key in [
        "sub",
        "aud",
        "client_id",
        "azp",
        "scope",
        "sid",
        "iss",
        "iat",
        "exp",
        "jti",
        "cnf",
        "auth_time",
        "acr",
        "amr",
    ] {
        _ = claims.remove(key);
    }
    claims
}

pub(super) fn callback_context<S: AuthSchema>(
    ctx: &AuthContext<S>,
    req: &impl SessionRequest,
) -> CallbackContext {
    let mut callback = CallbackContext::new(ctx, req.physical_request());
    callback.endpoint = req.endpoint_call().cloned().or(callback.endpoint);
    callback
}

impl OAuthProviderPlugin {
    pub(super) async fn collect_token_claims(
        &self,
        context: CallbackContext,
        params: &OAuthTokenIssueParams,
        grant_type: Option<&str>,
        kind: TokenClaimKind,
    ) -> AuthResult<Map<String, Value>> {
        let mut claims = Map::new();
        for extension in &self.config.extensions {
            let contributor = match kind {
                TokenClaimKind::Access => extension.claims.access_token.as_ref(),
                TokenClaimKind::Id => extension.claims.id_token.as_ref(),
            };
            if let Some(contributor) = contributor {
                let contribution = contributor
                    .contribute(OAuthTokenClaimsInput {
                        context: context.clone(),
                        options: &self.config,
                        params,
                        grant_type,
                        metadata: alibi_core::store::oauth_clients::metadata_to_columns(
                            params.client.metadata.clone(),
                        )?
                        .get("metadata")
                        .filter(|value| !value.is_null())
                        .cloned(),
                    })
                    .await?;
                merge_additive(&mut claims, contribution);
            }
        }
        Ok(claims)
    }

    pub(super) async fn extend_access_token_claims<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        req: &impl SessionRequest,
        params: &mut OAuthTokenIssueParams,
        grant_type: &str,
    ) -> AuthResult<()> {
        let mut claims = self
            .collect_token_claims(
                callback_context(ctx, req),
                params,
                Some(grant_type),
                TokenClaimKind::Access,
            )
            .await?;
        if let Some(per_request) = params
            .access_token_claims
            .as_ref()
            .and_then(Value::as_object)
        {
            claims.extend(per_request.clone());
        }
        params.access_token_claims = Some(Value::Object(claims));
        Ok(())
    }

    pub(super) async fn extend_id_token_claims<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        req: &impl SessionRequest,
        params: &mut OAuthTokenIssueParams,
        grant_type: &str,
    ) -> AuthResult<()> {
        if params.user.is_some() && params.scopes.iter().any(|scope| scope == "openid") {
            let mut claims = self
                .collect_token_claims(
                    callback_context(ctx, req),
                    params,
                    Some(grant_type),
                    TokenClaimKind::Id,
                )
                .await?;
            if let Some(per_request) = params.id_token_claims.as_ref().and_then(Value::as_object) {
                claims.extend(per_request.clone());
            }
            params.id_token_claims = Some(Value::Object(claims));
        }
        Ok(())
    }

    pub(super) async fn collect_user_info_claims(
        &self,
        input: OAuthUserInfoClaimsInput<'_>,
    ) -> AuthResult<Map<String, Value>> {
        let mut claims = Map::new();
        for extension in &self.config.extensions {
            if let Some(contributor) = &extension.claims.user_info {
                let contribution = contributor.contribute(input.clone()).await?;
                merge_additive(&mut claims, contribution);
            }
        }
        Ok(claims)
    }
}
