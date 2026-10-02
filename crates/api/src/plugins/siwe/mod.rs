//! Sign in with Ethereum using a single-use challenge and application-owned
//! signature verification, including contract-wallet RPC providers.

mod config;

mod crypto;

mod date;

mod parse;

mod validation;

#[cfg(test)]
mod tests;

use super::helpers::{apply_default_role, issue_user_session_record};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, AuthSession,
    AuthUser, CreateAccount, CreateUser, CreateVerification, CreateWalletAddress, RequestMeta,
};
use chrono::{Duration, Utc};
pub use config::{
    Cacao, CacaoHeader, CacaoPayload, CacaoSignature, EnsLookup, EnsProfile, RandomSiweNonce,
    SiweCallbackError, SiweCallbackResult, SiweConfig, SiweNonceProvider, SiweVerification,
    SiweVerifier,
};
pub use crypto::{Eip191Verifier, ethereum_message_hash};
use serde_json::json;
use validation::VerifyBody;

#[derive(Debug, Clone)]
pub struct SiwePlugin {
    config: SiweConfig,
}

impl SiwePlugin {
    #[must_use]
    pub const fn new(config: SiweConfig) -> Self {
        Self { config }
    }

    async fn handle_nonce<S: AuthSchema>(
        &self,
        request: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        if let Err(response) = validation::nonce_body(request) {
            return Ok(response);
        }
        let nonce = match self.config.nonce_provider.get_nonce().await {
            Ok(nonce) => nonce,
            Err(SiweCallbackError::Api(response)) => return Ok(response),
            Err(error) => return Err(AuthError::internal(error.to_string())),
        };
        if !parse::valid_nonce(&nonce) {
            return Ok(AuthResponse::json(
                500,
                &json!({
                    "message":"SIWE getNonce must return an ERC-4361 nonce: 8-250 alphanumeric characters.",
                    "status":500,"code":"SIWE_INVALID_NONCE"
                }),
            )?);
        }
        drop(
            ctx.database
                .create_verification(CreateVerification {
                    identifier: format!("siwe:{nonce}"),
                    value: nonce.clone(),
                    expires_at: Utc::now() + Duration::seconds(900),
                })
                .await?,
        );
        Ok(AuthResponse::json(200, &json!({"nonce":nonce}))?)
    }

    async fn handle_verify<S: AuthSchema>(
        &self,
        request: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let body = match validation::verify_body(request, self.config.anonymous) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        match self.verify(request, ctx, body).await {
            Ok(response) | Err(SiweCallbackError::Api(response)) => Ok(response),
            Err(error) => Ok(AuthResponse::json(
                401,
                &json!({
                    "message":"Something went wrong. Please try again later.", "error":error.to_string(), "status":401
                }),
            )?),
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Keep proof validation, identity updates, and session callbacks in their protocol order"
    )]
    async fn verify<S: AuthSchema>(
        &self,
        request: &AuthRequest,
        ctx: &AuthContext<S>,
        body: VerifyBody,
    ) -> SiweCallbackResult<AuthResponse> {
        let parsed = parse::parse_message(&body.message);
        let nonce = parsed
            .nonce
            .filter(|nonce| parse::valid_nonce(nonce))
            .ok_or_else(mismatch)?;
        let consumed = ctx
            .database
            .consume_verification_by_identifier(&format!("siwe:{nonce}"))
            .await
            .map_err(storage_error)?;
        if consumed.is_none() {
            return Err(endpoint_error(
                "Unauthorized: Invalid or expired nonce",
                "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
            ));
        }
        let address = parsed
            .address
            .and_then(crypto::checksum_address)
            .ok_or_else(mismatch)?;
        let chain_id = parsed
            .chain_id
            .filter(|chain| *chain > 0.0)
            .ok_or_else(mismatch)?;
        if parsed.domain.is_none_or(|domain| {
            parse::normalize_domain(domain) != parse::normalize_domain(&self.config.domain)
        }) {
            return Err(mismatch());
        }
        let now = Utc::now().timestamp_millis();
        if parsed
            .expiration_time
            .and_then(date::parse_date_millis)
            .is_some_and(|expiry| now >= expiry)
        {
            return Err(endpoint_error(
                "Unauthorized: SIWE message has expired",
                "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED",
            ));
        }
        if parsed
            .not_before
            .and_then(date::parse_date_millis)
            .is_some_and(|start| now < start)
        {
            return Err(endpoint_error(
                "Unauthorized: SIWE message is not yet valid",
                "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
            ));
        }
        let cacao = Cacao {
            h: CacaoHeader {
                t: "caip122".to_owned(),
            },
            p: CacaoPayload {
                domain: self.config.domain.clone(),
                aud: self.config.domain.clone(),
                nonce: nonce.to_owned(),
                iss: self.config.domain.clone(),
                version: "1".to_owned(),
            },
            s: CacaoSignature {
                t: "eip191".to_owned(),
                s: body.signature.clone(),
            },
        };
        let verified = self
            .config
            .verifier
            .verify_message(SiweVerification {
                message: body.message.clone(),
                signature: body.signature,
                address: address.clone(),
                chain_id,
                cacao,
            })
            .await?;
        if !verified {
            return Err(SiweCallbackError::Api(
                AuthResponse::json(
                    401,
                    &json!({"message":"Unauthorized: Invalid SIWE signature","status":401}),
                )
                .map_err(|error| storage_error(error.into()))?,
            ));
        }
        let exact_wallet = ctx
            .database
            .get_wallet_address(&address, Some(chain_id))
            .await
            .map_err(storage_error)?;
        let wallet = if exact_wallet.is_some() {
            exact_wallet.clone()
        } else {
            ctx.database
                .get_wallet_address(&address, None)
                .await
                .map_err(storage_error)?
        };
        let user = if let Some(wallet) = wallet {
            ctx.database
                .get_user_by_id(&wallet.user_id)
                .await
                .map_err(storage_error)?
        } else {
            None
        };
        let user = if let Some(user) = user {
            if exact_wallet.is_none() {
                self.link_wallet(ctx, &user.id(), &address, chain_id, false)
                    .await?;
            }
            user
        } else {
            let user_2 = self
                .create_user(ctx, &address, body.email.as_deref())
                .await?;
            self.link_wallet(ctx, &user_2.id(), &address, chain_id, true)
                .await?;
            user_2
        };
        let meta = RequestMeta::from_request(request);
        let issued = issue_user_session_record(ctx, &user.id(), meta.ip_address, meta.user_agent)
            .await
            .map_err(|error| storage_error(error.into_auth_error()))?;
        let token = issued.session.token();
        let mut response = AuthResponse::json(200, &json!({"token":token,"success":true,"user":{"id":issued.user.id(),"walletAddress":address,"chainId":chain_id}})).map_err(|error| storage_error(error.into()))?;
        Self::session_cookies(request, ctx, token, &mut response);
        Ok(response)
    }

    async fn create_user<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        address: &str,
        email: Option<&str>,
    ) -> SiweCallbackResult<S::User> {
        let normalized_email = email.map(str::to_lowercase);
        let wallet_email = self
            .config
            .email_domain_name
            .as_deref()
            .filter(|domain| !domain.is_empty())
            .map_or_else(
                || format!("{address}@siwe.placeholder.invalid"),
                |domain| format!("{address}@{domain}"),
            )
            .to_lowercase();
        let mut user_email = wallet_email.clone();
        let mut claim = None;
        if !self.config.anonymous
            && let Some(email_2) = &normalized_email
        {
            let identifier = format!("siwe-email-claim-{email_2}");
            let reserved = ctx
                .database
                .reserve_verification(CreateVerification {
                    identifier: identifier.clone(),
                    value: address.to_owned(),
                    expires_at: Utc::now() + Duration::seconds(60),
                })
                .await
                .unwrap_or(false);
            if reserved {
                claim = Some(identifier);
                if ctx
                    .database
                    .get_user_by_email(email_2)
                    .await
                    .map_err(storage_error)?
                    .is_none()
                {
                    user_email = email_2.clone();
                }
            }
        }
        // Keep the reference ordering: ENS failures leave an email claim in
        // place. User-creation success/failure below always consumes its claim.
        let profile = match &self.config.ens_lookup {
            Some(lookup) => lookup.lookup(address).await?,
            None => EnsProfile::default(),
        };
        let mut create = CreateUser::new()
            .with_email(&user_email)
            .with_name(profile.name.unwrap_or_else(|| address.to_owned()));
        create.image = Some(profile.avatar.unwrap_or_default());
        apply_default_role(ctx, &mut create);
        let created = ctx
            .database
            .create_user_with_source(
                create.clone(),
                better_auth_core::user_validation::UserValidationSource::creation("siwe"),
            )
            .await;
        let created = match created {
            Ok(user) => Ok(user),
            Err(error) if Some(&user_email) == normalized_email.as_ref() => {
                let email_3 = normalized_email.as_deref().unwrap_or_default();
                match ctx.database.get_user_by_email(email_3).await {
                    Ok(Some(_)) => {
                        create.email = Some(wallet_email);
                        ctx.database
                            .create_user_with_source(
                                create,
                                better_auth_core::user_validation::UserValidationSource::creation(
                                    "siwe",
                                ),
                            )
                            .await
                            .map_err(storage_error)
                    }
                    Ok(None) => Err(storage_error(error)),
                    Err(error_2) => Err(storage_error(error_2)),
                }
            }
            Err(error) => Err(storage_error(error)),
        };
        if let Some(identifier) = claim {
            drop(
                ctx.database
                    .consume_verification_by_identifier(&identifier)
                    .await,
            );
        }
        created
    }

    async fn link_wallet<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        user_id: &str,
        address: &str,
        chain_id: f64,
        primary: bool,
    ) -> SiweCallbackResult<()> {
        drop(
            ctx.database
                .create_wallet_address(CreateWalletAddress {
                    user_id: user_id.to_owned(),
                    address: address.to_owned(),
                    chain_id,
                    is_primary: primary,
                })
                .await
                .map_err(storage_error)?,
        );
        let mut number = ryu_js::Buffer::new();
        drop(
            ctx.database
                .create_account(CreateAccount {
                    additional_fields: Default::default(),
                    user_id: user_id.to_owned(),
                    account_id: format!("{address}:{}", number.format(chain_id)),
                    provider_id: "siwe".to_owned(),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                    password: None,
                })
                .await
                .map_err(storage_error)?,
        );
        Ok(())
    }

    fn session_cookies<S: AuthSchema>(
        request: &AuthRequest,
        ctx: &AuthContext<S>,
        token: &str,
        response: &mut AuthResponse,
    ) {
        use better_auth_core::utils::cookie_utils::{
            create_session_cookie_with_max_age, create_session_like_cookie, related_cookie_name,
            sign_cookie_value, verify_cookie_value,
        };
        let name = related_cookie_name(&ctx.config, "dont_remember");
        let preference = super::helpers::get_cookie(request, &name)
            .and_then(|value| verify_cookie_value(&value, &ctx.config.secret))
            .is_some_and(|value| !value.is_empty());
        response.headers.append(
            "Set-Cookie",
            create_session_cookie_with_max_age(
                Some(token),
                (!preference).then(|| ctx.config.session.expires_in.num_seconds()),
                &ctx.config,
            ),
        );
        if preference {
            response.headers.append(
                "Set-Cookie",
                create_session_like_cookie(
                    &name,
                    &sign_cookie_value("true", &ctx.config.secret),
                    None,
                    &ctx.config,
                ),
            );
        }
    }
}

better_auth_core::impl_auth_plugin! {
    SiwePlugin, "siwe";
    routes {
        post "/siwe/nonce" => handle_nonce, "get_siwe_nonce";
        post "/siwe/get-nonce" => handle_nonce, "get_nonce";
        post "/siwe/verify" => handle_verify, "verify_siwe_message";
    }
}

fn mismatch() -> SiweCallbackError {
    endpoint_error(
        "Unauthorized: SIWE message does not match the expected nonce, domain, address, or chain ID",
        "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH",
    )
}

fn endpoint_error(message: &str, code: &str) -> SiweCallbackError {
    match AuthResponse::json(401, &json!({"message":message,"status":401,"code":code})) {
        Ok(response) => SiweCallbackError::Api(response),
        Err(error) => SiweCallbackError::Failed(error.to_string()),
    }
}

fn storage_error(error: AuthError) -> SiweCallbackError {
    if error.status_code() < 500 || matches!(error, AuthError::Upstream { .. }) {
        SiweCallbackError::Api(error.to_auth_response())
    } else {
        SiweCallbackError::Failed(error.to_string())
    }
}
