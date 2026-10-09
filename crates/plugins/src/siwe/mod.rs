//! Sign in with Ethereum using a single-use challenge and application-owned
//! signature verification, including contract-wallet RPC providers.

mod config;

mod crypto;

use alibi_core::field_policy::FieldValues;
use alibi_core::utils::datetime as date;

mod parse;

mod validation;

use super::helpers::{apply_default_role, issue_selected_user_session_record};
use alibi_core::{
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
            ctx.verifications()
                .create(CreateVerification {
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
            .verifications()
            .consume(&format!("siwe:{nonce}"))
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
                .get_user_by_id_record(&wallet.user_id)
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
        let issued =
            issue_selected_user_session_record(ctx, user, meta.ip_address, meta.user_agent)
                .await
                .map_err(|error| storage_error(error.into_auth_error()))?;
        let token = issued.session.token();
        let mut response = AuthResponse::json(200, &json!({"token":token,"success":true,"user":{"id":issued.user.id(),"walletAddress":address,"chainId":chain_id}})).map_err(|error| storage_error(error.into()))?;
        Self::session_cookies(request, ctx, token, &mut response).map_err(|error| match error {
            // The installed SIWE endpoint catches ordinary serializer errors and
            // returns its own 401 body with the serializer message.
            AuthError::CallbackFailure(cause) => match *cause {
                AuthError::Internal(message) => SiweCallbackError::Failed(message),
                other => storage_error(other),
            },
            other => storage_error(other),
        })?;
        Ok(response)
    }

    async fn create_user<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        address: &str,
        email: Option<&str>,
    ) -> SiweCallbackResult<alibi_core::AdapterRecord<S::User>> {
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
                .verifications()
                .reserve(CreateVerification {
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
                    .get_user_by_email_record(email_2)
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
            .create_user_with_source_record(
                create.clone(),
                alibi_core::user_validation::UserValidationSource::creation("siwe"),
            )
            .await;
        let created = match created {
            Ok(user) => Ok(user),
            Err(error) if Some(&user_email) == normalized_email.as_ref() => {
                let email_3 = normalized_email.as_deref().unwrap_or_default();
                match ctx.database.get_user_by_email_record(email_3).await {
                    Ok(Some(_)) => {
                        create.email = Some(wallet_email);
                        ctx.database
                            .create_user_with_source_record(
                                create,
                                alibi_core::user_validation::UserValidationSource::creation("siwe"),
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
            drop(ctx.verifications().consume(&identifier).await);
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
                .create_account_record(CreateAccount {
                    additional_fields: FieldValues::default(),
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
    ) -> AuthResult<()> {
        use alibi_core::utils::cookie_utils::{
            create_session_cookie_with_max_age, create_session_like_cookie, related_cookie_name,
            sign_cookie_value, verify_cookie_value,
        };
        let name = related_cookie_name(&ctx.config, "dont_remember");
        let preference = super::helpers::get_cookie(request, &name)
            .and_then(|value| verify_cookie_value(&value, ctx.config.current_secret()))
            .is_some_and(|value| !value.is_empty());
        response.headers.append(
            "Set-Cookie",
            create_session_cookie_with_max_age(
                Some(token),
                (!preference).then(|| ctx.config.session.expires_in.num_seconds()),
                &ctx.config,
            )?,
        );
        if preference {
            response.headers.append(
                "Set-Cookie",
                create_session_like_cookie(
                    &name,
                    &sign_cookie_value("true", ctx.config.current_secret()),
                    None,
                    &ctx.config,
                )?,
            );
        }
        Ok(())
    }
}

alibi_core::impl_auth_plugin! {
    SiwePlugin, "siwe";
    routes {
        post "/siwe/nonce" => handle_nonce, "get_siwe_nonce";
        post "/siwe/get-nonce" => handle_nonce, "get_nonce";
        post "/siwe/verify" => handle_verify, "verify_siwe_message";
    }

 extra {
    fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self))
    }

    fn openapi_metadata(&self, ctx: &alibi_core::AuthInitContext<S>) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self), ctx)
    }
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

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        reason = "protocol tests assert concrete persisted and signed payloads"
    )]

    use super::*;
    use alibi_core::{AuthAccount, AuthPlugin, AuthVerification, HttpMethod};
    use alibi_seaorm::sea_orm::{EntityTrait, PaginatorTrait};
    use alibi_seaorm::store::entities::wallet_address;
    use alibi_seaorm::{Database, DatabaseConnection, SeaOrmStore};
    use async_trait::async_trait;
    use k256::ecdsa::SigningKey;
    use std::fmt::Write;
    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };
    use tokio::sync::Mutex;

    type TestSchema = alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    const ADDRESS: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

    #[derive(Default)]
    struct Nonces(AtomicU32);
    #[async_trait]
    impl SiweNonceProvider for Nonces {
        async fn get_nonce(&self) -> SiweCallbackResult<String> {
            Ok(format!(
                "FixtureNonce{:08}",
                self.0.fetch_add(1, Ordering::SeqCst)
            ))
        }
    }
    struct FixedNonce(&'static str);
    #[async_trait]
    impl SiweNonceProvider for FixedNonce {
        async fn get_nonce(&self) -> SiweCallbackResult<String> {
            Ok(self.0.to_owned())
        }
    }

    #[derive(Default)]
    struct Verifier {
        inputs: Mutex<Vec<SiweVerification>>,
    }
    #[async_trait]
    impl SiweVerifier for Verifier {
        async fn verify_message(&self, input: SiweVerification) -> SiweCallbackResult<bool> {
            self.inputs.lock().await.push(input.clone());
            Eip191Verifier.verify_message(input).await
        }
    }

    async fn context() -> (AuthContext<TestSchema>, DatabaseConnection) {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        alibi_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let config = Arc::new(alibi_core::AuthConfig::new(
            "siwe-native-context-secret-at-least-32-characters",
        ));
        let store = Arc::new(SeaOrmStore::<TestSchema>::new(
            Arc::clone(&config),
            database.clone(),
        ));
        (AuthContext::new(config, store), database)
    }

    fn plugin() -> (SiwePlugin, Arc<Verifier>) {
        let verifier = Arc::new(Verifier::default());
        let config = SiweConfig::new(
            "fixture.example",
            Arc::new(Nonces::default()),
            Arc::<Verifier>::clone(&verifier),
        );
        (SiwePlugin::new(config), verifier)
    }

    fn request(path: &str, body: &serde_json::Value) -> AuthRequest {
        let mut request = AuthRequest::new(HttpMethod::Post, path);
        request.body = Some(serde_json::to_vec(&body).unwrap());
        drop(
            request
                .headers
                .insert("content-type".into(), "application/json".into()),
        );
        request
    }
    fn body(response: &AuthResponse) -> serde_json::Value {
        serde_json::from_slice(&response.body).unwrap()
    }

    async fn issue(plugin: &SiwePlugin, ctx: &AuthContext<TestSchema>, path: &str) -> String {
        let response = plugin
            .on_request(&request(path, &(json!({}))), ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 200, "{}", body(&response));
        body(&response)["nonce"].as_str().unwrap().to_owned()
    }

    fn message(nonce: &str, domain: &str, address: &str, chain: &str, extra: &str) -> String {
        format!(
            "{domain} wants you to sign in with your Ethereum account:\n{address}\n\nSign in — Ελληνικά\n\nURI: not-a-url\nVersion: 999\nChain ID: {chain}\nNonce: {nonce}\nIssued At: invalid date\n{extra}"
        )
    }

    fn sign(message: &str, scalar: u8) -> String {
        use sha3::{Digest, Keccak256};
        let mut secret = [0u8; 32];
        secret[31] = scalar;
        let key = SigningKey::from_slice(&secret).unwrap();
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut digest = Keccak256::new();
        digest.update(prefix.as_bytes());
        digest.update(message.as_bytes());
        let (signature, recovery) = key.sign_prehash_recoverable(&digest.finalize());
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery.to_byte() + 27);
        format!(
            "0x{}",
            bytes.iter().fold(String::new(), |mut output, byte| {
                _ = write!(output, "{byte:02x}");
                output
            })
        )
    }

    async fn verify(
        plugin: &SiwePlugin,
        ctx: &AuthContext<TestSchema>,
        message: &str,
        scalar: u8,
        email: Option<&str>,
    ) -> AuthResponse {
        let mut body = json!({"message":message,"signature":sign(message, scalar)});
        if let Some(email) = email {
            body["email"] = json!(email);
        }
        plugin
            .on_request(&request("/siwe/verify", &(body)), ctx)
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn independent_unicode_signature_creates_an_authenticated_wallet_identity_and_rotates_only_sessions()
     {
        let (ctx, database) = context().await;
        let verifier = Arc::new(Verifier::default());
        let plugin = SiwePlugin::new(SiweConfig::new(
            "fixture.example",
            Arc::new(FixedNonce("GoldenNonce0001")),
            Arc::<Verifier>::clone(&verifier),
        ));
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/siwe/eip191-noble-2.0.1.json"
        ))
        .unwrap();
        let nonce = issue(&plugin, &ctx, "/siwe/get-nonce").await;
        let proof = ctx
            .database
            .get_latest_verification_by_identifier(&format!("siwe:{nonce}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(proof.value(), nonce);
        assert!(
            ((proof.expires_at() - proof.created_at()).num_milliseconds() - 900_000).abs() < 1_000
        );
        let response = plugin.on_request(&request("/siwe/verify", &(json!({"message":fixture["message"],"signature":fixture["signature"],"email":"ignored@fixture.test"}))), &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 200, "{}", body(&response));
        let result = body(&response);
        assert_eq!(result.as_object().unwrap().len(), 3);
        assert_eq!(result["success"], true);
        assert_eq!(result["user"]["walletAddress"], ADDRESS);
        assert_eq!(result["user"]["chainId"].as_f64(), Some(1.0));
        let user_id = result["user"]["id"].as_str().unwrap();
        let user = ctx.database.get_user_by_id(user_id).await.unwrap().unwrap();
        assert_eq!(
            user.email.as_deref(),
            Some("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf@siwe.placeholder.invalid")
        );
        assert_eq!(user.name.as_deref(), Some(ADDRESS));
        assert_eq!(user.image.as_deref(), Some(""));
        assert!(!user.email_verified);
        let wallet = ctx
            .database
            .get_wallet_address(ADDRESS, Some(1.0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(wallet.user_id, user_id);
        assert!(wallet.is_primary);
        let accounts = ctx.database.get_user_accounts(user_id).await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].provider_id(), "siwe");
        assert_eq!(accounts[0].account_id(), format!("{ADDRESS}:1"));
        let cookie = response
            .headers
            .get_all("Set-Cookie")
            .find(|header| header.starts_with("better-auth.session_token="))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let mut read = AuthRequest::new(HttpMethod::Get, "/get-session");
        drop(read.headers.insert("cookie".into(), cookie.to_owned()));
        let (_, session) = ctx.require_session(&read).await.unwrap();
        assert_eq!(session.user_id, user_id);
        assert_eq!(session.token, result["token"].as_str().unwrap());
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(&format!("siwe:{nonce}"))
                .await
                .unwrap()
                .is_none()
        );
        let replay = plugin
            .on_request(
                &request(
                    "/siwe/verify",
                    &(json!({"message":fixture["message"],"signature":fixture["signature"]})),
                ),
                &ctx,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            body(&replay)["code"],
            "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"
        );
        let next = issue(&plugin, &ctx, "/siwe/nonce").await;
        let signed = message(
            &next,
            "HTTPS://FIXTURE.EXAMPLE/ignored",
            &ADDRESS.to_lowercase(),
            "0x10",
            "Expiration Time: not a date\nNot Before: not a date",
        );
        let cross_chain = verify(&plugin, &ctx, &signed, 1, None).await;
        assert_eq!(cross_chain.status, 200, "{}", body(&cross_chain));
        assert_eq!(body(&cross_chain)["user"]["id"], user_id);
        assert_ne!(body(&cross_chain)["token"], result["token"]);
        assert!(
            !ctx.database
                .get_wallet_address(ADDRESS, Some(16.0))
                .await
                .unwrap()
                .unwrap()
                .is_primary
        );
        assert_eq!(
            wallet_address::Entity::find()
                .count(&database)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            ctx.database.get_user_sessions(user_id).await.unwrap().len(),
            2
        );
        assert_eq!(
            ctx.database.get_user_accounts(user_id).await.unwrap().len(),
            2
        );
        let next_2 = issue(&plugin, &ctx, "/siwe/nonce").await;
        let huge = verify(
            &plugin,
            &ctx,
            &message(&next_2, "fixture.example", ADDRESS, "1e21", ""),
            1,
            None,
        )
        .await;
        assert_eq!(huge.status, 200, "{}", body(&huge));
        assert!(
            ctx.database
                .get_user_accounts(user_id)
                .await
                .unwrap()
                .iter()
                .any(|account| account.account_id() == format!("{ADDRESS}:1e+21"))
        );
        let observed = verifier.inputs.lock().await;
        assert_eq!(observed.len(), 3);
        assert_eq!(observed[0].cacao.p.nonce, "GoldenNonce0001");
        assert_eq!(observed[0].cacao.p.domain, "fixture.example");
        assert_eq!(observed[0].cacao.p.aud, "fixture.example");
        assert_eq!(observed[0].cacao.p.iss, "fixture.example");
        assert_eq!(
            observed[0].cacao.s.s,
            fixture["signature"].as_str().unwrap()
        );
        assert_eq!(
            observed
                .get(1)
                .expect("callback receives the second fixture")
                .chain_id
                .to_bits(),
            16.0_f64.to_bits()
        );
        assert_eq!(
            observed
                .get(2)
                .expect("third observed proof")
                .chain_id
                .to_bits(),
            1e21_f64.to_bits()
        );
    }

    #[tokio::test]
    async fn signed_preferences_change_cookie_persistence_without_shortening_siwe_sessions() {
        use alibi_core::utils::cookie_utils::{related_cookie_name, sign_cookie_value};
        let (ctx, _) = context().await;
        let (plugin, _) = plugin();
        let preference_name = related_cookie_name(&ctx.config, "dont_remember");
        for (preference, temporary) in [
            (None, false),
            (Some(""), false),
            (Some("false"), true),
            (Some("true"), true),
        ] {
            let nonce = issue(&plugin, &ctx, "/siwe/nonce").await;
            let signed = message(&nonce, "fixture.example", ADDRESS, "1", "");
            let mut req = request(
                "/siwe/verify",
                &(json!({"message":signed,"signature":sign(&signed,1)})),
            );
            if let Some(preference) = preference {
                drop(req.headers.insert(
                    "cookie".into(),
                    format!(
                        "{preference_name}={}",
                        sign_cookie_value(preference, &ctx.config.secret)
                    ),
                ));
            }
            let response = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
            assert_eq!(response.status, 200);
            let result = body(&response);
            let session = ctx
                .database
                .get_session(result["token"].as_str().unwrap())
                .await
                .unwrap()
                .unwrap();
            assert!(
                ((session.expires_at - session.created_at) - ctx.config.session.expires_in)
                    .num_milliseconds()
                    .abs()
                    < 1_000
            );
            let cookie = response
                .headers
                .get_all("Set-Cookie")
                .find(|cookie| cookie.starts_with("better-auth.session_token="))
                .unwrap();
            assert_eq!(
                !cookie.contains("Max-Age="),
                temporary,
                "preference={preference:?}"
            );
            assert_eq!(
                response
                    .headers
                    .get_all("Set-Cookie")
                    .any(|candidate| candidate.starts_with(&format!("{preference_name}="))),
                temporary
            );
        }
        assert_eq!(
            ctx.database
                .get_user_sessions(
                    &ctx.database
                        .get_wallet_address(ADDRESS, Some(1.0))
                        .await
                        .unwrap()
                        .unwrap()
                        .user_id
                )
                .await
                .unwrap()
                .len(),
            4
        );
    }
}
// LCOV_EXCL_STOP
