//! Real EIP-191 and local ERC-1271 provider configurations of the public plugin.
use crate::TestSchema;
use alibi::AuthResponse;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::siwe::{
    Eip191Verifier, EnsLookup, EnsProfile, SiweCallbackError, SiweCallbackResult, SiweConfig,
    SiweNonceProvider, SiwePlugin, SiweVerification, SiweVerifier, ethereum_message_hash,
};
use alibi::plugins::{AdminPlugin, EmailPasswordPlugin, SessionManagementPlugin, TwoFactorPlugin};
use alibi::prelude::{CreateUser, UpdateUser};
use alibi::seaorm::sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, sea_query::Expr,
};
use alibi::seaorm::store::entities::{account, session, user, verification, wallet_address};
use alibi::{AuthBuilder, AuthConfig, AuthResult, BetterAuth};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

const CONTRACT: &str = "0x1111111111111111111111111111111111111111";
const CONTRACT_OWNER: &str = "0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69";

#[derive(Default)]
pub(crate) struct FixtureState {
    counter: u32,
    nonce: Option<String>,
    verifier: String,
    ens: String,
    rpc: String,
    inputs: Vec<Value>,
    lookups: Vec<String>,
    rpc_calls: Vec<Value>,
    release: Arc<Notify>,
    entered: Arc<Notify>,
}
pub(crate) type SharedState = Arc<Mutex<FixtureState>>;

pub(crate) fn state() -> SharedState {
    Arc::new(Mutex::new(FixtureState::default()))
}
pub(crate) async fn reset(state: &SharedState) {
    *state.lock().await = FixtureState::default();
}

struct Nonce(SharedState);
#[async_trait]
impl SiweNonceProvider for Nonce {
    async fn get_nonce(&self) -> SiweCallbackResult<String> {
        let mut state = self.0.lock().await;
        if let Some(nonce) = &state.nonce {
            return Ok(nonce.clone());
        }
        let nonce = format!("SiweFixtureNonce{:016}", state.counter);
        state.counter += 1;
        Ok(nonce)
    }
}

struct SignatureProvider {
    state: SharedState,
    rpc_url: Option<String>,
}
#[async_trait]
impl SiweVerifier for SignatureProvider {
    async fn verify_message(&self, input: SiweVerification) -> SiweCallbackResult<bool> {
        let mode = {
            let mut state = self.state.lock().await;
            state.inputs.push(json!({"message":input.message,"signature":input.signature,"address":input.address,"chainId":input.chain_id,"cacao":input.cacao}));
            state.verifier.clone()
        };
        if mode == "hold" {
            let release = {
                let state = self.state.lock().await;
                state.entered.notify_one();
                state.release.clone()
            };
            release.notified().await;
        }
        match mode.as_str() {
            "throw"=>return Err(SiweCallbackError::Failed("deterministic verifier failure".to_owned())),
            "api-error"=>return Err(SiweCallbackError::Api(AuthResponse::json(403,&json!({"message":"configured wallet policy rejected","code":"WALLET_POLICY_REJECTED"})).map_err(|error|SiweCallbackError::Failed(error.to_string()))?)),
            "false"=>return Ok(false),
            _=>{}
        }
        let Some(url) = &self.rpc_url else {
            return Eip191Verifier.verify_message(input).await;
        };
        if input.address != CONTRACT || input.chain_id != 31337.0 {
            return Ok(false);
        }
        let hash = ethereum_message_hash(&input.message)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let signature = input.signature.strip_prefix("0x").unwrap_or_default();
        let data = format!(
            "0x1626ba7e{hash}{:0>64}{:064x}{:0<width$}",
            "40",
            signature.len() / 2,
            signature,
            width = signature.len().div_ceil(64) * 64
        );
        let response=reqwest::Client::new().post(url).json(&json!({"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":input.address,"data":data},"latest"]})).send().await.map_err(|error|SiweCallbackError::Failed(error.to_string()))?;
        let result: Value = response
            .json()
            .await
            .map_err(|error| SiweCallbackError::Failed(error.to_string()))?;
        Ok(result
            .get("result")
            .and_then(Value::as_str)
            .is_some_and(|result| result.starts_with("0x1626ba7e")))
    }
}

struct Lookup(SharedState);
#[async_trait]
impl EnsLookup for Lookup {
    async fn lookup(&self, address: &str) -> SiweCallbackResult<EnsProfile> {
        let mut state = self.0.lock().await;
        state.lookups.push(address.to_owned());
        if state.ens == "throw" {
            return Err(SiweCallbackError::Failed(
                "deterministic ENS failure".to_owned(),
            ));
        }
        Ok(EnsProfile {
            name: Some("Wallet Fixture".to_owned()),
            avatar: Some("https://fixture.example/avatar.png".to_owned()),
        })
    }
}

#[derive(Clone)]
struct ControlState {
    state: SharedState,
    database: DatabaseConnection,
    auth: Arc<BetterAuth<TestSchema>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Control {
    operation: String,
    nonce: Option<String>,
    value: Option<String>,
    email: Option<String>,
    user_id: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    banned: Option<bool>,
    two_factor_enabled: Option<bool>,
    verifier: Option<String>,
    ens: Option<String>,
    rpc: Option<String>,
}

fn date(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

async fn persisted(
    State(control): State<ControlState>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let database = &control.database;
    let users = user::Entity::find()
        .order_by_asc(Expr::cust("rowid"))
        .all(database)
        .await
        .map_err(failure)?;
    let wallets = wallet_address::Entity::find()
        .order_by_asc(Expr::cust("rowid"))
        .all(database)
        .await
        .map_err(failure)?;
    let accounts = account::Entity::find()
        .order_by_asc(Expr::cust("rowid"))
        .all(database)
        .await
        .map_err(failure)?;
    let sessions = session::Entity::find()
        .order_by_asc(Expr::cust("rowid"))
        .all(database)
        .await
        .map_err(failure)?;
    let proofs = verification::Entity::find()
        .filter(verification::Column::Identifier.starts_with("siwe"))
        .order_by_asc(Expr::cust("rowid"))
        .all(database)
        .await
        .map_err(failure)?;
    let state = control.state.lock().await;
    Ok(Json(json!({
        "users":users.into_iter().map(|row|json!({"id":row.id,"name":row.name,"email":row.email,"emailVerified":row.email_verified,"image":row.image,"role":row.role,"banned":row.banned,"twoFactorEnabled":row.two_factor_enabled,"createdAt":date(row.created_at),"updatedAt":date(row.updated_at)})).collect::<Vec<_>>(),
        "wallets":wallets.into_iter().map(|row|json!({"id":row.id,"userId":row.user_id,"address":row.address,"chainId":row.chain_id.0,"isPrimary":row.is_primary,"createdAt":date(row.created_at)})).collect::<Vec<_>>(),
        "accounts":accounts.into_iter().map(|row|json!({"id":row.id,"userId":row.user_id,"accountId":row.account_id,"providerId":row.provider_id,"createdAt":date(row.created_at),"updatedAt":date(row.updated_at)})).collect::<Vec<_>>(),
        "sessions":sessions.into_iter().map(|row|json!({"id":row.id,"userId":row.user_id,"token":row.token,"createdAt":date(row.created_at),"updatedAt":date(row.updated_at),"expiresAt":date(row.expires_at),"ipAddress":row.ip_address,"userAgent":row.user_agent})).collect::<Vec<_>>(),
        "proofs":proofs.into_iter().map(|row|json!({"id":row.id,"identifier":row.identifier,"value":row.value,"createdAt":date(row.created_at),"updatedAt":date(row.updated_at),"expiresAt":date(row.expires_at)})).collect::<Vec<_>>(),
        "inputs":state.inputs,"lookups":state.lookups,"rpcCalls":state.rpc_calls,
    })))
}
fn failure(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

async fn configure(
    State(control): State<ControlState>,
    Json(body): Json<Control>,
) -> Result<Json<Value>, (StatusCode, String)> {
    match body.operation.as_str() {
        "wait-verifier" => {
            let entered = control.state.lock().await.entered.clone();
            entered.notified().await;
        }
        "release-verifier" => {
            control.state.lock().await.release.notify_one();
        }
        "configure" => {
            let mut state = control.state.lock().await;
            if let Some(nonce) = body.nonce {
                state.nonce = Some(nonce);
            }
            if let Some(mode) = body.verifier {
                state.verifier = mode;
            }
            if let Some(mode) = body.ens {
                state.ens = mode;
            }
            if let Some(mode) = body.rpc {
                state.rpc = mode;
            }
        }
        "proof" => {
            let mut update = verification::Entity::update_many().filter(
                verification::Column::Identifier
                    .eq(format!("siwe:{}", body.nonce.unwrap_or_default())),
            );
            if let Some(value) = body.value {
                update = update.col_expr(verification::Column::Value, Expr::value(value));
            }
            if let Some(value) = body.expires_at {
                update = update.col_expr(verification::Column::ExpiresAt, Expr::value(value));
            }
            let _ = update.exec(&control.database).await.map_err(failure)?;
        }
        "create-user" => {
            let mut create = CreateUser::new()
                .with_email(body.email.unwrap_or_default())
                .with_name("Existing Email User");
            create.role = Some("user".to_owned());
            let user = control
                .auth
                .store()
                .create_user(create)
                .await
                .map_err(failure)?;
            return Ok(Json(json!({"userId":user.id})));
        }
        "update-user" => {
            let _ = control
                .auth
                .store()
                .update_user(
                    &body.user_id.unwrap_or_default(),
                    UpdateUser {
                        banned: body.banned,
                        two_factor_enabled: body.two_factor_enabled,
                        ..Default::default()
                    },
                )
                .await
                .map_err(failure)?;
        }
        "delete-user" => control
            .auth
            .store()
            .delete_user(&body.user_id.unwrap_or_default())
            .await
            .map_err(failure)?,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "Unknown SIWE fixture operation".to_owned(),
            ));
        }
    }
    Ok(Json(json!({"status":true})))
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            Some(
                (char::from(*pair.first()?).to_digit(16)? * 16
                    + char::from(*pair.get(1)?).to_digit(16)?) as u8,
            )
        })
        .collect()
}

async fn rpc(State(control): State<ControlState>, Json(body): Json<Value>) -> Json<Value> {
    let mode = {
        let mut state = control.state.lock().await;
        state.rpc_calls.push(body.clone());
        state.rpc.clone()
    };
    let valid = (|| {
        if mode == "false" || body.get("method")?.as_str()? != "eth_call" {
            return None;
        }
        let call = body.get("params")?.get(0)?;
        if call.get("to")?.as_str()? != CONTRACT {
            return None;
        }
        let data = call.get("data")?.as_str()?.strip_prefix("0x1626ba7e")?;
        let hash: [u8; 32] = decode_hex(data.get(..64)?)?.try_into().ok()?;
        let offset = usize::from_str_radix(data.get(64..128)?, 16)
            .ok()?
            .checked_mul(2)?;
        let length = usize::from_str_radix(data.get(offset..offset.checked_add(64)?)?, 16)
            .ok()?
            .checked_mul(2)?;
        let start = offset.checked_add(64)?;
        let signature = format!("0x{}", data.get(start..start.checked_add(length)?)?);
        Some(
            Eip191Verifier::recover_hash_address(&hash, &signature).as_deref()
                == Some(CONTRACT_OWNER),
        )
    })()
    .unwrap_or(false);
    Json(
        json!({"jsonrpc":"2.0","id":body.get("id"),"result":format!("{}{}",if valid {"0x1626ba7e"}else{"0xffffffff"},"0".repeat(56))}),
    )
}

pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
    state: SharedState,
) -> AuthResult<Router> {
    let mut router = Router::new();
    let mut primary = None;
    for name in ["siwe", "siwe-email", "siwe-contract", "siwe-cookie-limit"] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        if name == "siwe-cookie-limit" {
            config.session.expires_in = chrono::Duration::seconds(34_560_001);
        }
        let mut options = SiweConfig::new(
            "HTTPS://Fixture.Example/ignored",
            Arc::new(Nonce(state.clone())),
            Arc::new(SignatureProvider {
                state: state.clone(),
                rpc_url: (name == "siwe-contract")
                    .then(|| format!("{}/__test/siwe-rpc", base.base_url.trim_end_matches('/'))),
            }),
        );
        if name == "siwe-email" {
            options.anonymous = false;
            options.email_domain_name = Some("Wallet.Fixture.Test".to_owned());
            options.ens_lookup = Some(Arc::new(Lookup(state.clone())));
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(AdminPlugin::new())
                .plugin(TwoFactorPlugin::new())
                .plugin(SiwePlugin::new(options))
                .build()
                .await?,
        );
        if name == "siwe" {
            primary = Some(auth.clone());
        }
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let auth = primary
        .ok_or_else(|| alibi::AuthError::internal("SIWE fixture missing primary profile"))?;
    Ok(router.merge(
        Router::new()
            .route("/__test/siwe-state", get(persisted))
            .route("/__test/siwe-control", post(configure))
            .route("/__test/siwe-rpc", post(rpc))
            .with_state(ControlState {
                state,
                database,
                auth,
            }),
    ))
}
