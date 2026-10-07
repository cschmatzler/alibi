//! Local delivery, configuration and server-only OTP fixture interfaces.
use crate::fixtures::passwordless_numeric_fixture::numeric_setting;
use crate::{CompatVerificationSender, EmailOutboxRecord, TestSchema};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::Query,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::email_otp::{
    EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, EmailOtpStorage, EmailOtpType,
    OtpResendStrategy, SendEmailOtp,
};
use alibi::plugins::{
    EmailPasswordPlugin, EmailVerificationPlugin, PasswordManagementPlugin, SessionManagementPlugin,
};
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use alibi_core::{
    AuthRequest, CreateVerification, DatabaseError, HttpMethod, wire::VerificationView,
};
use alibi_seaorm::{
    sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder},
    store::entities::verification,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

pub(super) type Outbox = Arc<Mutex<HashMap<String, Value>>>;
#[derive(Clone)]
pub(super) struct Sender(pub Outbox);
#[async_trait]
impl SendEmailOtp for Sender {
    async fn send(
        &self,
        delivery: &EmailOtpDelivery,
        _context: &alibi_core::CallbackContext,
    ) -> AuthResult<()> {
        let identifier = if delivery.otp_type == EmailOtpType::ChangeEmail
            && _context.request.as_ref().is_some_and(|request| {
                request
                    .headers
                    .get("x-callback-probe")
                    .is_some_and(|value| value == "issue207")
            }) {
            let auth = _context.context::<TestSchema>().unwrap();
            let proof = auth
                .database
                .get_verification_by_value(&format!("{}:0", delivery.otp))
                .await?
                .ok_or_else(|| AuthError::internal("missing issued change proof"))?;
            alibi_core::AuthVerification::identifier(&proof).to_string()
        } else {
            format!("{}-otp-{}", delivery.otp_type.as_str(), delivery.email)
        };
        let context =
            crate::fixtures::passwordless_context::snapshot(_context, &identifier).await?;
        let key = format!("{}:{}", delivery.otp_type.as_str(), delivery.email);
        let generator = self
            .0
            .lock()
            .await
            .get(&key)
            .and_then(|value| value.get("generator"))
            .cloned();
        let mut value = json!({"otp":delivery.otp});
        if let Some(context) = context {
            value["context"] = context;
        }
        if let Some(generator) = generator {
            value["generator"] = generator;
        }
        _ = self.0.lock().await.insert(
            format!("{}:{}", delivery.otp_type.as_str(), delivery.email),
            value,
        );
        Ok(())
    }
}
#[async_trait]
impl alibi::plugins::email_otp::EmailOtpGenerator for Sender {
    async fn generate(
        &self,
        email: &str,
        kind: EmailOtpType,
        context: &alibi_core::CallbackContext,
    ) -> AuthResult<Option<String>> {
        if let Some(mut snapshot) = crate::fixtures::passwordless_context::snapshot(
            context,
            &format!("{}-otp-{email}", kind.as_str()),
        )
        .await?
        {
            _ = snapshot.as_object_mut().unwrap().remove("proofExists");
            _ = self.0.lock().await.insert(
                format!("{}:{email}", kind.as_str()),
                json!({"generator":snapshot}),
            );
        }
        Ok(None)
    }
}
#[derive(Clone)]
struct Runtime {
    auth: Arc<BetterAuth<TestSchema>>,
    otp: EmailOtpPlugin,
}
#[derive(Deserialize)]
struct CodeQuery {
    email: String,
    #[serde(rename = "type")]
    kind: String,
}
#[derive(Deserialize)]
struct VerificationQuery {
    identifier: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerificationAction {
    action: String,
    identifier: String,
    value: Option<String>,
    expires_at: String,
}
#[derive(Deserialize)]
struct Operation {
    operation: String,
    profile: Option<String>,
    email: String,
    #[serde(rename = "type")]
    kind: EmailOtpType,
    otp: Option<String>,
}
fn response(result: AuthResult<Value>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => {
            let auth_response = error.to_auth_response();
            let mut response = auth_response.body.into_response();
            *response.status_mut() =
                axum::http::StatusCode::from_u16(auth_response.status).unwrap();
            for (name, value) in auth_response.headers {
                _ = response.headers_mut().insert(
                    name.parse::<axum::http::HeaderName>().unwrap(),
                    value.parse().unwrap(),
                );
            }
            response
        }
    }
}

pub(super) fn plugin(outbox: Outbox) -> EmailOtpPlugin {
    EmailOtpPlugin::new(EmailOtpConfig {
        generate_otp: Some(Arc::new(Sender(outbox.clone()))),
        send_verification_otp: Some(Arc::new(Sender(outbox))),
        change_email_enabled: true,
        ..Default::default()
    })
}

pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    outbox: Outbox,
    verification_outbox: Arc<Mutex<HashMap<String, EmailOutboxRecord>>>,
    default_auth: Arc<BetterAuth<TestSchema>>,
    default_otp: EmailOtpPlugin,
) -> AuthResult<Router> {
    let mut router = Router::new();
    let mut runtimes = HashMap::new();
    _ = runtimes.insert(
        "default".to_string(),
        Runtime {
            auth: default_auth.clone(),
            otp: default_otp,
        },
    );
    for name in [
        "passwordless-hashed",
        "passwordless-encrypted-reuse",
        "passwordless-proof",
        "passwordless-proof-explicit",
        "passwordless-disabled",
        "verification-cleanup",
        "verification-no-cleanup",
        "passwordless-numeric-length-zero",
        "passwordless-numeric-length-fraction",
        "passwordless-numeric-length-negative",
        "passwordless-numeric-length-nan",
        "passwordless-numeric-length-negative-infinity",
        "passwordless-numeric-attempts-zero",
        "passwordless-numeric-attempts-fraction",
        "passwordless-numeric-attempts-negative",
        "passwordless-numeric-attempts-nan",
        "passwordless-numeric-attempts-infinity",
        "passwordless-numeric-attempts-negative-infinity",
        "passwordless-numeric-lifetime-zero",
        "passwordless-numeric-lifetime-fraction",
        "passwordless-numeric-lifetime-negative",
        "passwordless-numeric-lifetime-nan",
        "passwordless-numeric-lifetime-infinity",
        "passwordless-numeric-lifetime-negative-infinity",
    ] {
        let proof = name.starts_with("passwordless-proof");
        let mut config = config
            .clone()
            .base_path(format!("/__test/profiles/{name}/api/auth"));
        config.verification.disable_cleanup = name == "verification-no-cleanup";
        let otp = EmailOtpPlugin::new(EmailOtpConfig {
            generate_otp: Some(Arc::new(Sender(outbox.clone()))),
            send_verification_otp: Some(Arc::new(Sender(outbox.clone()))),
            change_email_enabled: true,
            storage: match name {
                "passwordless-hashed" => EmailOtpStorage::Hashed,
                "passwordless-encrypted-reuse" => EmailOtpStorage::Encrypted,
                _ => EmailOtpStorage::Plain,
            },
            resend_strategy: if name == "passwordless-encrypted-reuse" {
                OtpResendStrategy::Reuse
            } else {
                OtpResendStrategy::Rotate
            },
            override_default_email_verification: proof,
            verify_current_email: proof,
            disable_sign_up: name == "passwordless-disabled",
            otp_length: numeric_setting(name, "length", 6.0),
            allowed_attempts: numeric_setting(name, "attempts", 3.0),
            expires_in: numeric_setting(name, "lifetime", 300.0),
            ..Default::default()
        });
        let verification = EmailVerificationPlugin::new()
            .send_on_sign_up(false)
            .auto_sign_in_after_verification(proof);
        let verification = if name == "passwordless-proof" {
            verification
        } else {
            verification.custom_send_verification_email(Arc::new(CompatVerificationSender {
                outbox: verification_outbox.clone(),
            }))
        };
        let auth = Arc::new(
            AuthBuilder::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config.clone(),
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(
                    EmailPasswordPlugin::new()
                        .enable_username(false)
                        .password_min_length(8),
                )
                .plugin(PasswordManagementPlugin::new())
                .plugin(verification)
                .plugin(SessionManagementPlugin::new())
                .plugin(otp.clone())
                .build()
                .await?,
        );
        router = router.nest(
            &config.base_path,
            auth.clone().axum_router().with_state(auth.clone()),
        );
        _ = runtimes.insert(name.to_string(), Runtime { auth, otp });
    }
    let runtimes = Arc::new(runtimes);
    let outbox_for_get = outbox.clone();
    let read_database = database.clone();
    let write_database = database.clone();
    let server_runtimes = runtimes.clone();
    router=router.route("/__test/email-otp",get(move |Query(query):Query<CodeQuery>| {
        let outbox=outbox_for_get.clone();async move {Json(outbox.lock().await.get(&format!("{}:{}",query.kind,query.email)).cloned().unwrap_or(Value::Null))}
    })).route("/__test/verification-state",get(move |Query(query):Query<VerificationQuery>| {
        let database=read_database.clone();async move {response(async {
            let rows=verification::Entity::find().filter(verification::Column::Identifier.eq(query.identifier)).order_by_desc(verification::Column::CreatedAt).all(&database).await.map_err(|error|DatabaseError::Query(error.to_string()))?;
            Ok(json!(rows.iter().map(VerificationView::from).collect::<Vec<_>>()))
        }.await)}
    }).post(move |Json(body):Json<VerificationAction>| {
        let database=write_database.clone();let auth=default_auth.clone();async move {response(async {
            let expires_at:DateTime<Utc>=body.expires_at.parse().map_err(|_|AuthError::bad_request("invalid expiresAt"))?;
            if body.action=="seed" {
                let _=auth.store().create_verification(CreateVerification {identifier:body.identifier,value:body.value.ok_or_else(||AuthError::bad_request("value is required"))?,expires_at}).await?;
            } else if body.action=="expire" {
                use alibi_seaorm::sea_orm::sea_query::Expr;
                let _=verification::Entity::update_many().col_expr(verification::Column::ExpiresAt,Expr::value(expires_at)).col_expr(verification::Column::UpdatedAt,Expr::value(Utc::now())).filter(verification::Column::Identifier.eq(body.identifier)).exec(&database).await.map_err(|error|DatabaseError::Query(error.to_string()))?;
            } else {return Err(AuthError::bad_request("unknown verification action"));}
            Ok(json!({"status":true}))
        }.await)}
    })).route("/__test/server-api",post(move |Json(body):Json<Operation>| {
        let runtimes=server_runtimes.clone();async move {response(async {
            let selected=runtimes.get(body.profile.as_deref().unwrap_or("default")).ok_or_else(||AuthError::bad_request("unknown fixture profile"))?;
            match body.operation.as_str() {
                "create-email-otp"=>Ok(json!(selected.otp.create_verification_otp(selected.auth.context(),&body.email,body.kind).await?)),
                "get-email-otp"=>Ok(json!({"otp":selected.otp.get_verification_otp(selected.auth.context(),&body.email,body.kind).await?})),
                "race-email-otp"=> {
                    let mut request=AuthRequest::new(HttpMethod::Post,format!("{}/sign-in/email-otp",selected.auth.config().base_path));
                    request.body=Some(serde_json::to_vec(&json!({"email":body.email,"otp":body.otp.ok_or_else(||AuthError::bad_request("otp is required"))?}))?);
                    _ = request.headers.insert("content-type".into(),"application/json".into());
                    let (left,right)=tokio::join!(selected.auth.handle_request(request.clone()),selected.auth.handle_request(request));
                    let mut results=vec![left,right].into_iter().map(|result| {let response=result.unwrap_or_else(|error|error.to_auth_response());json!({"status":response.status,"body":serde_json::from_slice::<Value>(&response.body).unwrap_or(Value::Null)})}).collect::<Vec<_>>();
                    results.sort_by_key(|value|value["status"].as_u64().unwrap_or_default());
                    Ok(json!({"results":results}))
                },
                _=>Err(AuthError::bad_request("unknown server operation"))
            }
        }.await)}
    }));
    Ok(router)
}
