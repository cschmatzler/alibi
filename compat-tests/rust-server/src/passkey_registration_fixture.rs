//! Application-owned, signed enrollment proof and genuine registration policy callbacks.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{
    EmailPasswordPlugin, PasskeyPlugin, PasskeyRegistrationAfterVerification,
    PasskeyRegistrationConfig, PasskeyRegistrationContext, PasskeyRegistrationOverride,
    PasskeyRegistrationUser, PasskeyUserResolver, SessionManagementPlugin,
    VerifiedPasskeyRegistration,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::{
    utils::{
        cookie_utils::{sign_cookie_value, verify_cookie_value},
        json::JsValue,
    },
    AuthRequest, AuthUser, CreateSession, HttpMethod,
};
use better_auth_seaorm::{
    hooks::{HookControl, SeaOrmHookContext, SeaOrmHooks},
    DatabaseConnection, SeaOrmStore,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Enrollment(Arc<Mutex<Vec<Value>>>);
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Proof {
    user_id: String,
    context: String,
    mode: String,
    exp: i64,
}
fn denied() -> AuthError {
    AuthError::Upstream {
        status: 403,
        code: "ENROLLMENT_DENIED",
        message: "Enrollment proof is invalid",
    }
}
fn read_proof(ctx: &PasskeyRegistrationContext<'_>) -> AuthResult<Proof> {
    let token = ctx
        .request
        .headers
        .get("cookie")
        .and_then(|header| {
            header
                .split(';')
                .map(str::trim)
                .find_map(|part| part.strip_prefix("passkey_enrollment="))
        })
        .ok_or_else(denied)?;
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(denied());
    }
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| denied())?)
            .map_err(|_| denied())?;
    if header != json!({"alg":"HS256","typ":"JWT"}) {
        return Err(denied());
    }
    let signature = STANDARD.encode(URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| denied())?);
    let signed = format!("{}.{}.{}", parts[0], parts[1], signature);
    if verify_cookie_value(&signed, &ctx.auth_config.secret).is_none() {
        return Err(denied());
    }
    let proof: Proof =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| denied())?)
            .map_err(|_| denied())?;
    if proof.user_id.is_empty() || proof.exp <= Utc::now().timestamp() {
        return Err(denied());
    }
    Ok(proof)
}
impl Enrollment {
    fn record(&self, event: Value) {
        self.0.lock().unwrap().push(event);
    }
}
#[async_trait]
impl PasskeyUserResolver for Enrollment {
    async fn resolve_user(
        &self,
        ctx: &PasskeyRegistrationContext<'_>,
        requested: Option<&str>,
    ) -> AuthResult<Option<PasskeyRegistrationUser>> {
        let proof = read_proof(ctx)?;
        if requested != Some(proof.context.as_str()) {
            return Err(denied());
        }
        self.record(json!({"stage":"resolved","context":requested,"userId":proof.user_id}));
        match proof.mode.as_str() {
            "resolver-invalid-id" => {
                return Ok(Some(PasskeyRegistrationUser {
                    id: String::new(),
                    name: "Passkey Applicant".into(),
                    display_name: None,
                }));
            }
            "resolver-invalid-name" => {
                return Ok(Some(PasskeyRegistrationUser {
                    id: format!("pending:{}", proof.user_id),
                    name: String::new(),
                    display_name: None,
                }));
            }
            "resolver-throw" => return Err(AuthError::internal("resolver failed")),
            "resolver-api" => {
                return Err(AuthError::Upstream {
                    status: 403,
                    code: "RESOLVER_DENIED",
                    message: "Resolver denied enrollment",
                });
            }
            _ => {}
        }
        Ok(Some(PasskeyRegistrationUser {
            id: format!("pending:{}", proof.user_id),
            name: "Passkey Applicant".into(),
            display_name: Some("Passkey Applicant".into()),
        }))
    }
}
#[async_trait]
impl PasskeyRegistrationAfterVerification for Enrollment {
    async fn after_verification(
        &self,
        ctx: &PasskeyRegistrationContext<'_>,
        verified: &VerifiedPasskeyRegistration,
        user: &PasskeyRegistrationUser,
        client_data: &JsValue,
        context: Option<&str>,
    ) -> AuthResult<Option<PasskeyRegistrationOverride>> {
        let proof = read_proof(ctx)?;
        if context != Some(proof.context.as_str())
            || (user.id.starts_with("pending:") && user.id != format!("pending:{}", proof.user_id))
        {
            return Err(denied());
        }
        self.record(json!({"stage":"verified","context":context,"user":user,"userId":proof.user_id,"credentialID":verified.credential_id,"publicKey":STANDARD.encode(&verified.public_key),"counter":verified.counter,"aaguid":verified.aaguid,"deviceType":verified.device_type,"backedUp":verified.backed_up,"clientData":client_data}));
        match proof.mode.as_str() {
            "after-dynamic-api" => {
                return Err(AuthError::Api {
                    status: 500,
                    code: Some("APPLICATION_POLICY_DENIED".to_owned()),
                    message: format!(
                        "Application enrollment denied: {}",
                        context.unwrap_or_default()
                    ),
                });
            }
            "after-forbidden" => {
                return Err(AuthError::forbidden(
                    "session creation cancelled by database hook",
                ));
            }
            "after-validation" => {
                return Err(AuthError::Validation("Callback validation rejected".into()));
            }
            "after-throw" => return Err(AuthError::internal("after verification failed")),
            "after-api" => {
                return Err(AuthError::Upstream {
                    status: 403,
                    code: "CALLBACK_DENIED",
                    message: "Callback denied enrollment",
                });
            }
            _ => {}
        }
        Ok(Some(PasskeyRegistrationOverride {
            user_id: Some(if proof.mode == "missing-user" {
                "missing-passkey-owner".into()
            } else {
                proof.user_id
            }),
            name: Some(" \u{FEFF}Callback Label\u{FEFF} ".into()),
        }))
    }
}
struct CancelSession;
#[async_trait]
impl SeaOrmHooks<TestSchema> for CancelSession {
    async fn before_create_session(
        &self,
        _session: &mut CreateSession,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        if ctx
            .request
            .as_ref()
            .and_then(|request| request.headers.get("x-passkey-policy"))
            .is_some_and(|value| value == "session-error")
        {
            return Err(AuthError::forbidden(
                "session creation cancelled by database hook",
            ));
        }
        Ok(
            if ctx
                .request
                .as_ref()
                .and_then(|request| request.headers.get("x-passkey-policy"))
                .is_some_and(|value| value == "session-deny")
            {
                HookControl::Cancel
            } else {
                HookControl::Continue
            },
        )
    }
}
#[derive(Deserialize)]
struct Issue {
    context: String,
    mode: Option<String>,
}
pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let enrollment = Enrollment::default();
    let mut router = Router::new();
    let mut first = None;
    for name in ["passkey-first", "passkey-first-missing"] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let configured = config.clone().base_path(&path);
        let registration = PasskeyRegistrationConfig {
            require_session: false,
            resolve_user: (name == "passkey-first")
                .then(|| Arc::new(enrollment.clone()) as Arc<dyn PasskeyUserResolver>),
            after_verification: (name == "passkey-first").then(|| {
                Arc::new(enrollment.clone()) as Arc<dyn PasskeyRegistrationAfterVerification>
            }),
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(configured.clone())
                .store(
                    SeaOrmStore::<TestSchema>::new(configured, database.clone())
                        .with_hooks(vec![Arc::new(CancelSession)]),
                )
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(PasskeyPlugin::new().registration(registration))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        if name == "passkey-first" {
            first = Some(auth);
        }
    }
    let auth = first.unwrap();
    router=router.route("/__test/passkey-enrollment",post(move |headers:HeaderMap,Json(body):Json<Issue>| {
        let auth=auth.clone(); async move {
            let outcome:AuthResult<_>=async {
                let mut request=AuthRequest::new(HttpMethod::Post,"/__test/passkey-enrollment");
                for (name,value) in &headers {if let Ok(value)=value.to_str() {request.headers.insert(name.as_str().to_owned(),value.to_owned());}}
                let (user,_)=auth.context().require_session(&request).await?;
                if body.context.is_empty() {return Err(AuthError::bad_request("Invalid enrollment context"));}
                let now=Utc::now().timestamp(); let mode=body.mode.as_deref().unwrap_or("normal");
                let header=URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
                let payload=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"userId":user.id(),"context":body.context,"mode":mode,"iat":now,"exp":if mode=="expired"{now-1}else{now+300}}))?);
                let encoded=sign_cookie_value(&format!("{header}.{payload}"),&auth.config().secret);
                let decoded=url::form_urlencoded::parse(format!("value={encoded}").as_bytes()).next().unwrap().1.into_owned();
                let (prefix,signature)=decoded.rsplit_once('.').unwrap();
                let token=format!("{prefix}.{}",URL_SAFE_NO_PAD.encode(STANDARD.decode(signature).unwrap()));
                Ok((token,user.id().into_owned()))
            }.await;
            match outcome {
                Ok((token,user_id))=>([("set-cookie",format!("passkey_enrollment={token}; Max-Age=300; Path=/; HttpOnly; SameSite=Lax"))],Json(json!({"token":token,"userId":user_id}))).into_response(),
                Err(_)=>(StatusCode::UNAUTHORIZED,Json(json!({"code":"UNAUTHORIZED","message":"Unauthorized"}))).into_response()
            }
        }
    })).route("/__test/passkey-registration-events",get(move ||{let enrollment=enrollment.clone();async move {Json(json!({"events":std::mem::take(&mut *enrollment.0.lock().unwrap())}))}}));
    Ok(router)
}
