//! Optional native records through real handlers: SQLx, SeaORM and no database.
use super::{Backend, Db, TestResult, backend_tests};
use better_auth::plugins::{EmailPasswordPlugin, PasskeyPlugin, TwoFactorConfig, TwoFactorPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthSchema, BetterAuth};
use better_auth_core::{AuthRequest, AuthResponse, CreatePasskey, HttpMethod};
use serde_json::{Value, json};
use std::sync::Arc;

const SECRET: &str = "optional-record-172-secret-at-least-32-characters";
const ORIGIN: &str = "http://localhost:43173";
backend_tests!(optional_record_workflow);

fn request(path: &str, body: Option<Value>, cookie: &str) -> AuthRequest {
    let mut req = AuthRequest::new(
        if body.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        path,
    );
    drop(req.headers.insert("origin".into(), ORIGIN.into()));
    drop(
        req.headers
            .insert("content-type".into(), "application/json".into()),
    );
    drop(req.headers.insert("cookie".into(), cookie.into()));
    req.body = body.map(|body| serde_json::to_vec(&body).unwrap());
    req
}
fn body(response: &AuthResponse) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}
fn cookies(response: &AuthResponse) -> String {
    response
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}
fn plugins<S: AuthSchema>(builder: AuthBuilder<S>) -> AuthBuilder<S> {
    builder
        .plugin(EmailPasswordPlugin::new())
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            skip_verification_on_enable: true,
            ..Default::default()
        }))
        .plugin(PasskeyPlugin::new())
}
async fn optional_record_workflow<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session = config.session.stateless();
    let auth =
        plugins(AuthBuilder::new(config.clone()).store(B::store(Arc::new(config), &connection)))
            .build()
            .await?;
    workflow(
        &auth,
        std::any::type_name::<B>().rsplit("::").next().unwrap(),
    )
    .await?;
    assert_eq!(db.count("sessions").await?, 0);
    assert_eq!(db.count("two_factor").await?, 0);
    assert_eq!(db.count("passkeys").await?, 0);
    B::close(connection).await
}
#[tokio::test]
async fn without_database_optional_record_workflow() -> TestResult {
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = plugins(AuthBuilder::without_database(config.clone()))
        .build()
        .await?;
    workflow(&auth, "without-database").await?;
    let restarted = plugins(AuthBuilder::without_database(config))
        .build()
        .await?;
    assert!(
        restarted
            .store()
            .get_two_factor_by_user_id("missing")
            .await?
            .is_none()
    );
    assert!(
        restarted
            .store()
            .list_passkeys_by_user("missing")
            .await?
            .is_empty()
    );
    Ok(())
}
async fn workflow<S: AuthSchema>(auth: &BetterAuth<S>, owner: &str) -> TestResult {
    let mut trace = Vec::new();
    let signup = auth.handle_request(request("/sign-up/email", Some(json!({"name":"Owner", "email":"optional172@fixture.test", "password":"Password123!"})), "")).await?;
    assert_eq!(signup.status, 200, "{}", body(&signup));
    let user_id = body(&signup)["user"]["id"].as_str().unwrap().to_owned();
    let cookie = cookies(&signup);
    let other = auth
        .handle_request(request(
            "/sign-up/email",
            Some(
                json!({"name":"Other", "email":"other172@fixture.test", "password":"Password456!"}),
            ),
            "",
        ))
        .await?;
    assert_eq!(other.status, 200);
    let other_cookie = cookies(&other);
    let enable = auth
        .handle_request(request(
            "/two-factor/enable",
            Some(json!({"password":"Password123!"})),
            &cookie,
        ))
        .await?;
    trace.push(json!({"path":"/two-factor/enable", "status":enable.status, "body":String::from_utf8_lossy(&enable.body), "cookies":enable.headers.get_all("set-cookie").collect::<Vec<_>>() }));
    if let Ok(directory) = std::env::var("PLUGIN_172_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&directory).join(format!("{owner}-workflow.json")),
            serde_json::to_vec_pretty(&trace)?,
        )?;
    }
    assert_eq!(enable.status, 200, "{}", body(&enable));
    let enabled_cookie = cookies(&enable);
    let factor = auth
        .store()
        .get_two_factor_by_user_id(&user_id)
        .await?
        .unwrap();
    assert_eq!(factor.user_id, user_id);
    assert_eq!(factor.verified, Some(true));
    assert!(!factor.secret.contains("otpauth"));
    let code = body(&enable)["backupCodes"][0].as_str().unwrap().to_owned();
    assert!(
        !factor.backup_codes.contains(&code),
        "default storage must encrypt backup codes"
    );
    let verify = auth
        .handle_request(request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":code})),
            &enabled_cookie,
        ))
        .await?;
    assert_eq!(verify.status, 200, "{}", body(&verify));
    trace.push(json!({"path":"/two-factor/verify-backup-code", "status":verify.status, "body":String::from_utf8_lossy(&verify.body)}));
    assert_ne!(
        auth.store()
            .get_two_factor_by_user_id(&user_id)
            .await?
            .unwrap()
            .backup_codes,
        factor.backup_codes
    );
    let replay = auth
        .handle_request(request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":code})),
            &enabled_cookie,
        ))
        .await?;
    assert_eq!(replay.status, 401, "{}", body(&replay));
    let passkey = auth
        .store()
        .create_passkey(CreatePasskey {
            user_id: user_id.clone(),
            name: Some("Original".into()),
            credential_id: "Y3JlZGVudGlhbDE3Mg".into(),
            public_key: "fixture-public-key".into(),
            counter: 1,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: Some("internal".into()),
            credential: "private-credential".into(),
            aaguid: None,
        })
        .await?;
    let list = auth
        .handle_request(request(
            "/passkey/list-user-passkeys",
            None,
            &enabled_cookie,
        ))
        .await?;
    assert_eq!(list.status, 200, "{}", body(&list));
    assert_eq!(body(&list)[0]["id"], passkey.id);
    assert!(!String::from_utf8_lossy(&list.body).contains("private-credential"));
    for path in ["/passkey/update-passkey", "/passkey/delete-passkey"] {
        let denied = auth
            .handle_request(request(
                path,
                Some(json!({"id":passkey.id,"name":"Stolen"})),
                &other_cookie,
            ))
            .await?;
        assert_eq!(denied.status, 401);
    }
    assert_eq!(
        auth.store()
            .get_passkey_by_id(&passkey.id)
            .await?
            .unwrap()
            .name
            .as_deref(),
        Some("Original")
    );
    let rename = auth
        .handle_request(request(
            "/passkey/update-passkey",
            Some(json!({"id":passkey.id,"name":"Renamed"})),
            &enabled_cookie,
        ))
        .await?;
    assert_eq!(rename.status, 200, "{}", body(&rename));
    assert_eq!(
        auth.store()
            .get_passkey_by_id(&passkey.id)
            .await?
            .unwrap()
            .name
            .as_deref(),
        Some("Renamed")
    );
    let remove = auth
        .handle_request(request(
            "/passkey/delete-passkey",
            Some(json!({"id":passkey.id})),
            &enabled_cookie,
        ))
        .await?;
    assert_eq!(remove.status, 200);
    assert!(auth.store().get_passkey_by_id(&passkey.id).await?.is_none());
    let mut disable_request = request(
        "/two-factor/disable",
        Some(json!({"password":"Password123!"})),
        &enabled_cookie,
    );
    drop(
        disable_request
            .query
            .insert("disableCookieCache".into(), "true".into()),
    );
    let disable = auth.handle_request(disable_request).await?;
    assert_eq!(disable.status, 200, "{}", body(&disable));
    assert!(
        auth.store()
            .get_two_factor_by_user_id(&user_id)
            .await?
            .is_none()
    );
    trace.push(json!({"path":"/passkey/list-user-passkeys", "status":list.status, "body":String::from_utf8_lossy(&list.body)}));
    trace.push(json!({"path":"/two-factor/disable", "status":disable.status, "body":String::from_utf8_lossy(&disable.body)}));
    if let Ok(directory) = std::env::var("PLUGIN_172_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&directory).join(format!("{owner}-workflow.json")),
            serde_json::to_vec_pretty(&trace)?,
        )?;
    }
    Ok(())
}
