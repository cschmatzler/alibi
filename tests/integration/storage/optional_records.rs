//! Optional native records through real handlers: SQLx, SeaORM and no database.
use super::postgres_tests;
use super::{Backend, Db, TestResult, backend_tests};
use alibi::plugins::{EmailPasswordPlugin, PasskeyPlugin, TwoFactorConfig, TwoFactorPlugin};
use alibi::types::UpdatePasskeyAuthentication;
use alibi::{AuthBuilder, AuthConfig, AuthSchema, BetterAuth};
use alibi::{
    AuthRequest, AuthResponse, CreatePasskey, CreateTwoFactor, HttpMethod, UpdateTwoFactor,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::sync::Arc;

const SECRET: &str = "optional-record-172-secret-at-least-32-characters";
const ORIGIN: &str = "http://localhost:43173";
backend_tests!(optional_record_workflow);
postgres_tests!(optional_record_workflow);

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
        Some(&db),
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
    workflow(&auth, None, "without-database").await?;
    // Retain live records before constructing a fresh instance. A restart must
    // lose actual provisioned state, rather than merely miss an arbitrary ID.
    let owner = auth
        .store()
        .get_user_by_email("optional172@fixture.test")
        .await?
        .unwrap();
    let factor = auth
        .store()
        .create_two_factor(CreateTwoFactor {
            user_id: owner.id.clone(),
            secret: "retained-secret".into(),
            backup_codes: "retained-backup".into(),
            failed_verification_count: None,
            ..Default::default()
        })
        .await?;
    let sibling = auth
        .store()
        .create_two_factor(CreateTwoFactor {
            user_id: owner.id.clone(),
            secret: "sibling-secret".into(),
            backup_codes: "sibling-backup".into(),
            ..Default::default()
        })
        .await?;
    assert_eq!(
        auth.store()
            .increment_two_factor_failure(&factor.id)
            .await?
            .unwrap()
            .failed_verification_count,
        Some(1.0)
    );
    let now = Utc::now();
    let until = now + Duration::minutes(1);
    assert!(
        auth.store()
            .set_two_factor_lock_if_count_at_least(&factor.id, 1.5, until)
            .await?
            .is_none()
    );
    assert!(
        auth.store()
            .set_two_factor_lock_if_count_at_least(&factor.id, 1.0, until)
            .await?
            .is_some()
    );
    assert!(
        auth.store()
            .clear_expired_two_factor_lock(&factor.id, now)
            .await?
            .is_none()
    );
    let cleared = auth
        .store()
        .clear_expired_two_factor_lock(&factor.id, until)
        .await?
        .unwrap();
    assert_eq!(cleared.failed_verification_count, Some(0.0));
    assert_eq!(cleared.locked_until, None);
    let rotated = auth
        .store()
        .update_two_factor(
            &factor.id,
            UpdateTwoFactor {
                secret: Some("rotated-secret".into()),
                ..Default::default()
            },
        )
        .await?
        .unwrap();
    assert_eq!(rotated.created_at, factor.created_at);
    assert_eq!(rotated.updated_at, factor.updated_at);
    let mut claims = tokio::task::JoinSet::new();
    for index in 0..4 {
        let store = Arc::clone(auth.store());
        let id = factor.id.clone();
        drop(claims.spawn(async move {
            store
                .compare_and_swap_two_factor_backup_codes(
                    &id,
                    "retained-backup",
                    &format!("claimed-{index}"),
                )
                .await
        }));
    }
    let mut winners = 0;
    while let Some(claim) = claims.join_next().await {
        if claim?? {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
    auth.store().reset_two_factor_failures(&factor.id).await?;
    assert_eq!(
        auth.store()
            .update_two_factor(&sibling.id, UpdateTwoFactor::default())
            .await?
            .unwrap()
            .backup_codes,
        "sibling-backup"
    );
    let key = auth
        .store()
        .create_passkey(passkey_input(&owner.id))
        .await?;
    assert_eq!(
        auth.store()
            .get_passkey_by_credential_id(&key.credential_id)
            .await?
            .unwrap()
            .id,
        key.id
    );
    let update = || UpdatePasskeyAuthentication {
        credential: "verified-private-credential".into(),
        counter: 7,
        backed_up: true,
        device_type: "multiDevice".into(),
    };
    let authenticated = auth
        .store()
        .update_passkey_authentication(&key.id, update())
        .await?
        .unwrap();
    assert_eq!(authenticated.counter, 7);
    assert!(authenticated.backed_up);
    assert_eq!(authenticated.credential, "verified-private-credential");
    assert_eq!(authenticated.created_at, key.created_at);
    let restarted = plugins(AuthBuilder::without_database(config))
        .build()
        .await?;
    assert!(
        restarted
            .store()
            .get_two_factor_by_user_id(&owner.id)
            .await?
            .is_none()
    );
    assert!(
        restarted
            .store()
            .get_passkey_by_credential_id(&key.credential_id)
            .await?
            .is_none()
    );
    assert!(
        restarted
            .store()
            .list_passkeys_by_user(&owner.id)
            .await?
            .is_empty()
    );
    auth.store().delete_two_factor(&owner.id).await?;
    assert!(
        auth.store()
            .update_two_factor(&factor.id, UpdateTwoFactor::default())
            .await?
            .is_none()
    );
    assert!(
        auth.store()
            .increment_two_factor_failure(&factor.id)
            .await?
            .is_none()
    );
    assert!(
        !auth
            .store()
            .compare_and_swap_two_factor_backup_codes(&factor.id, "retained-backup", "resurrected")
            .await?
    );
    auth.store().delete_passkey(&key.id).await?;
    assert!(
        auth.store()
            .update_passkey_authentication(&key.id, update())
            .await?
            .is_none()
    );
    assert!(auth.store().get_passkey_by_id(&key.id).await?.is_none());
    Ok(())
}
async fn workflow<S: AuthSchema>(
    auth: &BetterAuth<S>,
    physical: Option<&Db>,
    owner: &str,
) -> TestResult {
    let mut trace = Vec::new();
    let signup = Box::pin(auth.handle_request(request(
        "/sign-up/email",
        Some(
            json!({"name":"Owner", "email":"optional172@fixture.test", "password":"Password123!"}),
        ),
        "",
    )))
    .await?;
    observe(&mut trace, "/sign-up/email", &signup);
    assert_eq!(signup.status, 200, "{}", body(&signup));
    let user_id = body(&signup)["user"]["id"].as_str().unwrap().to_owned();
    let cookie = cookies(&signup);
    let other = Box::pin(auth.handle_request(request(
        "/sign-up/email",
        Some(json!({"name":"Other", "email":"other172@fixture.test", "password":"Password456!"})),
        "",
    )))
    .await?;
    observe(&mut trace, "/sign-up/email", &other);
    assert_eq!(other.status, 200);
    let other_cookie = cookies(&other);
    let enable = Box::pin(auth.handle_request(request(
        "/two-factor/enable",
        Some(json!({"password":"Password123!"})),
        &cookie,
    )))
    .await?;
    observe(&mut trace, "/two-factor/enable", &enable);
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
    let verify = Box::pin(auth.handle_request(request(
        "/two-factor/verify-backup-code",
        Some(json!({"code":code})),
        &enabled_cookie,
    )))
    .await?;
    assert_eq!(verify.status, 200, "{}", body(&verify));
    observe(&mut trace, "/two-factor/verify-backup-code", &verify);
    assert_ne!(
        auth.store()
            .get_two_factor_by_user_id(&user_id)
            .await?
            .unwrap()
            .backup_codes,
        factor.backup_codes
    );
    let replay = Box::pin(auth.handle_request(request(
        "/two-factor/verify-backup-code",
        Some(json!({"code":code})),
        &enabled_cookie,
    )))
    .await?;
    observe(&mut trace, "/two-factor/verify-backup-code", &replay);
    assert_eq!(replay.status, 401, "{}", body(&replay));
    let mut input = passkey_input(&user_id);
    if physical.is_some() {
        input.name = None;
        input.transports = None;
    }
    let expected_name = input.name.clone();
    let passkey = auth.store().create_passkey(input).await?;
    let before_list = if let Some(db) = physical {
        let rows: Value = serde_json::from_str(&db.raw.table("passkeys").await?)?;
        assert_eq!(rows.as_array().unwrap().len(), 1);
        let row = &rows[0];
        assert_eq!(row.get("name"), Some(&Value::Null));
        assert_eq!(row.get("transports"), Some(&Value::Null));
        Some(rows)
    } else {
        None
    };
    let list = Box::pin(auth.handle_request(request(
        "/passkey/list-user-passkeys",
        None,
        &enabled_cookie,
    )))
    .await?;
    observe(&mut trace, "/passkey/list-user-passkeys", &list);
    assert_eq!(list.status, 200, "{}", body(&list));
    assert_eq!(body(&list)[0]["id"], passkey.id);
    if let Some(db) = physical {
        let payload = body(&list);
        assert_eq!(payload.as_array().unwrap().len(), 1);
        let row = &payload[0];
        assert_eq!(row.get("name"), Some(&Value::Null));
        assert_eq!(row.get("transports"), Some(&Value::Null));
        assert!(!row.as_object().unwrap().contains_key("updatedAt"));
        let after_list: Value = serde_json::from_str(&db.raw.table("passkeys").await?)?;
        assert_eq!(
            Some(after_list),
            before_list,
            "listing must not write the row"
        );
    }
    assert!(!String::from_utf8_lossy(&list.body).contains("private-credential"));
    for path in ["/passkey/update-passkey", "/passkey/delete-passkey"] {
        let denied = Box::pin(auth.handle_request(request(
            path,
            Some(json!({"id":passkey.id,"name":"Stolen"})),
            &other_cookie,
        )))
        .await?;
        observe(&mut trace, path, &denied);
        assert_eq!(denied.status, 401);
    }
    assert_eq!(
        auth.store()
            .get_passkey_by_id(&passkey.id)
            .await?
            .unwrap()
            .name
            .as_deref(),
        expected_name.as_deref()
    );
    let rename = Box::pin(auth.handle_request(request(
        "/passkey/update-passkey",
        Some(json!({"id":passkey.id,"name":"Renamed"})),
        &enabled_cookie,
    )))
    .await?;
    observe(&mut trace, "/passkey/update-passkey", &rename);
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
    let remove = Box::pin(auth.handle_request(request(
        "/passkey/delete-passkey",
        Some(json!({"id":passkey.id})),
        &enabled_cookie,
    )))
    .await?;
    observe(&mut trace, "/passkey/delete-passkey", &remove);
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
    let disable = Box::pin(auth.handle_request(disable_request)).await?;
    observe(&mut trace, "/two-factor/disable", &disable);
    assert_eq!(disable.status, 200, "{}", body(&disable));
    assert!(
        auth.store()
            .get_two_factor_by_user_id(&user_id)
            .await?
            .is_none()
    );
    if let Ok(directory) = std::env::var("PLUGIN_172_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&directory).join(format!("{owner}-workflow.json")),
            serde_json::to_vec_pretty(&trace)?,
        )?;
    }
    Ok(())
}

fn passkey_input(user_id: &str) -> CreatePasskey {
    CreatePasskey {
        user_id: user_id.to_owned(),
        name: Some("Original".into()),
        credential_id: "Y3JlZGVudGlhbDE3Mg".into(),
        public_key: "fixture-public-key".into(),
        counter: 1,
        device_type: "singleDevice".into(),
        backed_up: false,
        transports: Some("internal".into()),
        credential: "private-credential".into(),
        aaguid: None,
    }
}

fn observe(trace: &mut Vec<Value>, path: &str, response: &AuthResponse) {
    trace.push(json!({
        "path": path, "status": response.status,
        "body": String::from_utf8_lossy(&response.body),
        "cookies": response.headers.get_all("set-cookie").collect::<Vec<_>>(),
    }));
}
