//! A provider's `getAccountFields` values reach the provider account on every
//! write path: callback sign-up, implicit link, returning sign-in, explicit
//! link, and ID-token sign-in and linking. Upstream: api/routes/account.test.ts
//! ("provider getAccountFields", #12734).
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified wire fields and fixtures"
)]
#![allow(
    unreachable_pub,
    reason = "the test account models expose associated types for the adapter derives"
)]
use super::social_flows::{Social, authorize, callback};
use super::*;
use alibi::field_policy::FieldConfig;
use alibi::plugins::oauth::{
    OAuthAccountFieldsResolver, OAuthTokenSet, OAuthUserInfo,
};
use alibi::plugins::{AccountManagementPlugin, OAuthPlugin};
use alibi::store::AuthStore;
use alibi::utils::json::{JsObject, JsValue};
use alibi::{AccountConfig, AuthError, AuthResult};

backend_tests!(
    provider_account_fields_reach_every_account_write,
    provider_account_fields_are_validated_and_reject_the_callback
);
postgres_tests!(
    provider_account_fields_reach_every_account_write,
    provider_account_fields_are_validated_and_reject_the_callback
);

macro_rules! account_model {
    ($(#[$model:meta])*; $(#[$id:meta])*; $adapter:ident, $rename:ident) => {
        $(#[$model])*
        pub struct Model {
            $(#[$id])*
            pub id: String,
            #[$adapter($rename = "accountId")]
            pub account_id: String,
            #[$adapter($rename = "providerId")]
            pub provider_id: String,
            #[$adapter($rename = "userId")]
            pub user_id: String,
            #[$adapter($rename = "accessToken")]
            pub access_token: Option<String>,
            #[$adapter($rename = "refreshToken")]
            pub refresh_token: Option<String>,
            #[$adapter($rename = "idToken")]
            pub id_token: Option<String>,
            #[$adapter($rename = "accessTokenExpiresAt")]
            pub access_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
            #[$adapter($rename = "refreshTokenExpiresAt")]
            pub refresh_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
            pub scope: Option<String>,
            pub password: Option<String>,
            #[$adapter($rename = "createdAt")]
            pub created_at: chrono::DateTime<chrono::Utc>,
            #[$adapter($rename = "updatedAt")]
            pub updated_at: chrono::DateTime<chrono::Utc>,
            pub label: Option<String>,
        }
    };
}

mod sqlx_model {
    account_model! {
        #[derive(alibi::sqlx::AuthEntity, Clone, Debug, serde::Serialize, sqlx::FromRow)]
        #[auth(role = "account", table = "account")];
        ; sqlx, rename
    }
}

mod seaorm_model {
    use alibi::seaorm::sea_orm::{self, entity::prelude::*};
    account_model! {
        #[derive(alibi::seaorm::AuthEntity, Clone, Debug, serde::Serialize, DeriveEntityModel)]
        #[auth(role = "account")]
        #[sea_orm(table_name = "account")];
        #[sea_orm(primary_key, auto_increment = false)]; sea_orm, column_name
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

struct AccountFieldsSchema<B, A>(std::marker::PhantomData<(B, A)>);

impl<B: Backend, A: alibi::AuthAccount> AuthSchema for AccountFieldsSchema<B, A> {
    type User = <B::Schema as AuthSchema>::User;
    type Session = <B::Schema as AuthSchema>::Session;
    type Account = A;
    type Verification = <B::Schema as AuthSchema>::Verification;
}

trait AccountFieldsBackend: Backend {
    type Account: alibi::AuthAccount;

    fn account_field_store(
        config: Arc<AuthConfig>,
        connection: &Self::Connection,
    ) -> impl AuthStore<AccountFieldsSchema<Self, Self::Account>> + 'static;
}

impl AccountFieldsBackend for super::super::Sqlx {
    type Account = sqlx_model::Model;

    fn account_field_store(
        config: Arc<AuthConfig>,
        connection: &Self::Connection,
    ) -> impl AuthStore<AccountFieldsSchema<Self, Self::Account>> + 'static {
        alibi::sqlx::SqlxStore::new(config, connection.clone())
    }
}

impl AccountFieldsBackend for super::super::SeaOrm {
    type Account = seaorm_model::Model;

    fn account_field_store(
        config: Arc<AuthConfig>,
        connection: &Self::Connection,
    ) -> impl AuthStore<AccountFieldsSchema<Self, Self::Account>> + 'static {
        alibi::seaorm::SeaOrmStore::new(config, connection.clone())
    }
}

async fn auth<B: AccountFieldsBackend>(
    connection: &B::Connection,
    config: AuthConfig,
    social: &Social,
    hook: &Arc<Hook>,
) -> TestResult<Alibi<AccountFieldsSchema<B, B::Account>>> {
    let provider = social.google(|_| {}).with_account_fields(hook.clone());
    Ok(AuthBuilder::new(config.clone())
        .store(B::account_field_store(Arc::new(config), connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .plugin(OAuthPlugin::new().add_provider("google", provider))
        .build()
        .await?)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reply {
    Value,
    Nothing,
    Fails,
}

/// Returns `value` for the declared field, alongside keys the hook must not write.
struct Hook {
    value: Mutex<String>,
    reply: Mutex<Reply>,
    calls: Mutex<Vec<(OAuthTokenSet, OAuthUserInfo)>>,
}

impl Hook {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            value: Mutex::new("Initial-Value".into()),
            reply: Mutex::new(Reply::Value),
            calls: Mutex::default(),
        })
    }
    fn set(&self, value: &str) {
        value.clone_into(&mut self.value.lock().unwrap());
    }
}

#[async_trait::async_trait]
impl OAuthAccountFieldsResolver for Hook {
    async fn account_fields(
        &self,
        tokens: &OAuthTokenSet,
        user: &OAuthUserInfo,
    ) -> AuthResult<Option<JsObject>> {
        self.calls
            .lock()
            .unwrap()
            .push((tokens.clone(), user.clone()));
        match *self.reply.lock().unwrap() {
            Reply::Nothing => return Ok(None),
            Reply::Fails => return Err(AuthError::internal("lookup failed")),
            Reply::Value => {}
        }
        let mut fields: JsObject = [
            ("id", "attacker-id"),
            ("userId", "attacker-user"),
            ("providerId", "attacker-provider"),
            ("accountId", "attacker-account"),
            ("accessToken", "attacker-access-token"),
            ("idToken", "attacker-id-token"),
            ("scope", "attacker-scope"),
            ("alternateToken", "attacker-aliased-token"),
            ("readOnlyField", "attacker-read-only-value"),
            ("notDeclared", "ignored"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), JsValue::String(value.into())))
        .collect();
        _ = fields.insert(
            "providerField".into(),
            JsValue::String(self.value.lock().unwrap().as_str().into()),
        );
        _ = fields.insert("undefinedField".into(), JsValue::Undefined);
        Ok(Some(fields))
    }
}

fn config(field: FieldConfig, update_account_on_sign_in: bool) -> AuthConfig {
    let mut account = AccountConfig::default();
    account.account_linking.allow_different_emails = true;
    account.update_account_on_sign_in = update_account_on_sign_in;
    account.store_account_cookie = true;
    let text = || FieldConfig::new(json!({"type":"string"}));
    account.additional_fields.extend([
        ("providerField".into(), field.field_name("label")),
        ("alternateToken".into(), text().field_name("accessToken")),
        ("readOnlyField".into(), text().read_only().field_name("label")),
        ("undefinedField".into(), text().field_name("label")),
    ]);
    AuthConfig::new(SECRET).base_url(ORIGIN).account(account)
}

/// The input transform must run exactly once, at the store.
fn prefixed() -> FieldConfig {
    FieldConfig::new(json!({"type":"string"})).transform(|value| {
        Ok(value.map(|value| {
            JsValue::String(format!("prefix:{}", value.as_str().unwrap_or_default()).into())
        }))
    })
}

/// The stored `providerField` and access token of a Google account.
async fn stored(db: &Db, account_id: &str) -> TestResult<(Option<String>, Option<String>)> {
    let column = |name: &str| {
        format!(
            "SELECT \"{name}\" FROM \"account\" WHERE \"providerId\" = 'google' AND \"accountId\" = $1"
        )
    };
    Ok((
        db.text(&column("label"), &[account_id]).await?,
        db.text(&column("accessToken"), &[account_id]).await?,
    ))
}

async fn google_accounts(db: &Db) -> TestResult<i64> {
    db.count_where(
        "SELECT COUNT(*) FROM \"account\" WHERE \"providerId\" = 'google'",
        &[],
    )
    .await
}

async fn sign_in<S: AuthSchema>(auth: &Alibi<S>) -> AuthResponse {
    let (state, cookies) = authorize(
        auth,
        "/sign-in/social",
        json!({"provider": "google", "callbackURL": "/home", "errorCallbackURL": "/failed"}),
        "",
    )
    .await;
    callback(auth, &[("code", "grant"), ("state", &state)], &cookies).await
}

async fn id_token<S: AuthSchema>(auth: &Alibi<S>, path: &str, cookie: &str) -> AuthResponse {
    call(
        auth,
        request(
            path,
            Some(json!({
                "provider": "google",
                "callbackURL": "/home",
                "idToken": {"token": "client-id-token", "accessToken": "client-access-token"},
            })),
            cookie,
        ),
        200,
    )
    .await
}

fn location(response: &AuthResponse) -> String {
    response.headers["location"].clone()
}

fn account_cookie(response: &AuthResponse) -> TestResult<Value> {
    let token = response
        .headers
        .get_all("set-cookie")
        .find_map(|header| header.strip_prefix("better-auth.account_data="))
        .and_then(|cookie| cookie.split(';').next())
        .ok_or("missing account data cookie")?;
    Ok(alibi::utils::jwe::decode(SECRET, "better-auth-account", token)?)
}

fn redirect_query(response: &AuthResponse) -> std::collections::HashMap<String, String> {
    url::Url::parse(ORIGIN)
        .unwrap()
        .join(&location(response))
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

async fn provider_account_fields_reach_every_account_write<B: AccountFieldsBackend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    _ = db.execute("ALTER TABLE \"account\" ADD COLUMN label TEXT", &[]).await?;
    let social = Social::start().await;
    let hook = Hook::new();
    let auth = auth::<B>(&connection, config(prefixed(), true), &social, &hook).await?;
    let expect = async |account: &str, value: &str, access: &str| -> TestResult {
        assert_eq!(
            stored(&db, account).await?,
            (Some(format!("prefix:{value}")), Some(access.to_owned())),
            "{account}"
        );
        Ok(())
    };

    // A new user signs up through the callback.
    social.profile.set("sign-up-sub", "sign-up@example.com", true);
    let response = sign_in(&auth).await;
    assert!(location(&response).ends_with("/home"), "{response:?}");
    expect("sign-up-sub", "Initial-Value", "provider-access").await?;
    {
        let calls = hook.calls.lock().unwrap();
        let (tokens, user) = calls.last().unwrap();
        assert_eq!(tokens.access_token.as_deref(), Some("provider-access"));
        assert_eq!(tokens.refresh_token.as_deref(), Some("provider-refresh"));
        assert_eq!(user.email, "sign-up@example.com");
        assert!(user.email_verified);
    }

    // The same user signs in again; the stored value follows the hook.
    hook.set("Second-Value");
    let returning = sign_in(&auth).await;
    expect("sign-up-sub", "Second-Value", "provider-access").await?;
    assert_eq!(account_cookie(&returning)?["providerField"], "Second-Value");

    // Returning `None` stores nothing and keeps the stored value.
    *hook.reply.lock().unwrap() = Reply::Nothing;
    _ = sign_in(&auth).await;
    expect("sign-up-sub", "Second-Value", "provider-access").await?;
    *hook.reply.lock().unwrap() = Reply::Value;

    // Sign-in links the provider to an existing verified user.
    let owner = cookies(&signup(&auth, "owner@example.com").await);
    let owner_id = body(&call(&auth, request("/get-session", None, &owner), 200).await)["user"]
        ["id"]
        .as_str()
        .unwrap()
        .to_owned();
    _ = auth
        .store()
        .update_user(
            &owner_id,
            alibi::UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            },
        )
        .await?;
    hook.set("Implicit-Link");
    social.profile.set("implicit-sub", "owner@example.com", true);
    _ = sign_in(&auth).await;
    expect("implicit-sub", "Implicit-Link", "provider-access").await?;

    // An explicit link creates a new account, and linking it again updates it.
    social.profile.set("linked-sub", "linked@example.com", true);
    for value in ["Explicit-Link", "Relinked"] {
        hook.set(value);
        let (state, cookies) = authorize(
            &auth,
            "/link-social",
            json!({"provider": "google", "callbackURL": "/settings"}),
            &owner,
        )
        .await;
        let response = callback(&auth, &[("code", "grant"), ("state", &state)], &cookies).await;
        assert!(location(&response).ends_with("/settings"), "{response:?}");
        expect("linked-sub", value, "provider-access").await?;
    }

    // ID-token sign-in passes the tokens the client sent.
    social
        .profile
        .set("id-token-sub", "id-token@example.com", true);
    for value in ["Id-Token", "Id-Token-Again"] {
        hook.set(value);
        let response = id_token(&auth, "/sign-in/social", "").await;
        assert!(account_cookie(&response)?.get("providerField").is_some());
        expect("id-token-sub", value, "client-access-token").await?;
    }
    {
        let calls = hook.calls.lock().unwrap();
        let (tokens, _) = calls.last().unwrap();
        assert_eq!(tokens.id_token.as_deref(), Some("client-id-token"));
        assert_eq!(tokens.access_token.as_deref(), Some("client-access-token"));
    }

    // Linking with an ID token creates the account, and linking it again updates it.
    social.profile.set("id-link-sub", "id-link@example.com", true);
    for value in ["Id-Link", "Id-Relinked"] {
        hook.set(value);
        let response = id_token(&auth, "/link-social", &owner).await;
        assert_eq!(body(&response)["status"], true);
        expect("id-link-sub", value, "client-access-token").await?;
    }
    assert_eq!(google_accounts(&db).await?, 5);
    // The hook can never replace Alibi's own account columns.
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"account\" WHERE \"id\" = 'attacker-id' OR \"userId\" = 'attacker-user' OR \"scope\" = 'attacker-scope' OR \"idToken\" = 'attacker-id-token'",
            &[],
        )
        .await?,
        0
    );

    // With account updates on sign-in off, the hook runs but writes nothing.
    let frozen = self::auth::<B>(&connection, config(prefixed(), false), &social, &hook).await?;
    let calls = hook.calls.lock().unwrap().len();
    hook.set("Frozen");
    social.profile.set("sign-up-sub", "sign-up@example.com", true);
    _ = sign_in(&frozen).await;
    assert_eq!(hook.calls.lock().unwrap().len(), calls + 1);
    expect("sign-up-sub", "Second-Value", "provider-access").await?;
    B::close(connection).await
}

async fn provider_account_fields_are_validated_and_reject_the_callback<B: AccountFieldsBackend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    _ = db.execute("ALTER TABLE \"account\" ADD COLUMN label TEXT", &[]).await?;
    let social = Social::start().await;
    let hook = Hook::new();
    let checked = FieldConfig::new(json!({"type":"string"}))
        .validate(|value| {
            if value.as_str().is_some_and(|value| value.contains('@')) {
                Ok(value.clone())
            } else {
                Err("Invalid email address".into())
            }
        })
        .transform(|value| {
            Ok(value.map(|value| {
                JsValue::String(value.as_str().unwrap_or_default().to_lowercase().into())
            }))
        });
    let auth = auth::<B>(&connection, config(checked, true), &social, &hook).await?;
    social.profile.set("checked-sub", "checked@example.com", true);

    hook.set("not-an-email");
    let query = redirect_query(&sign_in(&auth).await);
    assert_eq!(query["error"], "VALIDATION_ERROR");
    assert_eq!(query["error_description"], "Invalid email address");
    assert_eq!(google_accounts(&db).await?, 0);

    *hook.reply.lock().unwrap() = Reply::Fails;
    let query = redirect_query(&sign_in(&auth).await);
    assert_eq!(query["error"], "unable_to_get_user_info");
    assert_eq!(google_accounts(&db).await?, 0);

    *hook.reply.lock().unwrap() = Reply::Value;
    hook.set("Mixed.Case@Example.com");
    _ = sign_in(&auth).await;
    assert_eq!(
        stored(&db, "checked-sub").await?.0.as_deref(),
        Some("mixed.case@example.com")
    );

    // ID-token sign-in answers with the validation error.
    hook.set("not-an-email");
    social
        .profile
        .set("id-token-sub", "id-token@example.com", true);
    let response = call(
        &auth,
        request(
            "/sign-in/social",
            Some(json!({"provider": "google", "idToken": {"token": "client-id-token"}})),
            "",
        ),
        400,
    )
    .await;
    assert_eq!(body(&response)["code"], "VALIDATION_ERROR");
    assert_eq!(google_accounts(&db).await?, 1);
    B::close(connection).await
}
