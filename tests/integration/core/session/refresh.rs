//! Persisted expiry, deferred writes and authoritative session boundaries.

use better_auth::plugins::SessionManagementPlugin;
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::{AuthRequest, AuthResponse, AuthSession, AuthUser, CreateUser, HttpMethod};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use better_auth_seaorm::{Database, SeaOrmStore};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

const ORIGIN: &str = "http://session.fixture.test";

async fn fixture(deferred: bool, disabled: bool) -> (BetterAuth<Schema>, DatabaseConnection) {
    let mut config =
        AuthConfig::new("session-fixture-secret-at-least-32-characters").base_url(ORIGIN);
    config.session.defer_session_refresh = deferred;
    config.session.disable_session_refresh = disabled;
    fixture_with_config(config).await
}

async fn fixture_with_config(config: AuthConfig) -> (BetterAuth<Schema>, DatabaseConnection) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
        .await
        .unwrap();
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, db.clone()))
        .plugin(SessionManagementPlugin::new())
        .plugin(better_auth::plugins::EmailPasswordPlugin::new())
        .plugin(better_auth::plugins::OrganizationPlugin::new())
        .plugin(better_auth::plugins::one_time_token::OneTimeTokenPlugin::new())
        .build()
        .await
        .unwrap();
    (auth, db)
}

async fn issued(auth: &BetterAuth<Schema>, email: &str) -> (String, String, String) {
    let user = auth
        .store()
        .create_user(CreateUser::new().with_email(email))
        .await
        .unwrap();
    let session = auth
        .session_manager()
        .create_session(&user, None, None)
        .await
        .unwrap();
    let cookie = better_auth_core::utils::cookie_utils::create_session_cookie(
        session.token(),
        auth.config(),
    );
    (
        user.id().into_owned(),
        session.token().to_owned(),
        cookie.split(';').next().unwrap().to_owned(),
    )
}

async fn request(
    auth: &BetterAuth<Schema>,
    method: HttpMethod,
    path: &str,
    cookie: &str,
    body: Option<Value>,
) -> (AuthResponse, Value) {
    let mut req = AuthRequest::new(method, format!("/api/auth{path}"));
    drop(req.headers.insert("origin".into(), ORIGIN.into()));
    drop(req.headers.insert("cookie".into(), cookie.into()));
    if let Some(body) = body {
        drop(
            req.headers
                .insert("content-type".into(), "application/json".into()),
        );
        req.body = Some(serde_json::to_vec(&body).unwrap());
    }
    let response = auth.handle_request(req).await.unwrap();
    let body_2 = serde_json::from_slice(&response.body).unwrap();
    (response, body_2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expiry_based_refresh_returns_the_persisted_snapshot_and_renews_cookie_once() {
        let (auth, _) = fixture(false, false).await;
        let (user, token, cookie) = issued(&auth, "expiry@session.fixture.test").await;
        let stale_expiry = Utc::now() + Duration::hours(1);
        auth.store()
            .update_session_expiry(&token, stale_expiry)
            .await
            .unwrap();
        let before = auth.store().get_session(&token).await.unwrap().unwrap();
        assert!(before.updated_at() > Utc::now() - Duration::seconds(5));
        let (response, value) =
            request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
        assert_eq!(response.status, 200, "{value}");
        let stored = auth.store().get_session(&token).await.unwrap().unwrap();
        assert_eq!(stored.id(), before.id());
        assert_eq!(stored.token(), token);
        assert_eq!(stored.user_id().as_ref(), user);
        assert!(stored.expires_at() > stale_expiry + Duration::days(6));
        assert_eq!(
            (*(*(value).get("session").unwrap_or(&Value::Null))
                .get("expiresAt")
                .unwrap_or(&Value::Null)),
            json!(
                stored
                    .expires_at()
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            )
        );
        assert!(
            response
                .headers
                .get_all("set-cookie")
                .any(|header| header.contains("Max-Age=604800"))
        );
        let (again, repeated) =
            request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
        assert_eq!(repeated, value);
        assert!(again.headers.get_all("set-cookie").next().is_none());
    }

    #[tokio::test]
    async fn deferred_get_is_read_only_and_post_updates_and_cleans_expired_rows() {
        let (auth, _) = fixture(true, false).await;
        let (_, token, cookie) = issued(&auth, "deferred@session.fixture.test").await;
        auth.store()
            .update_session_expiry(&token, Utc::now() + Duration::hours(1))
            .await
            .unwrap();
        let before = auth.store().get_session(&token).await.unwrap().unwrap();
        let (get, value) = request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
        assert_eq!(get.status, 200);
        assert_eq!((*(value).get("needsRefresh").unwrap_or(&Value::Null)), true);
        assert_eq!(
            auth.store()
                .get_session(&token)
                .await
                .unwrap()
                .unwrap()
                .expires_at(),
            before.expires_at()
        );
        let (post, value_2) = request(
            &auth,
            HttpMethod::Post,
            "/get-session",
            &cookie,
            Some(json!({})),
        )
        .await;
        assert_eq!(post.status, 200, "{value_2}");
        assert!(value_2.get("needsRefresh").is_none());
        assert!(
            auth.store()
                .get_session(&token)
                .await
                .unwrap()
                .unwrap()
                .expires_at()
                > before.expires_at() + Duration::days(6)
        );
        auth.store()
            .update_session_expiry(&token, Utc::now() - Duration::seconds(1))
            .await
            .unwrap();
        let (get_2, value_3) = request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
        assert_eq!(value_3, Value::Null);
        assert_eq!(get_2.headers.get_all("set-cookie").count(), 3);
        assert!(auth.store().get_session(&token).await.unwrap().is_some());
        let (post_2, value_4) = request(
            &auth,
            HttpMethod::Post,
            "/get-session",
            &cookie,
            Some(json!({})),
        )
        .await;
        assert_eq!(post_2.status, 200);
        assert_eq!(value_4, Value::Null);
        assert!(auth.store().get_session(&token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_nested_middleware_forwards_cleanup_cookies_and_respects_deferral() {
        for deferred in [false, true] {
            let (auth, _) = fixture(deferred, false).await;
            let (_, token, cookie) = issued(&auth, "expired@session.fixture.test").await;
            auth.store()
                .update_session_expiry(&token, Utc::now() - Duration::seconds(1))
                .await
                .unwrap();
            let (response, value) =
                request(&auth, HttpMethod::Get, "/list-sessions", &cookie, None).await;
            assert_eq!(response.status, 401, "{value}");
            assert_eq!(
                (*(value).get("code").unwrap_or(&Value::Null)),
                "UNAUTHORIZED"
            );
            assert_eq!(response.headers.get_all("set-cookie").count(), 3);
            assert!(
                response
                    .headers
                    .get_all("set-cookie")
                    .all(|expired_cookie| expired_cookie.contains("Max-Age=0"))
            );
            assert_eq!(
                auth.store().get_session(&token).await.unwrap().is_some(),
                deferred
            );
        }
    }

    #[tokio::test]
    async fn concurrent_deletion_during_refresh_never_returns_a_revoked_session() {
        let (auth, db) = fixture(false, false).await;
        let (_, token, cookie) = issued(&auth, "revocation-race@session.fixture.test").await;
        auth.store()
            .update_session_expiry(&token, Utc::now() + Duration::hours(1))
            .await
            .unwrap();
        _ = db.execute_raw(Statement::from_string(DbBackend::Sqlite,
        "CREATE TRIGGER revoke_on_refresh BEFORE UPDATE OF expires_at ON sessions BEGIN DELETE FROM sessions WHERE token = OLD.token; SELECT RAISE(IGNORE); END".to_owned())).await.unwrap();
        let (response, value) =
            request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
        assert_eq!(response.status, 401, "{value}");
        assert_eq!(
            value,
            json!({"code":"FAILED_TO_GET_SESSION","message":"Failed to get session"})
        );
        assert_eq!(response.headers.get_all("set-cookie").count(), 3);
        assert!(auth.store().get_session(&token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn failed_refresh_reports_upstream_error_instead_of_authenticating_the_old_snapshot() {
        let (auth, db) = fixture(false, false).await;
        let (_, token, cookie) = issued(&auth, "write-error@session.fixture.test").await;
        let expiry = Utc::now() + Duration::hours(1);
        auth.store()
            .update_session_expiry(&token, expiry)
            .await
            .unwrap();
        _ = db.execute_raw(Statement::from_string(DbBackend::Sqlite,
        "CREATE TRIGGER fail_refresh BEFORE UPDATE OF expires_at ON sessions BEGIN SELECT RAISE(ABORT, 'fixture refresh failure'); END".to_owned())).await.unwrap();
        let (response, value) =
            request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
        assert_eq!(response.status, 500, "{value}");
        assert_eq!(
            value,
            json!({"code":"FAILED_TO_GET_SESSION","message":"Failed to get session"})
        );
        assert_eq!(
            auth.store()
                .get_session(&token)
                .await
                .unwrap()
                .unwrap()
                .expires_at(),
            expiry
        );
        assert!(response.headers.get_all("set-cookie").next().is_none());
        assert_eq!(
            response.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            response.headers.get("pragma").map(String::as_str),
            Some("no-cache")
        );
    }

    #[tokio::test]
    async fn authoritative_revocation_bypasses_virtual_sessions_and_preserves_foreign_expiry() {
        let (auth, _) = fixture(false, false).await;
        let (_, owner_token, owner_cookie) = issued(&auth, "owner@session.fixture.test").await;
        let (_, foreign_token, _) = issued(&auth, "foreign@session.fixture.test").await;
        let expiry = Utc::now() + Duration::hours(1);
        auth.store()
            .update_session_expiry(&foreign_token, expiry)
            .await
            .unwrap();
        let foreign = auth
            .store()
            .get_session(&foreign_token)
            .await
            .unwrap()
            .unwrap();
        let mut request = AuthRequest::new(HttpMethod::Post, "/revoke-session");
        request.set_virtual_session(auth.context().session_view(&foreign));
        assert!(
            auth.context()
                .require_authoritative_session(&request)
                .await
                .is_err()
        );
        drop(
            request
                .headers
                .insert("cookie".into(), owner_cookie.clone()),
        );
        let (_, authenticated) = auth
            .context()
            .require_authoritative_session(&request)
            .await
            .unwrap();
        assert_eq!(authenticated.token, owner_token);
        let (response, value) = self::request(
            &auth,
            HttpMethod::Post,
            "/revoke-session",
            &owner_cookie,
            Some(json!({"token":foreign_token})),
        )
        .await;
        assert_eq!(response.status, 200);
        assert_eq!(value, json!({"status":true}));
        assert_eq!(
            auth.store()
                .get_session(&foreign_token)
                .await
                .unwrap()
                .unwrap()
                .expires_at(),
            expiry
        );
    }
}

#[cfg(test)]
mod secondary {
    //! Public persistence modes exercised against physical SQLite and real cache backends.
    use super::*;
    use better_auth_core::store::{CacheAdapter, MemoryCacheAdapter};
    use better_auth_seaorm::sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use better_auth_seaorm::store::entities::session;
    use std::sync::Arc;

    async fn mode(
        cache: Arc<dyn CacheAdapter>,
        stored: bool,
        preserved: bool,
    ) -> (BetterAuth<Schema>, DatabaseConnection) {
        let mut config =
            AuthConfig::new("secondary-session-fixture-secret-at-least-32").base_url(ORIGIN);
        config.verification.secondary_storage = Some(cache.clone());
        config.session.secondary_storage = Some(cache);
        config.session.store_in_database = stored;
        config.session.preserve_in_database = preserved;
        fixture_with_config(config).await
    }

    async fn physical(db: &DatabaseConnection, token: &str) -> Option<session::Model> {
        session::Entity::find()
            .filter(session::Column::Token.eq(token))
            .one(db)
            .await
            .unwrap()
    }

    async fn exercise_modes(cache: Arc<dyn CacheAdapter>) {
        for (stored, preserved) in [(false, false), (false, true), (true, false), (true, true)] {
            cache.clear().await.unwrap();
            let (auth, db) = mode(cache.clone(), stored, preserved).await;
            let (owner, token, cookie) = issued(&auth, "owner@secondary.fixture.test").await;
            let (foreign, foreign_token, foreign_cookie) =
                issued(&auth, "foreign@secondary.fixture.test").await;
            let original = auth.store().get_session(&token).await.unwrap().unwrap();
            assert_eq!(physical(&db, &token).await.is_some(), stored);
            assert!(cache.get(&token).await.unwrap().is_some());
            assert!(
                cache
                    .get(&format!("active-sessions-{owner}"))
                    .await
                    .unwrap()
                    .is_some()
            );
            let (read, view) = request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
            assert_eq!(read.status, 200);
            assert_eq!(
                view.get("user").and_then(|user| user.get("id")),
                Some(&json!(owner))
            );
            let (foreign_revoke, _) = request(
                &auth,
                HttpMethod::Post,
                "/revoke-session",
                &foreign_cookie,
                Some(json!({"token":token})),
            )
            .await;
            assert_eq!(foreign_revoke.status, 200);
            assert!(auth.store().get_session(&token).await.unwrap().is_some());
            assert!(
                auth.store()
                    .get_session(&foreign_token)
                    .await
                    .unwrap()
                    .is_some()
            );
            let target = Utc::now() + Duration::hours(1);
            let updated = auth
                .store()
                .refresh_session(&token, target)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(updated.expires_at(), target);
            assert_eq!(updated.id(), original.id());
            assert_eq!(updated.user_id().as_ref(), owner);
            if stored {
                assert_eq!(physical(&db, &token).await.unwrap().expires_at, target);
            }
            let (refreshed, refreshed_view) =
                request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
            assert_eq!(refreshed.status, 200);
            assert!(refreshed_view.get("session").is_some());
            assert!(
                auth.store()
                    .get_session(&token)
                    .await
                    .unwrap()
                    .unwrap()
                    .expires_at()
                    > target + Duration::days(6)
            );
            let (list, listed) =
                request(&auth, HttpMethod::Get, "/list-sessions", &cookie, None).await;
            assert_eq!(list.status, 200);
            assert_eq!(listed.as_array().unwrap().len(), 1);
            let (generated, handoff) = request(
                &auth,
                HttpMethod::Get,
                "/one-time-token/generate",
                &cookie,
                None,
            )
            .await;
            assert_eq!(generated.status, 200);
            let handoff = handoff.get("token").and_then(Value::as_str).unwrap();
            let redeem = || {
                request(
                    &auth,
                    HttpMethod::Post,
                    "/one-time-token/verify",
                    "",
                    Some(json!({"token": handoff})),
                )
            };
            let (first, second) = tokio::join!(redeem(), redeem());
            assert_ne!(first.0.status == 200, second.0.status == 200);
            let (accepted, rejected) = if first.0.status == 200 {
                (first, second)
            } else {
                (second, first)
            };
            assert_eq!(
                accepted
                    .1
                    .get("session")
                    .and_then(|session| session.get("token")),
                Some(&json!(token))
            );
            assert_eq!(rejected.0.status, 400);
            assert_eq!(physical(&db, &token).await.is_some(), stored);
            drop(
                auth.store()
                    .update_user(
                        &owner,
                        better_auth_core::UpdateUser {
                            name: Some("Renamed cached owner".into()),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap(),
            );
            let (_, renamed) = request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
            assert_eq!(
                renamed.get("user").and_then(|user| user.get("name")),
                Some(&json!("Renamed cached owner"))
            );
            drop(
                auth.store()
                    .update_session_active_organization(&token, Some("organization-scope"))
                    .await
                    .unwrap(),
            );
            drop(
                auth.store()
                    .update_session_active_team(&token, Some("team-scope"))
                    .await
                    .unwrap(),
            );
            let scoped = auth.store().get_session(&token).await.unwrap().unwrap();
            assert_eq!(scoped.active_organization_id(), Some("organization-scope"));
            assert_eq!(scoped.active_team_id(), Some("team-scope"));
            cache.delete(&token).await.unwrap();
            assert_eq!(
                auth.store().get_session(&token).await.unwrap().is_some(),
                stored && !preserved
            );
            assert!(
                auth.store()
                    .get_user_sessions(&owner)
                    .await
                    .unwrap()
                    .is_empty()
            );
            // Revocation cannot leave an audit row usable as fallback authority.
            auth.store().delete_session(&token).await.unwrap();
            assert!(auth.store().get_session(&token).await.unwrap().is_none());
            let ended = physical(&db, &token).await;
            if stored && preserved {
                assert!(ended.unwrap().expires_at <= Utc::now());
            } else {
                assert!(ended.is_none());
            }
            auth.store().delete_session(&token).await.unwrap();
            assert!(
                auth.store()
                    .get_session(&foreign_token)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(
                auth.store()
                    .get_user_sessions(&foreign)
                    .await
                    .unwrap()
                    .len(),
                1
            );
            auth.store().delete_user(&foreign).await.unwrap();
            assert!(cache.get(&foreign_token).await.unwrap().is_none());
            assert!(
                auth.store()
                    .get_session(&foreign_token)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(physical(&db, &foreign_token).await.is_none());
        }
    }

    #[tokio::test]
    async fn secondary_session_modes_keep_cache_authority_and_physical_database_effects() {
        exercise_modes(Arc::new(MemoryCacheAdapter::new())).await;
    }

    #[cfg(feature = "redis-cache")]
    #[tokio::test]
    #[ignore = "requires an isolated Redis instance in BETTER_AUTH_TEST_REDIS_URL"]
    async fn real_redis_session_modes_keep_cache_authority_and_physical_database_effects() {
        let url =
            std::env::var("BETTER_AUTH_TEST_REDIS_URL").expect("isolated Redis URL is required");
        let cache = better_auth_core::store::RedisAdapter::new(&url)
            .await
            .unwrap();
        exercise_modes(Arc::new(cache)).await;
    }

    #[tokio::test]
    async fn secondary_expiry_and_malformed_credentials_never_fall_back_to_a_preserved_audit_row() {
        let cache = Arc::new(MemoryCacheAdapter::new());
        let (auth, db) = mode(cache.clone(), true, true).await;
        let (_, token, cookie) = issued(&auth, "expired@secondary.fixture.test").await;
        cache.expire(&token, Duration::zero()).await.unwrap();
        let (_, missing) = request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
        assert_eq!(missing, Value::Null);
        assert!(physical(&db, &token).await.unwrap().expires_at > Utc::now());
        cache
            .set(&token, "malformed", Duration::hours(1))
            .await
            .unwrap();
        let (_, malformed) = request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
        assert_eq!(malformed, Value::Null);
        // Combined fallback is permitted only for an absent entry, never for corrupt data.
        let (combined, combined_db) = mode(cache.clone(), true, false).await;
        let (_, combined_token, combined_cookie) =
            issued(&combined, "corrupt@secondary.fixture.test").await;
        let issued_snapshot: Value =
            serde_json::from_str(&cache.get(&combined_token).await.unwrap().unwrap()).unwrap();
        for (field, value) in [
            ("expires_at", json!(Utc::now() - Duration::seconds(1))),
            ("active", json!(false)),
            ("user_id", json!("foreign-snapshot-owner")),
        ] {
            let mut snapshot = issued_snapshot.clone();
            let session = snapshot
                .get_mut("session")
                .and_then(Value::as_object_mut)
                .unwrap();
            drop(session.insert(field.into(), value));
            cache
                .set(&combined_token, &snapshot.to_string(), Duration::hours(1))
                .await
                .unwrap();
            assert!(
                combined
                    .store()
                    .get_sessions_by_tokens(std::slice::from_ref(&combined_token))
                    .await
                    .unwrap()
                    .is_empty()
            );
            let (_, rejected) = request(
                &combined,
                HttpMethod::Get,
                "/get-session",
                &combined_cookie,
                None,
            )
            .await;
            assert_eq!(rejected, Value::Null);
        }
        cache
            .set(&combined_token, "malformed", Duration::hours(1))
            .await
            .unwrap();
        assert!(
            combined
                .store()
                .get_session(&combined_token)
                .await
                .unwrap()
                .is_none()
        );
        cache.delete(&combined_token).await.unwrap();
        let (_, fallback) = request(
            &combined,
            HttpMethod::Get,
            "/get-session",
            &combined_cookie,
            None,
        )
        .await;
        assert!(fallback.get("session").is_some());
        assert!(physical(&combined_db, &combined_token).await.is_some());
    }

    #[tokio::test]
    async fn transactional_secondary_issuance_and_scope_keep_actual_cache_partial_effects_on_rollback()
     {
        for stored in [false, true] {
            let cache = Arc::new(MemoryCacheAdapter::new());
            let (auth, db) = mode(cache.clone(), stored, false).await;
            let (owner, token, cookie) = issued(&auth, "rollback@secondary.fixture.test").await;
            let user_id = owner.clone();
            let new_token = "transaction-issued-secondary-token".to_owned();
            let input = better_auth_core::CreateSession {
                additional_fields: Default::default(),
                token: Some(new_token.clone()),
                user_id,
                expires_at: Utc::now() + Duration::days(7),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                active_team_id: None,
            };
            let result = better_auth_core::store::transaction::<Schema, (), _>(
                auth.store().as_ref(),
                move |tx| {
                    Box::pin(async move {
                        drop(tx.create_session(input).await?);
                        Err(better_auth::AuthError::internal(
                            "Actual transaction rollback",
                        ))
                    })
                },
            )
            .await;
            assert!(result.is_err());
            assert!(physical(&db, &new_token).await.is_none());
            assert!(cache.get(&new_token).await.unwrap().is_some());
            let signed = better_auth_core::utils::cookie_utils::create_session_cookie(
                &new_token,
                auth.config(),
            );
            let (_, surviving) = request(
                &auth,
                HttpMethod::Get,
                "/get-session",
                signed.split(';').next().unwrap(),
                None,
            )
            .await;
            assert_eq!(
                surviving.get("user").and_then(|user| user.get("id")),
                Some(&json!(owner)),
                "stored={stored}, response={surviving}"
            );
            assert!(physical(&db, &new_token).await.is_none());
            let token_for_update = token.clone();
            let result = better_auth_core::store::transaction::<Schema, (), _>(
                auth.store().as_ref(),
                move |tx| {
                    Box::pin(async move {
                        drop(
                            tx.update_session_active_organization(
                                &token_for_update,
                                Some("rolled-back-organization"),
                            )
                            .await?,
                        );
                        drop(
                            tx.update_session_active_team(
                                &token_for_update,
                                Some("rolled-back-team"),
                            )
                            .await?,
                        );
                        Err(better_auth::AuthError::internal("Actual scope rollback"))
                    })
                },
            )
            .await;
            assert!(result.is_err());
            let (_, surviving_scope) =
                request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
            assert_eq!(
                surviving_scope
                    .get("session")
                    .and_then(|session| session.get("activeOrganizationId")),
                Some(&json!("rolled-back-organization"))
            );
            if stored {
                assert!(
                    physical(&db, &token)
                        .await
                        .unwrap()
                        .active_organization_id
                        .is_none()
                );
            }
        }
    }

    struct RejectCredentialWrites {
        inner: MemoryCacheAdapter,
    }
    #[async_trait::async_trait]
    impl CacheAdapter for RejectCredentialWrites {
        async fn set(&self, key: &str, value: &str, ttl: Duration) -> better_auth::AuthResult<()> {
            if !key.starts_with("active-sessions-") {
                return Err(better_auth::AuthError::internal(
                    "Actual secondary credential write rejected",
                ));
            }
            self.inner.set(key, value, ttl).await
        }
        async fn get(&self, key: &str) -> better_auth::AuthResult<Option<String>> {
            self.inner.get(key).await
        }
        async fn delete(&self, key: &str) -> better_auth::AuthResult<()> {
            self.inner.delete(key).await
        }
        async fn exists(&self, key: &str) -> better_auth::AuthResult<bool> {
            self.inner.exists(key).await
        }
        async fn expire(&self, key: &str, ttl: Duration) -> better_auth::AuthResult<()> {
            self.inner.expire(key, ttl).await
        }
        async fn clear(&self) -> better_auth::AuthResult<()> {
            self.inner.clear().await
        }
    }

    #[tokio::test]
    async fn failed_http_secondary_issuance_rolls_back_sql_and_exposes_no_cookie() {
        for stored in [false, true] {
            let cache = Arc::new(RejectCredentialWrites {
                inner: MemoryCacheAdapter::new(),
            });
            let (auth, db) = mode(cache, stored, false).await;
            let (response, _) = request(&auth, HttpMethod::Post, "/sign-up/email", "", Some(json!({"email":"failed@secondary.fixture.test","name":"Failed issuance","password":"password123"}))).await;
            assert_eq!(response.status, 500);
            assert!(response.headers.get_all("set-cookie").next().is_none());
            assert!(
                auth.store()
                    .get_user_by_email("failed@secondary.fixture.test")
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(session::Entity::find().all(&db).await.unwrap().is_empty());
        }
    }
}
