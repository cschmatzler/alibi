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
        let (list, listed) = request(&auth, HttpMethod::Get, "/list-sessions", &cookie, None).await;
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
    let url = std::env::var("BETTER_AUTH_TEST_REDIS_URL").expect("isolated Redis URL is required");
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
        let signed =
            better_auth_core::utils::cookie_utils::create_session_cookie(&new_token, auth.config());
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
                        tx.update_session_active_team(&token_for_update, Some("rolled-back-team"))
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
