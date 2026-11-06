//! Session persistence through an application-owned secondary backend.
use super::PluginStore;
use crate::field_policy::FieldValues;
use crate::{
    AdapterOutput, AdapterRecord, AuthError, AuthResult, AuthSchema, AuthSession, AuthUser,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Serialize, Deserialize)]
struct CachedSession {
    session: serde_json::Value,
    #[serde(default)]
    user: serde_json::Value,
    #[serde(default)]
    absent_fields: BTreeSet<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Reference {
    token: String,
    #[serde(rename = "expiresAt", with = "chrono::serde::ts_milliseconds")]
    expires_at: DateTime<Utc>,
}

struct CachedUserRevocation<S: AuthSchema> {
    store: PluginStore<S>,
    user_id: String,
    tokens: Vec<String>,
    cutoff: i64,
}

#[async_trait::async_trait]
impl<S: AuthSchema> super::SessionRevocation for CachedUserRevocation<S> {
    async fn revoke(&self) -> AuthResult<()> {
        self.store
            .apply_cached_user_revocation(&self.user_id, self.tokens.clone(), self.cutoff)
            .await
    }
}

struct DeferredSessionPublication<S: AuthSchema> {
    store: PluginStore<S>,
    session: S::Session,
    created_at: DateTime<Utc>,
    creation_fields: FieldValues,
    native: AdapterOutput,
}

#[async_trait::async_trait]
impl<S: AuthSchema> crate::session::SessionPublication for DeferredSessionPublication<S> {
    async fn publish(&self) {
        if let Err(error) = self
            .store
            .mirror_created_session(
                &self.session,
                self.created_at,
                &self.creation_fields,
                &self.native,
            )
            .await
        {
            tracing::error!(%error, "Failed to mirror committed session to secondary storage");
        }
    }
}

impl CachedSession {
    fn absent_fields(raw: &str) -> BTreeSet<String> {
        serde_json::from_str::<Self>(raw)
            .map(|cached| cached.absent_fields)
            .unwrap_or_default()
    }
}

impl<S: AuthSchema> PluginStore<S> {
    pub(super) fn secondary(&self) -> Option<&std::sync::Arc<dyn super::CacheAdapter>> {
        self.config.session.secondary_storage.as_ref()
    }

    pub(super) fn session_uses_database(&self) -> bool {
        !self.config.session.stateless
            && (self.secondary().is_none() || self.config.session.store_in_database)
    }

    /// Secondary storage with database sessions that are deleted on revocation:
    /// the database then holds every session and can serve cache misses.
    pub(super) fn database_session_fallback(&self) -> bool {
        self.secondary().is_some()
            && !self.config.session.stateless
            && self.config.session.store_in_database
            && !self.config.session.preserve_in_database
    }

    pub(super) fn remember_ephemeral_session(&self, session: &S::Session) -> AuthResult<()> {
        if self.config.session.stateless {
            _ = self
                .ephemeral()?
                .insert(session.token().to_owned(), session.clone());
        }
        Ok(())
    }

    /// Set one nullable session scope field (`activeOrganizationId`, `activeTeamId`).
    pub(super) async fn update_session_scope(
        &self,
        token: &str,
        field: &str,
        value: Option<&str>,
    ) -> AuthResult<S::Session> {
        let mut fields = FieldValues::new();
        _ = fields.insert(
            field.into(),
            value.map_or(crate::utils::json::JsValue::Null, |value| {
                crate::utils::json::JsValue::String(value.to_owned().into())
            }),
        );
        if self.session_uses_database() {
            self.adapter_fields.attach(&mut fields, false);
        }
        let updated = if self.config.session.stateless {
            self.update_ephemeral_session(token, None, fields).await?
        } else {
            self.update_secondary_session(token, None, fields).await?
        };
        updated.ok_or(AuthError::SessionNotFound)
    }

    pub(super) async fn update_ephemeral_session(
        &self,
        token: &str,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        let original = self.ephemeral()?.get(token).cloned();
        let Some(original) = original else {
            return Ok(None);
        };
        let Some((session, fields)) = self
            .inner
            .prepare_secondary_session_update(original, expires_at, fields)
            .await?
        else {
            return Ok(None);
        };
        // Never resurrect a session concurrently removed while hooks awaited.
        {
            let mut sessions = self.ephemeral()?;
            let Some(destination) = sessions.get_mut(token) else {
                return Ok(None);
            };
            *destination = session.clone();
        }
        self.inner
            .complete_secondary_session_update(token, session, expires_at, fields, false)
            .await
    }

    async fn references(&self, user_id: &str) -> AuthResult<Vec<Reference>> {
        let Some(cache) = self.secondary() else {
            return Ok(Vec::new());
        };
        let Some(raw) = cache.get(&format!("active-sessions-{user_id}")).await? else {
            return Ok(Vec::new());
        };
        Ok(serde_json::from_str(&raw).unwrap_or_default())
    }

    async fn write_references(
        &self,
        user_id: &str,
        mut references: Vec<Reference>,
    ) -> AuthResult<()> {
        let Some(cache) = self.secondary() else {
            return Ok(());
        };
        let now = Utc::now();
        references.retain(|reference| reference.expires_at > now);
        references.sort_by_key(|reference| reference.expires_at);
        let key = format!("active-sessions-{user_id}");
        if let Some(last) = references.last() {
            let ttl = Duration::seconds((last.expires_at - now).num_seconds());
            if ttl > Duration::zero() {
                return cache
                    .set(&key, &serde_json::to_string(&references)?, ttl)
                    .await;
            }
        }
        cache.delete(&key).await
    }

    async fn stored_session(
        &self,
        token: &str,
    ) -> AuthResult<Option<(S::Session, Option<AdapterRecord<S::User>>)>> {
        let Some(cache) = self.secondary() else {
            return Ok(None);
        };
        let Some(raw) = cache.get(token).await? else {
            return Ok(None);
        };
        let Ok(snapshot) = serde_json::from_str::<CachedSession>(&raw) else {
            return Ok(None);
        };
        let Ok(session) = S::Session::from_secondary_snapshot(snapshot.session) else {
            return Ok(None);
        };
        let user = if snapshot.user.is_null() {
            None
        } else {
            let registered = self
                .projection_context
                .extensions
                .get::<crate::field_policy::UserFields>();
            let fields = registered
                .as_ref()
                .map_or(&self.config.user.additional_fields, |fields| &fields.0.0);
            let Ok(user) =
                S::User::from_secondary_snapshot_record_with_fields(snapshot.user, fields)
            else {
                return Ok(None);
            };
            Some(user)
        };
        Ok(Some((session, user)))
    }

    pub(super) async fn cached_session(
        &self,
        token: &str,
    ) -> AuthResult<Option<(S::Session, S::User)>> {
        Ok(self
            .cached_session_record(token)
            .await?
            .map(|(session, user)| (session, user.into_stored())))
    }

    pub(super) async fn cached_session_record(
        &self,
        token: &str,
    ) -> AuthResult<Option<(S::Session, AdapterRecord<S::User>)>> {
        let Some((session, user)) = self.stored_session(token).await? else {
            return Ok(None);
        };
        if session.expires_at() <= Utc::now() {
            return Ok(None);
        }
        if let Some(cache) = self.secondary() {
            let cutoff = cache
                .get(&format!("revoked-sessions-before-{}", session.user_id()))
                .await?
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(0);
            if session.created_at().timestamp_millis() < cutoff {
                return Ok(None);
            }
        }
        let user = user.ok_or_else(|| AuthError::internal("Secondary session owner is absent"))?;
        Ok(Some((session, user)))
    }

    pub(super) async fn secondary_session_for_update(
        &self,
        token: &str,
    ) -> AuthResult<Option<(S::Session, serde_json::Value)>> {
        let Some(cache) = self.secondary() else {
            return Ok(None);
        };
        let Some(raw) = cache.get(token).await? else {
            return Ok(None);
        };
        let Ok(snapshot) = serde_json::from_str::<CachedSession>(&raw) else {
            return Ok(None);
        };
        let session = S::Session::from_secondary_snapshot(snapshot.session)?;
        Ok(Some((session, snapshot.user)))
    }

    pub(super) async fn mirror_session_fields(
        &self,
        token: &str,
        session: &S::Session,
        user: serde_json::Value,
        updated_fields: Option<&FieldValues>,
    ) -> AuthResult<()> {
        if self.secondary().is_none() {
            return Ok(());
        }
        let now = Utc::now();
        let mut references = self.references(session.user_id().as_ref()).await?;
        references.retain(|reference| reference.token != token);
        references.push(Reference {
            token: token.to_owned(),
            expires_at: session.expires_at(),
        });
        let ttl = Duration::seconds((session.expires_at() - now).num_seconds());
        if ttl > Duration::zero() {
            self.write_session_snapshot(token, session, user, updated_fields, None, None, ttl)
                .await?;
            self.write_references(session.user_id().as_ref(), references)
                .await?;
        }
        Ok(())
    }

    async fn write_session_snapshot(
        &self,
        token: &str,
        session: &S::Session,
        user: serde_json::Value,
        updated_fields: Option<&FieldValues>,
        created_at: Option<DateTime<Utc>>,
        native: Option<&AdapterOutput>,
        ttl: Duration,
    ) -> AuthResult<()> {
        let Some(cache) = self.secondary() else {
            return Ok(());
        };
        let mut absent_fields = if let Some(raw) = cache.get(token).await? {
            CachedSession::absent_fields(&raw)
        } else if !self.config.session.store_in_database {
            let mut absent = BTreeSet::new();
            for (name, value) in [
                ("impersonatedBy", session.impersonated_by()),
                ("activeOrganizationId", session.active_organization_id()),
                ("activeTeamId", session.active_team_id()),
            ] {
                if value.is_none() {
                    _ = absent.insert(name.to_owned());
                }
            }
            for (name, value) in session.additional_fields() {
                if value.is_null()
                    && self
                        .config
                        .session
                        .additional_fields
                        .get(&name)
                        .is_none_or(|field| field.default.is_none())
                {
                    _ = absent.insert(name);
                }
            }
            absent
        } else {
            BTreeSet::new()
        };
        if let Some(fields) = updated_fields {
            for name in fields.keys() {
                _ = absent_fields.remove(name);
            }
        }
        if let Some(native) = native {
            for name in self.adapter_fields.0.keys() {
                if native.field_is_undefined(name) {
                    _ = absent_fields.insert(name.clone());
                }
            }
            _ = absent_fields.remove("createdAt");
        }
        let session_snapshot = match created_at {
            Some(created_at) => match native {
                Some(native) => session
                    .secondary_snapshot_for_creation_with_native_output(created_at, native)?,
                None => session.secondary_snapshot_for_creation(created_at)?,
            },
            None => session.secondary_snapshot()?,
        };
        let session_snapshot = if created_at.is_none() {
            let mut merged = if let Some(raw) = cache.get(token).await? {
                serde_json::from_str::<CachedSession>(&raw)?.session
            } else {
                serde_json::Value::Object(serde_json::Map::new())
            };
            let (Some(merged), serde_json::Value::Object(updated)) =
                (merged.as_object_mut(), &session_snapshot)
            else {
                return Err(AuthError::internal("Invalid secondary session snapshot"));
            };
            merged.extend(updated.clone());
            let mut output = S::Session::output_from_secondary_snapshot(
                serde_json::Value::Object(merged.clone()),
            )?;
            for name in &absent_fields {
                output.insert(name.clone(), None);
            }
            let registered = self
                .projection_context
                .extensions
                .get::<crate::field_policy::SessionFields>();
            let fields = registered
                .as_ref()
                .map_or(&self.config.session.additional_fields, |fields| &fields.0);
            for (name, field) in fields {
                if !field.returned {
                    output.insert(name.clone(), None);
                    _ = absent_fields.insert(name.clone());
                }
            }
            session.secondary_snapshot_with_native_output(&output)?
        } else {
            session_snapshot
        };
        let snapshot = CachedSession {
            session: session_snapshot,
            user,
            absent_fields,
        };
        cache
            .set(token, &serde_json::to_string(&snapshot)?, ttl)
            .await?;
        Ok(())
    }

    pub(super) async fn secondary_session_output(&self, token: &str) -> AuthResult<AdapterOutput> {
        let cache = self
            .secondary()
            .ok_or_else(|| AuthError::internal("No secondary session storage"))?;
        let raw = cache.get(token).await?.ok_or(AuthError::SessionNotFound)?;
        let snapshot: CachedSession = serde_json::from_str(&raw)?;
        let mut output = S::Session::output_from_secondary_snapshot(snapshot.session)?;
        for name in snapshot.absent_fields {
            output.insert(name, None);
        }
        Ok(output)
    }

    pub(super) async fn secondary_absent_fields(
        &self,
        token: &str,
    ) -> AuthResult<BTreeSet<String>> {
        let Some(cache) = self.secondary() else {
            return Ok(BTreeSet::new());
        };
        let Some(raw) = cache.get(token).await? else {
            return Ok(BTreeSet::new());
        };
        Ok(CachedSession::absent_fields(&raw))
    }

    pub(super) fn deferred_session_publication(
        &self,
        session: S::Session,
        created_at: DateTime<Utc>,
        creation_fields: FieldValues,
        native: AdapterOutput,
    ) -> std::sync::Arc<dyn crate::session::SessionPublication> {
        std::sync::Arc::new(DeferredSessionPublication {
            store: self.clone(),
            session,
            created_at,
            creation_fields,
            native,
        })
    }

    pub(super) async fn mirror_created_session(
        &self,
        session: &S::Session,
        created_at: DateTime<Utc>,
        creation_fields: &FieldValues,
        native: &AdapterOutput,
    ) -> AuthResult<()> {
        let user_id = session.user_id();
        self.mirror_session_creation(
            session,
            created_at,
            creation_fields,
            native,
            self.inner.get_user_by_id_record(user_id.as_ref()),
        )
        .await
    }

    pub(super) async fn mirror_session_creation(
        &self,
        session: &S::Session,
        created_at: DateTime<Utc>,
        creation_fields: &FieldValues,
        native: &AdapterOutput,
        user: impl Future<Output = AuthResult<Option<AdapterRecord<S::User>>>> + Send,
    ) -> AuthResult<()> {
        if self.secondary().is_none() {
            return Ok(());
        }
        let now = Utc::now();
        let mut references = self.references(session.user_id().as_ref()).await?;
        references.retain(|reference| reference.token != session.token());
        references.push(Reference {
            token: session.token().to_owned(),
            expires_at: session.expires_at(),
        });
        self.write_references(session.user_id().as_ref(), references)
            .await?;
        let user = user.await?;
        let ttl = Duration::seconds((session.expires_at() - now).num_seconds());
        if ttl > Duration::zero() {
            let user = match user {
                Some(user) => self
                    .user_record_with_native_output(
                        user.stored().clone(),
                        user.raw_snapshot().clone(),
                    )
                    .await?
                    .secondary_snapshot()?,
                None => serde_json::Value::Null,
            };
            self.write_session_snapshot(
                session.token(),
                session,
                user,
                Some(creation_fields),
                Some(created_at),
                Some(native),
                ttl,
            )
            .await?;
        }
        Ok(())
    }

    pub(super) async fn cached_collection_session(
        &self,
        token: &str,
        public: bool,
        require_owner: bool,
    ) -> AuthResult<Option<AdapterRecord<S::Session>>> {
        let Some(cache) = self.secondary() else {
            return Ok(None);
        };
        let Some(raw) = cache.get(token).await? else {
            return Ok(None);
        };
        let Ok(snapshot) = serde_json::from_str::<CachedSession>(&raw) else {
            return Ok(None);
        };
        // findSessions reads user dates; listSessions never reads the owner.
        if require_owner && snapshot.user.is_null() {
            return Ok(None);
        }
        let Ok(session) = S::Session::from_secondary_snapshot(snapshot.session.clone()) else {
            return Ok(None);
        };
        let cutoff = cache
            .get(&format!("revoked-sessions-before-{}", session.user_id()))
            .await?
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0);
        if session.created_at().timestamp_millis() < cutoff {
            return Ok(None);
        }
        let mut output = S::Session::output_from_secondary_snapshot(snapshot.session)?;
        output.insert(
            "expiresAt".into(),
            Some(serde_json::Value::String(
                crate::utils::datetime::json_date_millis(session.expires_at().timestamp_millis()),
            )),
        );
        for name in snapshot.absent_fields {
            output.insert(name, None);
        }
        if public {
            let registered = self
                .projection_context
                .extensions
                .get::<crate::field_policy::SessionFields>();
            let fields = registered
                .as_ref()
                .map_or(&self.config.session.additional_fields, |fields| &fields.0);
            output = output.filter_returned(fields);
        }
        Ok(Some(AdapterRecord::with_output(session, output)))
    }

    pub(super) async fn cached_user_session_records(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<AdapterRecord<S::Session>>> {
        let now = Utc::now();
        let mut sessions = Vec::new();
        let mut seen = BTreeSet::new();
        for reference in self.references(user_id).await? {
            if reference.expires_at <= now || !seen.insert(reference.token.clone()) {
                continue;
            }
            if let Some(session) = self
                .cached_collection_session(&reference.token, true, false)
                .await?
            {
                sessions.push(session);
            }
        }
        Ok(sessions)
    }

    pub(super) async fn cached_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>> {
        Ok(self
            .cached_user_session_records(user_id)
            .await?
            .into_iter()
            .map(AdapterRecord::into_stored)
            .collect())
    }

    pub(super) async fn cached_user_tokens(&self, user_id: &str) -> AuthResult<Vec<String>> {
        Ok(self
            .references(user_id)
            .await?
            .into_iter()
            .map(|reference| reference.token)
            .collect())
    }

    pub(super) async fn remove_cached_user_sessions(
        &self,
        user_id: &str,
        tokens: Vec<String>,
    ) -> AuthResult<()> {
        let Some(cache) = self.secondary() else {
            return Ok(());
        };
        for token in &tokens {
            // An index is only a locator: the issued snapshot establishes ownership.
            if let Some((session, _)) = self.stored_session(token).await?
                && session.user_id().as_ref() == user_id
            {
                cache.delete(token).await?;
            }
        }
        let mut current = self.references(user_id).await?;
        let removed = BTreeSet::from_iter(tokens);
        current.retain(|reference| !removed.contains(&reference.token));
        self.write_references(user_id, current).await
    }

    pub(super) async fn cached_user_revocation(
        &self,
        user_id: &str,
        mut tokens: Vec<String>,
    ) -> AuthResult<std::sync::Arc<dyn super::SessionRevocation>> {
        tokens.extend(self.cached_user_tokens(user_id).await?);
        tokens.sort();
        tokens.dedup();
        Ok(std::sync::Arc::new(CachedUserRevocation {
            store: self.clone(),
            user_id: user_id.to_owned(),
            tokens,
            cutoff: Utc::now().timestamp_millis(),
        }))
    }

    async fn apply_cached_user_revocation(
        &self,
        user_id: &str,
        tokens: Vec<String>,
        revoked_at: i64,
    ) -> AuthResult<()> {
        let Some(cache) = self.secondary() else {
            return Ok(());
        };
        let key = format!("revoked-sessions-before-{user_id}");
        let previous = cache
            .get(&key)
            .await?
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0);
        let cutoff = revoked_at.max(previous);
        let impersonation_ttl = self
            .projection_context
            .get_metadata("admin.impersonation_session_duration")
            .and_then(serde_json::Value::as_f64)
            .and_then(|seconds| std::time::Duration::try_from_secs_f64(seconds).ok())
            .and_then(|duration| Duration::from_std(duration).ok())
            .unwrap_or_default();
        let ttl = self
            .config
            .session
            .expires_in
            .max(Duration::days(1))
            .max(impersonation_ttl);
        cache.set(&key, &cutoff.to_string(), ttl).await?;
        self.remove_cached_user_sessions(user_id, tokens).await
    }

    pub(super) async fn remove_cached_session(&self, token: &str) -> AuthResult<()> {
        let Some(cache) = self.secondary() else {
            return Ok(());
        };
        if let Some((session, _)) = self.stored_session(token).await? {
            let mut references = self.references(session.user_id().as_ref()).await?;
            references.retain(|reference| reference.token != token);
            self.write_references(session.user_id().as_ref(), references)
                .await?;
        }
        cache.delete(token).await
    }

    pub(super) async fn refresh_cached_user(&self, user: &S::User) -> AuthResult<()> {
        let Some(cache) = self.secondary() else {
            return Ok(());
        };
        let now = Utc::now();
        let mut user_snapshot: Option<serde_json::Value> = None;
        for session in self.cached_user_sessions(user.id().as_ref()).await? {
            let Some(raw) = cache.get(session.token()).await? else {
                continue;
            };
            let Ok(mut snapshot) = serde_json::from_str::<CachedSession>(&raw) else {
                continue;
            };
            let ttl = Duration::seconds((session.expires_at() - now).num_seconds());
            if ttl > Duration::zero() {
                snapshot.user = match &user_snapshot {
                    Some(snapshot) => snapshot.clone(),
                    None => {
                        let native = AdapterOutput::from_values(
                            self.inner
                                .native_user_output_for(user)
                                .await?
                                .into_iter()
                                .collect(),
                        );
                        let snapshot = self
                            .user_record_with_native_output(user.clone(), native)
                            .await?
                            .secondary_snapshot()?;
                        user_snapshot = Some(snapshot.clone());
                        snapshot
                    }
                };
                cache
                    .set(session.token(), &serde_json::to_string(&snapshot)?, ttl)
                    .await?;
            }
        }
        Ok(())
    }

    pub(super) async fn update_secondary_session(
        &self,
        token: &str,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        let Some((session, user)) = self.secondary_session_for_update(token).await? else {
            // A combined database write may still occur, but it must not revive
            // an absent authoritative secondary session in preserved mode.
            return if self.session_uses_database() {
                if let Some(expiry) = expires_at {
                    self.inner
                        .refresh_session_with_fields(token, expiry, fields)
                        .await
                } else {
                    self.inner.update_session_fields(token, fields).await
                }
            } else {
                Ok(None)
            };
        };
        let Some((updated, fields)) = self
            .inner
            .prepare_secondary_session_update(session, expires_at, fields)
            .await?
        else {
            return Ok(None);
        };
        self.mirror_session_fields(token, &updated, user, Some(&fields))
            .await?;
        self.inner
            .complete_secondary_session_update(
                token,
                updated,
                expires_at,
                fields,
                self.session_uses_database(),
            )
            .await
    }
}

#[cfg(test)]
mod creation_order_tests {
    use super::*;
    use crate::store::{CacheAdapter, SessionStore};
    use crate::test_store::{BundledSchema, MemoryStore};
    use std::sync::Arc;

    #[tokio::test]
    async fn creation_indexes_before_owner_lookup_and_propagates_lookup_errors() {
        let cache = Arc::new(crate::store::MemoryCacheAdapter::new());
        let mut config = crate::AuthConfig::new("test-secret-min-32-chars-1234567");
        config.session.secondary_storage = Some(cache.clone());
        let config = Arc::new(config);
        let raw = Arc::new(MemoryStore::default());
        let session = raw
            .create_session(crate::CreateSession {
                user_id: "owner".into(),
                token: Some("indexed-before-lookup".into()),
                expires_at: Utc::now() + Duration::hours(1),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                active_team_id: None,
                additional_fields: Default::default(),
            })
            .await
            .unwrap();
        let context = crate::AuthContext::new(config.clone(), raw.clone());
        let store = PluginStore::<BundledSchema>::new(
            raw,
            config,
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            context,
        );
        let result = store
            .mirror_session_creation(
                &session,
                session.created_at(),
                &FieldValues::new(),
                &AdapterOutput::default(),
                async {
                    let index = cache.get("active-sessions-owner").await?.unwrap();
                    assert!(index.contains(session.token()));
                    Err(AuthError::internal("owner lookup failed"))
                },
            )
            .await;
        assert!(
            matches!(result, Err(AuthError::Internal(message)) if message == "owner lookup failed")
        );
        assert!(cache.get(session.token()).await.unwrap().is_none());
    }
}
