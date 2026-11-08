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
    session: crate::utils::json::JsValue,
    #[serde(default)]
    user: crate::utils::json::JsValue,
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

const SESSION_FIELDS: &[&str] = &[
    "expiresAt",
    "token",
    "createdAt",
    "updatedAt",
    "ipAddress",
    "userAgent",
    "userId",
];
const USER_FIELDS: &[&str] = &[
    "name",
    "email",
    "emailVerified",
    "image",
    "createdAt",
    "updatedAt",
];

fn ordered_snapshot(
    mut values: crate::utils::json::JsObject,
    core: &[&str],
    declared: &crate::field_policy::FieldConfigs,
    retain_unknown: bool,
) -> crate::utils::json::JsValue {
    let mut output = crate::utils::json::JsObject::new();
    for name in core
        .iter()
        .copied()
        .chain(declared.keys().map(String::as_str))
        .filter(|name| *name != "id")
    {
        if let Some(value) = values.shift_remove(name) {
            _ = output.insert(name.into(), value);
        }
    }
    let id = values.shift_remove("id");
    if retain_unknown {
        output.extend(values);
    }
    if let Some(id) = id {
        _ = output.insert("id".into(), id);
    }
    crate::utils::json::JsValue::Object(output)
}

impl<S: AuthSchema> PluginStore<S> {
    fn snapshot_absent_fields(
        &self,
        snapshot: crate::utils::json::JsValue,
    ) -> AuthResult<BTreeSet<String>> {
        let output = S::Session::output_from_secondary_snapshot(snapshot.clone())?;
        let mut absent = output
            .values()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .is_undefined()
                    .then(|| name.as_str().map(str::to_owned))
                    .flatten()
            })
            .collect::<BTreeSet<_>>();
        for name in self.adapter_fields.0.keys() {
            if snapshot.get(name.as_str()).is_none() {
                _ = absent.insert(name.clone());
            }
        }
        Ok(absent)
    }
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
        Ok(crate::utils::json::from_str(&raw).unwrap_or_default())
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
                    .set(&key, &crate::utils::json::to_string(&references)?, ttl)
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
        let Ok(snapshot) = crate::utils::json::from_storage_str::<CachedSession>(&raw) else {
            return Ok(None);
        };
        let Ok(session) = S::Session::from_secondary_snapshot_with_fields(
            snapshot.session,
            &self.adapter_fields.0,
        ) else {
            return Ok(None);
        };
        let user = if snapshot.user.is_null() {
            None
        } else {
            let policies = self.field_policies();
            let fields = &policies.user.0;
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
    ) -> AuthResult<Option<(S::Session, crate::utils::json::JsValue)>> {
        let Some(cache) = self.secondary() else {
            return Ok(None);
        };
        let Some(raw) = cache.get(token).await? else {
            return Ok(None);
        };
        let Ok(snapshot) = crate::utils::json::from_storage_str::<CachedSession>(&raw) else {
            return Ok(None);
        };
        let session = S::Session::from_secondary_snapshot_with_fields(
            snapshot.session,
            &self.adapter_fields.0,
        )?;
        Ok(Some((session, snapshot.user)))
    }

    pub(super) async fn mirror_session_fields(
        &self,
        token: &str,
        session: &S::Session,
        user: crate::utils::json::JsValue,
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
        user: crate::utils::json::JsValue,
        updated_fields: Option<&FieldValues>,
        created_at: Option<DateTime<Utc>>,
        native: Option<&AdapterOutput>,
        ttl: Duration,
    ) -> AuthResult<()> {
        let Some(cache) = self.secondary() else {
            return Ok(());
        };
        let Some(created_at) = created_at else {
            let crate::utils::json::JsValue::Object(model) = session.secondary_snapshot()? else {
                return Err(AuthError::internal("Invalid secondary session snapshot"));
            };
            let mut values = if let Some(raw) = cache.get(token).await? {
                crate::utils::json::from_storage_str::<CachedSession>(&raw)?.session
            } else {
                ordered_snapshot(
                    model.clone(),
                    SESSION_FIELDS,
                    &self.adapter_fields.0,
                    !self.session_uses_database(),
                )
            };
            let Some(values) = values.as_object_mut() else {
                return Err(AuthError::internal("Invalid secondary session snapshot"));
            };
            if let Some(fields) = updated_fields {
                values.extend(
                    fields
                        .iter()
                        .filter(|(name, _)| {
                            !matches!(name.as_str(), "expiresAt" | "createdAt" | "updatedAt")
                        })
                        .map(|(name, value)| (name.clone().into(), value.clone())),
                );
            }
            // The mirror revives expiry and update clocks before SQL policies;
            // its creation clock remains the one already stored in the cache.
            for name in ["expiresAt", "updatedAt"] {
                if let Some(value) = model.get(name) {
                    _ = values.insert(name.into(), value.clone());
                }
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
                    _ = values.shift_remove(name.as_str());
                }
            }
            let snapshot = CachedSession {
                session: crate::utils::json::JsValue::Object(values.clone()),
                user,
            };
            cache
                .set(token, &crate::utils::json::to_string(&snapshot)?, ttl)
                .await?;
            return Ok(());
        };
        let mut absent_fields = if let Some(raw) = cache.get(token).await? {
            let cached: CachedSession = crate::utils::json::from_storage_str(&raw)?;
            self.snapshot_absent_fields(cached.session)?
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
            for (name, value) in session.additional_js_fields()? {
                let Some(name) = name.as_str() else {
                    continue;
                };
                if value.is_null()
                    && self
                        .config
                        .session
                        .additional_fields
                        .get(name)
                        .is_none_or(|field| field.default.is_none())
                {
                    _ = absent.insert(name.to_owned());
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
        let session_snapshot = match native {
            Some(native) => {
                session.secondary_snapshot_for_creation_with_native_output(created_at, native)?
            }
            None => session.secondary_snapshot_for_creation(created_at)?,
        };
        let crate::utils::json::JsValue::Object(mut values) = session_snapshot else {
            return Err(AuthError::internal("Invalid secondary session snapshot"));
        };
        for name in absent_fields {
            _ = values.shift_remove(name.as_str());
        }
        let snapshot = CachedSession {
            session: ordered_snapshot(
                values,
                SESSION_FIELDS,
                &self.adapter_fields.0,
                !self.session_uses_database(),
            ),
            user,
        };
        cache
            .set(token, &crate::utils::json::to_string(&snapshot)?, ttl)
            .await?;
        Ok(())
    }

    pub(super) async fn secondary_session_output(&self, token: &str) -> AuthResult<AdapterOutput> {
        let cache = self
            .secondary()
            .ok_or_else(|| AuthError::internal("No secondary session storage"))?;
        let raw = cache.get(token).await?.ok_or(AuthError::SessionNotFound)?;
        let snapshot: CachedSession = crate::utils::json::from_storage_str(&raw)?;
        let absent = self.snapshot_absent_fields(snapshot.session.clone())?;
        let mut output = S::Session::output_from_secondary_snapshot(snapshot.session)?;
        for name in absent {
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
        let cached: CachedSession = crate::utils::json::from_storage_str(&raw)?;
        self.snapshot_absent_fields(cached.session)
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
        // The source mirror reads getTime() on the original creation input,
        // after SQL conversion, not on the returned storage model.
        let expires_at = match creation_fields.get("expiresAt") {
            Some(crate::utils::json::JsValue::Date(date)) => *date,
            value => {
                let message = match value {
                    Some(crate::utils::json::JsValue::Null) => {
                        "Cannot read properties of null (reading 'getTime')"
                    }
                    None | Some(crate::utils::json::JsValue::Undefined) => {
                        "Cannot read properties of undefined (reading 'getTime')"
                    }
                    _ => "data.expiresAt.getTime is not a function",
                };
                return Err(crate::store::adapter::callback_error(AuthError::internal(
                    message,
                )));
            }
        };
        let now = Utc::now();
        let mut references = self.references(session.user_id().as_ref()).await?;
        references.retain(|reference| reference.token != session.token());
        references.push(Reference {
            token: session.token().to_owned(),
            expires_at,
        });
        self.write_references(session.user_id().as_ref(), references)
            .await?;
        let user = user.await?;
        let ttl = Duration::seconds(
            (expires_at.timestamp_millis() - now.timestamp_millis())
                .div_euclid(1000)
                .max(0),
        );
        if ttl > Duration::zero() {
            let user = match user {
                Some(user) => {
                    let record = self
                        .user_record_with_native_output(
                            user.stored().clone(),
                            user.raw_snapshot().clone(),
                        )
                        .await?;
                    ordered_snapshot(
                        record.raw_snapshot().values().clone(),
                        USER_FIELDS,
                        &self.field_policies().user.0,
                        false,
                    )
                }
                None => crate::utils::json::JsValue::Null,
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
        let Ok(snapshot) = crate::utils::json::from_storage_str::<CachedSession>(&raw) else {
            return Ok(None);
        };
        // findSessions reads user dates; listSessions never reads the owner.
        if require_owner && snapshot.user.is_null() {
            return Ok(None);
        }
        let Ok(session) = S::Session::from_secondary_snapshot_with_fields(
            snapshot.session.clone(),
            &self.adapter_fields.0,
        ) else {
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
        let absent = self.snapshot_absent_fields(snapshot.session.clone())?;
        let mut output = S::Session::output_from_secondary_snapshot(snapshot.session)?;
        output.insert(
            "expiresAt".into(),
            Some(crate::utils::json::JsValue::String(
                crate::utils::datetime::json_date_millis(session.expires_at().timestamp_millis())
                    .into(),
            )),
        );
        for name in absent {
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
        let mut user_snapshot: Option<crate::utils::json::JsValue> = None;
        for session in self.cached_user_sessions(user.id().as_ref()).await? {
            let Some(raw) = cache.get(session.token()).await? else {
                continue;
            };
            let Ok(mut snapshot) = crate::utils::json::from_storage_str::<CachedSession>(&raw)
            else {
                continue;
            };
            let ttl = Duration::seconds((session.expires_at() - now).num_seconds());
            if ttl > Duration::zero() {
                snapshot.user = match &user_snapshot {
                    Some(snapshot) => snapshot.clone(),
                    None => {
                        let native = AdapterOutput::from_js_values(
                            self.inner
                                .native_user_output_for(user)
                                .await?
                                .into_iter()
                                .map(|(name, value)| (name.into(), value))
                                .collect(),
                        );
                        let record = self
                            .user_record_with_native_output(user.clone(), native)
                            .await?;
                        let snapshot = ordered_snapshot(
                            record.raw_snapshot().values().clone(),
                            USER_FIELDS,
                            &self.field_policies().user.0,
                            false,
                        );
                        user_snapshot = Some(snapshot.clone());
                        snapshot
                    }
                };
                cache
                    .set(
                        session.token(),
                        &crate::utils::json::to_string(&snapshot)?,
                        ttl,
                    )
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
        let mut creation_fields = FieldValues::new();
        _ = creation_fields.insert(
            "expiresAt".to_owned(),
            crate::utils::json::JsValue::Date(session.expires_at()),
        );
        let result = store
            .mirror_session_creation(
                &session,
                session.created_at(),
                &creation_fields,
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
