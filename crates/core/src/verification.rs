//! Initialized verification policy, raw snapshots and adapter publication phases.
//!
//! Adapter models remain physical database projections. Secondary-only values
//! carry the actual admitted data, including an absent primary ID.

use crate::{
    AuthContext, AuthError, AuthResult, AuthSchema, AuthVerification, CreateVerification,
    UpdateVerification,
    config::VerificationConfig,
    store::{AuthStore, AuthTransaction, CacheAdapter},
    utils::json::{self, JsValue},
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use indexmap::IndexMap;
use sha2::{Digest, Sha256};
use std::{any::Any, fmt, sync::Arc};

/// Application-owned asynchronous identifier transform. Errors stop the
/// operation before any cache or database mutation.
#[async_trait]
pub trait VerificationIdentifierHasher: Send + Sync {
    async fn hash(&self, identifier: &str) -> AuthResult<String>;
}

#[derive(Clone, Default)]
pub enum VerificationIdentifierStrategy {
    #[default]
    Plain,
    Hashed,
    Custom(Arc<dyn VerificationIdentifierHasher>),
}
impl fmt::Debug for VerificationIdentifierStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Plain => "Plain",
            Self::Hashed => "Hashed",
            Self::Custom(_) => "Custom",
        })
    }
}
impl VerificationIdentifierStrategy {
    async fn process(&self, identifier: &str) -> AuthResult<String> {
        match self {
            Self::Plain => Ok(identifier.to_owned()),
            Self::Hashed => Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(identifier.as_bytes()))),
            Self::Custom(hasher) => hasher.hash(identifier).await,
        }
    }
}

/// Prefix overrides have JavaScript Object.entries order: integer keys first
/// in numeric order, then other keys in their registered insertion order.
#[derive(Clone, Debug, Default)]
pub struct VerificationIdentifierPolicy {
    pub default: VerificationIdentifierStrategy,
    pub overrides: IndexMap<String, VerificationIdentifierStrategy>,
}
impl VerificationIdentifierPolicy {
    fn strategy(&self, identifier: &str) -> &VerificationIdentifierStrategy {
        let integer_key = |key: &str| {
            key.parse::<u32>()
                .ok()
                .filter(|number| *number != u32::MAX && number.to_string() == key)
        };
        let mut integers: Vec<_> = self
            .overrides
            .iter()
            .filter_map(|(key, value)| integer_key(key).map(|number| (number, key, value)))
            .collect();
        integers.sort_by_key(|entry| entry.0);
        for (_, key, value) in integers {
            if identifier.starts_with(key) {
                return value;
            }
        }
        self.overrides
            .iter()
            .find(|(key, _)| integer_key(key).is_none() && identifier.starts_with(key.as_str()))
            .map_or(&self.default, |(_, value)| value)
    }
}

/// Trusted creation candidate supplied to adapter hooks before persistence.
/// Dates and an explicitly supplied primary ID survive hook transformations.
#[derive(Clone, Debug)]
pub struct VerificationCreation {
    pub id: Option<String>,
    pub identifier: String,
    pub value: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl From<CreateVerification> for VerificationCreation {
    fn from(data: CreateVerification) -> Self {
        let now = Utc::now();
        Self {
            id: None,
            identifier: data.identifier,
            value: data.value,
            expires_at: data.expires_at,
            created_at: now,
            updated_at: now,
        }
    }
}
impl VerificationCreation {
    #[must_use]
    pub fn data(&self) -> CreateVerification {
        CreateVerification {
            identifier: self.identifier.clone(),
            value: self.value.clone(),
            expires_at: self.expires_at,
        }
    }
    #[must_use]
    pub fn snapshot(&self) -> VerificationSnapshot {
        let mut fields = IndexMap::new();
        if let Some(id) = &self.id {
            drop(fields.insert("id".into(), JsValue::String(id.clone())));
        }
        for (key, value) in [
            ("identifier", self.identifier.clone()),
            ("value", self.value.clone()),
            ("expiresAt", date_json(self.expires_at)),
            ("createdAt", date_json(self.created_at)),
            ("updatedAt", date_json(self.updated_at)),
        ] {
            drop(fields.insert(key.into(), JsValue::String(value)));
        }
        VerificationSnapshot {
            data: JsValue::Object(fields),
            expiry: Some(self.expires_at.timestamp_millis()),
            physical_expiry: None,
            original_model: None,
        }
    }
}

/// Actual verification data, without manufacturing a database model or ID.
/// Cached find preserves every truthy JSON value and safeJSONParse's ISO date
/// reviver. Consume separately hydrates expiresAt before its liveness gate.
#[derive(Clone)]
pub struct VerificationSnapshot {
    data: JsValue,
    expiry: Option<i64>,
    physical_expiry: Option<DateTime<Utc>>,
    original_model: Option<Arc<dyn Any + Send + Sync>>,
}
impl fmt::Debug for VerificationSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerificationSnapshot")
            .field("data", &self.data)
            .field("physical", &self.original_model.is_some())
            .finish()
    }
}
impl VerificationSnapshot {
    #[must_use]
    pub fn from_model<T: AuthVerification + Clone + Send + Sync + 'static>(model: &T) -> Self {
        let creation = VerificationCreation {
            id: Some(model.id().into_owned()),
            identifier: model.identifier().to_owned(),
            value: model.value().to_owned(),
            expires_at: model.expires_at(),
            created_at: model.created_at(),
            updated_at: model.updated_at(),
        };
        let mut snapshot = creation.snapshot();
        snapshot.physical_expiry = Some(model.expires_at());
        snapshot.original_model = Some(Arc::new(model.clone()));
        snapshot
    }
    #[must_use]
    pub fn data(&self) -> &JsValue {
        &self.data
    }
    #[must_use]
    pub fn original_model<T: Any>(&self) -> Option<&T> {
        self.original_model.as_ref()?.downcast_ref()
    }
    /// An absent ID is a real secondary-only snapshot, not a synthetic ID.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.data.get("id").and_then(JsValue::as_str)
    }
    pub fn identifier(&self) -> AuthResult<&str> {
        self.text("identifier")
    }
    pub fn value(&self) -> AuthResult<&str> {
        self.text("value")
    }
    fn text(&self, key: &str) -> AuthResult<&str> {
        self.data
            .get(key)
            .and_then(JsValue::as_str)
            .ok_or_else(|| AuthError::internal(format!("verification {key} is not a string")))
    }
    pub fn expires_at(&self) -> AuthResult<DateTime<Utc>> {
        if let Some(expiry) = self.physical_expiry {
            return Ok(expiry);
        }
        let millis = self
            .expiry
            .or_else(|| date_value(self.data.get("expiresAt")))
            .ok_or_else(|| AuthError::internal("verification expiry is not a valid date"))?;
        DateTime::from_timestamp_millis(millis).ok_or_else(|| {
            AuthError::NotImplemented(
                "The verification expiry is outside the physical model date range".into(),
            )
        })
    }
    /// Source compares the actual cached field to a Date. ISO-Z values were
    /// revived; other strings retain their numeric relational coercion.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let expiry = self.expiry.map_or_else(
            || number(self.data.get("expiresAt")),
            |millis| millis as f64,
        );
        expiry < Utc::now().timestamp_millis() as f64
    }
    fn cached(raw: &str) -> Option<Self> {
        let mut data = json::parse_value(raw).ok()?;
        if !truthy(&data) {
            return None;
        }
        let expiry = data
            .get("expiresAt")
            .and_then(JsValue::as_str)
            .and_then(crate::cache::date::parse)
            .map(|date| date.timestamp_millis());
        crate::cache::date::revive(&mut data);
        Some(Self {
            data,
            expiry,
            physical_expiry: None,
            original_model: None,
        })
    }
    fn hydrate(mut self) -> Option<Self> {
        let expiry = self
            .expiry
            .or_else(|| date_value(self.data.get("expiresAt")))?;
        self.expiry = Some(expiry);
        if let JsValue::Object(fields) = &mut self.data {
            drop(fields.insert(
                "expiresAt".into(),
                JsValue::String(crate::utils::datetime::json_date_millis(expiry)),
            ));
        }
        Some(self)
    }
}

/// The adapter owns this phase between its real write and after-create hooks.
/// It is also used inside transactions, before commit/deferred after hooks.
#[derive(Clone)]
pub struct VerificationPublication {
    pub store_in_database: bool,
    pub secondary_storage: Option<Arc<dyn CacheAdapter>>,
    pub cache_key: String,
}
impl VerificationPublication {
    pub async fn publish(&self, snapshot: &VerificationSnapshot) -> AuthResult<()> {
        if let Some(cache) = &self.secondary_storage
            && let Some(expiry) = snapshot
                .expiry
                .or_else(|| date_value(snapshot.data.get("expiresAt")))
        {
            let ttl = (expiry - Utc::now().timestamp_millis()).div_euclid(1000);
            if ttl > 0 {
                cache
                    .set(
                        &self.cache_key,
                        &json::to_string(snapshot.data())?,
                        Duration::seconds(ttl),
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

pub struct VerificationService<'a, S: AuthSchema> {
    config: &'a VerificationConfig,
    database: &'a dyn AuthStore<S>,
}
impl<S: AuthSchema> AuthContext<S> {
    #[must_use]
    pub fn verifications(&self) -> VerificationService<'_, S> {
        VerificationService {
            config: &self.config.verification,
            database: self.database.as_ref(),
        }
    }
}
impl<S: AuthSchema> VerificationService<'_, S> {
    fn physical(&self) -> bool {
        self.config.secondary_storage.is_none() || self.config.store_in_database
    }
    async fn identifiers(&self, identifier: &str) -> AuthResult<Vec<String>> {
        let strategy = self.config.store_identifier.strategy(identifier);
        let stored = strategy.process(identifier).await?;
        let mut identifiers = vec![stored];
        if !matches!(strategy, VerificationIdentifierStrategy::Plain) {
            identifiers.push(identifier.to_owned());
        }
        Ok(identifiers)
    }
    async fn prepare(
        &self,
        mut data: VerificationCreation,
    ) -> AuthResult<(VerificationCreation, VerificationPublication)> {
        data.identifier = self
            .config
            .store_identifier
            .strategy(&data.identifier)
            .process(&data.identifier)
            .await?;
        let publication = VerificationPublication {
            store_in_database: self.physical(),
            secondary_storage: self.config.secondary_storage.clone(),
            cache_key: key(&data.identifier),
        };
        Ok((data, publication))
    }
    pub async fn create(
        &self,
        data: impl Into<VerificationCreation>,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        let (data, publication) = self.prepare(data.into()).await?;
        self.database
            .create_verification_record(data, publication)
            .await
    }
    pub async fn create_in_transaction(
        &self,
        tx: &dyn AuthTransaction<S>,
        data: impl Into<VerificationCreation>,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        let (data, publication) = self.prepare(data.into()).await?;
        tx.create_verification_record(data, publication).await
    }
    pub async fn find(&self, identifier: &str) -> AuthResult<Option<VerificationSnapshot>> {
        let identifiers = self.identifiers(identifier).await?;
        if let Some(cache) = &self.config.secondary_storage {
            for stored in &identifiers {
                if let Some(snapshot) = cache
                    .get(&key(stored))
                    .await?
                    .as_deref()
                    .and_then(VerificationSnapshot::cached)
                {
                    return Ok(Some(snapshot));
                }
            }
            if !self.physical() {
                return Ok(None);
            }
        }
        let mut found = None;
        for stored in &identifiers {
            found = self
                .database
                .get_latest_verification_by_identifier(stored)
                .await?;
            if found.is_some() {
                break;
            }
        }
        if !self.config.disable_cleanup {
            let _deleted = self.database.delete_expired_verifications().await?;
        }
        Ok(found.as_ref().map(VerificationSnapshot::from_model))
    }
    pub async fn delete(&self, identifier: &str) -> AuthResult<()> {
        let stored = self
            .config
            .store_identifier
            .strategy(identifier)
            .process(identifier)
            .await?;
        if let Some(cache) = &self.config.secondary_storage {
            cache.delete(&key(&stored)).await?;
        }
        if self.physical() {
            self.database
                .delete_verifications_by_identifier(&stored)
                .await?;
        }
        Ok(())
    }
    pub async fn consume(&self, identifier: &str) -> AuthResult<Option<VerificationSnapshot>> {
        let identifiers = self.identifiers(identifier).await?;
        let mut consumed = None;
        if let Some(cache) = self
            .config
            .secondary_storage
            .as_ref()
            .filter(|_| !self.physical())
        {
            for stored in &identifiers {
                consumed = cache
                    .get_and_delete(&key(stored))
                    .await?
                    .as_deref()
                    .and_then(VerificationSnapshot::cached)
                    .and_then(VerificationSnapshot::hydrate);
                if consumed.is_some() {
                    for other in &identifiers {
                        if other != stored {
                            cache.delete(&key(other)).await?;
                        }
                    }
                    break;
                }
            }
        } else {
            for stored in &identifiers {
                consumed = self
                    .database
                    .consume_verification_snapshot(stored)
                    .await?
                    .as_ref()
                    .map(VerificationSnapshot::from_model);
                if consumed.is_some() {
                    break;
                }
            }
            if consumed.is_some()
                && let Some(cache) = &self.config.secondary_storage
            {
                for stored in &identifiers {
                    cache.delete(&key(stored)).await?;
                }
            }
        }
        Ok(consumed.filter(|value| !value.is_expired()))
    }
    pub async fn update(
        &self,
        identifier: &str,
        data: UpdateVerification,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        let stored = self
            .config
            .store_identifier
            .strategy(identifier)
            .process(identifier)
            .await?;
        if let Some(cache) = &self.config.secondary_storage
            && let Some(mut snapshot) = cache
                .get(&key(&stored))
                .await?
                .as_deref()
                .and_then(VerificationSnapshot::cached)
        {
            let mut fields = spread(&snapshot.data);
            patch(&mut fields, &data);
            snapshot.data = JsValue::Object(fields);
            snapshot.expiry = date_value(snapshot.data.get("expiresAt"));
            let publication = VerificationPublication {
                store_in_database: self.physical(),
                secondary_storage: Some(cache.clone()),
                cache_key: key(&stored),
            };
            publication.publish(&snapshot).await?;
            if !self.physical() {
                return Ok(Some(snapshot));
            }
        }
        if self.physical() {
            self.database
                .update_verification_by_identifier(&stored, data)
                .await
        } else {
            let mut fields = IndexMap::new();
            patch(&mut fields, &data);
            Ok(Some(VerificationSnapshot {
                data: JsValue::Object(fields),
                expiry: data.expires_at.map(|date| date.timestamp_millis()),
                physical_expiry: None,
                original_model: None,
            }))
        }
    }
    pub async fn reserve(&self, mut data: CreateVerification) -> AuthResult<bool> {
        let logical = data.identifier.clone();
        data.identifier = self
            .config
            .store_identifier
            .strategy(&logical)
            .process(&logical)
            .await?;
        if !self.physical() {
            return Err(AuthError::internal(
                "reserveVerificationValue requires database-backed verification storage. Set verification.storeInDatabase to true for flows that reserve verification values.",
            ));
        }
        let Some(model) = self
            .database
            .reserve_verification_record(&logical, data)
            .await?
        else {
            return Ok(false);
        };
        let mut snapshot = VerificationSnapshot::from_model(&model);
        if let JsValue::Object(fields) = &mut snapshot.data {
            drop(fields.shift_remove("createdAt"));
            drop(fields.shift_remove("updatedAt"));
        }
        VerificationPublication {
            store_in_database: true,
            secondary_storage: self.config.secondary_storage.clone(),
            cache_key: key(model.identifier()),
        }
        .publish(&snapshot)
        .await?;
        Ok(true)
    }
}

fn date_json(date: DateTime<Utc>) -> String {
    date.to_rfc3339_opts(SecondsFormat::Millis, true)
}
fn key(identifier: &str) -> String {
    format!("verification:{identifier}")
}
fn truthy(value: &JsValue) -> bool {
    match value {
        JsValue::Null => false,
        JsValue::Bool(value) => *value,
        JsValue::Number(value) => *value != 0.0 && !value.is_nan(),
        JsValue::String(value) => !value.is_empty(),
        JsValue::Array(_) | JsValue::Object(_) => true,
    }
}
fn number(value: Option<&JsValue>) -> f64 {
    match value {
        Some(JsValue::Null) => 0.0,
        Some(JsValue::Bool(value)) => f64::from(u8::from(*value)),
        Some(JsValue::Number(value)) => *value,
        Some(JsValue::String(value)) => {
            crate::utils::javascript::string_to_number(value).unwrap_or(f64::NAN)
        }
        Some(JsValue::Array(values)) => {
            crate::utils::javascript::string_to_number(&array_string(values)).unwrap_or(f64::NAN)
        }
        _ => f64::NAN,
    }
}
fn date_value(value: Option<&JsValue>) -> Option<i64> {
    match value {
        Some(JsValue::String(value)) => crate::utils::datetime::parse_date_millis(value),
        Some(JsValue::Array(values)) => {
            crate::utils::datetime::parse_date_millis(&array_string(values))
        }
        Some(JsValue::Object(_)) | None => None,
        _ => {
            let millis = number(value);
            if millis.is_finite() && millis.abs() <= 8_640_000_000_000_000.0 {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "JavaScript Date TimeClip truncates finite milliseconds within its exact range"
                )]
                Some(millis.trunc() as i64)
            } else {
                None
            }
        }
    }
}
fn array_string(values: &[JsValue]) -> String {
    values
        .iter()
        .map(|value| match value {
            JsValue::Null => String::new(),
            JsValue::Bool(value) => value.to_string(),
            JsValue::Number(value) => ryu_js::Buffer::new().format(*value).to_owned(),
            JsValue::String(value) => value.clone(),
            JsValue::Array(values) => array_string(values),
            JsValue::Object(_) => "[object Object]".into(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn spread(value: &JsValue) -> IndexMap<String, JsValue> {
    match value {
        JsValue::Object(fields) => fields.clone(),
        JsValue::Array(values) => values
            .iter()
            .enumerate()
            .map(|(index, value)| (index.to_string(), value.clone()))
            .collect(),
        JsValue::String(value) => value
            .chars()
            .enumerate()
            .map(|(index, value)| (index.to_string(), JsValue::String(value.to_string())))
            .collect(),
        _ => IndexMap::new(),
    }
}
fn patch(fields: &mut IndexMap<String, JsValue>, data: &UpdateVerification) {
    if let Some(value) = &data.value {
        drop(fields.insert("value".into(), JsValue::String(value.clone())));
    }
    if let Some(expires) = data.expires_at {
        drop(fields.insert("expiresAt".into(), JsValue::String(date_json(expires))));
    }
}
