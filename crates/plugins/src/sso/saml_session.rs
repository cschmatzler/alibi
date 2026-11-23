use alibi_core::store::{AdapterAfterHook, AdapterEvent};
use alibi_core::{
    AuthContext, AuthResult, AuthSchema, AuthSession, AuthStore, AuthVerification,
    UpdateVerification,
};
use serde_json::Value;

pub(super) struct ExtendSamlSession<S: AuthSchema>(pub AuthContext<S>);

#[async_trait::async_trait]
impl<S: AuthSchema> AdapterAfterHook<S> for ExtendSamlSession<S> {
    async fn after_write(
        &self,
        event: &AdapterEvent<S>,
        _: &dyn AuthStore<S>,
    ) -> AuthResult<()> {
        if let AdapterEvent::SessionUpdated(record) = event
            && let Err(error) = self.extend(record.stored()).await
        {
            tracing::warn!(%error, "Failed to extend SAML session records");
        }
        Ok(())
    }
}

impl<S: AuthSchema> ExtendSamlSession<S> {
    async fn extend(&self, session: &S::Session) -> AuthResult<()> {
        let id = session.id();
        let lookup_key = format!("saml-session-by-id:{id}");
        let verifications = self.0.verifications();
        let Some(lookup) = verifications.find(&lookup_key).await? else {
            return Ok(());
        };
        let expires_at = session.expires_at();
        if lookup.expires_at()? >= expires_at {
            return Ok(());
        }
        let key = lookup.value()?;
        let expiry = || UpdateVerification {
            expires_at: Some(expires_at),
            ..Default::default()
        };
        if let Some(latest) = verifications.find(key).await? {
            let owns = |value: &str| {
                serde_json::from_str::<Value>(value).is_ok_and(|data| {
                    data.get("sessionId").and_then(Value::as_str) == Some(id.as_ref())
                })
            };
            let config = &self.0.config.verification;
            if config.secondary_storage.is_some() && !config.store_in_database {
                // The cache holds only the latest sign-in for a NameID.
                if owns(latest.value()?) {
                    _ = verifications.update(key, expiry()).await?;
                }
            } else {
                // Each sign-in adds a generation. Update only the row belonging
                // to this session and leave the shared cache entry to expire.
                const PAGE_SIZE: u32 = 100;
                let identifier = latest.identifier()?;
                for offset in (0..).step_by(PAGE_SIZE as usize) {
                    let page = self
                        .0
                        .database
                        .list_verifications_by_identifier(identifier, PAGE_SIZE, offset)
                        .await?;
                    if let Some(row) = page.iter().find(|row| owns(row.value())) {
                        if row.expires_at() < expires_at {
                            _ = self
                                .0
                                .database
                                .compare_and_swap_verification(
                                    row.id().as_ref(),
                                    row.value(),
                                    row.value(),
                                    expires_at,
                                )
                                .await?;
                        }
                        break;
                    }
                    if page.len() < PAGE_SIZE as usize {
                        break;
                    }
                }
            }
        }
        // The lookup gates the early return, so write it after the owned row.
        _ = verifications.update(&lookup_key, expiry()).await?;
        Ok(())
    }
}
