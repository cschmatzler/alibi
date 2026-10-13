//! Capture dependant tokens before a session FK is cleared; retire them after deletion.
use alibi_core::store::{OAuthTokenKind, SessionDeletionHook, SessionDeletionWork};
use alibi_core::{AuthResult, AuthSchema, AuthSession, AuthStore};
use async_trait::async_trait;
use serde_json::Value;
pub(super) struct TokenRetirementHook;
struct RetirementWork(Vec<(OAuthTokenKind, String)>);
#[async_trait]
impl<S: AuthSchema> SessionDeletionHook<S> for TokenRetirementHook {
    async fn prepare(
        &self,
        session: &S::Session,
        database: &dyn AuthStore<S>,
    ) -> AuthResult<Option<Box<dyn SessionDeletionWork<S>>>> {
        let mut selected = Vec::new();
        for kind in [OAuthTokenKind::Access, OAuthTokenKind::Refresh] {
            let rows = match database
                .list_oauth_tokens_for_session(kind, session.id().as_ref())
                .await
            {
                Ok(rows) => rows,
                Err(error) => {
                    tracing::error!(%error,"Unable to prepare OAuth session token retirement");
                    return Ok(None);
                }
            };
            for row in rows {
                let offline = row
                    .metadata
                    .get("scopes")
                    .and_then(Value::as_array)
                    .is_some_and(|scopes| {
                        scopes
                            .iter()
                            .any(|scope| scope.as_str() == Some("offline_access"))
                    });
                if row.metadata.get("revoked").is_none_or(Value::is_null)
                    && (matches!(kind, OAuthTokenKind::Access) || !offline)
                {
                    selected.push((kind, row.id));
                }
            }
        }
        Ok(if selected.is_empty() {
            None
        } else {
            Some(Box::new(RetirementWork(selected)))
        })
    }
}
#[async_trait]
impl<S: AuthSchema> SessionDeletionWork<S> for RetirementWork {
    async fn complete(&self, database: &dyn AuthStore<S>) -> AuthResult<()> {
        let at = chrono::Utc::now();
        for (kind, id) in &self.0 {
            if let Err(error) = database.mark_oauth_token_revoked(*kind, id, at).await {
                tracing::error!(%error,"Unable to retire OAuth token after session deletion");
            }
        }
        Ok(())
    }
}
