//! Ordinary local sign-out retires the active session's SAML tracking records.
use super::{AuthContext, AuthResult, AuthSchema, SsoPlugin};
impl SsoPlugin {
    pub(super) async fn clear_saml_signout_tracking<S: AuthSchema>(
        &self,
        request: &impl alibi_core::session::SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        // The source's nested session getter treats lookup errors as no session.
        let Ok((_, session)) = ctx.require_cached_session(request).await else {
            return Ok(());
        };
        let lookup = format!("saml-session-by-id:{}", session.id);
        if let Some(record) = ctx.verifications().find(&lookup).await? {
            let key = record.value()?.to_owned();
            if key.is_empty() {
                return Ok(());
            }
            // Both deletes are best effort; a cleanup failure must not prevent sign-out.
            _ = ctx.verifications().delete(&key).await;
            _ = ctx.verifications().delete(&lookup).await;
        }
        Ok(())
    }
}
