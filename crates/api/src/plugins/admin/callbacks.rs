//! Application messages for banned users, resolved from the stored user entity.
use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResult, entity::AuthUser};
use std::{
    any::{Any, TypeId},
    fmt,
    sync::Arc,
};

/// Resolves the message returned when a nonexpired banned user requests a session.
///
/// The user is the stored application entity, including fields hidden from HTTP
/// responses. This callback is awaited before any new session is created. Errors
/// are propagated as authentication framework errors, retaining their status.
#[async_trait]
pub trait AdminBannedUserMessage<U: AuthUser>: Send + Sync + 'static {
    async fn message(&self, user: &U) -> AuthResult<String>;
}

#[async_trait]
trait ErasedMessage: Send + Sync {
    fn user_type(&self) -> TypeId;
    async fn message(&self, user: &(dyn Any + Send + Sync)) -> AuthResult<String>;
}
struct TypedMessage<U, H> {
    handler: H,
    marker: std::marker::PhantomData<fn() -> U>,
}
#[async_trait]
impl<U: AuthUser, H: AdminBannedUserMessage<U>> ErasedMessage for TypedMessage<U, H> {
    fn user_type(&self) -> TypeId {
        TypeId::of::<U>()
    }
    async fn message(&self, user: &(dyn Any + Send + Sync)) -> AuthResult<String> {
        let user = user.downcast_ref::<U>().ok_or_else(|| AuthError::config(
            "Admin banned-user message callback user type does not match the authentication schema"
        ))?;
        self.handler.message(user).await
    }
}

/// Cloneable, type-checked application callback configuration.
#[derive(Clone)]
pub struct AdminBannedUserMessageHandler(Arc<dyn ErasedMessage>);
impl fmt::Debug for AdminBannedUserMessageHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminBannedUserMessageHandler(..)")
    }
}
impl AdminBannedUserMessageHandler {
    /// Stores a callback for the exact user entity of the application's schema.
    #[must_use]
    pub fn new<U: AuthUser, H: AdminBannedUserMessage<U>>(handler: H) -> Self {
        Self(Arc::new(TypedMessage::<U, H> {
            handler,
            marker: std::marker::PhantomData,
        }))
    }
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) fn validate<U: AuthUser>(&self) -> AuthResult<()> {
        if self.0.user_type() != TypeId::of::<U>() {
            return Err(AuthError::config(
                "Admin banned-user message callback user type does not match the authentication schema",
            ));
        }
        Ok(())
    }
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn message<U: AuthUser>(&self, user: &U) -> AuthResult<String> {
        self.0.message(user).await
    }
}

#[derive(Clone)]
pub(in crate::plugins) struct BannedUserMessagePolicy(pub(super) AdminBannedUserMessageHandler);
impl BannedUserMessagePolicy {
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(in crate::plugins) async fn message<U: AuthUser>(&self, user: &U) -> AuthResult<String> {
        self.0.message(user).await
    }
}
