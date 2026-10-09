use crate::AdapterRecord;
use crate::{AuthResult, AuthSchema, AuthStore, CreateUser};
use async_trait::async_trait;

/// Registered model defaults applied by an adapter after its creation hooks.
/// Keeping this phase separate preserves a validation candidate's absent fields.
#[derive(Clone, Default)]
pub struct UserCreationDefaults(pub(crate) Vec<UserCreateTransform>);
impl UserCreationDefaults {
    pub fn apply(self, data: CreateUser) -> AuthResult<CreateUser> {
        create_data(data, &self.0)
    }
}

/// Application/plugin adapter hook observing a successfully persisted session.
/// Transactional hooks execute only after commit against the finalized store,
/// including registered user transforms. Hook failures do not roll back commit.
#[async_trait]
pub trait SessionCreatedHook<S: AuthSchema>: Send + Sync {
    async fn after_create(
        &self,
        session: &S::Session,
        database: &dyn AuthStore<S>,
    ) -> AuthResult<()>;
}

/// A persisted adapter result after declared output transforms. Hidden fields
/// remain present; public response filtering has not run on this record.
pub enum AdapterEvent<S: AuthSchema> {
    UserCreated(AdapterRecord<S::User>),
    UserUpdated(AdapterRecord<S::User>),
    SessionCreated(AdapterRecord<S::Session>),
    SessionUpdated(AdapterRecord<S::Session>),
    AccountCreated(AdapterRecord<S::Account>),
    AccountUpdated(AdapterRecord<S::Account>),
}

/// Record-aware application adapter after observer. Output errors prevent this
/// observer; transaction observers run only after commit. Observer errors do not
/// roll back committed writes. Typed physical storage hooks remain separate.
#[async_trait]
pub trait AdapterAfterHook<S: AuthSchema>: Send + Sync {
    async fn after_write(
        &self,
        event: &AdapterEvent<S>,
        database: &dyn AuthStore<S>,
    ) -> AuthResult<()>;
}

use std::sync::Arc;

pub(crate) type UserCreateTransform =
    Arc<dyn Fn(CreateUser) -> AuthResult<CreateUser> + Send + Sync>;

pub(in crate::store) fn create_data(
    mut data: CreateUser,
    transforms: &[UserCreateTransform],
) -> AuthResult<CreateUser> {
    for transform in transforms {
        data = transform(data)?;
    }
    Ok(data)
}
