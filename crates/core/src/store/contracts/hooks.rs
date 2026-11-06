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

/// An ordered, asynchronous user creation hook after identity admission.
/// Transactional hooks must use the supplied transaction for database operations.
#[async_trait]
pub trait UserCreateHook<S: AuthSchema>: Send + Sync {
    async fn before_create(
        &self,
        input: CreateUser,
        context: &crate::AuthContext<S>,
        transaction: Option<&dyn crate::AuthTransaction<S>>,
    ) -> AuthResult<CreateUser>;
}

pub(crate) enum UserCreateStep<S: AuthSchema> {
    Transform(UserCreateTransform),
    Hook(Arc<dyn UserCreateHook<S>>),
}

impl<S: AuthSchema> Clone for UserCreateStep<S> {
    fn clone(&self) -> Self {
        match self {
            Self::Transform(transform) => Self::Transform(Arc::clone(transform)),
            Self::Hook(hook) => Self::Hook(Arc::clone(hook)),
        }
    }
}

pub(in crate::store) async fn create_user_data<S: AuthSchema>(
    mut data: CreateUser,
    steps: &[UserCreateStep<S>],
    context: &crate::AuthContext<S>,
    transaction: Option<&dyn crate::AuthTransaction<S>>,
) -> AuthResult<CreateUser> {
    for step in steps {
        data = match step {
            UserCreateStep::Transform(transform) => {
                let before = data.clone();
                let mut transformed = transform(data)?;
                transformed.reconcile_native_shadows(&before);
                transformed
            }
            UserCreateStep::Hook(hook) => hook.before_create(data, context, transaction).await?,
        };
    }
    Ok(data)
}

/// An ordered asynchronous user update hook. Transactional reads must use the
/// supplied transaction, not a root store checkout.
#[async_trait]
pub trait UserUpdateHook<S: AuthSchema>: Send + Sync {
    async fn before_update(
        &self,
        id: &str,
        input: crate::UpdateUser,
        context: &crate::AuthContext<S>,
        transaction: Option<&dyn crate::AuthTransaction<S>>,
    ) -> AuthResult<crate::UpdateUser>;
}

pub(crate) enum UserUpdateStep<S: AuthSchema> {
    Transform(Arc<dyn Fn(&str, crate::UpdateUser) -> AuthResult<crate::UpdateUser> + Send + Sync>),
    Hook(Arc<dyn UserUpdateHook<S>>),
}

impl<S: AuthSchema> Clone for UserUpdateStep<S> {
    fn clone(&self) -> Self {
        match self {
            Self::Transform(transform) => Self::Transform(Arc::clone(transform)),
            Self::Hook(hook) => Self::Hook(Arc::clone(hook)),
        }
    }
}

pub(in crate::store) async fn update_user_data<S: AuthSchema>(
    id: &str,
    mut data: crate::UpdateUser,
    steps: &[UserUpdateStep<S>],
    context: &crate::AuthContext<S>,
    transaction: Option<&dyn crate::AuthTransaction<S>>,
) -> AuthResult<crate::UpdateUser> {
    for step in steps {
        data = match step {
            UserUpdateStep::Transform(transform) => {
                let before = data.clone();
                let mut transformed = transform(id, data)?;
                transformed.reconcile_native_shadows(&before);
                transformed
            }
            UserUpdateStep::Hook(hook) => {
                hook.before_update(id, data, context, transaction).await?
            }
        };
    }
    Ok(data)
}

/// Guard creation and observe successfully persisted sessions.
/// Before hooks must use the supplied transaction for transactional reads/writes.
/// After hooks run only after commit; their errors do not roll back the write.
#[async_trait]
pub trait SessionCreatedHook<S: AuthSchema>: Send + Sync {
    async fn before_create(
        &self,
        _input: &crate::CreateSession,
        _context: &crate::AuthContext<S>,
        _transaction: Option<&dyn crate::AuthTransaction<S>>,
    ) -> AuthResult<()> {
        Ok(())
    }

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
