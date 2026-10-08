//! Application-owned adapter wrapper delegates every required operation to the selected real SQL store.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::{DeviceAuthorizationPlugin, EmailPasswordPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema};
use alibi_core::store::*;
use alibi_core::types::*;
use alibi_seaorm::DatabaseConnection;
use axum::{Json, Router, routing::post};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
#[derive(Default)]
struct State {
    mode: String,
    events: Vec<String>,
}
struct DeviceApplication {
    selector: Mutex<(String, String)>,
    events: Mutex<Vec<Value>>,
    first: tokio::sync::watch::Sender<bool>,
}
impl Default for DeviceApplication {
    fn default() -> Self {
        Self {
            selector: Mutex::new((String::new(), String::new())),
            events: Mutex::new(Vec::new()),
            first: tokio::sync::watch::channel(true).0,
        }
    }
}
async fn wait_device_gate(signal: &tokio::sync::watch::Sender<bool>) -> AuthResult<()> {
    let mut receiver = signal.subscribe();
    while !*receiver.borrow_and_update() {
        receiver
            .changed()
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
    }
    Ok(())
}
struct ApplicationStore {
    inner: Arc<dyn AuthStore<TestSchema>>,
    state: Arc<Mutex<State>>,
    device: Arc<DeviceApplication>,
}
impl ApplicationStore {
    fn check(&self, operation: &str) -> AuthResult<()> {
        let mut state = self.state.lock().unwrap();
        if !state.mode.is_empty()
            && [
                "get_session",
                "get_user_sessions",
                "delete_session",
                "delete_user_sessions",
                "get_user_by_email",
            ]
            .contains(&operation)
        {
            state.events.push(operation.into());
        }
        if state.mode == operation {
            return Err(AuthError::internal(
                "application-selected-session-adapter-failure",
            ));
        }
        Ok(())
    }
}
// The wrapper changes only its selected error policy; successful reads/writes use the actual selected backend.
macro_rules! forward {
    ($trait:ident $(<$schema:ty>)? { $(async fn $method:ident (&self $(, $arg:ident: $input:ty)*) -> $output:ty;)* }) => {
        #[async_trait::async_trait]
        impl $trait $(<$schema>)? for ApplicationStore {
            $(async fn $method(&self $(, $arg: $input)*) -> $output {
                self.check(stringify!($method))?;
                self.inner.$method($($arg),*).await
            })*
        }
    };
}
forward!(PasskeyStore {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey>;
    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>>;
    async fn get_passkey_by_credential_id( &self, credential_id: &str ) -> AuthResult<Option<Passkey>>;
    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>>;
    async fn update_passkey_authentication( &self, id: &str, update: UpdatePasskeyAuthentication ) -> AuthResult<Option<Passkey>>;
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey>;
    async fn delete_passkey(&self, id: &str) -> AuthResult<()>;
});

forward!(UserStore<TestSchema> {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<<TestSchema as AuthSchema>::User>;
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<<TestSchema as AuthSchema>::User>>;
    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<<TestSchema as AuthSchema>::User>>;
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<<TestSchema as AuthSchema>::User>>;
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<<TestSchema as AuthSchema>::User>>;
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<<TestSchema as AuthSchema>::User>;
    async fn delete_user(&self, id: &str) -> AuthResult<()>;
    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<<TestSchema as AuthSchema>::User>, usize)>;
});

forward!(OrganizationStore {
    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization>;
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>>;
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>>;
    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>>;
    async fn update_organization( &self, id: &str, update: UpdateOrganization ) -> AuthResult<Organization>;
    async fn delete_organization(&self, id: &str) -> AuthResult<()>;
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>>;
});

forward!(MemberStore {
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member>;
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>>;
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>>;
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member>;
    async fn delete_member(&self, member_id: &str) -> AuthResult<()>;
    async fn list_organization_members(&self, org_id: &str) -> AuthResult<Vec<Member>>;
    async fn query_organization_members( &self, params: &ListOrganizationMembersParams ) -> AuthResult<(Vec<Member>, usize)>;
    async fn count_organization_members(&self, org_id: &str) -> AuthResult<i64>;
    async fn count_organization_owners(&self, org_id: &str) -> AuthResult<i64>;
});

forward!(InvitationStore {
    async fn create_invitation(&self, invitation: CreateInvitation) -> AuthResult<Invitation>;
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>>;
    async fn get_pending_invitation( &self, org_id: &str, email: &str ) -> AuthResult<Option<Invitation>>;
    async fn update_invitation_status( &self, id: &str, status: InvitationStatus ) -> AuthResult<Invitation>;
    async fn list_organization_invitations(&self, org_id: &str) -> AuthResult<Vec<Invitation>>;
    async fn count_pending_organization_invitations(&self, org_id: &str) -> AuthResult<i64>;
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>>;
});

forward!(VerificationStore<TestSchema> {
    async fn create_verification( &self, verification: CreateVerification ) -> AuthResult<<TestSchema as AuthSchema>::Verification>;
    async fn get_verification( &self, identifier: &str, value: &str ) -> AuthResult<Option<<TestSchema as AuthSchema>::Verification>>;
    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<<TestSchema as AuthSchema>::Verification>>;
    async fn get_verification_by_identifier( &self, identifier: &str ) -> AuthResult<Option<<TestSchema as AuthSchema>::Verification>>;
    async fn consume_verification( &self, identifier: &str, value: &str ) -> AuthResult<Option<<TestSchema as AuthSchema>::Verification>>;
    async fn delete_verification(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_verifications(&self) -> AuthResult<usize>;
});

forward!(AccountStore<TestSchema> {
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<<TestSchema as AuthSchema>::Account>;
    async fn get_account( &self, provider: &str, provider_account_id: &str ) -> AuthResult<Option<<TestSchema as AuthSchema>::Account>>;
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<<TestSchema as AuthSchema>::Account>>;
    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<<TestSchema as AuthSchema>::Account>;
    async fn delete_account(&self, id: &str) -> AuthResult<()>;
});

forward!(ApiKeyStore {
    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey>;
    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>>;
    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>>;
    async fn list_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<Vec<ApiKey>>;
    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<ApiKey>;
    async fn delete_api_key(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_api_keys(&self) -> AuthResult<usize>;
    async fn consume_api_key_usage( &self, id: &str, global_rate_limit_enabled: bool ) -> AuthResult<ConsumeApiKeyResult>;
});

forward!(TransactionStore<TestSchema> {
    async fn transaction_boxed( &self, work: Box<TransactionWork<TestSchema>> ) -> AuthResult<BoxedTransactionValue>;
});

forward!(TwoFactorStore {
    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<TwoFactor>;
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>>;
    async fn update_two_factor_backup_codes( &self, user_id: &str, backup_codes: &str ) -> AuthResult<TwoFactor>;
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()>;
});

forward!(SessionStore<TestSchema> {
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<<TestSchema as AuthSchema>::Session>;
    async fn get_session(&self, token: &str) -> AuthResult<Option<<TestSchema as AuthSchema>::Session>>;
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<<TestSchema as AuthSchema>::Session>>;
    async fn update_session_expiry( &self, token: &str, expires_at: chrono::DateTime<chrono::Utc> ) -> AuthResult<()>;
    async fn delete_session(&self, token: &str) -> AuthResult<()>;
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()>;
    async fn delete_expired_sessions(&self) -> AuthResult<usize>;
    async fn update_session_active_organization( &self, token: &str, organization_id: Option<&str> ) -> AuthResult<<TestSchema as AuthSchema>::Session>;
});

#[async_trait::async_trait]
impl DeviceCodeStore for ApplicationStore {
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        self.check("create_device_code")?;
        self.inner.create_device_code(input).await
    }
    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.check("get_device_code_by_device_code")?;
        self.inner.get_device_code_by_device_code(device_code).await
    }
    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.check("get_device_code_by_user_code")?;
        self.inner.get_device_code_by_user_code(user_code).await
    }
    async fn update_device_code(
        &self,
        id: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        self.check("update_device_code")?;
        self.inner.update_device_code(id, update).await
    }
    async fn update_device_code_if_status(
        &self,
        id: &str,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        self.check("update_device_code_if_status")?;
        self.inner
            .update_device_code_if_status(id, current_status, update)
            .await
    }
    async fn claim_device_code(&self, id: &str, user_id: &str) -> AuthResult<bool> {
        self.check("claim_device_code")?;
        self.inner.claim_device_code(id, user_id).await
    }
    async fn delete_device_code(&self, id: &str) -> AuthResult<()> {
        self.check("delete_device_code")?;
        self.inner.delete_device_code(id).await
    }
    async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool> {
        let (selected, mode) = self.device.selector.lock().unwrap().clone();
        if mode == "consume" && selected == id {
            self.device
                .events
                .lock()
                .unwrap()
                .push(json!({"operation":"consume","id":id}));
            wait_device_gate(&self.device.first).await?;
        }
        self.inner.delete_device_code_if_status(id, status).await
    }
}

forward!(TeamStore {});

forward!(OrganizationRoleStore {});

forward!(WalletAddressStore {});

forward!(JwkStore {});

pub(crate) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let state = Arc::new(Mutex::new(State::default()));
    let device = Arc::new(DeviceApplication::default());
    let path = "/__test/profiles/session-adapter-failure/api/auth";
    let config = base.clone().base_path(path);
    let store = ApplicationStore {
        inner: Arc::new(crate::backend::store::<TestSchema>(
            config.clone(),
            database,
        )),
        state: state.clone(),
        device: device.clone(),
    };
    let auth = Arc::new(
        AuthBuilder::<TestSchema>::new(config)
            .store(store)
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(SessionManagementPlugin::new())
            .plugin(DeviceAuthorizationPlugin::new().interval(chrono::Duration::zero()))
            .build()
            .await?,
    );
    let router = Router::new().nest(path, auth.clone().axum_router().with_state(auth));
    Ok(router.route(
        "/__test/session-adapter-failure",
        post(move |Json(body): Json<Value>| {
            let state = state.clone();
            let device = device.clone();
            async move {
                if let Some(operation) = body["operation"].as_str() {
                    match operation {
                        "arm" => {
                            *device.selector.lock().unwrap() = (
                                body["id"].as_str().unwrap().to_owned(),
                                body["gate"].as_str().unwrap().to_owned(),
                            );
                            device.events.lock().unwrap().clear();
                            device.first.send_replace(false);
                        }
                        "release-first" => {
                            device.first.send_replace(true);
                        }
                        "restore" => {
                            device.first.send_replace(true);

                            device.selector.lock().unwrap().1 = String::new();
                        }
                        _ => {}
                    }
                    return Json(json!({"events":*device.events.lock().unwrap()}));
                }
                let mut state = state.lock().unwrap();
                if let Some(mode) = body.get("mode").and_then(Value::as_str) {
                    state.mode = mode.into();
                    state.events.clear();
                }
                Json(json!({"mode":state.mode,"events":state.events}))
            }
        }),
    ))
}
