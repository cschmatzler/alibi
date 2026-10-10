use crate::TestSchema;
use alibi::seaorm::{
    DatabaseConnection,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};
use alibi::{
    Alibi, AuthBuilder, AuthConfig, AuthError, AuthResult, BackgroundTaskCompletion,
    BackgroundTaskHandler,
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::{
        EmailPasswordPlugin, SessionManagementPlugin, TwoFactorPlugin,
        two_factor::{SendTwoFactorOtp, TwoFactorConfig},
    },
    wire::UserView,
};
use axum::{Router, extract::Json, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{Notify, oneshot};

struct Delivery {
    profile: String,
    user_id: String,
    otp: String,
    release: Option<oneshot::Sender<()>>,
}
#[derive(Default)]
struct Inner {
    next: usize,
    events: Vec<Value>,
    deliveries: BTreeMap<usize, Delivery>,
}
#[derive(Clone, Default)]
struct State {
    inner: Arc<Mutex<Inner>>,
    changed: Arc<Notify>,
}
impl State {
    fn event(&self, value: Value) {
        self.inner.lock().unwrap().events.push(value);
        self.changed.notify_waiters();
    }
    async fn wait(&self, predicate: impl Fn(&Inner) -> bool) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if predicate(&self.inner.lock().unwrap()) {
                return;
            }
            notified.await;
        }
    }
}
struct Application {
    state: State,
    profile: String,
    mode: &'static str,
}
#[async_trait::async_trait]
impl SendTwoFactorOtp for Application {
    async fn send(&self, user: &UserView, otp: &str) -> AuthResult<()> {
        let (release, gate) = oneshot::channel();
        let serial = {
            let mut inner = self.state.inner.lock().unwrap();
            inner.next += 1;
            let serial = inner.next;
            inner.deliveries.insert(
                serial,
                Delivery {
                    profile: self.profile.clone(),
                    user_id: user.id.clone(),
                    otp: otp.into(),
                    release: Some(release),
                },
            );
            serial
        };
        let snapshot = json!({"id":user.id,"email":user.email,"twoFactorEnabled":user.two_factor_enabled.unwrap_or(false)});
        self.state
            .event(json!({"kind":"entered","serial":serial,"user":snapshot,"otp":otp}));
        gate.await
            .map_err(|_| AuthError::internal("application delivery gate closed"))?;
        self.state
            .event(json!({"kind":"finished","serial":serial,"user":snapshot,"otp":otp}));
        Err(AuthError::internal("application OTP delivery rejected"))
    }
}
impl BackgroundTaskHandler for Application {
    fn handle(&self, completion: BackgroundTaskCompletion) -> AuthResult<()> {
        let serial = self
            .state
            .inner
            .lock()
            .unwrap()
            .deliveries
            .iter()
            .rev()
            .find(|(_, value)| value.profile == self.profile)
            .map(|(serial, _)| *serial)
            .expect("actual delivery required");
        self.state.event(json!({"kind":"register","serial":serial}));
        if self.mode == "observe" {
            let state = self.state.clone();
            drop(tokio::spawn(async move {
                let ok = completion.await.is_ok();
                state.event(json!({"kind":"complete","serial":serial,"ok":ok}));
            }));
        }
        if self.mode == "throw" {
            return Err(AuthError::internal(
                "application OTP background observer rejected",
            ));
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Control {
    action: String,
    serial: Option<usize>,
    kind: Option<String>,
    user_id: Option<String>,
    identifier: Option<String>,
}

pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router<Arc<Alibi<TestSchema>>>> {
    let state = State::default();
    let mut router = Router::new();
    for mode in ["default", "observe", "ignore", "throw"] {
        let profile = format!("two-factor-delivery-{mode}");
        let application = Arc::new(Application {
            state: state.clone(),
            profile: profile.clone(),
            mode,
        });
        let path = format!("/__test/profiles/{profile}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.background_tasks = if mode == "default" {
            None
        } else {
            Some(application.clone())
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(
                    EmailPasswordPlugin::new()
                        .enable_signup(true)
                        .enable_username(false),
                )
                .plugin(SessionManagementPlugin::new())
                .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                    send_otp: Some(application),
                    ..Default::default()
                }))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router.route(
        "/__test/two-factor-delivery",
        post(move |Json(body): Json<Control>| control(body, state.clone(), database.clone())),
    ))
}
async fn control(body: Control, state: State, database: DatabaseConnection) -> Json<Value> {
    if body.action == "reset" {
        {
            let mut inner = state.inner.lock().unwrap();
            for delivery in inner.deliveries.values_mut() {
                if let Some(release) = delivery.release.take() {
                    let _ = release.send(());
                }
            }
        }
        state
            .wait(|inner| {
                inner
                    .events
                    .iter()
                    .filter(|event| event["kind"] == "finished")
                    .count()
                    == inner.deliveries.len()
                    && inner
                        .deliveries
                        .iter()
                        .filter(|(_, value)| value.profile.ends_with("observe"))
                        .all(|(serial, _)| {
                            inner.events.iter().any(|event| {
                                event["kind"] == "complete" && event["serial"] == *serial
                            })
                        })
            })
            .await;
        let mut inner = state.inner.lock().unwrap();
        inner.events.clear();
        inner.deliveries.clear();
        inner.next = 0;
    }
    if body.action == "wait" {
        state
            .wait(|inner| {
                inner.events.iter().any(|event| {
                    event["kind"].as_str() == body.kind.as_deref()
                        && (body.serial.is_none()
                            || event["serial"].as_u64() == body.serial.map(|value| value as u64))
                })
            })
            .await;
        if let (Some("entered"), Some(serial)) = (body.kind.as_deref(), body.serial) {
            let default = state.inner.lock().unwrap().deliveries[&serial]
                .profile
                .ends_with("default");
            if !default {
                state
                    .wait(|inner| {
                        inner.events.iter().any(|event| {
                            event["kind"] == "register"
                                && event["serial"].as_u64() == body.serial.map(|value| value as u64)
                        })
                    })
                    .await;
            }
        }
    }
    if body.action == "release" {
        let release = state
            .inner
            .lock()
            .unwrap()
            .deliveries
            .get_mut(&body.serial.expect("serial required"))
            .expect("actual delivery required")
            .release
            .take();
        if let Some(release) = release {
            let _ = release.send(());
        }
        state
            .wait(|inner| {
                inner.events.iter().any(|event| {
                    event["kind"] == "finished"
                        && event["serial"].as_u64() == body.serial.map(|value| value as u64)
                })
            })
            .await;
        let observe = state.inner.lock().unwrap().deliveries[&body.serial.unwrap()]
            .profile
            .ends_with("observe");
        if observe {
            state
                .wait(|inner| {
                    inner.events.iter().any(|event| {
                        event["kind"] == "complete"
                            && event["serial"].as_u64() == body.serial.map(|value| value as u64)
                    })
                })
                .await;
        }
    }
    if body.action == "expire" {
        let _ = database
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE verifications SET expires_at=? WHERE identifier=?",
                [
                    "1970-01-01T00:00:00.000Z".into(),
                    body.identifier.unwrap().into(),
                ],
            ))
            .await
            .unwrap();
    }
    let rows = if let Some(user_id) = &body.user_id {
        database.query_all_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"SELECT * FROM verifications WHERE identifier LIKE ? OR identifier IN(SELECT '2fa-otp-'||identifier FROM verifications WHERE value=? AND identifier LIKE '2fa-%') ORDER BY created_at,id",[format!("2fa-otp-{user_id}!%").into(),user_id.clone().into()])).await.unwrap().into_iter().map(|row|json!({"id":row.try_get::<String>("","id").unwrap(),"identifier":row.try_get::<String>("","identifier").unwrap(),"value":row.try_get::<String>("","value").unwrap(),"expiresAt":row.try_get::<String>("","expires_at").unwrap(),"createdAt":row.try_get::<String>("","created_at").unwrap(),"updatedAt":row.try_get::<String>("","updated_at").unwrap()})).collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let challenges = if let Some(user_id) = &body.user_id {
        database.query_all_raw(Statement::from_sql_and_values(DbBackend::Sqlite, "SELECT * FROM verifications WHERE value=? AND identifier LIKE '2fa-%' ORDER BY created_at,id", [user_id.clone().into()])).await.unwrap().into_iter().map(|row| json!({"id":row.try_get::<String>("","id").unwrap(),"identifier":row.try_get::<String>("","identifier").unwrap(),"value":row.try_get::<String>("","value").unwrap(),"expiresAt":row.try_get::<String>("","expires_at").unwrap(),"createdAt":row.try_get::<String>("","created_at").unwrap(),"updatedAt":row.try_get::<String>("","updated_at").unwrap()})).collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let inner = state.inner.lock().unwrap();
    let deliveries=inner.deliveries.iter().filter(|(_,value)|body.user_id.as_ref().is_none_or(|user|user==&value.user_id)).map(|(serial,value)|json!({"serial":serial,"profile":value.profile,"userId":value.user_id,"otp":value.otp})).collect::<Vec<_>>();
    Json(json!({"events":inner.events,"deliveries":deliveries,"rows":rows,"challenges":challenges}))
}
