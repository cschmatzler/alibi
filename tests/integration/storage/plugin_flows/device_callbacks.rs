//! Callback rejection must preserve issued codes and never partially issue a new one.
use super::*;
use better_auth::plugins::DeviceAuthorizationPlugin;
use better_auth_core::{AuthError, AuthResult};

backend_tests!(device_callback_errors_stop_at_the_failing_phase_and_preserve_pending_codes);
postgres_tests!(device_callback_errors_stop_at_the_failing_phase_and_preserve_pending_codes);

#[derive(Default)]
struct Callbacks {
    mode: Mutex<(&'static str, bool)>,
    events: Mutex<Vec<&'static str>>,
}
impl Callbacks {
    fn enter(&self, phase: &'static str) -> AuthResult<()> {
        self.events.lock().unwrap().push(phase);
        let (failure, explicit) = *self.mode.lock().unwrap();
        if failure == phase {
            if explicit {
                Err(AuthError::Upstream {
                    status: 403,
                    code: "APPLICATION_DENIED",
                    message: "Application rejected device",
                })
            } else {
                Err(AuthError::bad_request("private application failure"))
            }
        } else {
            Ok(())
        }
    }
}
async fn device_callback_errors_stop_at_the_failing_phase_and_preserve_pending_codes<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let callbacks = Arc::new(Callbacks::default());
    let validator = callbacks.clone();
    let requested = callbacks.clone();
    let device = callbacks.clone();
    let user = callbacks.clone();
    let plugin = DeviceAuthorizationPlugin::new()
        .validate_client(move |client| {
            let state = validator.clone();
            async move {
                assert_eq!(client, "native-client");
                state.enter("validate")?;
                Ok(state.mode.lock().unwrap().0 != "false")
            }
        })
        .on_device_auth_request(move |client, scope| {
            let state = requested.clone();
            async move {
                assert_eq!(client, "native-client");
                assert_eq!(scope.as_deref(), Some("profile"));
                state.enter("request")
            }
        })
        .generate_device_code_async_with(move || {
            let state = device.clone();
            async move {
                state.enter("device")?;
                Ok("configured-device-proof".into())
            }
        })
        .generate_user_code_async_with(move || {
            let state = user.clone();
            async move {
                state.enter("user")?;
                Ok("NATIVE-CODE".into())
            }
        });
    let auth = builder::<B>(&connection).plugin(plugin).build().await?;
    let phases = ["validate", "request", "device", "user"];
    for explicit in [false, true] {
        for (index, phase) in phases.iter().enumerate() {
            *callbacks.mode.lock().unwrap() = (phase, explicit);
            callbacks.events.lock().unwrap().clear();
            let denied = call(
                &auth,
                request(
                    "/device/code",
                    Some(json!({"client_id":"native-client","scope":"profile"})),
                    "",
                ),
                if explicit { 403 } else { 500 },
            )
            .await;
            assert_eq!(*callbacks.events.lock().unwrap(), phases[..=index]);
            assert_eq!(
                denied.headers.get("cache-control").map(String::as_str),
                explicit.then_some("no-store")
            );
            assert_eq!(
                denied.headers.get("pragma").map(String::as_str),
                explicit.then_some("no-cache")
            );
            if explicit {
                assert_eq!(body(&denied)["code"], "APPLICATION_DENIED");
            } else {
                assert!(denied.body.is_empty());
            }
            assert_eq!(db.count("device_code").await?, 0);
        }
    }
    *callbacks.mode.lock().unwrap() = ("", false);
    callbacks.events.lock().unwrap().clear();
    let issued = call(
        &auth,
        request(
            "/device/code",
            Some(json!({"client_id":"native-client","scope":"profile"})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&issued)["device_code"], "configured-device-proof");
    assert_eq!(*callbacks.events.lock().unwrap(), phases);
    assert_eq!(body(&issued)["user_code"], "NATIVE-CODE");
    assert_eq!(db.count("device_code").await?, 1);
    assert_eq!(db.count_where("SELECT COUNT(*) FROM device_code WHERE device_code=$1 AND user_code=$2 AND client_id=$3 AND scope=$4", &["configured-device-proof", "NATIVE-CODE", "native-client", "profile"]).await?, 1);
    let pending = db.table("device_code").await?;
    for (phase, explicit, status) in [
        ("false", false, 400),
        ("validate", false, 500),
        ("validate", true, 403),
    ] {
        *callbacks.mode.lock().unwrap() = (phase, explicit);
        callbacks.events.lock().unwrap().clear();
        let denied = call(&auth, request("/device/token", Some(json!({"client_id":"native-client","device_code":"configured-device-proof","grant_type":"urn:ietf:params:oauth:grant-type:device_code"})), ""), status).await;
        assert_eq!(*callbacks.events.lock().unwrap(), ["validate"]);
        if phase == "false" {
            assert_eq!(body(&denied)["error"], "invalid_grant");
        }
        assert_eq!(db.table("device_code").await?, pending);
        assert_eq!(db.count("sessions").await?, 0);
    }
    B::close(connection).await
}
