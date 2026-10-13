//! Passkey registration and authentication outcomes across client data,
//! authenticator flags, key shapes and origin policies.
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::PasskeyPlugin;
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use ed25519_dalek::Signer as _;
use serde_cbor_2::Value as Cbor;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

backend_tests!(
    passkey_ceremony_matrix,
    passkey_signed_backup_changes_preserve_registration_snapshots,
    passkey_concurrent_real_ceremonies_single_owner
);

pub(super) const USER_PRESENT: u8 = 0x01;
pub(super) const USER_VERIFIED: u8 = 0x04;
pub(super) const BACKUP_ELIGIBLE: u8 = 0x08;
pub(super) const BACKUP_STATE: u8 = 0x10;
pub(super) const ATTESTED: u8 = 0x40;

pub(super) struct Authenticator {
    pub(super) signing: ed25519_dalek::SigningKey,
    pub(super) id: Vec<u8>,
}

impl Authenticator {
    pub(super) fn new(seed: u8, id: &str) -> Self {
        Self {
            signing: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            id: id.as_bytes().to_vec(),
        }
    }

    pub(super) fn cose_key(&self, curve: i128) -> Vec<u8> {
        serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(1)),
            (Cbor::Integer(3), Cbor::Integer(-8)),
            (Cbor::Integer(-1), Cbor::Integer(curve)),
            (
                Cbor::Integer(-2),
                Cbor::Bytes(self.signing.verifying_key().as_bytes().to_vec()),
            ),
        ])))
        .unwrap()
    }

    fn attestation(&self, rp_id: &str, flags: u8, curve: i128) -> Vec<u8> {
        let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
        data.push(flags | ATTESTED);
        data.extend_from_slice(&1_u32.to_be_bytes());
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&u16::try_from(self.id.len()).unwrap().to_be_bytes());
        data.extend_from_slice(&self.id);
        data.extend_from_slice(&self.cose_key(curve));
        serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
            (Cbor::Text("authData".into()), Cbor::Bytes(data)),
        ])))
        .unwrap()
    }

    pub(super) fn registration(&self, client: &Value, attestation: &[u8], padded: bool) -> Value {
        let client = serde_json::to_vec(client).unwrap();
        let client = if padded {
            URL_SAFE.encode(client)
        } else {
            URL_SAFE_NO_PAD.encode(client)
        };
        json!({
            "id": URL_SAFE_NO_PAD.encode(&self.id),
            "rawId": URL_SAFE_NO_PAD.encode(&self.id),
            "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": client,
                "attestationObject": URL_SAFE_NO_PAD.encode(attestation),
                "transports": ["internal"],
            },
        })
    }

    pub(super) fn assertion(&self, client: &Value, rp_id: &str, flags: u8, counter: u32) -> Value {
        let client = serde_json::to_vec(client).unwrap();
        let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
        data.push(flags);
        data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = data.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        json!({
            "id": URL_SAFE_NO_PAD.encode(&self.id),
            "rawId": URL_SAFE_NO_PAD.encode(&self.id),
            "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client),
                "authenticatorData": URL_SAFE_NO_PAD.encode(data),
                "signature": URL_SAFE_NO_PAD.encode(self.signing.sign(&signed).to_bytes()),
            },
        })
    }
}

fn endpoint_error_response(error: alibi::endpoint::EndpointError) -> alibi::AuthResponse {
    assert_ne!(
        error.error.status_code(),
        404,
        "server operation unavailable: {}",
        error.error
    );
    let mut response = error.error.to_auth_response();
    if let Some(body) = error.body {
        response.body = serde_json::to_vec(&*body).unwrap();
    }
    if error.body_absent {
        response.body.clear();
    }
    if let Some(headers) = error.headers {
        for (name, value) in headers.iter() {
            if name.eq_ignore_ascii_case("set-cookie") {
                response.headers.append(name, value);
            } else {
                _ = response.headers.insert(name, value);
            }
        }
    }
    response
}

async fn passkey_ceremony_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    // No RP ID: the configured base URL's host is used. Two allowed origins.
    let auth = builder::<B>(&connection)
        .plugin(
            PasskeyPlugin::new()
                .rp_name("Matrix")
                .origins(vec![ORIGIN.into(), "https://app.example".into()]),
        )
        .build()
        .await?;
    let owner = cookies(&signup(&auth, "passkey-matrix@example.com").await);
    let before_options = db
        .tables(&["user", "account", "session", "passkey", "verification"])
        .await?;
    for (query, cookie, status, code) in [
        (None, None, 401, "UNAUTHORIZED"),
        (
            Some(json!({"name":42})),
            Some(owner.as_str()),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"authenticatorAttachment":"invalid"})),
            Some(owner.as_str()),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"context":null})),
            Some(owner.as_str()),
            400,
            "VALIDATION_ERROR",
        ),
    ] {
        let mut endpoint = PasskeyPlugin::generate_passkey_registration_options_endpoint();
        if let Some(query) = query {
            endpoint = endpoint.with_query(&query)?;
        }
        let error = Box::pin(
            auth.dispatch_endpoint(
                endpoint,
                alibi::endpoint::EndpointOptions {
                    headers: cookie
                        .map(|cookie| [("cookie".into(), cookie.to_owned())].into_iter().collect()),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(error.error.error_payload().1.as_deref(), Some(code));
        assert_eq!(
            db.tables(&["user", "account", "session", "passkey", "verification"])
                .await?,
            before_options
        );
    }
    let register = async |authenticator: &Authenticator,
                          client: &dyn Fn(&Value) -> Value,
                          flags: u8,
                          curve: i128,
                          padded: bool| {
        let options = Box::pin(auth.dispatch_endpoint(
            PasskeyPlugin::generate_passkey_registration_options_endpoint()
                .with_query(&json!({"name":"Matrix credential","context":"native-enrollment","authenticatorAttachment":"platform"})).unwrap(),
            alibi::endpoint::EndpointOptions { headers: Some([("cookie".to_owned(),owner.clone())].into_iter().collect()), ..Default::default() }
        )).await.unwrap().into_response().unwrap();
        assert_eq!(body(&options)["user"]["name"], "Matrix credential");
        assert_eq!(
            body(&options)["authenticatorSelection"]["authenticatorAttachment"],
            "platform"
        );
        let proof = authenticator.registration(
            &client(&body(&options)["challenge"]),
            &authenticator.attestation("localhost", flags, curve),
            padded,
        );
        if authenticator.id == b"matrix-key-one" {
            let before = db
                .tables(&["user", "account", "session", "passkey", "verification"])
                .await
                .unwrap();
            for (input, cookie, status, code) in [
                (
                    json!({"response":proof,"name":42}),
                    Some(format!("{owner}; {}", cookies(&options))),
                    400,
                    "VALIDATION_ERROR",
                ),
                (
                    json!({"response":proof,"createSession":"true"}),
                    Some(format!("{owner}; {}", cookies(&options))),
                    400,
                    "VALIDATION_ERROR",
                ),
                (
                    json!({}),
                    Some(format!("{owner}; {}", cookies(&options))),
                    400,
                    "VALIDATION_ERROR",
                ),
                (json!({"response":proof}), None, 401, "UNAUTHORIZED"),
                (
                    json!({"response":proof}),
                    Some(owner.clone()),
                    400,
                    "CHALLENGE_NOT_FOUND",
                ),
            ] {
                let error = Box::pin(
                    auth.dispatch_endpoint(
                        alibi::endpoint::ServerEndpoint::<Value>::new(
                            "passkey",
                            "verifyPasskeyRegistration",
                        )
                        .with_body(&input)
                        .unwrap(),
                        alibi::endpoint::EndpointOptions {
                            headers: cookie.map(|cookie| {
                                [("cookie".into(), cookie), ("origin".into(), ORIGIN.into())]
                                    .into_iter()
                                    .collect()
                            }),
                            ..Default::default()
                        },
                    ),
                )
                .await
                .unwrap_err();
                assert_eq!(error.error.status_code(), status);
                assert_eq!(error.error.error_payload().1.as_deref(), Some(code));
                assert_eq!(
                    db.tables(&["user", "account", "session", "passkey", "verification"])
                        .await
                        .unwrap(),
                    before
                );
            }
        }
        let result = Box::pin(
            auth.dispatch_endpoint(
                PasskeyPlugin::verify_passkey_registration_endpoint(
                    alibi::plugins::passkey::PasskeyRegistrationInput {
                        response: alibi::utils::json::parse_value(&proof.to_string()).unwrap(),
                        name: Some(" \u{feff}matrix key\u{a0} ".into()),
                        create_session: None,
                    },
                ),
                alibi::endpoint::EndpointOptions {
                    headers: Some(
                        [
                            (
                                "cookie".to_owned(),
                                format!("{owner}; {}", cookies(&options)),
                            ),
                            ("origin".to_owned(), ORIGIN.to_owned()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await;
        match result {
            Ok(output) => {
                if authenticator.id == b"matrix-key-one" {
                    let before = db
                        .tables(&["user", "account", "session", "passkey", "verification"])
                        .await
                        .unwrap();
                    let replay = Box::pin(
                        auth.dispatch_endpoint(
                            alibi::endpoint::ServerEndpoint::<Value>::new(
                                "passkey",
                                "verifyPasskeyRegistration",
                            )
                            .with_body(&json!({"response":proof}))
                            .unwrap(),
                            alibi::endpoint::EndpointOptions {
                                headers: Some(
                                    [
                                        (
                                            "cookie".into(),
                                            format!("{owner}; {}", cookies(&options)),
                                        ),
                                        ("origin".into(), ORIGIN.into()),
                                    ]
                                    .into_iter()
                                    .collect(),
                                ),
                                ..Default::default()
                            },
                        ),
                    )
                    .await
                    .unwrap_err();
                    assert_eq!(replay.error.status_code(), 400);
                    assert_eq!(
                        replay.error.error_payload().1.as_deref(),
                        Some("CHALLENGE_NOT_FOUND")
                    );
                    assert_eq!(
                        db.tables(&["user", "account", "session", "passkey", "verification"])
                            .await
                            .unwrap(),
                        before
                    );
                }
                output.into_response().unwrap()
            }
            Err(error) => endpoint_error_response(error),
        }
    };
    let create = |origin: &'static str| move |challenge: &Value| json!({"type": "webauthn.create", "challenge": challenge, "origin": origin});
    let with_binding = |binding: Value| move |challenge: &Value| json!({"type": "webauthn.create", "challenge": challenge, "origin": ORIGIN, "tokenBinding": binding});

    let cases = [
        ("unlisted origin", "https://evil.example", USER_PRESENT, 6),
        ("not present", ORIGIN, USER_VERIFIED, 6),
        (
            "backed up without eligibility",
            ORIGIN,
            USER_PRESENT | BACKUP_STATE,
            6,
        ),
        ("ed25519 on the wrong curve", ORIGIN, USER_PRESENT, 7),
    ];
    for (index, (label, origin, flags, curve)) in cases.into_iter().enumerate() {
        let key = Authenticator::new(20 + u8::try_from(index)?, &format!("matrix-case-{index}"));
        trace.response(
            label,
            &register(&key, &create(origin), flags, curve, false).await,
        );
    }
    let bindings = [
        json!(null),
        json!(false),
        json!("bound"),
        json!({"status": "present"}),
        json!({"status": "unknown"}),
        json!([]),
    ];
    for (index, binding) in bindings.into_iter().enumerate() {
        let key = Authenticator::new(
            40 + u8::try_from(index)?,
            &format!("matrix-binding-{index}"),
        );
        trace.response(
            &format!("token binding {binding}"),
            &register(&key, &with_binding(binding.clone()), USER_PRESENT, 6, false).await,
        );
    }
    let key = Authenticator::new(11, "matrix-key-one");
    trace.response(
        "registered",
        &register(
            &key,
            &create(ORIGIN),
            USER_PRESENT | USER_VERIFIED,
            6,
            false,
        )
        .await,
    );
    let synced = Authenticator::new(12, "matrix-key-synced");
    trace.response(
        "multi-device from second origin",
        &register(
            &synced,
            &create("https://app.example"),
            USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | BACKUP_STATE,
            6,
            true,
        )
        .await,
    );
    trace.response(
        "multi-device",
        &register(
            &synced,
            &create(ORIGIN),
            USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | BACKUP_STATE,
            6,
            true,
        )
        .await,
    );
    let foreign = cookies(&signup(&auth, "passkey-matrix-foreign@example.com").await);
    let before_list = db
        .tables(&["user", "account", "session", "passkey"])
        .await?;
    let guest = Box::pin(auth.dispatch_endpoint(
        PasskeyPlugin::list_passkeys_endpoint(),
        alibi::endpoint::EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(guest.error.status_code(), 401);
    assert_eq!(
        guest.error.error_payload().1.as_deref(),
        Some("UNAUTHORIZED")
    );
    let other = Box::pin(
        auth.dispatch_endpoint(
            PasskeyPlugin::list_passkeys_endpoint(),
            alibi::endpoint::EndpointOptions {
                headers: Some(
                    [("cookie".to_owned(), foreign.clone())]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        ),
    )
    .await?;
    assert!(other.decode()?.is_empty());
    let listed = Box::pin(
        auth.dispatch_endpoint(
            PasskeyPlugin::list_passkeys_endpoint()
                .with_body(&json!({"userId":"foreign-owner-selector"}))?,
            alibi::endpoint::EndpointOptions {
                headers: Some([("cookie".to_owned(), owner.clone())].into_iter().collect()),
                ..Default::default()
            },
        ),
    )
    .await?;
    assert!(!listed.decode()?.is_empty());
    assert!(listed.headers().get("set-cookie").is_none());
    assert_eq!(
        db.tables(&["user", "account", "session", "passkey"])
            .await?,
        before_list
    );
    trace.response("listed keys", &listed.into_response()?);

    for (cookie, hints) in [
        (Some(owner.as_str()), true),
        (Some(foreign.as_str()), false),
        (None, false),
    ] {
        let before = db
            .tables(&["user", "account", "session", "passkey"])
            .await?;
        let output = Box::pin(
            auth.dispatch_endpoint(
                PasskeyPlugin::generate_passkey_authentication_options_endpoint()
                    .with_query(&json!({"userId":"ignored-selector"}))?
                    .with_body(&json!({"userId":"ignored-selector"}))?,
                alibi::endpoint::EndpointOptions {
                    headers: cookie
                        .map(|cookie| [("cookie".into(), cookie.to_owned())].into_iter().collect()),
                    ..Default::default()
                },
            ),
        )
        .await?;
        let options = output.decode()?;
        assert_eq!(options.get("allowCredentials").is_some(), hints);
        if hints {
            assert!(
                options["allowCredentials"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|credential| credential["id"] == URL_SAFE_NO_PAD.encode(&key.id))
            );
        }
        assert_eq!(
            db.tables(&["user", "account", "session", "passkey"])
                .await?,
            before
        );
        assert!(
            output
                .headers()
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("set-cookie")
                    && value.contains("better-auth-passkey="))
        );
    }
    let authenticate = async |authenticator: &Authenticator,
                              origin: &str,
                              binding: Option<Value>,
                              flags: u8,
                              counter: u32| {
        let options = Box::pin(auth.dispatch_endpoint(
            PasskeyPlugin::generate_passkey_authentication_options_endpoint(),
            alibi::endpoint::EndpointOptions::default(),
        ))
        .await
        .unwrap()
        .into_response()
        .unwrap();
        assert!(body(&options).get("allowCredentials").is_none());
        let mut client = json!({"type": "webauthn.get", "challenge": body(&options)["challenge"], "origin": origin});
        if let Some(binding) = binding {
            client["tokenBinding"] = binding;
        }
        let proof = authenticator.assertion(&client, "localhost", flags, counter);
        if authenticator.id == b"matrix-key-one" && flags == USER_PRESENT | USER_VERIFIED {
            let before = db
                .tables(&["user", "account", "session", "passkey", "verification"])
                .await
                .unwrap();
            for (input, cookie, status, code) in [
                (
                    json!({"response":null}),
                    cookies(&options),
                    400,
                    "VALIDATION_ERROR",
                ),
                (
                    json!({"response":42}),
                    cookies(&options),
                    400,
                    "VALIDATION_ERROR",
                ),
                (json!({}), cookies(&options), 400, "VALIDATION_ERROR"),
                (
                    json!({"response":proof}),
                    String::new(),
                    400,
                    "CHALLENGE_NOT_FOUND",
                ),
            ] {
                let error = Box::pin(
                    auth.dispatch_endpoint(
                        alibi::endpoint::ServerEndpoint::<Value>::new(
                            "passkey",
                            "verifyPasskeyAuthentication",
                        )
                        .with_body(&input)
                        .unwrap(),
                        alibi::endpoint::EndpointOptions {
                            headers: Some(
                                [("cookie".into(), cookie), ("origin".into(), ORIGIN.into())]
                                    .into_iter()
                                    .collect(),
                            ),
                            ..Default::default()
                        },
                    ),
                )
                .await
                .unwrap_err();
                assert_eq!(error.error.status_code(), status);
                assert_eq!(error.error.error_payload().1.as_deref(), Some(code));
                assert_eq!(
                    db.tables(&["user", "account", "session", "passkey", "verification"])
                        .await
                        .unwrap(),
                    before
                );
            }
        }
        let output = Box::pin(
            auth.dispatch_endpoint(
                PasskeyPlugin::verify_passkey_authentication_endpoint(
                    alibi::utils::json::parse_value(&proof.to_string()).unwrap(),
                )
                .with_body(&json!({"response":proof,"userId":"foreign-owner-selector"}))
                .unwrap(),
                alibi::endpoint::EndpointOptions {
                    headers: Some(
                        [
                            ("cookie".into(), cookies(&options)),
                            ("origin".into(), ORIGIN.into()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await;
        match output {
            Ok(output) => {
                let user = output.decode().unwrap().user;
                let response = output.into_response().unwrap();
                if authenticator.id == b"matrix-key-one" {
                    assert_eq!(user["email"], "passkey-matrix@example.com");
                    let live = Box::pin(auth.handle_request(request(
                        "/get-session",
                        None,
                        &cookies(&response),
                    )))
                    .await
                    .unwrap();
                    assert_eq!(live.status, 200);
                    assert_eq!(body(&live)["user"]["id"], user["id"]);
                    let before = db
                        .tables(&["user", "account", "session", "passkey", "verification"])
                        .await
                        .unwrap();
                    let replay = Box::pin(
                        auth.dispatch_endpoint(
                            PasskeyPlugin::verify_passkey_authentication_endpoint(
                                alibi::utils::json::parse_value(&proof.to_string()).unwrap(),
                            ),
                            alibi::endpoint::EndpointOptions {
                                headers: Some(
                                    [
                                        ("cookie".into(), cookies(&options)),
                                        ("origin".into(), ORIGIN.into()),
                                    ]
                                    .into_iter()
                                    .collect(),
                                ),
                                ..Default::default()
                            },
                        ),
                    )
                    .await
                    .unwrap_err();
                    assert_eq!(replay.error.status_code(), 400);
                    assert_eq!(
                        replay.error.error_payload().1.as_deref(),
                        Some("CHALLENGE_NOT_FOUND")
                    );
                    assert_eq!(
                        db.tables(&["user", "account", "session", "passkey", "verification"])
                            .await
                            .unwrap(),
                        before
                    );
                }
                response
            }
            Err(error) => endpoint_error_response(error),
        }
    };
    trace.response(
        "assertion wrong origin",
        &authenticate(&key, "https://evil.example", None, USER_PRESENT, 2).await,
    );
    trace.response(
        "assertion not present",
        &authenticate(&key, ORIGIN, None, USER_VERIFIED, 2).await,
    );
    trace.response(
        "assertion bad binding",
        &authenticate(
            &key,
            ORIGIN,
            Some(json!({"status": "unknown"})),
            USER_PRESENT,
            2,
        )
        .await,
    );
    trace.response(
        "assertion backed up",
        &authenticate(&key, ORIGIN, None, USER_PRESENT | BACKUP_STATE, 2).await,
    );
    trace.response(
        "assertion",
        &authenticate(&key, ORIGIN, None, USER_PRESENT | USER_VERIFIED, 2).await,
    );
    trace.response(
        "synced assertion",
        &authenticate(
            &synced,
            ORIGIN,
            None,
            USER_PRESENT | BACKUP_ELIGIBLE | BACKUP_STATE,
            2,
        )
        .await,
    );
    let registered = auth
        .store()
        .get_passkey_by_credential_id(&URL_SAFE_NO_PAD.encode(&key.id))
        .await?
        .unwrap();
    let before_update = db
        .tables(&["user", "account", "session", "passkey"])
        .await?;
    for (input, cookie, status, code) in [
        (
            json!({"id":registered.id,"name":42}),
            Some(owner.as_str()),
            400,
            Some("VALIDATION_ERROR"),
        ),
        (
            json!({"id":registered.id,"name":" \u{feff}\u{a0}\u{2028}\t "}),
            Some(owner.as_str()),
            400,
            Some("VALIDATION_ERROR"),
        ),
        (
            json!({"id":registered.id,"name":"Renamed"}),
            None,
            401,
            Some("UNAUTHORIZED"),
        ),
        (
            json!({"id":registered.id,"name":"Hijacked"}),
            Some(foreign.as_str()),
            401,
            Some("YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"),
        ),
        (
            json!({"id":"missing-passkey","name":"Renamed"}),
            Some(owner.as_str()),
            404,
            Some("PASSKEY_NOT_FOUND"),
        ),
        (
            json!({"id":"","name":"Renamed"}),
            Some(owner.as_str()),
            400,
            None,
        ),
    ] {
        let error = Box::pin(
            auth.dispatch_endpoint(
                alibi::endpoint::ServerEndpoint::<Value>::new("passkey", "updatePasskey")
                    .with_body(&input)?,
                alibi::endpoint::EndpointOptions {
                    headers: cookie
                        .map(|cookie| [("cookie".into(), cookie.to_owned())].into_iter().collect()),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(error.error.error_payload().1.as_deref(), code);
        assert_eq!(
            db.tables(&["user", "account", "session", "passkey"])
                .await?,
            before_update
        );
    }
    let renamed = Box::pin(auth.dispatch_endpoint(
        PasskeyPlugin::update_passkey_endpoint(&registered.id, " \u{feff}\u{a0}Renamed\u{2028}\t ")
            .with_body(&json!({"id":registered.id,"name":" \u{feff}\u{a0}Renamed\u{2028}\t ","userId":"foreign-selector"}))?,
        alibi::endpoint::EndpointOptions { headers: Some([("cookie".to_owned(), owner.clone())].into_iter().collect()), ..Default::default() }
    )).await?;
    assert_eq!(renamed.decode()?.passkey["name"], "Renamed");
    assert_eq!(renamed.decode()?.passkey["id"], registered.id);
    let after_update = db
        .tables(&["user", "account", "session", "passkey"])
        .await?;
    assert_eq!(&after_update[..3], &before_update[..3]);
    let mut expected: Vec<Value> = serde_json::from_str(&before_update[3])?;
    for row in &mut expected {
        if row["id"] == registered.id {
            row["name"] = json!("Renamed");
        }
    }
    assert_eq!(
        serde_json::from_str::<Vec<Value>>(&after_update[3])?,
        expected
    );
    let before_delete = db
        .tables(&["user", "account", "session", "passkey"])
        .await?;
    for (input, cookie, status, code, absent) in [
        (
            json!({"id":42}),
            Some(owner.as_str()),
            400,
            Some("VALIDATION_ERROR"),
            false,
        ),
        (
            json!({"id":registered.id}),
            None,
            401,
            Some("UNAUTHORIZED"),
            false,
        ),
        (
            json!({"id":registered.id}),
            Some(foreign.as_str()),
            401,
            None,
            true,
        ),
        (
            json!({"id":"missing-passkey"}),
            Some(owner.as_str()),
            404,
            Some("PASSKEY_NOT_FOUND"),
            false,
        ),
        (json!({"id":""}), Some(owner.as_str()), 400, None, false),
    ] {
        let error = Box::pin(
            auth.dispatch_endpoint(
                alibi::endpoint::ServerEndpoint::<Value>::new("passkey", "deletePasskey")
                    .with_body(&input)?,
                alibi::endpoint::EndpointOptions {
                    headers: cookie.map(|cookie| {
                        [("cookie".to_owned(), cookie.to_owned())]
                            .into_iter()
                            .collect()
                    }),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(error.error.error_payload().1.as_deref(), code);
        assert_eq!(error.body_absent, absent);
        assert_eq!(
            db.tables(&["user", "account", "session", "passkey"])
                .await?,
            before_delete
        );
    }
    let empty_http = call(
        &auth,
        request("/passkey/delete-passkey", Some(json!({"id":""})), &owner),
        400,
    )
    .await;
    assert_eq!(
        body(&empty_http),
        json!({"message":"Missing required parameter: id"})
    );
    assert_eq!(
        db.tables(&["user", "account", "session", "passkey"])
            .await?,
        before_delete
    );
    let deleted = Box::pin(
        auth.dispatch_endpoint(
            PasskeyPlugin::delete_passkey_endpoint(&registered.id)
                .with_body(&json!({"id":registered.id,"userId":"foreign-owner-selector"}))?,
            alibi::endpoint::EndpointOptions {
                headers: Some([("cookie".to_owned(), owner.clone())].into_iter().collect()),
                ..Default::default()
            },
        ),
    )
    .await?;
    assert!(deleted.decode()?.status);
    assert!(
        auth.store()
            .get_passkey_by_credential_id(&URL_SAFE_NO_PAD.encode(&key.id))
            .await?
            .is_none()
    );
    let after_delete = db
        .tables(&["user", "account", "session", "passkey"])
        .await?;
    assert_eq!(&after_delete[..3], &before_delete[..3]);
    let expected: Vec<Value> = serde_json::from_str::<Vec<Value>>(&before_delete[3])?
        .into_iter()
        .filter(|row| row["id"] != registered.id)
        .collect();
    assert_eq!(
        serde_json::from_str::<Vec<Value>>(&after_delete[3])?,
        expected
    );
    let replay = Box::pin(auth.dispatch_endpoint(
        PasskeyPlugin::delete_passkey_endpoint(&registered.id),
        alibi::endpoint::EndpointOptions {
            headers: Some([("cookie".to_owned(), owner.clone())].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(replay.error.status_code(), 404);
    assert_eq!(
        replay.error.error_payload().1.as_deref(),
        Some("PASSKEY_NOT_FOUND")
    );
    assert_eq!(
        db.tables(&["user", "account", "session", "passkey"])
            .await?,
        after_delete
    );
    trace.assert("passkey/ceremony-matrix");
    B::close(connection).await
}

// Compat owner: tests/plugins/passkey/authentication-snapshot.test.ts.
// Signed backup-state changes advance verification without replacing the public
// registration snapshot; the existing matrix starts with an already backed-up key.
async fn passkey_signed_backup_changes_preserve_registration_snapshots<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(PasskeyPlugin::new().origins(vec![ORIGIN.into()]))
        .build()
        .await?;
    let owner = signup(&auth, "backup-snapshot-owner@example.test").await;
    let foreign = signup(&auth, "backup-snapshot-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let key = Authenticator::new(110, "backup-snapshot-key");
    let options = call(
        &auth,
        request("/passkey/generate-register-options", None, &cookies(&owner)),
        200,
    )
    .await;
    let client = json!({
        "type": "webauthn.create",
        "challenge": body(&options)["challenge"],
        "origin": ORIGIN
    });
    let signed = key.registration(
        &client,
        &key.attestation(
            "localhost",
            USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE,
            6,
        ),
        false,
    );
    _ = call(
        &auth,
        request(
            "/passkey/verify-registration",
            Some(json!({"response": signed, "name": "Owned device"})),
            &format!("{}; {}", cookies(&owner), cookies(&options)),
        ),
        200,
    )
    .await;
    let initial = body(
        &call(
            &auth,
            request("/passkey/list-user-passkeys", None, &cookies(&owner)),
            200,
        )
        .await,
    );
    assert_eq!(initial.as_array().unwrap().len(), 1);
    assert_eq!(initial[0]["userId"], owner_id);
    assert_eq!(initial[0]["counter"], 1);
    assert_eq!(initial[0]["deviceType"], "multiDevice");
    assert_eq!(initial[0]["backedUp"], false);
    let initial_physical: Vec<Value> = serde_json::from_str(&db.table("passkey").await?)?;
    assert_eq!(initial_physical.len(), 1);
    _ = call(
        &auth,
        request("/sign-out", Some(json!({})), &cookies(&owner)),
        200,
    )
    .await;
    let stable_identity = db.tables(&["user", "account"]).await?;
    let sessions: Vec<Value> = serde_json::from_str(&db.table("session").await?)?;
    let foreign_session = sessions
        .iter()
        .find(|row| row["userId"] == foreign_id)
        .unwrap()
        .clone();

    // The shared authenticator registers counter 1, so these are its next two
    // genuine assertions. Only the signed assertion turns backup state on.
    for counter in [2, 3] {
        let options = call(
            &auth,
            request("/passkey/generate-authenticate-options", None, ""),
            200,
        )
        .await;
        let client = json!({
            "type": "webauthn.get",
            "challenge": body(&options)["challenge"],
            "origin": ORIGIN
        });
        let signed = key.assertion(
            &client,
            "localhost",
            USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | BACKUP_STATE,
            counter,
        );
        let verified = call(
            &auth,
            request(
                "/passkey/verify-authentication",
                Some(json!({"response": signed})),
                &cookies(&options),
            ),
            200,
        )
        .await;
        assert_eq!(body(&verified)["user"]["id"], owner_id);
        assert_eq!(body(&verified)["session"]["userId"], owner_id);
        let cookie = cookies(&verified);
        authenticated(&auth, &cookie, "backup-snapshot-owner@example.test").await;
        let listed = body(
            &call(
                &auth,
                request("/passkey/list-user-passkeys", None, &cookie),
                200,
            )
            .await,
        );
        let mut expected = initial.clone();
        expected[0]["counter"] = json!(counter);
        assert_eq!(listed, expected);
        let physical: Vec<Value> = serde_json::from_str(&db.table("passkey").await?)?;
        assert_eq!(physical.len(), 1);
        for field in [
            "id",
            "userId",
            "credentialID",
            "backedUp",
            "deviceType",
            "name",
            "createdAt",
        ] {
            assert_eq!(physical[0][field], initial_physical[0][field], "{field}");
        }
        assert_eq!(physical[0]["counter"], counter);
        assert_eq!(db.tables(&["user", "account"]).await?, stable_identity);
        let sessions: Vec<Value> = serde_json::from_str(&db.table("session").await?)?;
        assert_eq!(sessions.len(), 2);
        assert_eq!(
            sessions.iter().find(|row| row["userId"] == foreign_id),
            Some(&foreign_session)
        );
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM \"session\" WHERE \"userId\"=$1",
                &[&owner_id]
            )
            .await?,
            1
        );
        authenticated(
            &auth,
            &cookies(&foreign),
            "backup-snapshot-foreign@example.test",
        )
        .await;
        if counter == 2 {
            _ = call(&auth, request("/sign-out", Some(json!({})), &cookie), 200).await;
        }
    }
    B::close(connection).await
}

async fn passkey_concurrent_real_ceremonies_single_owner<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(PasskeyPlugin::new().origins(vec![ORIGIN.into()]))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let baseline = db.tables(&["user", "account", "session"]).await?;
    let jar = cookies(&owner);
    let key = Authenticator::new(109, "raced-genuine-key");
    let options = call(
        &auth,
        request("/passkey/generate-register-options", None, &jar),
        200,
    )
    .await;
    let client =
        json!({"type":"webauthn.create","challenge":body(&options)["challenge"],"origin":ORIGIN});
    let signed = key.registration(
        &client,
        &key.attestation("localhost", USER_PRESENT | USER_VERIFIED, 6),
        false,
    );
    let submit = request(
        "/passkey/verify-registration",
        Some(json!({"response":signed,"name":"One Physical Key"})),
        &format!("{jar}; {}", cookies(&options)),
    );
    let (left, right) = tokio::join!(
        Box::pin(auth.handle_request(submit.clone())),
        Box::pin(auth.handle_request(submit.clone()))
    );
    let mut results = [left?, right?];
    results.sort_by_key(|r| r.status);
    assert_eq!(results.each_ref().map(|r| r.status), [200, 400]);
    assert_eq!(body(&results[1])["code"], "CHALLENGE_NOT_FOUND");
    let rejected = call(&auth, submit, 400).await;
    assert_eq!(body(&rejected)["code"], "CHALLENGE_NOT_FOUND");
    assert_eq!(db.count("passkey").await?, 1);
    assert_eq!(db.tables(&["user", "account", "session"]).await?, baseline);
    _ = call(&auth, request("/sign-out", Some(json!({})), &jar), 200).await;
    let options = call(
        &auth,
        request("/passkey/generate-authenticate-options", None, ""),
        200,
    )
    .await;
    let signed = key.assertion(
        &json!({"type":"webauthn.get","challenge":body(&options)["challenge"],"origin":ORIGIN}),
        "localhost",
        USER_PRESENT | USER_VERIFIED,
        2,
    );
    let submit = request(
        "/passkey/verify-authentication",
        Some(json!({"response":signed})),
        &cookies(&options),
    );
    let (left, right) = tokio::join!(
        Box::pin(auth.handle_request(submit.clone())),
        Box::pin(auth.handle_request(submit.clone()))
    );
    let mut results = [left?, right?];
    results.sort_by_key(|r| r.status);
    assert_eq!(results[0].status, 200);
    assert_eq!(results[1].status, 400);
    assert_eq!(body(&results[1])["code"], "CHALLENGE_NOT_FOUND");
    assert_eq!(body(&results[0])["user"]["id"], id);
    authenticated(&auth, &cookies(&results[0]), "owner@example.test").await;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"session\" WHERE \"userId\"=$1",
            &[&id]
        )
        .await?,
        1
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"passkey\" WHERE \"userId\"=$1 AND \"counter\"=2",
            &[&id]
        )
        .await?,
        1
    );
    let after = db
        .tables(&["user", "account", "session", "passkey", "verification"])
        .await?;
    _ = call(&auth, submit, 400).await;
    assert_eq!(
        db.tables(&["user", "account", "session", "passkey", "verification"])
            .await?,
        after
    );
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}
