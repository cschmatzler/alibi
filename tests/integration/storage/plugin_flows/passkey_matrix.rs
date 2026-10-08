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

backend_tests!(passkey_ceremony_matrix);

const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
const BACKUP_ELIGIBLE: u8 = 0x08;
const BACKUP_STATE: u8 = 0x10;
const ATTESTED: u8 = 0x40;

struct Authenticator {
    signing: ed25519_dalek::SigningKey,
    id: Vec<u8>,
}

impl Authenticator {
    fn new(seed: u8, id: &str) -> Self {
        Self {
            signing: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            id: id.as_bytes().to_vec(),
        }
    }

    fn cose_key(&self, curve: i128) -> Vec<u8> {
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

    fn registration(&self, client: &Value, attestation: &[u8], padded: bool) -> Value {
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

    fn assertion(&self, client: &Value, rp_id: &str, flags: u8, counter: u32) -> Value {
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
    let register = async |authenticator: &Authenticator,
                          client: &dyn Fn(&Value) -> Value,
                          flags: u8,
                          curve: i128,
                          padded: bool| {
        let options = call(
            &auth,
            request("/passkey/generate-register-options", None, &owner),
            200,
        )
        .await;
        let proof = authenticator.registration(
            &client(&body(&options)["challenge"]),
            &authenticator.attestation("localhost", flags, curve),
            padded,
        );
        Box::pin(auth.handle_request(request(
            "/passkey/verify-registration",
            Some(json!({"response": proof, "name": "matrix key"})),
            &format!("{owner}; {}", cookies(&options)),
        )))
        .await
        .unwrap()
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
    trace.response(
        "listed keys",
        &call(
            &auth,
            request("/passkey/list-user-passkeys", None, &owner),
            200,
        )
        .await,
    );

    let authenticate = async |authenticator: &Authenticator,
                              origin: &str,
                              binding: Option<Value>,
                              flags: u8,
                              counter: u32| {
        let options = call(
            &auth,
            request("/passkey/generate-authenticate-options", None, ""),
            200,
        )
        .await;
        let mut client = json!({"type": "webauthn.get", "challenge": body(&options)["challenge"], "origin": origin});
        if let Some(binding) = binding {
            client["tokenBinding"] = binding;
        }
        Box::pin(auth.handle_request(request(
            "/passkey/verify-authentication",
            Some(
                json!({"response": authenticator.assertion(&client, "localhost", flags, counter)}),
            ),
            &cookies(&options),
        )))
        .await
        .unwrap()
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
    trace.assert("passkey/ceremony-matrix");
    B::close(connection).await
}
