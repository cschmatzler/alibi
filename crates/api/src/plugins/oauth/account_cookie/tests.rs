use super::*;

#[test]
fn account_cookie_accepts_pinned_encrypted_vectors_and_rejects_unauthenticated_values() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../account-cookie-vectors.json")).unwrap();
        let secret = vectors["secret"].as_str().unwrap();
        for name in ["valid", "noKid"] {
            let decoded = crate::plugins::oauth::state::decode_account_cookie_value(
                secret,
                vectors[name].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), vectors["payload"]);
        }
        for name in ["wrongSalt", "wrongSecret", "expired", "gcm", "jws"] {
            assert!(
                crate::plugins::oauth::state::decode_account_cookie_value(
                    secret,
                    vectors[name].as_str().unwrap()
                )
                .is_err(),
                "{name} must not resolve a provider account"
            );
        }
        let original = vectors["valid"].as_str().unwrap();
        for segment in [0, 2, 3, 4] {
            let mut parts: Vec<_> = original.split('.').map(str::to_owned).collect();
            let mut bytes = BASE64.decode(&parts[segment]).unwrap();
            bytes[0] ^= 1;
            parts[segment] = BASE64.encode(bytes);
            assert!(
                crate::plugins::oauth::state::decode_account_cookie_value(secret, &parts.join("."))
                    .is_err(),
                "changed segment {segment} must not authenticate"
            );
        }
    }
