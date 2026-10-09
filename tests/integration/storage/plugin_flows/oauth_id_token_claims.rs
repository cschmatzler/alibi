//! ID-token admission policy: algorithm, key selection, audience and date claims.
use super::social_flows::Social;
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::oauth::{HttpOAuthJwksSource, OAuthJwksSelection, OAuthProvider};
use alibi_core::AccountConfig;
use jsonwebtoken::Algorithm;

backend_tests!(id_token_policy_decides_admission_from_header_keys_and_claims);

fn claims() -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({"iss":"https://accounts.google.com","aud":"google-client","sub":"token-sub","email":"token@example.com","email_verified":true,"iat":now,"exp":now+300})
}

fn jwks(edit: impl FnOnce(&mut Value)) -> Value {
    let mut document: Value =
        serde_json::from_str(include_str!("../../../fixtures/one-tap/jwks.json")).unwrap();
    edit(&mut document["keys"][0]);
    document
}

struct Case {
    label: &'static str,
    configure: fn(&mut OAuthProvider),
    keys: Value,
    claims: Value,
    header: Value,
    token: Option<&'static str>,
}

impl Case {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            configure: |_| {},
            keys: jwks(|_| {}),
            claims: claims(),
            header: json!({"alg":"RS256","kid":"one-tap-local-rs256"}),
            token: None,
        }
    }
    fn claims(mut self, edit: impl FnOnce(&mut Value)) -> Self {
        edit(&mut self.claims);
        self
    }
    fn header(mut self, header: Value) -> Self {
        self.header = header;
        self
    }
    fn keys(mut self, edit: impl FnOnce(&mut Value)) -> Self {
        self.keys = jwks(edit);
        self
    }
    fn provider(mut self, configure: fn(&mut OAuthProvider)) -> Self {
        self.configure = configure;
        self
    }
}

fn id_token(provider: &mut OAuthProvider) -> &mut alibi::plugins::oauth::OAuthIdTokenConfig {
    provider.id_token.as_mut().unwrap()
}

async fn id_token_policy_decides_admission_from_header_keys_and_claims<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    let mut opaque = Case::new("opaque token allowed").provider(|provider| {
        provider.verify_id_token = None;
        id_token(provider).allow_opaque_token = true;
    });
    opaque.token = Some("opaque-token");
    let mut refused = Case::new("opaque token refused").provider(|provider| {
        provider.verify_id_token = None;
    });
    refused.token = Some("opaque-token");
    let cases = vec![
        Case::new("valid"),
        opaque,
        refused,
        Case::new("unexpected algorithm")
            .header(json!({"alg":"RS384","kid":"one-tap-local-rs256"})),
        Case::new("audience list")
            .claims(|claims| claims["aud"] = json!(["other-client", "google-client"])),
        Case::new("foreign audience list")
            .claims(|claims| claims["aud"] = json!(["other-client", 5])),
        Case::new("numeric audience").claims(|claims| claims["aud"] = json!(5)),
        Case::new("non-numeric expiry").claims(|claims| claims["exp"] = json!("soon")),
        Case::new("non-numeric not-before").claims(|claims| claims["nbf"] = json!("now")),
        Case::new("non-numeric issued-at").claims(|claims| claims["iat"] = json!("then")),
        Case::new("missing issued-at").claims(|claims| {
            drop(claims.as_object_mut().unwrap().remove("iat"));
        }),
        Case::new("truthy numeric key id").header(json!({"alg":"RS256","kid":7})),
        Case::new("truthy boolean key id").header(json!({"alg":"RS256","kid":true})),
        Case::new("truthy array key id").header(json!({"alg":"RS256","kid":[1]})),
        Case::new("truthy object key id").header(json!({"alg":"RS256","kid":{"id":1}})),
        Case::new("falsy numeric key id").header(json!({"alg":"RS256","kid":0})),
        Case::new("falsy empty key id").header(json!({"alg":"RS256","kid":""})),
        Case::new("falsy null key id").header(json!({"alg":"RS256","kid":null})),
        Case::new("unpinned algorithm differs from key")
            .provider(|provider| id_token(provider).algorithm = None)
            .header(json!({"alg":"RS384","kid":"one-tap-local-rs256"})),
        Case::new("unpinned algorithm without key algorithm")
            .provider(|provider| id_token(provider).algorithm = None)
            .keys(|key| drop(key.as_object_mut().unwrap().remove("alg"))),
        Case::new("unpinned algorithm matches key")
            .provider(|provider| id_token(provider).algorithm = None),
        Case::new("remote key operations verify")
            .provider(remote)
            .keys(|key| key["key_ops"] = json!(["verify"])),
        Case::new("remote key operations sign")
            .provider(remote)
            .keys(|key| key["key_ops"] = json!(["sign"])),
        Case::new("remote key operations repeated")
            .provider(remote)
            .keys(|key| key["key_ops"] = json!(["verify", "verify"])),
        Case::new("remote key operations mixed")
            .provider(remote)
            .keys(|key| key["key_ops"] = json!(["verify", 5])),
        Case::new("remote key operations not a list")
            .provider(remote)
            .keys(|key| key["key_ops"] = json!("verify")),
        Case::new("remote key extractable flag")
            .provider(remote)
            .keys(|key| key["ext"] = json!(true)),
        Case::new("remote key extractable text")
            .provider(remote)
            .keys(|key| key["ext"] = json!("yes")),
        Case::new("remote key private")
            .provider(remote)
            .keys(|key| key["d"] = json!("AQAB")),
        Case::new("remote key too small")
            .provider(remote)
            .keys(|key| key["n"] = json!("AAAAAQ")),
        Case::new("remote key empty modulus")
            .provider(remote)
            .keys(|key| key["n"] = json!("AAAA")),
        Case::new("remote key unreadable modulus")
            .provider(remote)
            .keys(|key| key["n"] = json!("***")),
        Case::new("remote key wrong use")
            .provider(remote)
            .keys(|key| key["use"] = json!("enc")),
        Case::new("remote key wrong algorithm")
            .provider(remote)
            .keys(|key| key["alg"] = json!("RS384")),
    ];
    for (index, case) in cases.into_iter().enumerate() {
        let social = Social::start().await;
        social.provider.respond_at("/keys", 200, case.keys.clone());
        let keys = Arc::new(HttpOAuthJwksSource::new(
            social.provider.url.join("keys")?.to_string(),
        ));
        let configure = case.configure;
        let auth = social
            .auth::<B>(&connection, AccountConfig::default(), |provider| {
                provider.verify_id_token = None;
                id_token(provider).jwks_source = keys;
                id_token(provider).max_age_secs = Some(3600);
                configure(provider);
            })
            .await?;
        social.profile.set(
            &format!("claims-sub-{index}"),
            &format!("claims-{index}@example.com"),
            true,
        );
        let proof = match case.token {
            Some(token) => token.to_owned(),
            None => super::oauth_signed::protected_token(&case.claims, case.header)?,
        };
        let response = Box::pin(auth.handle_request(request(
            "/sign-in/social",
            Some(json!({"provider":"google","idToken":{"token":proof}})),
            "",
        )))
        .await?;
        trace.response(case.label, &response);
    }
    trace.assert("social/id-token-claims");
    B::close(connection).await
}

fn remote(provider: &mut OAuthProvider) {
    id_token(provider).selection = OAuthJwksSelection::RemoteRs256;
    id_token(provider).algorithm = Some(Algorithm::RS256);
}
