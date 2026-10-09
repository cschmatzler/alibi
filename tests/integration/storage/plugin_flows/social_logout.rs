//! Provider logout destinations after local sign-out, for each combination of
//! configured redirect, caller redirect and ID-token availability.
use super::social_flows::{Social, authorize, callback};
use super::*;
use alibi::plugins::oauth::{OAuthEndSessionConfig, OAuthProvider};
use alibi_core::AccountConfig;

backend_tests!(sign_out_builds_the_provider_logout_destination);

async fn sign_out_builds_the_provider_logout_destination<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cases: Vec<(&str, Option<&str>, bool, Value, Option<&str>)> = vec![
        (
            "caller redirect, state and token",
            Some("https://idp.example/logout?keep=yes"),
            true,
            json!({"callbackURL":"/bye","state":"caller"}),
            None,
        ),
        (
            "configured redirect resolved against the auth base",
            Some("https://idp.example/logout"),
            true,
            json!({}),
            Some("/signed-out"),
        ),
        (
            "no redirect and no token identifies the client",
            Some("https://idp.example/logout"),
            false,
            json!({}),
            None,
        ),
        (
            "redirect without a token",
            Some("https://idp.example/logout"),
            false,
            json!({"callbackURL":"/bye"}),
            None,
        ),
        (
            "provider without logout endpoint",
            None,
            true,
            json!({"callbackURL":"/bye"}),
            None,
        ),
        (
            "unparsable logout endpoint",
            Some("not a url"),
            true,
            json!({}),
            None,
        ),
    ];
    for (index, (label, endpoint, token, input, configured)) in cases.into_iter().enumerate() {
        let social = Social::start().await;
        let mut grant = json!({"access_token":"logout-access","token_type":"Bearer"});
        if token {
            grant["id_token"] = json!("provider-id-token");
        }
        social
            .provider
            .respond(200, "application/json", grant.to_string());
        social.profile.set(
            &format!("logout-sub-{index}"),
            &format!("logout-{index}@example.com"),
            true,
        );
        let auth = social
            .auth::<B>(
                &connection,
                AccountConfig::default(),
                |provider: &mut OAuthProvider| {
                    provider.authorization.as_mut().unwrap().end_session =
                        endpoint.map(|endpoint| OAuthEndSessionConfig {
                            endpoint: endpoint.into(),
                            post_logout_redirect_uri: configured.map(Into::into),
                        });
                },
            )
            .await?;
        let (state, cookie) = authorize(
            &auth,
            "/sign-in/social",
            json!({"provider":"google","callbackURL":"/home"}),
            "",
        )
        .await;
        let signed_in = callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await;
        assert_eq!(signed_in.status, 302, "{label}");
        let mut input = input;
        input["disableRedirect"] = json!(true);
        let response = call(
            &auth,
            request("/sign-out", Some(input), &cookies(&signed_in)),
            200,
        )
        .await;
        let result = body(&response);
        assert_eq!(result["success"], true, "{label}");
        let expected: Option<Vec<(&str, &str)>> = match label {
            "caller redirect, state and token" => Some(vec![
                ("keep", "yes"),
                ("id_token_hint", "provider-id-token"),
                ("post_logout_redirect_uri", "http://localhost:43219/bye"),
                ("client_id", "google-client"),
                ("state", "caller"),
            ]),
            "configured redirect resolved against the auth base" => Some(vec![
                ("id_token_hint", "provider-id-token"),
                (
                    "post_logout_redirect_uri",
                    "http://localhost:43219/signed-out",
                ),
                ("client_id", "google-client"),
            ]),
            "no redirect and no token identifies the client" => {
                Some(vec![("client_id", "google-client")])
            }
            "redirect without a token" => Some(vec![
                ("post_logout_redirect_uri", "http://localhost:43219/bye"),
                ("client_id", "google-client"),
            ]),
            _ => None,
        };
        match expected {
            Some(expected) => {
                let url = url::Url::parse(result["url"].as_str().unwrap())?;
                let actual: Vec<_> = url.query_pairs().into_owned().collect();
                let expected: Vec<_> = expected
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
                    .collect();
                assert_eq!(actual, expected, "{label}");
            }
            None => assert!(
                result.get("url").is_none_or(Value::is_null),
                "{label}: {result}"
            ),
        }
    }
    B::close(connection).await
}
