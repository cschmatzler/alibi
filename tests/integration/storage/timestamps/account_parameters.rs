use super::*;
use serde_json::Value;

pub(super) async fn exercise<S: AuthSchema>(
    raw: &Raw,
    store: &dyn AuthStore<S>,
    naive: bool,
) -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/account-timestamp-parameters.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let backend = if raw.is_postgres() {
        "postgres"
    } else {
        "sqlite"
    };
    let profiles = fixture["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    let profile = profiles
        .iter()
        .find(|profile| profile["backend"] == backend)
        .unwrap();
    let cases = profile["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    let user = store
        .create_user(
            CreateUser::new()
                .with_name("Timestamp")
                .with_email("account-timestamp@example.com"),
        )
        .await?;
    for case in cases {
        let operation = case["operation"].as_str().unwrap();
        let kind = case["kind"].as_str().unwrap();
        let key = format!("{operation}-{kind}");
        let mut input = CreateAccount {
            additional_fields: Default::default(),
            user_id: user.id().into_owned(),
            account_id: key.as_str().into(),
            provider_id: "timestamp-provider".into(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: None,
        };
        let account = match operation {
            "create" => {
                if kind == "date" {
                    input.access_token_expires_at = Some(case["input"].as_str().unwrap().parse()?);
                } else {
                    _ = input
                        .additional_fields
                        .insert("accessTokenExpiresAt".into(), case["input"].clone().into());
                }
                store
                    .create_account(input)
                    .await
                    .map_err(|error| format!("{backend}/{operation}/{kind}: {error}"))?
            }
            "update" => {
                input.access_token_expires_at = Some("2030-01-01T00:00:00.123Z".parse()?);
                let original = store.create_account(input).await?;
                let mut update = UpdateAccount::default();
                if kind == "date" {
                    update.access_token_expires_at = Some(case["input"].as_str().unwrap().parse()?);
                } else {
                    _ = update
                        .additional_fields
                        .insert("accessTokenExpiresAt".into(), case["input"].clone().into());
                }
                let account = store
                    .update_account(original.id().as_ref(), update)
                    .await
                    .map_err(|error| format!("{backend}/{operation}/{kind}: {error}"))?;
                assert_eq!(account.id(), original.id(), "{backend}/{operation}/{kind}");
                account
            }
            _ => panic!("unknown source account operation: {operation}"),
        };
        let expected: Option<DateTime<Utc>> =
            case["output"].as_str().map(str::parse).transpose()?;
        assert_eq!(
            account.access_token_expires_at(),
            expected,
            "{backend}/{operation}/{kind}"
        );
        let readback = store
            .get_account("timestamp-provider", &key.as_str().into())
            .await?
            .ok_or("timestamp account missing")?;
        assert_eq!(readback.id(), account.id(), "{backend}/{operation}/{kind}");
        assert_eq!(
            readback.access_token_expires_at(),
            expected,
            "{backend}/{operation}/{kind} readback"
        );
        assert_eq!(
            stored_date(
                raw,
                "account",
                "accessTokenExpiresAt",
                account.id().as_ref(),
                naive
            )
            .await?,
            expected,
            "{backend}/{operation}/{kind} physical timestamp"
        );
    }
    Ok(())
}
