//! The private operator API on real application-owned SQLx and SeaORM models.
#![allow(
    dead_code,
    unreachable_pub,
    reason = "generated application schemas contain all plugin models"
)]

use crate::storage::{Db, TestResult};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use alibi::plugins::oauth_token_conversion::*;
use alibi::{AuthConfig, AuthSchema, ManagedSecrets};
use alibi_core::{AuthAccount, AuthUser, CreateAccount, CreateUser, store::AuthStore};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

const ORIGINAL: &str = "legacy-original-operator-fixture-secret-190";
const CURRENT: &str = "current-operator-fixture-secret-190";

#[cfg(feature = "sqlx")]
mod sqlx_schema {
    include!("../../../fixtures/cli/sqlx_all.rs");
    #[tokio::test]
    async fn legacy_conversion_sqlx() -> super::TestResult {
        let db = super::Db::sqlite().await?;
        let pool = SqlxPool::connect(&db.url).await?;
        run_app_migrations(&pool).await?;
        let store = alibi::sqlx::SqlxStore::<AppAuthSchema>::new(super::config(), pool.clone());
        super::exercise(&store, &db).await?;
        pool.close().await;
        Ok(())
    }
}

#[cfg(feature = "seaorm")]
mod seaorm_schema {
    include!("../../../fixtures/cli/seaorm_all.rs");
    #[tokio::test]
    async fn legacy_conversion_seaorm() -> super::TestResult {
        let db = super::Db::sqlite().await?;
        let database = alibi::seaorm::Database::connect(&db.url).await?;
        run_app_migrations(&database).await?;
        let store =
            alibi::seaorm::SeaOrmStore::<AppAuthSchema>::new(super::config(), database.clone());
        super::exercise(&store, &db).await?;
        database.close().await?;
        Ok(())
    }
}

fn config() -> AuthConfig {
    let mut config = AuthConfig::new(CURRENT).managed_secrets(ManagedSecrets::new(7, CURRENT));
    config.account.encrypt_oauth_tokens = true;
    config
}

// Independent historical writer, with a fixed nonce for reproducible fixtures.
// This is the published native format, not a call to the conversion reader.
fn legacy(plain: &str) -> TestResult<String> {
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(None, ORIGINAL.as_bytes())
        .expand(b"better-auth-oauth-token-encryption", &mut key)
        .map_err(|_| "fixture HKDF")?;
    let nonce = Nonce::from([19u8; 12]);
    let ciphertext = Aes256Gcm::new_from_slice(&key)?
        .encrypt(&Nonce::from(nonce), plain.as_bytes())
        .map_err(|_| "fixture encryption")?;
    Ok(STANDARD.encode(nonce.into_iter().chain(ciphertext).collect::<Vec<_>>()))
}

// Independent Source reader: current-version envelope, SHA256 key, managed
// 24-byte nonce, hex ciphertext/tag. Never uses the implementation under test.
fn source_plain(value: &str) -> TestResult<String> {
    let value = value
        .strip_prefix("$ba$7$")
        .ok_or("missing managed envelope")?;
    let bytes = value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| -> TestResult<u8> { Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?) })
        .collect::<TestResult<Vec<_>>>()?;
    let (nonce, ciphertext) = bytes.split_at(24);
    let plain = XChaCha20Poly1305::new(&Sha256::digest(CURRENT.as_bytes()))
        .decrypt(
            &XNonce::try_from(nonce).map_err(|_| "Source nonce")?,
            ciphertext,
        )
        .map_err(|_| "Source authentication")?;
    Ok(String::from_utf8(plain)?)
}

fn manifest<A: AuthAccount>(account: &A) -> TrustedOAuthTokenManifest {
    TrustedOAuthTokenManifest {
        observed: OAuthTokenSnapshot {
            id: account.id().into_owned(),
            user_id: account.user_id().into_owned(),
            provider_id: account.provider_id().into(),
            account_id: account.account_id().into(),
            tokens: OAuthTokenValues {
                access_token: account.access_token().map(str::to_owned),
                refresh_token: account.refresh_token().map(str::to_owned),
                id_token: account.id_token().map(str::to_owned),
            },
        },
        access_encoding: TokenEncoding::LegacyNative,
        refresh_encoding: TokenEncoding::LegacyNative,
        id_encoding: TokenEncoding::LegacyNative,
    }
}

async fn exercise<S: AuthSchema>(
    store: &(impl AuthStore<S> + OAuthTokenConversionStore<S>),
    db: &Db,
) -> TestResult {
    use alibi::plugins::oauth::encryption::{
        decrypt_token_with_config, encrypt_token, encrypt_token_with_config,
    };
    let bare = encrypt_token("legacy-reader-token", ORIGINAL)?;
    assert!(decrypt_token_with_config(&bare, &config()).is_err());
    let reader = config().managed_secrets(ManagedSecrets::new(7, CURRENT).legacy(ORIGINAL));
    assert_eq!(
        decrypt_token_with_config(&bare, &reader)?,
        "legacy-reader-token"
    );
    let wrong =
        config().managed_secrets(ManagedSecrets::new(7, CURRENT).legacy("wrong-legacy-reader"));
    assert!(decrypt_token_with_config(&bare, &wrong).is_err());
    let written = encrypt_token_with_config("current-writer-token", &reader)?;
    assert_eq!(source_plain(&written)?, "current-writer-token");
    // Application-defined collations must not weaken snapshot CAS. Recreate
    // only this empty owned fixture table with NOCASE token/identity columns.
    let schema = db
        .text(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='accounts'",
            &[],
        )
        .await?
        .ok_or("account DDL")?;
    _ = db.execute("DROP TABLE accounts", &[]).await?;
    _ = db
        .execute(
            &schema
                .replace("TEXT", "TEXT COLLATE NOCASE")
                .replace("text", "text COLLATE NOCASE"),
            &[],
        )
        .await?;
    let owner = store
        .create_user(CreateUser::new().with_email("owner@conversion190.test"))
        .await?;
    let other = store
        .create_user(CreateUser::new().with_email("other@conversion190.test"))
        .await?;
    let account = store
        .create_account(CreateAccount {
            user_id: owner.id().into_owned(),
            provider_id: "operator-fixture".into(),
            account_id: "legacy-row".into(),
            access_token: Some(legacy("access190")?),
            refresh_token: Some(legacy("refresh190")?),
            id_token: Some(legacy("id190")?),
            scope: Some("retained-scope".into()),
            password: Some("retained-password".into()),
            access_token_expires_at: Some(chrono::Utc::now()),
            refresh_token_expires_at: Some(chrono::Utc::now()),
            additional_fields: Default::default(),
        })
        .await?;
    let input = manifest(&account);
    let initial = db.table("accounts").await?;
    assert!(OAuthTokenConversion::prepare(input.clone(), "wrong-secret", &config()).is_err());
    for field in 0..3 {
        let mut damaged = input.clone();
        let token = match field {
            0 => &mut damaged.observed.tokens.access_token,
            1 => &mut damaged.observed.tokens.refresh_token,
            _ => &mut damaged.observed.tokens.id_token,
        };
        *token = Some(legacy("tamper")?);
        // Change an authenticated ciphertext byte.
        let token = token.as_mut().ok_or("fixture token")?;
        token.replace_range(
            20..21,
            if token.get(20..21) == Some("A") {
                "B"
            } else {
                "A"
            },
        );
        assert!(OAuthTokenConversion::prepare(damaged, ORIGINAL, &config()).is_err());
    }
    assert_eq!(db.table("accounts").await?, initial);
    let plan = OAuthTokenConversion::prepare(input.clone(), ORIGINAL, &config())?;
    // FAIL preserves prior statement/trigger writes unless the adapter rolls
    // back an explicit transaction; ABORT alone cannot prove that contract.
    for action in ["ABORT", "FAIL"] {
        _ = db.execute(&format!("CREATE TRIGGER conversion190_fail AFTER UPDATE OF access_token ON accounts BEGIN UPDATE accounts SET refresh_token='trigger-change' WHERE id=NEW.id; SELECT RAISE({action}, 'owned fixture failure'); END"), &[]).await?;
        assert!(plan.apply(store).await.is_err());
        assert!(
            db.table("accounts").await? == initial,
            "{action} must roll back token and trigger writes"
        );
        _ = db.execute("DROP TRIGGER conversion190_fail", &[]).await?;
    }
    assert!(plan.apply(store).await?);
    let converted = store
        .get_account("operator-fixture", "legacy-row")
        .await?
        .ok_or("account")?;
    assert_eq!(
        source_plain(converted.access_token().ok_or("access")?)?,
        "access190"
    );
    assert_eq!(
        source_plain(converted.refresh_token().ok_or("refresh")?)?,
        "refresh190"
    );
    assert_eq!(converted.id_token(), Some("id190"));
    let mut before: serde_json::Value = serde_json::from_str(&initial)?;
    let mut after: serde_json::Value = serde_json::from_str(&db.table("accounts").await?)?;
    for rows in [&mut before, &mut after] {
        let row = rows
            .as_array_mut()
            .and_then(|rows| rows.first_mut())
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("physical row")?;
        for field in ["access_token", "refresh_token", "id_token"] {
            _ = row.remove(field);
        }
    }
    assert_eq!(before, after); // All untouched physical columns, including timestamps.
    assert!(!plan.apply(store).await?); // Retry cannot reapply old legacy observations.
    let stable = db.table("accounts").await?;
    let mut current = manifest(&converted);
    current.access_encoding = TokenEncoding::Source;
    current.refresh_encoding = TokenEncoding::Source;
    current.id_encoding = TokenEncoding::Plain;
    assert!(
        OAuthTokenConversion::prepare(current, ORIGINAL, &config())?
            .apply(store)
            .await?
    );
    assert_eq!(db.table("accounts").await?, stable); // Explicit already-converted retry.

    // Restore only the owned fixture's tokens, then interleave real side-pool writes.
    for (change, case_only) in [
        ("refresh_token", false),
        ("access_token", false),
        ("id_token", false),
        ("user_id", false),
        ("provider_id", false),
        ("account_id", false),
        ("refresh_token", true),
        ("access_token", true),
        ("id_token", true),
        ("provider_id", true),
        ("account_id", true),
        ("user_id", true),
    ] {
        _ = db.execute("UPDATE accounts SET access_token=$1, refresh_token=$2, id_token=$3, user_id=$4, provider_id=$5, account_id=$6 WHERE id=$7", &[
            input.observed.tokens.access_token.as_deref().ok_or("access")?, input.observed.tokens.refresh_token.as_deref().ok_or("refresh")?, input.observed.tokens.id_token.as_deref().ok_or("id")?, &input.observed.user_id, &input.observed.provider_id, &input.observed.account_id, &input.observed.id]).await?;
        let pending = OAuthTokenConversion::prepare(input.clone(), ORIGINAL, &config())?;
        let value = if case_only {
            match change {
                "access_token" => input
                    .observed
                    .tokens
                    .access_token
                    .as_deref()
                    .ok_or("access")?,
                "refresh_token" => input
                    .observed
                    .tokens
                    .refresh_token
                    .as_deref()
                    .ok_or("refresh")?,
                "id_token" => input.observed.tokens.id_token.as_deref().ok_or("id")?,
                "provider_id" => &input.observed.provider_id,
                "account_id" => &input.observed.account_id,
                _ => &input.observed.user_id,
            }
            .to_uppercase()
        } else if change == "user_id" {
            other.id().into_owned()
        } else {
            "concurrent-change".into()
        };
        _ = db
            .execute(
                &format!("UPDATE accounts SET {change}=$1 WHERE id=$2"),
                &[&value, &input.observed.id],
            )
            .await?;
        let concurrent = db.table("accounts").await?;
        assert!(!pending.apply(store).await?);
        assert_eq!(db.table("accounts").await?, concurrent);
    }
    // Mixed plaintext and NULL require explicit classifications; no guessing.
    _ = db.execute("UPDATE accounts SET access_token=$1, refresh_token=NULL, id_token=$2, user_id=$3, provider_id=$4, account_id=$5 WHERE id=$6", &["plain-access", "plain-id", &input.observed.user_id, &input.observed.provider_id, &input.observed.account_id, &input.observed.id]).await?;
    let mixed = store
        .get_account("operator-fixture", "legacy-row")
        .await?
        .ok_or("mixed account")?;
    let mut mixed = manifest(&mixed);
    assert!(OAuthTokenConversion::prepare(mixed.clone(), ORIGINAL, &config()).is_err());
    mixed.access_encoding = TokenEncoding::Plain;
    mixed.refresh_encoding = TokenEncoding::Absent;
    mixed.id_encoding = TokenEncoding::Plain;
    assert!(
        OAuthTokenConversion::prepare(mixed, ORIGINAL, &config())?
            .apply(store)
            .await?
    );
    let mixed = store
        .get_account("operator-fixture", "legacy-row")
        .await?
        .ok_or("mixed account")?;
    assert_eq!(
        source_plain(mixed.access_token().ok_or("mixed access")?)?,
        "plain-access"
    );
    assert_eq!(mixed.refresh_token(), None);
    assert_eq!(mixed.id_token(), Some("plain-id"));
    let mut missing = manifest(&mixed);
    missing.access_encoding = TokenEncoding::Source;
    missing.refresh_encoding = TokenEncoding::Absent;
    missing.id_encoding = TokenEncoding::Plain;
    let pending = OAuthTokenConversion::prepare(missing, ORIGINAL, &config())?;
    _ = db
        .execute("DELETE FROM accounts WHERE id=$1", &[&input.observed.id])
        .await?;
    assert!(!pending.apply(store).await?);
    Ok(())
}
