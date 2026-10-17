use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead as _, KeyInit as _},
};
use alibi::plugins::{
    OAuthDecodedRefreshToken, OAuthRefreshTokenEncryption, OAuthRefreshTokenFormatter,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

pub(crate) const KEY: &[u8; 32] = b"application-refresh-key-32-bytes";

#[derive(Debug, Default)]
pub(crate) struct Formatter {
    pub encrypt_mode: Mutex<String>,
    pub decrypt_mode: Mutex<String>,
    pub calls: Mutex<Vec<Value>>,
    pub completed: Arc<Mutex<Vec<Value>>>,
}

pub(crate) fn open(token: &str) -> alibi::AuthResult<Value> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| alibi::AuthError::internal("refresh decryption failed"))?;
    if bytes.len() < 28 {
        return Err(alibi::AuthError::internal("refresh decryption failed"));
    }
    let nonce = Nonce::try_from(&bytes[..12]).unwrap();
    let plain = Aes256Gcm::new_from_slice(KEY)
        .unwrap()
        .decrypt(&nonce, &bytes[12..])
        .map_err(|_| alibi::AuthError::internal("refresh decryption failed"))?;
    Ok(serde_json::from_slice(&plain)?)
}

fn seal(token: &str, session_id: Option<&str>) -> alibi::AuthResult<String> {
    let nonce = uuid::Uuid::new_v4();
    let nonce = &nonce.as_bytes()[..12];
    let payload = serde_json::to_vec(&json!({"token":token,"sessionId":session_id}))?;
    let nonce_value = Nonce::try_from(nonce).unwrap();
    let encrypted = Aes256Gcm::new_from_slice(KEY)
        .unwrap()
        .encrypt(&nonce_value, payload.as_slice())
        .map_err(|_| alibi::AuthError::internal("refresh encryption failed"))?;
    Ok(URL_SAFE_NO_PAD.encode([nonce, encrypted.as_slice()].concat()))
}

#[async_trait::async_trait]
impl OAuthRefreshTokenFormatter for Formatter {
    fn encrypt(
        &self,
        token: &str,
        session_id: Option<&str>,
    ) -> alibi::AuthResult<OAuthRefreshTokenEncryption> {
        self.calls
            .lock()
            .unwrap()
            .push(json!({"kind":"encrypt","token":token,"sessionId":session_id}));
        match self.encrypt_mode.lock().unwrap().as_str() {
            "error" => Err(alibi::AuthError::internal("refresh encryption failed")),
            "empty" => Ok(OAuthRefreshTokenEncryption::Immediate(String::new())),
            "async" => {
                let token = token.to_owned();
                let session_id = session_id.map(str::to_owned);
                let completed = self.completed.clone();
                Ok(OAuthRefreshTokenEncryption::Promise(Box::pin(async move {
                    let encrypted = seal(&token, session_id.as_deref())?;
                    completed
                        .lock()
                        .unwrap()
                        .push(json!({"token":token,"sessionId":session_id}));
                    Ok(encrypted)
                })))
            }
            _ => Ok(OAuthRefreshTokenEncryption::Immediate(seal(
                token, session_id,
            )?)),
        }
    }
    async fn decrypt(&self, token: &str) -> alibi::AuthResult<OAuthDecodedRefreshToken> {
        self.calls
            .lock()
            .unwrap()
            .push(json!({"kind":"decrypt","token":token}));
        let mode = self.decrypt_mode.lock().unwrap().clone();
        if mode != "sync" {
            tokio::task::yield_now().await;
        }
        if mode == "error" {
            return Err(alibi::AuthError::internal("refresh decryption failed"));
        }
        if mode == "api-error" {
            return Err(alibi::AuthError::Api {
                status: 429,
                code: Some("REFRESH_FORMAT_LIMIT".into()),
                message: "Refresh formatter limited".into(),
            });
        }
        if mode == "forbidden" {
            return Err(alibi::AuthError::forbidden("Refresh formatter forbidden"));
        }
        if mode == "upstream" {
            return Err(alibi::AuthError::Upstream {
                status: 503,
                code: "REFRESH_FORMAT_UNAVAILABLE",
                message: "Refresh formatter unavailable",
            });
        }
        if mode == "empty" {
            return Ok(OAuthDecodedRefreshToken {
                token: String::new(),
                session_id: None,
            });
        }
        let value = open(token)?;
        Ok(OAuthDecodedRefreshToken {
            token: value["token"].as_str().unwrap().into(),
            session_id: if mode == "wrong-session" {
                Some("not-the-persisted-session".into())
            } else if mode == "no-session" {
                None
            } else {
                value["sessionId"].as_str().map(str::to_owned)
            },
        })
    }
}
