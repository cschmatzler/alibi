//! Independent compact-JWS minting for validator interoperability cases.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
pub(super) fn sign(
    private: &serde_json::Value,
    payload: &serde_json::Value,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(
            private["d"]
                .as_str()
                .ok_or("Missing Ed25519 private material")?,
        )?
        .try_into()
        .map_err(|_| "Invalid Ed25519 seed length")?;
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"alg":"EdDSA"}))?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload)?)
    );
    let signature = SigningKey::from_bytes(&seed).sign(input.as_bytes());
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}
