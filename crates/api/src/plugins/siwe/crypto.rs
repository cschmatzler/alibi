use async_trait::async_trait;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

use super::config::{SiweCallbackResult, SiweVerification, SiweVerifier};
use super::parse::valid_address;

/// EIP-191 personal-sign message digest. The prefix uses the UTF-8 byte count,
/// including any non-ASCII statement or SIWE field in the original message.
pub fn ethereum_message_hash(message: &str) -> [u8; 32] {
    let mut digest = Keccak256::new();
    digest.update(b"\x19Ethereum Signed Message:\n");
    digest.update(message.len().to_string().as_bytes());
    digest.update(message.as_bytes());
    digest.finalize().into()
}

pub(super) fn checksum_address(address: &str) -> Option<String> {
    if !valid_address(address) {
        return None;
    }
    let lower = address.get(2..)?.to_ascii_lowercase();
    let digest = Keccak256::digest(lower.as_bytes());
    let mut checksum = String::from("0x");
    for (index, character) in lower.bytes().enumerate() {
        let byte = *digest.get(index / 2)?;
        let nibble = if index % 2 == 0 { byte >> 4 } else { byte & 15 };
        checksum.push(char::from(if nibble >= 8 {
            character.to_ascii_uppercase()
        } else {
            character
        }));
    }
    Some(checksum)
}

fn hex_bytes(value: &str) -> Option<Vec<u8>> {
    let value = value.strip_prefix("0x")?;
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let upper = char::from(*pair.first()?).to_digit(16)?;
            let lower = char::from(*pair.get(1)?).to_digit(16)?;
            Some(((upper << 4) | lower) as u8)
        })
        .collect()
}

/// Secure EIP-191 verifier for externally owned Ethereum accounts. Contract
/// wallets can use a custom [`SiweVerifier`] backed by the application's RPC.
#[derive(Debug, Clone, Copy, Default)]
pub struct Eip191Verifier;

impl Eip191Verifier {
    /// Recover the checksummed signer from a 65-byte `r,s,v` signature or an
    /// EIP-2098 compact signature. Invalid encodings return `None`.
    pub fn recover_address(message: &str, signature: &str) -> Option<String> {
        Self::recover_hash_address(&ethereum_message_hash(message), signature)
    }

    /// Recover a personal-sign signer from its already computed digest. This
    /// supports application-owned contract-wallet and JSON-RPC integrations.
    pub fn recover_hash_address(digest: &[u8; 32], signature: &str) -> Option<String> {
        let bytes = hex_bytes(signature)?;
        let (signature, recovery) = match bytes.len() {
            65 => {
                let signature = Signature::from_slice(bytes.get(..64)?).ok()?;
                let encoded = *bytes.get(64)?;
                let recovery = match encoded {
                    0 | 1 => encoded,
                    27 | 28 => encoded - 27,
                    _ => return None,
                };
                (signature, recovery)
            }
            64 => {
                let mut compact: [u8; 64] = bytes.try_into().ok()?;
                let recovery = *compact.get(32)? >> 7;
                if let Some(first) = compact.get_mut(32) {
                    *first &= 127;
                }
                (Signature::from_slice(&compact).ok()?, recovery)
            }
            _ => return None,
        };
        // Reject noncanonical signatures rather than allowing an alternative
        // high-S encoding to bypass the verifier's signature policy.
        if signature.normalize_s().is_some() {
            return None;
        }
        let key = VerifyingKey::recover_from_prehash(
            digest,
            &signature,
            RecoveryId::try_from(recovery).ok()?,
        )
        .ok()?;
        let public_key = key.to_encoded_point(false);
        let hash = Keccak256::digest(public_key.as_bytes().get(1..)?);
        let mut address = String::from("0x");
        use std::fmt::Write;
        for byte in hash.get(12..)? {
            write!(address, "{byte:02x}").ok()?;
        }
        checksum_address(&address)
    }
}

#[async_trait]
impl SiweVerifier for Eip191Verifier {
    async fn verify_message(&self, input: SiweVerification) -> SiweCallbackResult<bool> {
        Ok(Self::recover_address(&input.message, &input.signature)
            .is_some_and(|address| address == input.address))
    }
}
