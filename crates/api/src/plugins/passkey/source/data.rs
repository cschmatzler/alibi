//! Parse policy fields without changing the bytes authenticated by signatures.
use serde::Deserialize;
use std::marker::PhantomData;
use webauthn_rs_core::{error::WebauthnError, proto::*};

#[derive(Debug)]
pub(in crate::plugins::passkey) struct AuthenticatorData<T: Ceremony> {
    pub rp_id_hash: [u8; 32],
    pub counter: u32,
    pub user_verified: bool,
    pub user_present: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub acd: Option<AttestedCredentialData>,
    ceremony: PhantomData<T>,
}
impl<T: Ceremony> AuthenticatorData<T> {
    pub(in crate::plugins::passkey) fn from_source(bytes: &[u8]) -> Result<Self, WebauthnError> {
        let malformed = || WebauthnError::ParseNOMFailure;
        let rp_id_hash = bytes
            .get(..32)
            .ok_or_else(malformed)?
            .try_into()
            .map_err(|_| malformed())?;
        let flags = *bytes.get(32).ok_or_else(malformed)?;
        let counter = u32::from_be_bytes(
            bytes
                .get(33..37)
                .ok_or_else(malformed)?
                .try_into()
                .map_err(|_| malformed())?,
        );
        let acd = if flags & 0x40 != 0 {
            let aaguid = bytes
                .get(37..53)
                .ok_or_else(malformed)?
                .try_into()
                .map_err(|_| malformed())?;
            let size = u16::from_be_bytes(
                bytes
                    .get(53..55)
                    .ok_or_else(malformed)?
                    .try_into()
                    .map_err(|_| malformed())?,
            );
            let end = 55 + usize::from(size);
            let credential_id = bytes.get(55..end).ok_or_else(malformed)?.to_vec().into();
            let mut decoder =
                serde_cbor_2::de::Deserializer::from_slice(bytes.get(end..).ok_or_else(malformed)?);
            let credential_pk = serde_cbor_2::Value::deserialize(&mut decoder)?;
            Some(AttestedCredentialData {
                aaguid,
                credential_id,
                credential_pk,
            })
        } else {
            None
        };
        Ok(Self {
            rp_id_hash,
            counter,
            user_verified: flags & 4 != 0,
            user_present: flags & 1 != 0,
            backup_eligible: flags & 8 != 0,
            backup_state: flags & 16 != 0,
            acd,
            ceremony: PhantomData,
        })
    }
}

pub(super) struct AttestationObject<T: Ceremony> {
    pub fmt: String,
    pub att_stmt: serde_cbor_2::Value,
    pub auth_data: AuthenticatorData<T>,
    pub auth_data_bytes: Vec<u8>,
}
impl<T: Ceremony> AttestationObject<T> {
    pub(super) fn from_source(bytes: &[u8]) -> Result<Self, WebauthnError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Object<'a> {
            fmt: &'a str,
            att_stmt: serde_cbor_2::Value,
            auth_data: &'a [u8],
            ep_att: Option<bool>,
            large_blob_key: Option<&'a [u8]>,
        }
        let mut decoder = serde_cbor_2::de::Deserializer::from_slice(bytes);
        let _ = serde_cbor_2::Value::deserialize(&mut decoder)?;
        let inner: Object<'_> = serde_cbor_2::from_slice(
            bytes
                .get(..decoder.byte_offset())
                .ok_or(WebauthnError::ParseNOMFailure)?,
        )?;
        let _ = (inner.ep_att, inner.large_blob_key);
        Ok(Self {
            fmt: inner.fmt.into(),
            att_stmt: inner.att_stmt,
            auth_data: AuthenticatorData::from_source(inner.auth_data)?,
            auth_data_bytes: inner.auth_data.to_vec(),
        })
    }
}
