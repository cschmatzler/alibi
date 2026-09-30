//! Optional SIWE wallet persistence. Wallets are concrete plugin records and do
//! not add an associated entity to application-owned core schemas.

use async_trait::async_trait;

use crate::{AuthError, AuthResult, CreateWalletAddress, WalletAddress};

#[async_trait]
pub trait WalletAddressStore: Send + Sync {
    /// Return the adapter's first address match, optionally restricted to a
    /// chain. No expiry filter or implicit chain ordering applies.
    async fn get_wallet_address(
        &self,
        _address: &str,
        _chain_id: Option<f64>,
    ) -> AuthResult<Option<WalletAddress>> {
        Err(AuthError::NotImplemented(
            "Wallet address lookup is not supported by this store".to_owned(),
        ))
    }

    /// Validate that the owner exists and insert the wallet under the same
    /// transaction/lock. User deletion must remove these owned records under
    /// its transaction/lock, including application-owned user schemas.
    async fn create_wallet_address(&self, _data: CreateWalletAddress) -> AuthResult<WalletAddress> {
        Err(AuthError::NotImplemented(
            "Wallet address creation is not supported by this store".to_owned(),
        ))
    }
}
