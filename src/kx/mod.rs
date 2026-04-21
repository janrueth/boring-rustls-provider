use rustls::crypto::{
    self,
    kx::{NamedGroup, StartedKeyExchange, SupportedKxGroup},
};
use rustls_pki_types::FipsStatus;

use crate::helper::log_and_map;

mod ex;
#[cfg(feature = "mlkem")]
mod pq;
#[cfg(feature = "mlkem")]
pub(crate) use pq::X25519MlKem768;

/// Key type discriminant used by [`ex::KeyExchange`] to select the
/// appropriate peer key parsing and DH derivation logic.
enum DhKeyType {
    EC((boring::ec::EcGroup, i32)),
    #[cfg(not(feature = "fips"))]
    ED(i32),
}

/// A X25519-based key exchange
#[cfg(not(feature = "fips"))]
#[derive(Debug)]
pub struct X25519;

#[cfg(not(feature = "fips"))]
impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<StartedKeyExchange, rustls::Error> {
        Ok(StartedKeyExchange::Single(Box::new(
            ex::KeyExchange::with_x25519()
                .map_err(|e| log_and_map("X25519.start", e, crypto::GetRandomFailed))?,
        )))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn fips(&self) -> FipsStatus {
        FipsStatus::Unvalidated
    }
}

/// A secp256r1-based key exchange
#[derive(Debug)]
pub struct Secp256r1;

impl SupportedKxGroup for Secp256r1 {
    fn start(&self) -> Result<StartedKeyExchange, rustls::Error> {
        Ok(StartedKeyExchange::Single(Box::new(
            ex::KeyExchange::with_secp256r1()
                .map_err(|e| log_and_map("Secp256r1.start", e, crypto::GetRandomFailed))?,
        )))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }

    fn fips(&self) -> FipsStatus {
        if cfg!(feature = "fips") {
            FipsStatus::Pending
        } else {
            FipsStatus::Unvalidated
        }
    }
}

/// A secp384r1-based key exchange
#[derive(Debug)]
pub struct Secp384r1;

impl SupportedKxGroup for Secp384r1 {
    fn start(&self) -> Result<StartedKeyExchange, rustls::Error> {
        Ok(StartedKeyExchange::Single(Box::new(
            ex::KeyExchange::with_secp384r1()
                .map_err(|e| log_and_map("Secp384r1.start", e, crypto::GetRandomFailed))?,
        )))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }

    fn fips(&self) -> FipsStatus {
        if cfg!(feature = "fips") {
            FipsStatus::Pending
        } else {
            FipsStatus::Unvalidated
        }
    }
}
