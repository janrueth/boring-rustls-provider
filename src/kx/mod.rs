use rustls::crypto::{self, ActiveKeyExchange};

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
impl crypto::SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange + 'static>, rustls::Error> {
        Ok(Box::new(ex::KeyExchange::with_x25519().map_err(|e| {
            log_and_map("X25519.start", e, crypto::GetRandomFailed)
        })?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }

    fn fips(&self) -> bool {
        false
    }
}

/// A secp256r1-based key exchange
#[derive(Debug)]
pub struct Secp256r1;

impl crypto::SupportedKxGroup for Secp256r1 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange + 'static>, rustls::Error> {
        Ok(Box::new(ex::KeyExchange::with_secp256r1().map_err(
            |e| log_and_map("Secp256r1.start", e, crypto::GetRandomFailed),
        )?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp256r1
    }

    fn fips(&self) -> bool {
        cfg!(feature = "fips")
    }
}

/// A secp384r1-based key exchange
#[derive(Debug)]
pub struct Secp384r1;

impl crypto::SupportedKxGroup for Secp384r1 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange + 'static>, rustls::Error> {
        Ok(Box::new(ex::KeyExchange::with_secp384r1().map_err(
            |e| log_and_map("Secp384r1.start", e, crypto::GetRandomFailed),
        )?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp384r1
    }

    fn fips(&self) -> bool {
        cfg!(feature = "fips")
    }
}
