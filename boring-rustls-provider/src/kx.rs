use rustls::crypto::{self, ActiveKeyExchange};

use crate::helper::log_and_map;

mod dh;
mod ex;

enum DhKeyType {
    EC((boring::ec::EcGroup, i32)),
    ED(i32),
    FFDHE2048,
}

/// A X25519-based key exchange
#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(ex::KeyExchange::with_x25519().map_err(|e| {
            log_and_map("X25519.start", e, crypto::GetRandomFailed)
        })?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

/// A X448-based key exchange
#[derive(Debug)]
pub struct X448;

impl crypto::SupportedKxGroup for X448 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(ex::KeyExchange::with_x448().map_err(|e| {
            log_and_map("X448.start", e, crypto::GetRandomFailed)
        })?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X448
    }
}

/// A secp256r1-based key exchange
#[derive(Debug)]
pub struct Secp256r1;

impl crypto::SupportedKxGroup for Secp256r1 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(ex::KeyExchange::with_secp256r1().map_err(
            |e| log_and_map("Secp256r1.start", e, crypto::GetRandomFailed),
        )?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp256r1
    }
}

/// A secp384r1-based key exchange
#[derive(Debug)]
pub struct Secp384r1;

impl crypto::SupportedKxGroup for Secp384r1 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(ex::KeyExchange::with_secp384r1().map_err(
            |e| log_and_map("Secp384r1.start", e, crypto::GetRandomFailed),
        )?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp384r1
    }
}

/// A secp521r1-based key exchange
#[derive(Debug)]
pub struct Secp521r1;

impl crypto::SupportedKxGroup for Secp521r1 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(ex::KeyExchange::with_secp521r1().map_err(
            |e| log_and_map("Secp521r1.start", e, crypto::GetRandomFailed),
        )?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp521r1
    }
}

/// A ffedhe2048-based key exchange
#[derive(Debug)]
pub struct FfDHe2048;

impl crypto::SupportedKxGroup for FfDHe2048 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(dh::KeyExchange::generate_ffdhe_2048().map_err(
            |e| log_and_map("FfDHe2048.start", e, crypto::GetRandomFailed),
        )?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::FFDHE2048
    }
}
