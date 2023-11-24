use rustls::crypto::{self, ActiveKeyExchange};

use crate::helper::map_error_stack;

mod dh;
mod ex;

enum DhKeyType {
    EC((boring::ec::EcGroup, i32)),
    ED(i32),
    FFDHE2048,
}

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(ex::ExKeyExchange::with_x25519().map_err(|e| {
            map_error_stack("X25519.start", e, crypto::GetRandomFailed)
        })?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

#[derive(Debug)]
pub struct X448;

impl crypto::SupportedKxGroup for X448 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(ex::ExKeyExchange::with_x448().map_err(|e| {
            map_error_stack("X448.start", e, crypto::GetRandomFailed)
        })?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X448
    }
}

#[derive(Debug)]
pub struct Secp256r1;

impl crypto::SupportedKxGroup for Secp256r1 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(ex::ExKeyExchange::with_secp256r1().map_err(
            |e| map_error_stack("Secp256r1.start", e, crypto::GetRandomFailed),
        )?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp256r1
    }
}

#[derive(Debug)]
pub struct Secp384r1;

impl crypto::SupportedKxGroup for Secp384r1 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(ex::ExKeyExchange::with_secp384r1().map_err(
            |e| map_error_stack("Secp384r1.start", e, crypto::GetRandomFailed),
        )?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp384r1
    }
}

#[derive(Debug)]
pub struct Secp521r1;

impl crypto::SupportedKxGroup for Secp521r1 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(ex::ExKeyExchange::with_secp521r1().map_err(
            |e| map_error_stack("Secp521r1.start", e, crypto::GetRandomFailed),
        )?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp521r1
    }
}

#[derive(Debug)]
pub struct FfDHe2048;

impl crypto::SupportedKxGroup for FfDHe2048 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(dh::DhKeyExchange::generate_ffdhe_2048().map_err(
            |e| map_error_stack("FfDHe2048.start", e, crypto::GetRandomFailed),
        )?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::FFDHE2048
    }
}
