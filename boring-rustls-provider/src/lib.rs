use std::sync::Arc;

use rustls::{
    crypto::{CryptoProvider, GetRandomFailed, SupportedKxGroup},
    SupportedCipherSuite,
};
use rustls_pki_types::PrivateKeyDer;

mod aead;
mod hash;
mod helper;
mod hkdf;
mod hmac;
mod kx;
mod sign;
mod tls13;
mod verify;

pub static PROVIDER: &'static dyn CryptoProvider = &Provider;

#[derive(Debug)]
struct Provider;

impl CryptoProvider for Provider {
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        boring::rand::rand_bytes(bytes).map_err(|_| GetRandomFailed)
    }

    fn default_cipher_suites(&self) -> &'static [SupportedCipherSuite] {
        if boring::fips::enabled() {
            ALL_FIPS_SUITES
        } else {
            ALL_CIPHER_SUITES
        }
    }

    fn default_kx_groups(&self) -> &'static [&'static dyn SupportedKxGroup] {
        if boring::fips::enabled() {
            ALL_FIPS_KX_GROUPS
        } else {
            ALL_KX_GROUPS
        }
    }

    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        sign::BoringPrivateKey::try_from(key_der)
            .map(|x| Arc::new(x) as _)
            .map_err(|_| rustls::Error::General("invalid private key".into()))
    }

    fn signature_verification_algorithms(&self) -> rustls::WebPkiSupportedAlgorithms {
        verify::ALL_ALGORITHMS
    }
}

static ALL_FIPS_SUITES: &[SupportedCipherSuite] = &[
    SupportedCipherSuite::Tls13(&tls13::AES_128_GCM_SHA256),
    SupportedCipherSuite::Tls13(&tls13::AES_256_GCM_SHA256),
];

static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    SupportedCipherSuite::Tls13(&tls13::AES_128_GCM_SHA256),
    SupportedCipherSuite::Tls13(&tls13::AES_256_GCM_SHA256),
    SupportedCipherSuite::Tls13(&tls13::CHACHA20_POLY1305_SHA256),
];

pub const ALL_FIPS_KX_GROUPS: &[&dyn SupportedKxGroup] = &[];
pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    &kx::X25519 as _,
    &kx::X448 as _,
    &kx::Secp256r1 as _,
    &kx::Secp384r1 as _,
    &kx::Secp521r1 as _,
    &kx::FfDHe2048 as _,
];
