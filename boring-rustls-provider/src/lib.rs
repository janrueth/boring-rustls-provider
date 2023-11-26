use std::sync::Arc;

use helper::log_and_map;
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
#[cfg(feature = "tls12")]
mod prf;
pub mod sign;
#[cfg(feature = "tls12")]
pub mod tls12;
pub mod tls13;
pub mod verify;

/// The boringssl-based Rustls Crypto provider
pub static PROVIDER: &'static dyn CryptoProvider = &Provider;

#[derive(Debug)]
struct Provider;

impl CryptoProvider for Provider {
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        boring::rand::rand_bytes(bytes).map_err(|e| log_and_map("rand_bytes", e, GetRandomFailed))
    }

    fn default_cipher_suites(&self) -> &'static [SupportedCipherSuite] {
        #[cfg(feature = "fips-only")]
        {
            ALL_FIPS_CIPHER_SUITES
        }
        #[cfg(not(feature = "fips-only"))]
        {
            ALL_CIPHER_SUITES
        }
    }

    fn default_kx_groups(&self) -> &'static [&'static dyn SupportedKxGroup] {
        #[cfg(feature = "fips-only")]
        {
            ALL_FIPS_KX_GROUPS
        }
        #[cfg(not(feature = "fips-only"))]
        {
            ALL_KX_GROUPS
        }
    }

    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        sign::BoringPrivateKey::try_from(key_der).map(|x| Arc::new(x) as _)
    }

    fn signature_verification_algorithms(&self) -> rustls::WebPkiSupportedAlgorithms {
        #[cfg(feature = "fips-only")]
        {
            verify::ALL_FIPS_ALGORITHMS
        }
        #[cfg(not(feature = "fips-only"))]
        {
            verify::ALL_ALGORITHMS
        }
    }
}

#[allow(unused)]
static ALL_FIPS_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    SupportedCipherSuite::Tls13(&tls13::AES_256_GCM_SHA384),
    SupportedCipherSuite::Tls13(&tls13::AES_128_GCM_SHA256),
    #[cfg(feature = "tls12")]
    SupportedCipherSuite::Tls12(&tls12::ECDHE_ECDSA_AES256_GCM_SHA384),
    #[cfg(feature = "tls12")]
    SupportedCipherSuite::Tls12(&tls12::ECDHE_RSA_AES256_GCM_SHA384),
    #[cfg(feature = "tls12")]
    SupportedCipherSuite::Tls12(&tls12::ECDHE_ECDSA_AES128_GCM_SHA256),
    #[cfg(feature = "tls12")]
    SupportedCipherSuite::Tls12(&tls12::ECDHE_RSA_AES128_GCM_SHA256),
];

#[allow(unused)]
static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    SupportedCipherSuite::Tls13(&tls13::CHACHA20_POLY1305_SHA256),
    SupportedCipherSuite::Tls13(&tls13::AES_256_GCM_SHA384),
    SupportedCipherSuite::Tls13(&tls13::AES_128_GCM_SHA256),
    #[cfg(feature = "tls12")]
    SupportedCipherSuite::Tls12(&tls12::ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
    #[cfg(feature = "tls12")]
    SupportedCipherSuite::Tls12(&tls12::ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
    #[cfg(feature = "tls12")]
    SupportedCipherSuite::Tls12(&tls12::ECDHE_ECDSA_AES256_GCM_SHA384),
    #[cfg(feature = "tls12")]
    SupportedCipherSuite::Tls12(&tls12::ECDHE_RSA_AES256_GCM_SHA384),
    #[cfg(feature = "tls12")]
    SupportedCipherSuite::Tls12(&tls12::ECDHE_ECDSA_AES128_GCM_SHA256),
    #[cfg(feature = "tls12")]
    SupportedCipherSuite::Tls12(&tls12::ECDHE_RSA_AES128_GCM_SHA256),
];

/// Allowed KX curves for FIPS are recommended
/// in [NIST SP 800-186](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf)
///
/// See Sec. 3.1.2 Table 2
/// Ordered in decending order of security strength
#[allow(unused)]
pub const ALL_FIPS_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    &kx::Secp521r1 as _, // P-521 in FIPS lingo
    &kx::X448 as _,      // Curve448 in FIPS lingo
    &kx::Secp384r1 as _, // P-384 in FIPS lingo
    &kx::X25519 as _,    // Curve25519 in FIPS lingo
    &kx::Secp256r1 as _, // P-256 in FIPS lingo
];

#[allow(unused)]
pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    &kx::X25519 as _,
    &kx::X448 as _,
    &kx::Secp256r1 as _,
    &kx::Secp384r1 as _,
    &kx::Secp521r1 as _,
    &kx::FfDHe2048 as _,
];
