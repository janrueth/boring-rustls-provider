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

pub fn provider() -> CryptoProvider {
    #[cfg(feature = "fips")]
    {
        provider_with_ciphers(ALL_FIPS_CIPHER_SUITES.to_vec())
    }
    #[cfg(not(feature = "fips"))]
    {
        provider_with_ciphers(ALL_CIPHER_SUITES.to_vec())
    }
}

pub fn provider_with_ciphers(ciphers: Vec<rustls::SupportedCipherSuite>) -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ciphers,
        #[cfg(feature = "fips")]
        kx_groups: ALL_FIPS_KX_GROUPS.to_vec(),
        #[cfg(not(feature = "fips"))]
        kx_groups: ALL_KX_GROUPS.to_vec(),
        #[cfg(feature = "fips")]
        signature_verification_algorithms: verify::ALL_FIPS_ALGORITHMS,
        #[cfg(not(feature = "fips"))]
        signature_verification_algorithms: verify::ALL_ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

#[derive(Debug)]
struct Provider;

impl rustls::crypto::SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        boring::rand::rand_bytes(bytes).map_err(|e| log_and_map("rand_bytes", e, GetRandomFailed))
    }
}

impl rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        sign::BoringPrivateKey::try_from(key_der).map(|x| Arc::new(x) as _)
    }
}

#[cfg(feature = "fips")]
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

#[cfg(not(feature = "fips"))]
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

/// Allowed KX groups for FIPS per [SP 800-52r2](https://doi.org/10.6028/NIST.SP.800-52r2),
/// aligned with boring's `fips202205` compliance policy.
///
/// The `fips` feature implies `mlkem`, so X25519MLKEM768 is always
/// available and preferred in FIPS mode.
#[cfg(feature = "fips")]
static ALL_FIPS_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    &kx::X25519MlKem768 as _, // PQ hybrid preferred
    &kx::Secp256r1 as _,      // P-256
    &kx::Secp384r1 as _,      // P-384
];

/// All supported KX groups, ordered by preference.
///
/// Matches boring's default supported group list exactly:
/// X25519MLKEM768 (when mlkem enabled), X25519, P-256, P-384.
#[cfg(all(not(feature = "fips"), feature = "mlkem"))]
static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    &kx::X25519MlKem768 as _, // PQ hybrid preferred
    &kx::X25519 as _,
    &kx::Secp256r1 as _,
    &kx::Secp384r1 as _,
];

/// See [`ALL_KX_GROUPS`] (mlkem variant).
#[cfg(not(any(feature = "fips", feature = "mlkem")))]
static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] =
    &[&kx::X25519 as _, &kx::Secp256r1 as _, &kx::Secp384r1 as _];
