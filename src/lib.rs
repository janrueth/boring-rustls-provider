//! A [`rustls`] [`CryptoProvider`] backed by [BoringSSL](https://github.com/cloudflare/boring).
//!
//! # Quick start
//!
//! ```no_run
//! let config = rustls::ClientConfig::builder_with_provider(
//!         boring_rustls_provider::provider().into(),
//!     )
//!     .with_safe_default_protocol_versions()
//!     .unwrap()
//!     .with_root_certificates(rustls::RootCertStore::empty())
//!     .with_no_client_auth();
//! ```
//!
//! # Features
//!
//! No features are enabled by default. The provider ships with TLS 1.3 support
//! out of the box; additional capabilities are opt-in via feature flags:
//!
//! - **`fips`** — Build against FIPS-validated BoringSSL and restrict the
//!   provider to FIPS-approved algorithms (SP 800-52r2). Implies `mlkem`.
//! - **`mlkem`** — Enable the X25519MLKEM768 post-quantum hybrid key exchange
//!   group.
//! - **`tls12`** — Enable TLS 1.2 cipher suites.
//! - **`logging`** — Enable debug logging via the [`log`](https://docs.rs/log)
//!   crate.

use std::sync::Arc;

use helper::log_and_map;
#[cfg(all(feature = "fips", feature = "log"))]
use log::warn;
use rustls::{
    SupportedCipherSuite,
    crypto::{CryptoProvider, GetRandomFailed, SupportedKxGroup},
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
/// Private key loading and TLS signing operations.
pub mod sign;
/// TLS 1.2 cipher suite definitions (requires the `tls12` feature).
#[cfg(feature = "tls12")]
pub mod tls12;
/// TLS 1.3 cipher suite definitions.
pub mod tls13;
/// Signature verification algorithms for certificate validation.
pub mod verify;

/// Returns a [`CryptoProvider`] with the default set of cipher suites and
/// key exchange groups.
///
/// When the `fips` feature is enabled the provider is restricted to
/// FIPS-approved algorithms and will **panic** if the underlying BoringSSL
/// library is not running in FIPS mode.
pub fn provider() -> CryptoProvider {
    #[cfg(feature = "fips")]
    {
        if !boring::fips::enabled() {
            panic!(
                "boring-rustls-provider is built with the 'fips' feature, but the underlying \
                BoringSSL library is not in FIPS mode."
            );
        }
        provider_with_ciphers(ALL_FIPS_CIPHER_SUITES.to_vec())
    }
    #[cfg(not(feature = "fips"))]
    {
        provider_with_ciphers(ALL_CIPHER_SUITES.to_vec())
    }
}

/// Returns a [`CryptoProvider`] using the given cipher suites.
///
/// When the `fips` feature is enabled, any non-FIPS cipher suites in
/// `ciphers` are silently filtered out.
pub fn provider_with_ciphers(ciphers: Vec<rustls::SupportedCipherSuite>) -> CryptoProvider {
    #[cfg(feature = "fips")]
    let ciphers = {
        let original_len = ciphers.len();
        let filtered = ciphers
            .into_iter()
            .filter(|suite| ALL_FIPS_CIPHER_SUITES.contains(suite))
            .collect::<Vec<_>>();

        if filtered.len() != original_len {
            #[cfg(feature = "log")]
            warn!(
                "filtered {} non-FIPS cipher suite(s) from provider_with_ciphers",
                original_len - filtered.len()
            );
        }

        filtered
    };

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

    fn fips(&self) -> bool {
        cfg!(feature = "fips")
    }
}

impl rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        sign::BoringPrivateKey::try_from(key_der).map(|x| Arc::new(x) as _)
    }

    fn fips(&self) -> bool {
        cfg!(feature = "fips")
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
