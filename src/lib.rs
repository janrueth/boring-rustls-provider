//! A [`rustls`] [`CryptoProvider`] backed by [BoringSSL](https://github.com/cloudflare/boring).
//!
//! # Quick start
//!
//! ```no_run
//! let config = rustls::ClientConfig::builder(
//!         boring_rustls_provider::provider().into(),
//!     )
//!     .with_root_certificates(rustls::RootCertStore::empty())
//!     .with_no_client_auth()
//!     .unwrap();
//! ```
//!
//! # Features
//!
//! The `mldsa` feature is enabled by default. The provider ships with TLS 1.3
//! support out of the box; other capabilities are opt-in via feature flags:
//!
//! - **`fips`** — Build BoringSSL in FIPS mode and restrict the provider's
//!   classical algorithms according to SP 800-52r2. Implies `mlkem` and
//!   `mldsa`.
//! - **`mldsa`** — Enable ML-DSA-44, ML-DSA-65, and ML-DSA-87 certificate
//!   verification and TLS 1.3 authentication. Enabled by default.
//! - **`mlkem`** — Enable the X25519MLKEM768 post-quantum hybrid key exchange
//!   group.
//! - **`tls12`** — Enable TLS 1.2 cipher suites.
//! - **`logging`** — Enable debug logging via the [`log`](https://docs.rs/log)
//!   crate.
//!
//! # FIPS mode
//!
//! The `fips` feature applies the documented algorithm and key restrictions to
//! this crate's built-in provider configuration and key loader. Applications
//! that replace rustls components, particularly credential resolvers or signing
//! keys, must independently preserve those restrictions. Running BoringSSL in
//! FIPS mode does not by itself establish compliance for an application as a
//! whole. ML-DSA is standardized by FIPS 204. Its FIPS 140 validation status
//! depends on the exact BoringSSL module and its validation certificate.

use std::borrow::Cow;

use helper::log_and_map;
#[cfg(all(feature = "fips", feature = "log"))]
use log::warn;
use rustls::{
    SupportedCipherSuite,
    crypto::{CryptoProvider, GetRandomFailed, kx::SupportedKxGroup},
};
use rustls_pki_types::{FipsStatus, PrivateKeyDer};

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
/// When the `fips` feature is enabled the provider uses its documented FIPS
/// configuration and will **panic** if the underlying BoringSSL library is not
/// running in FIPS mode.
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

/// Returns a [`CryptoProvider`] using the given cipher suites.
///
/// When the `fips` feature is enabled, this will **panic** if the underlying
/// BoringSSL library is not running in FIPS mode. Cipher suites other than the
/// canonical FIPS implementations supplied by this crate are silently filtered
/// out, even if they use the same TLS codepoint as an approved suite.
pub fn provider_with_ciphers(ciphers: Vec<SupportedCipherSuite>) -> CryptoProvider {
    #[cfg(feature = "fips")]
    let ciphers = {
        assert_fips_mode();

        let original_len = ciphers.len();
        let filtered = ciphers
            .into_iter()
            .filter(is_canonical_fips_cipher_suite)
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

    // Split cipher suites by TLS version
    #[cfg_attr(not(feature = "tls12"), allow(unused_mut))]
    let mut tls12_suites = Vec::new();
    let mut tls13_suites = Vec::new();
    for suite in ciphers {
        match suite {
            SupportedCipherSuite::Tls13(s) => tls13_suites.push(s),
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(s) => tls12_suites.push(s),
            _ => {}
        }
    }

    CryptoProvider {
        tls13_cipher_suites: Cow::Owned(tls13_suites),
        tls12_cipher_suites: Cow::Owned(tls12_suites),
        #[cfg(feature = "fips")]
        kx_groups: Cow::Borrowed(ALL_FIPS_KX_GROUPS),
        #[cfg(not(feature = "fips"))]
        kx_groups: Cow::Borrowed(ALL_KX_GROUPS),
        #[cfg(feature = "fips")]
        signature_verification_algorithms: verify::ALL_FIPS_ALGORITHMS,
        #[cfg(not(feature = "fips"))]
        signature_verification_algorithms: verify::ALL_ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
        ticketer_factory: &Provider,
    }
}

#[cfg(feature = "fips")]
fn assert_fips_mode() {
    if !boring::fips::enabled() {
        panic!(
            "boring-rustls-provider is built with the 'fips' feature, but the underlying \
            BoringSSL library is not in FIPS mode."
        );
    }
}

#[cfg(feature = "fips")]
fn is_canonical_fips_cipher_suite(suite: &SupportedCipherSuite) -> bool {
    ALL_FIPS_CIPHER_SUITES
        .iter()
        .any(|allowed| same_cipher_suite_implementation(*suite, *allowed))
}

#[cfg(feature = "fips")]
fn same_cipher_suite_implementation(
    left: SupportedCipherSuite,
    right: SupportedCipherSuite,
) -> bool {
    match (left, right) {
        (SupportedCipherSuite::Tls12(left), SupportedCipherSuite::Tls12(right)) => {
            std::ptr::eq(left, right)
        }
        (SupportedCipherSuite::Tls13(left), SupportedCipherSuite::Tls13(right)) => {
            std::ptr::eq(left, right)
        }
        _ => false,
    }
}

#[derive(Debug)]
struct Provider;

impl rustls::crypto::SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        boring::rand::rand_bytes(bytes).map_err(|e| log_and_map("rand_bytes", e, GetRandomFailed))
    }

    fn fips(&self) -> FipsStatus {
        if cfg!(feature = "fips") {
            FipsStatus::Pending
        } else {
            FipsStatus::Unvalidated
        }
    }
}

impl rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Box<dyn rustls::crypto::SigningKey>, rustls::Error> {
        sign::BoringPrivateKey::try_from(key_der).map(|x| Box::new(x) as _)
    }

    fn fips(&self) -> FipsStatus {
        if cfg!(feature = "fips") {
            FipsStatus::Pending
        } else {
            FipsStatus::Unvalidated
        }
    }
}

impl rustls::crypto::TicketerFactory for Provider {
    fn ticketer(
        &self,
    ) -> Result<std::sync::Arc<dyn rustls::crypto::TicketProducer>, rustls::Error> {
        Err(rustls::Error::General("tickets not supported".into()))
    }

    fn fips(&self) -> FipsStatus {
        if cfg!(feature = "fips") {
            FipsStatus::Pending
        } else {
            FipsStatus::Unvalidated
        }
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

/// Allowed KX groups for FIPS per [SP 800-52r2](https://doi.org/10.6028/NIST.SP.800-52r2).
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
/// This is the subset of BoringSSL groups implemented by this provider:
/// X25519MLKEM768 (when ML-KEM is enabled), X25519, P-256, and P-384.
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
