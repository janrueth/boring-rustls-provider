use rustls::Tls13CipherSuite;

use crate::{aead, hash, hkdf};

/// TLS 1.3 AES-128-GCM with SHA-256.
pub static AES_128_GCM_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    protocol_version: rustls::version::TLS13_VERSION,
    common: rustls::crypto::CipherSuiteCommon {
        suite: rustls::crypto::CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: 1 << 23,
    },
    hkdf_provider: &hkdf::Hkdf::<hkdf::Sha256>::DEFAULT,
    aead_alg: &aead::Aead::<aead::aes::Aes128>::DEFAULT,
    quic: Some(&aead::Aead::<aead::aes::Aes128>::DEFAULT),
};

/// TLS 1.3 AES-256-GCM with SHA-384.
pub static AES_256_GCM_SHA384: Tls13CipherSuite = Tls13CipherSuite {
    protocol_version: rustls::version::TLS13_VERSION,
    common: rustls::crypto::CipherSuiteCommon {
        suite: rustls::crypto::CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: hash::SHA384,
        confidentiality_limit: 1 << 23,
    },
    hkdf_provider: &hkdf::Hkdf::<hkdf::Sha384>::DEFAULT,
    aead_alg: &aead::Aead::<aead::aes::Aes256>::DEFAULT,
    quic: Some(&aead::Aead::<aead::aes::Aes256>::DEFAULT),
};

/// TLS 1.3 ChaCha20-Poly1305 with SHA-256.
///
/// Not available in FIPS mode.
pub static CHACHA20_POLY1305_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    protocol_version: rustls::version::TLS13_VERSION,
    common: rustls::crypto::CipherSuiteCommon {
        suite: rustls::crypto::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },

    hkdf_provider: &hkdf::Hkdf::<hkdf::Sha256>::DEFAULT,
    aead_alg: &aead::Aead::<aead::chacha20::ChaCha20Poly1305>::DEFAULT,
    quic: Some(&aead::Aead::<aead::chacha20::ChaCha20Poly1305>::DEFAULT),
};
