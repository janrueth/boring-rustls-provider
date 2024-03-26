use rustls::{crypto, SignatureScheme, Tls12CipherSuite};

use crate::{aead, hash, prf};

static ALL_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED25519,
    SignatureScheme::ED448,
];

static ALL_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
];

const PRF_SHA256: prf::PrfTls1WithDigest = prf::PrfTls1WithDigest(boring::nid::Nid::SHA256);
const PRF_SHA384: prf::PrfTls1WithDigest = prf::PrfTls1WithDigest(boring::nid::Nid::SHA384);

pub static ECDHE_ECDSA_AES128_GCM_SHA256: Tls12CipherSuite = Tls12CipherSuite {
    common: rustls::crypto::CipherSuiteCommon {
        suite: rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: 1 << 23,
    },
    aead_alg: &aead::Aead::<aead::aes::Aes128>::DEFAULT,
    prf_provider: &PRF_SHA256,
    kx: crypto::KeyExchangeAlgorithm::ECDHE,
    sign: ALL_ECDSA_SCHEMES,
};

pub static ECDHE_RSA_AES128_GCM_SHA256: Tls12CipherSuite = Tls12CipherSuite {
    common: rustls::crypto::CipherSuiteCommon {
        suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: 1 << 23,
    },
    aead_alg: &aead::Aead::<aead::aes::Aes128>::DEFAULT,
    prf_provider: &PRF_SHA256,
    kx: crypto::KeyExchangeAlgorithm::ECDHE,
    sign: ALL_RSA_SCHEMES,
};

pub static ECDHE_ECDSA_AES256_GCM_SHA384: Tls12CipherSuite = Tls12CipherSuite {
    common: rustls::crypto::CipherSuiteCommon {
        suite: rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        hash_provider: hash::SHA384,
        confidentiality_limit: 1 << 23,
    },
    aead_alg: &aead::Aead::<aead::aes::Aes256>::DEFAULT,
    prf_provider: &PRF_SHA384,
    kx: crypto::KeyExchangeAlgorithm::ECDHE,
    sign: ALL_ECDSA_SCHEMES,
};

pub static ECDHE_RSA_AES256_GCM_SHA384: Tls12CipherSuite = Tls12CipherSuite {
    common: rustls::crypto::CipherSuiteCommon {
        suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        hash_provider: hash::SHA384,
        confidentiality_limit: 1 << 23,
    },
    aead_alg: &aead::Aead::<aead::aes::Aes256>::DEFAULT,
    prf_provider: &PRF_SHA384,
    kx: crypto::KeyExchangeAlgorithm::ECDHE,
    sign: ALL_RSA_SCHEMES,
};

pub static ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: Tls12CipherSuite = Tls12CipherSuite {
    common: rustls::crypto::CipherSuiteCommon {
        suite: rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    aead_alg: &aead::Aead::<aead::chacha20::ChaCha20Poly1305>::DEFAULT,
    prf_provider: &PRF_SHA256,
    kx: crypto::KeyExchangeAlgorithm::ECDHE,
    sign: ALL_ECDSA_SCHEMES,
};

pub static ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Tls12CipherSuite = Tls12CipherSuite {
    common: rustls::crypto::CipherSuiteCommon {
        suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    aead_alg: &aead::Aead::<aead::chacha20::ChaCha20Poly1305>::DEFAULT,
    prf_provider: &PRF_SHA256,
    kx: crypto::KeyExchangeAlgorithm::ECDHE,
    sign: ALL_RSA_SCHEMES,
};
