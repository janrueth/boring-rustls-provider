use rustls::Tls13CipherSuite;

use crate::{aead, hash, hkdf};

pub static AES_128_GCM_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: rustls::CipherSuiteCommon {
        suite: rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: hash::SHA256,
    },
    hkdf_provider: &hkdf::Hkdf::<hkdf::Sha256>::DEFAULT,
    aead_alg: &aead::Aead::<aead::aes::Aes128>::DEFAULT,
};

pub static AES_256_GCM_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: rustls::CipherSuiteCommon {
        suite: rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: hash::SHA256,
    },
    hkdf_provider: &hkdf::Hkdf::<hkdf::Sha256>::DEFAULT,
    aead_alg: &aead::Aead::<aead::aes::Aes256>::DEFAULT,
};

pub static CHACHA20_POLY1305_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: rustls::CipherSuiteCommon {
        suite: rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: hash::SHA256,
    },

    hkdf_provider: &hkdf::Hkdf::<hkdf::Sha256>::DEFAULT,
    aead_alg: &aead::Aead::<aead::chacha20::ChaCha20Poly1305>::DEFAULT,
};