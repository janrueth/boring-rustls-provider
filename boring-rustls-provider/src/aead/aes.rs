use super::{BoringAead, BoringCipher};
use aead::consts::{U12, U16};
use boring_additions::aead::Algorithm;
use rustls::{crypto::cipher, ConnectionTrafficSecrets};

/// Aes128 AEAD cipher
pub struct Aes128 {}

impl BoringAead for Aes128 {}

impl BoringCipher for Aes128 {
    const EXPLICIT_NONCE_LEN: usize = 8;

    const FIXED_IV_LEN: usize = 4;

    const KEY_SIZE: usize = 16;

    fn new_cipher() -> Algorithm {
        Algorithm::aes_128_gcm()
    }

    fn extract_keys(key: cipher::AeadKey, iv: cipher::Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
    }
}

impl aead::AeadCore for Aes128 {
    type NonceSize = U12;
    type TagSize = U16;
    type CiphertextOverhead = U16;
}

/// Aes256 AEAD cipher
pub struct Aes256 {}

impl BoringAead for Aes256 {}

impl BoringCipher for Aes256 {
    const EXPLICIT_NONCE_LEN: usize = 8;

    const FIXED_IV_LEN: usize = 4;

    const KEY_SIZE: usize = 32;

    fn new_cipher() -> Algorithm {
        Algorithm::aes_256_gcm()
    }

    fn extract_keys(key: cipher::AeadKey, iv: cipher::Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Aes256Gcm { key, iv }
    }
}

impl aead::AeadCore for Aes256 {
    type NonceSize = U12;
    type TagSize = U16;
    type CiphertextOverhead = U16;
}

#[cfg(test)]
mod tests {
    use aead::{generic_array::GenericArray, AeadCore, Nonce, Tag};

    use crate::aead::{
        aes::{Aes128, Aes256},
        BoringCipher,
    };

    #[test]
    fn ensure_aes128_aead_core() {
        let alg = Aes128::new_cipher();
        let nonce = Nonce::<Aes128>::default();
        assert_eq!(nonce.len(), alg.nonce_len());
        let tag = Tag::<Aes128>::default();
        assert_eq!(alg.max_tag_len(), tag.len());

        let overhead = GenericArray::<u8, <Aes128 as AeadCore>::CiphertextOverhead>::default();
        assert_eq!(alg.max_overhead(), overhead.len());
    }

    #[test]
    fn ensure_aes256_aead_core() {
        let alg = Aes256::new_cipher();
        let nonce = Nonce::<Aes256>::default();
        assert_eq!(nonce.len(), alg.nonce_len());
        let tag = Tag::<Aes256>::default();
        assert_eq!(alg.max_tag_len(), tag.len());

        let overhead = GenericArray::<u8, <Aes256 as AeadCore>::CiphertextOverhead>::default();
        assert_eq!(alg.max_overhead(), overhead.len());
    }
}
