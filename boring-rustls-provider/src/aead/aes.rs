use aead::consts::{U12, U16};
use rustls::{crypto::cipher, ConnectionTrafficSecrets};

use super::{aead2::Algorithm, BoringAead, BoringCipher};

pub struct Aes128 {}

impl BoringAead for Aes128 {}
unsafe impl Send for Aes128 {}
unsafe impl Sync for Aes128 {}

impl BoringCipher for Aes128 {
    fn new() -> Algorithm {
        Algorithm::aes_128_gcm()
    }

    fn key_size() -> usize {
        16
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

pub struct Aes256 {}

impl BoringAead for Aes256 {}
unsafe impl Send for Aes256 {}
unsafe impl Sync for Aes256 {}

impl BoringCipher for Aes256 {
    fn new() -> Algorithm {
        Algorithm::aes_256_gcm()
    }

    fn key_size() -> usize {
        32
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
        let alg = Aes128::new();
        let nonce = Nonce::<Aes128>::default();
        assert_eq!(nonce.len(), alg.nonce_len());
        let tag = Tag::<Aes128>::default();
        assert_eq!(alg.max_tag_len(), tag.len());

        let overhead = GenericArray::<u8, <Aes128 as AeadCore>::CiphertextOverhead>::default();
        assert_eq!(alg.max_overhead(), overhead.len());
    }

    #[test]
    fn ensure_aes256_aead_core() {
        let alg = Aes256::new();
        let nonce = Nonce::<Aes256>::default();
        assert_eq!(nonce.len(), alg.nonce_len());
        let tag = Tag::<Aes256>::default();
        assert_eq!(alg.max_tag_len(), tag.len());

        let overhead = GenericArray::<u8, <Aes256 as AeadCore>::CiphertextOverhead>::default();
        assert_eq!(alg.max_overhead(), overhead.len());
    }
}
