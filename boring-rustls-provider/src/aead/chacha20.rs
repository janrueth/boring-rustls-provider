use super::{BoringAead, BoringCipher};
use aead::{
    consts::{U12, U16},
    AeadCore,
};
use boring_additions::aead::Algorithm;
use rustls::{crypto::cipher, ConnectionTrafficSecrets};

/// `ChaCha20` with `Poly1305` cipher
pub struct ChaCha20Poly1305 {}

impl BoringAead for ChaCha20Poly1305 {}

impl BoringCipher for ChaCha20Poly1305 {
    const EXPLICIT_NONCE_LEN: usize = 0;

    const FIXED_IV_LEN: usize = 12;

    const KEY_SIZE: usize = 32;

    fn new_cipher() -> Algorithm {
        Algorithm::chacha20_poly1305()
    }

    fn extract_keys(key: cipher::AeadKey, iv: cipher::Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
    }
}

impl AeadCore for ChaCha20Poly1305 {
    type NonceSize = U12;

    type TagSize = U16;

    type CiphertextOverhead = U16;
}

#[cfg(test)]
mod tests {
    use aead::{generic_array::GenericArray, AeadCore, Nonce, Tag};

    use super::ChaCha20Poly1305;
    use crate::aead::BoringCipher;

    #[test]
    fn ensure_aead_core() {
        let alg = ChaCha20Poly1305::new_cipher();
        let nonce = Nonce::<ChaCha20Poly1305>::default();
        assert_eq!(nonce.len(), alg.nonce_len());
        let tag = Tag::<ChaCha20Poly1305>::default();
        assert_eq!(alg.max_tag_len(), tag.len());

        let overhead =
            GenericArray::<u8, <ChaCha20Poly1305 as AeadCore>::CiphertextOverhead>::default();
        assert_eq!(alg.max_overhead(), overhead.len());
    }
}
