use super::{BoringAead, BoringCipher, QuicCipher};
use aead::{
    AeadCore,
    consts::{U12, U16},
};
use boring::aead::Algorithm;
use rustls::{ConnectionTrafficSecrets, crypto::cipher};

/// `ChaCha20` with `Poly1305` cipher
pub struct ChaCha20Poly1305 {}

impl BoringAead for ChaCha20Poly1305 {}

impl BoringCipher for ChaCha20Poly1305 {
    const EXPLICIT_NONCE_LEN: usize = 0;

    #[cfg(feature = "tls12")]
    const FIXED_IV_LEN: usize = 12;

    const KEY_SIZE: usize = 32;

    const TAG_LEN: usize = 16;

    const INTEGRITY_LIMIT: u64 = 1 << 36;
    const CONFIDENTIALITY_LIMIT: u64 = u64::MAX;
    const FIPS_APPROVED: bool = false;

    fn new_cipher() -> Algorithm {
        Algorithm::chacha20_poly1305()
    }

    fn extract_keys(key: cipher::AeadKey, iv: cipher::Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
    }
}

impl QuicCipher for ChaCha20Poly1305 {
    const KEY_SIZE: usize = 32;
    const SAMPLE_LEN: usize = 16;

    fn header_protection_mask(hp_key: &[u8], sample: &[u8]) -> Result<[u8; 5], rustls::Error> {
        if hp_key.len() != <Self as QuicCipher>::KEY_SIZE {
            return Err(rustls::Error::General(
                "header protection key of invalid length".into(),
            ));
        }
        if sample.len() != <Self as QuicCipher>::SAMPLE_LEN {
            return Err(rustls::Error::General("sample of invalid length".into()));
        }

        let mut mask = [0u8; 5];
        // RFC9001 5.4.4: The first 4 bytes of the sampled ciphertext are the block counter. A ChaCha20 implementation could take a 32-bit integer in place of a byte sequence, in which case, the byte sequence is interpreted as a little-endian value.
        let mut counter_bytes = [0u8; 4];
        counter_bytes.copy_from_slice(&sample[0..4]);
        let counter = u32::from_le_bytes(counter_bytes);
        // RFC9001 5.4.4: The remaining 12 bytes are used as the nonce.
        let nonce = &sample[4..16];
        unsafe {
            boring_sys::CRYPTO_chacha_20(
                mask.as_mut_ptr(),
                mask.as_ptr(),
                mask.len(),
                hp_key.as_ptr(),
                nonce.as_ptr(),
                counter,
            );
        };
        Ok(mask)
    }
}

impl AeadCore for ChaCha20Poly1305 {
    type NonceSize = U12;

    type TagSize = U16;

    type CiphertextOverhead = U16;
}

#[cfg(test)]
mod tests {
    use aead::{AeadCore, Nonce, Tag, generic_array::GenericArray};
    use hex_literal::hex;

    use super::ChaCha20Poly1305;
    use crate::aead::{BoringCipher, QuicCipher};

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

    #[test]
    fn chacha20_quic_header_protection() {
        // from https://www.rfc-editor.org/rfc/rfc9001.html#name-chacha20-poly1305-short-hea
        let sample = hex!("5e5cd55c41f69080575d7999c25a5bfb");
        let hp_key = hex!("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
        let expected_mask = hex!("aefefe7d03");
        let mask = ChaCha20Poly1305::header_protection_mask(&hp_key, &sample)
            .expect("valid QUIC sample/key should produce a mask");
        assert_eq!(mask, expected_mask);
    }
}
