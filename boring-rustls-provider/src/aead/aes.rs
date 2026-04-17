use super::{BoringAead, BoringCipher, QuicCipher};
use aead::consts::{U12, U16};
use boring::aead::Algorithm;
use rustls::{crypto::cipher, ConnectionTrafficSecrets};

/// Aes128 AEAD cipher
pub struct Aes128 {}

impl BoringAead for Aes128 {}

impl BoringCipher for Aes128 {
    const EXPLICIT_NONCE_LEN: usize = 8;

    #[cfg(feature = "tls12")]
    const FIXED_IV_LEN: usize = 4;

    const KEY_SIZE: usize = 16;

    const TAG_LEN: usize = 16;

    const INTEGRITY_LIMIT: u64 = 1 << 52;
    const CONFIDENTIALITY_LIMIT: u64 = 1 << 23;
    const FIPS_APPROVED: bool = true;

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

impl QuicCipher for Aes128 {
    const KEY_SIZE: usize = <Self as BoringCipher>::KEY_SIZE;
    const SAMPLE_LEN: usize = 16;

    fn header_protection_mask(hp_key: &[u8], sample: &[u8]) -> Result<[u8; 5], rustls::Error> {
        quic_header_protection_mask::<
            { <Self as QuicCipher>::KEY_SIZE },
            { <Self as QuicCipher>::SAMPLE_LEN },
        >(boring::symm::Cipher::aes_128_ecb(), hp_key, sample)
    }
}

/// Aes256 AEAD cipher
pub struct Aes256 {}

impl BoringAead for Aes256 {}

impl BoringCipher for Aes256 {
    const EXPLICIT_NONCE_LEN: usize = 8;

    #[cfg(feature = "tls12")]
    const FIXED_IV_LEN: usize = 4;

    const KEY_SIZE: usize = 32;

    const TAG_LEN: usize = 16;

    const INTEGRITY_LIMIT: u64 = 1 << 52;
    const CONFIDENTIALITY_LIMIT: u64 = 1 << 23;
    const FIPS_APPROVED: bool = true;

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

impl QuicCipher for Aes256 {
    const KEY_SIZE: usize = <Self as BoringCipher>::KEY_SIZE;
    const SAMPLE_LEN: usize = 16;

    fn header_protection_mask(hp_key: &[u8], sample: &[u8]) -> Result<[u8; 5], rustls::Error> {
        quic_header_protection_mask::<
            { <Self as QuicCipher>::KEY_SIZE },
            { <Self as QuicCipher>::SAMPLE_LEN },
        >(boring::symm::Cipher::aes_256_ecb(), hp_key, sample)
    }
}

fn quic_header_protection_mask<const KEY_SIZE: usize, const SAMPLE_LEN: usize>(
    cipher: boring::symm::Cipher,
    hp_key: &[u8],
    sample: &[u8],
) -> Result<[u8; 5], rustls::Error> {
    if hp_key.len() != KEY_SIZE {
        return Err(rustls::Error::General(
            "header protection key of invalid length".into(),
        ));
    }
    if sample.len() != SAMPLE_LEN {
        return Err(rustls::Error::General("sample of invalid length".into()));
    }

    let mut output = [0u8; SAMPLE_LEN];

    let mut crypter = boring::symm::Crypter::new(cipher, boring::symm::Mode::Encrypt, hp_key, None)
        .map_err(|_| rustls::Error::General("failed generating header protection mask".into()))?;

    let len = crypter
        .update(sample, &mut output)
        .map_err(|_| rustls::Error::General("failed generating header protection mask".into()))?;
    let _total = len
        + crypter.finalize(&mut output[len..]).map_err(|_| {
            rustls::Error::General("failed generating header protection mask".into())
        })?;

    let mut mask = [0u8; 5];
    mask.copy_from_slice(&output[..5]);
    Ok(mask)
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
