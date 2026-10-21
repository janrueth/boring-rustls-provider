use super::{BoringAead, BoringCipher, QuicCipher};
use boring::aead::Algorithm;
use rustls::{ConnectionTrafficSecrets, crypto::cipher};

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

    #[cfg(feature = "tls12")]
    fn new_tls12_cipher() -> Algorithm {
        Algorithm::aes_128_gcm_tls12()
    }

    fn new_tls13_cipher() -> Algorithm {
        Algorithm::aes_128_gcm_tls13()
    }

    fn extract_keys(key: cipher::AeadKey, iv: cipher::Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
    }
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

    #[cfg(feature = "tls12")]
    fn new_tls12_cipher() -> Algorithm {
        Algorithm::aes_256_gcm_tls12()
    }

    fn new_tls13_cipher() -> Algorithm {
        Algorithm::aes_256_gcm_tls13()
    }

    fn extract_keys(key: cipher::AeadKey, iv: cipher::Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Aes256Gcm { key, iv }
    }
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
    use boring::aead::Algorithm;

    use crate::aead::{
        BoringCipher,
        aes::{Aes128, Aes256},
    };

    #[test]
    fn aes128_algorithm_metadata_and_tls_variants() {
        let alg = Aes128::new_cipher();
        assert_eq!(alg.nonce_len(), 12);
        assert_eq!(alg.max_tag_len(), Aes128::TAG_LEN);
        assert_eq!(alg.max_overhead(), Aes128::TAG_LEN);
        assert_eq!(Aes128::new_tls13_cipher(), Algorithm::aes_128_gcm_tls13());
        #[cfg(feature = "tls12")]
        assert_eq!(Aes128::new_tls12_cipher(), Algorithm::aes_128_gcm_tls12());
    }

    #[test]
    fn aes256_algorithm_metadata_and_tls_variants() {
        let alg = Aes256::new_cipher();
        assert_eq!(alg.nonce_len(), 12);
        assert_eq!(alg.max_tag_len(), Aes256::TAG_LEN);
        assert_eq!(alg.max_overhead(), Aes256::TAG_LEN);
        assert_eq!(Aes256::new_tls13_cipher(), Algorithm::aes_256_gcm_tls13());
        #[cfg(feature = "tls12")]
        assert_eq!(Aes256::new_tls12_cipher(), Algorithm::aes_256_gcm_tls12());
    }
}
