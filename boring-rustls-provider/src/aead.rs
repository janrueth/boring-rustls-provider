use std::marker::PhantomData;

use aead::{AeadCore, AeadInPlace, Nonce, Tag};
use boring::error::ErrorStack;
use boring_additions::aead::Algorithm;
use rustls::crypto::cipher::{self, make_tls12_aad, make_tls13_aad, Iv};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

use crate::helper::error_stack_to_aead_error;

pub(crate) mod aes;
pub(crate) mod chacha20;

pub(crate) trait BoringCipher {
    /// Constructs a new instance of this cipher as an AEAD algorithm
    fn new() -> Algorithm;
    /// The key size in bytes
    fn key_size() -> usize;
    /// The IV's fixed length (Not the full IV length, only the part that doesn't change).
    /// Together with [`BoringCipher::explicit_nonce_len`] it determines the total
    /// lengths of the used nonce.
    fn fixed_iv_len() -> usize;
    /// The lengths of the explicit nonce. (Not the full nonce length, only the part that changes)
    /// See also [`BoringCipher::fixed_iv_len`]
    fn explicit_nonce_len() -> usize;
    /// Extract keys
    fn extract_keys(key: cipher::AeadKey, iv: cipher::Iv) -> ConnectionTrafficSecrets;
}

pub(crate) trait BoringAead: BoringCipher + AeadCore + Send + Sync {}

pub(crate) struct BoringAeadCrypter<T: BoringAead> {
    crypter: boring_additions::aead::Crypter,
    iv: Iv,
    tls_version: ProtocolVersion,
    phantom: PhantomData<T>,
}

unsafe impl<T: BoringAead> Sync for BoringAeadCrypter<T> {}
unsafe impl<T: BoringAead> Send for BoringAeadCrypter<T> {}

impl<T: BoringAead> AeadCore for BoringAeadCrypter<T> {
    // inherit all properties from the Algorithm

    type NonceSize = T::NonceSize;

    type TagSize = T::TagSize;

    type CiphertextOverhead = T::CiphertextOverhead;
}

impl<T: BoringAead> BoringAeadCrypter<T> {
    pub fn new(iv: Iv, key: &[u8], tls_version: ProtocolVersion) -> Result<Self, ErrorStack> {
        assert!(match tls_version {
            #[cfg(feature = "tls12")]
            ProtocolVersion::TLSv1_2 => true,
            ProtocolVersion::TLSv1_3 => true,
            _ => false,
        });

        let cipher = <T as BoringCipher>::new();

        assert_eq!(
            cipher.nonce_len(),
            rustls::crypto::cipher::Nonce::new(&iv, 0).0.len()
        );

        let crypter = BoringAeadCrypter {
            crypter: boring_additions::aead::Crypter::new(cipher, key)?,
            iv,
            tls_version,
            phantom: PhantomData,
        };
        Ok(crypter)
    }
}

impl<T: BoringAead> aead::AeadInPlace for BoringAeadCrypter<T> {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<Tag<Self>> {
        let mut tag = Tag::<Self>::default();
        self.crypter
            .seal_in_place(&nonce, &associated_data, buffer, &mut tag)
            .map_err(|e| error_stack_to_aead_error("seal_in_place", e))?;

        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> aead::Result<()> {
        self.crypter
            .open_in_place(&nonce, &associated_data, buffer, tag)
            .map_err(|e| error_stack_to_aead_error("open_in_place", e))?;
        Ok(())
    }
}

impl<T> cipher::MessageEncrypter for BoringAeadCrypter<T>
where
    T: BoringAead,
{
    fn encrypt(
        &self,
        msg: cipher::BorrowedPlainMessage,
        seq: u64,
    ) -> Result<cipher::OpaqueMessage, rustls::Error> {
        let total_len = msg.payload.len() + 1 + self.crypter.max_overhead();

        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(msg.payload);
        payload.push(msg.typ.get_u8());

        let nonce = cipher::Nonce::new(&self.iv, seq);

        match self.tls_version {
            #[cfg(feature = "tls12")]
            ProtocolVersion::TLSv1_2 => {
                let aad = cipher::make_tls12_aad(seq, msg.typ, msg.version, total_len);
                self.encrypt_in_place(Nonce::<T>::from_slice(&nonce.0), &aad, &mut payload)
                    .map_err(|_| rustls::Error::EncryptError)
                    .map(|_| cipher::OpaqueMessage::new(msg.typ, msg.version, payload))
            }
            ProtocolVersion::TLSv1_3 => {
                let aad = cipher::make_tls13_aad(total_len);
                self.encrypt_in_place(Nonce::<T>::from_slice(&nonce.0), &aad, &mut payload)
                    .map_err(|_| rustls::Error::EncryptError)
                    .map(|_| {
                        cipher::OpaqueMessage::new(
                            ContentType::ApplicationData,
                            ProtocolVersion::TLSv1_2,
                            payload,
                        )
                    })
            }
            _ => unimplemented!(),
        }
    }

    // Next version seems to add this
    // fn encrypted_payload_len(&self, payload_len: usize) -> usize {
    //     payload_len + 1 + self.crypter.max_overhead()
    // }
}

impl<T> cipher::MessageDecrypter for BoringAeadCrypter<T>
where
    T: BoringAead,
{
    fn decrypt(
        &self,
        mut m: cipher::OpaqueMessage,
        seq: u64,
    ) -> Result<cipher::PlainMessage, rustls::Error> {
        // construct nonce
        let nonce = cipher::Nonce::new(&self.iv, seq);

        // construct the aad and decrypt
        match self.tls_version {
            #[cfg(feature = "tls12")]
            ProtocolVersion::TLSv1_2 => {
                let aad = make_tls12_aad(seq, m.typ, m.version, m.payload().len());
                self.decrypt_in_place(Nonce::<T>::from_slice(&nonce.0), &aad, m.payload_mut())
                    .map_err(|_| rustls::Error::DecryptError)
                    .map(|_| m.into_plain_message())
            }
            ProtocolVersion::TLSv1_3 => {
                let aad = make_tls13_aad(m.payload().len());
                self.decrypt_in_place(Nonce::<T>::from_slice(&nonce.0), &aad, m.payload_mut())
                    .map_err(|_| rustls::Error::DecryptError)
                    .and_then(|_| m.into_tls13_unpadded_message())
            }
            _ => unimplemented!(),
        }
    }
}

pub(crate) struct Aead<T: BoringCipher>(PhantomData<T>);

unsafe impl<T: BoringCipher> Sync for Aead<T> {}
unsafe impl<T: BoringCipher> Send for Aead<T> {}

impl<T: BoringCipher> Aead<T> {
    pub const DEFAULT: Self = Self(PhantomData);
}

impl<T: BoringAead + 'static> cipher::Tls13AeadAlgorithm for Aead<T> {
    fn encrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageEncrypter> {
        Box::new(
            BoringAeadCrypter::<T>::new(iv, key.as_ref(), ProtocolVersion::TLSv1_3)
                .expect("failed to create AEAD crypter"),
        )
    }

    fn decrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageDecrypter> {
        Box::new(
            BoringAeadCrypter::<T>::new(iv, key.as_ref(), ProtocolVersion::TLSv1_3)
                .expect("failed to create AEAD crypter"),
        )
    }

    fn key_len(&self) -> usize {
        <T as BoringCipher>::key_size()
    }

    fn extract_keys(
        &self,
        key: cipher::AeadKey,
        iv: cipher::Iv,
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        Ok(<T as BoringCipher>::extract_keys(key, iv))
    }
}

#[cfg(feature = "tls12")]
impl<T: BoringAead + 'static> cipher::Tls12AeadAlgorithm for Aead<T> {
    fn encrypter(
        &self,
        key: cipher::AeadKey,
        iv: &[u8],
        _extra: &[u8],
    ) -> Box<dyn cipher::MessageEncrypter> {
        Box::new(
            BoringAeadCrypter::<T>::new(Iv::copy(iv), key.as_ref(), ProtocolVersion::TLSv1_2)
                .expect("failed to create AEAD crypter"),
        )
    }

    fn decrypter(&self, key: cipher::AeadKey, iv: &[u8]) -> Box<dyn cipher::MessageDecrypter> {
        Box::new(
            BoringAeadCrypter::<T>::new(Iv::copy(iv), key.as_ref(), ProtocolVersion::TLSv1_2)
                .expect("failed to create AEAD crypter"),
        )
    }

    fn key_block_shape(&self) -> cipher::KeyBlockShape {
        cipher::KeyBlockShape {
            enc_key_len: <T as BoringCipher>::key_size(),
            // there is no benefit of splitting these up here, we'd need to stich them anyways
            // by only setting fixed_iv_len we get the full lengths
            fixed_iv_len: <T as BoringCipher>::fixed_iv_len()
                + <T as BoringCipher>::explicit_nonce_len(),
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: cipher::AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        Ok(<T as BoringCipher>::extract_keys(key, Iv::copy(iv)))
    }
}
