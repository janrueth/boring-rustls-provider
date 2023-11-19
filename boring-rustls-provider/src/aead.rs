use std::marker::PhantomData;

use aead::{AeadCore, AeadInPlace, Nonce, Tag};
use boring::error::ErrorStack;
use rustls::crypto::cipher::{self, make_tls13_aad, Iv};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

use crate::helper::error_stack_to_aead_error;

use self::aead2::Algorithm;

pub(crate) mod aead2;
pub(crate) mod aes;
pub(crate) mod chacha20;

pub(crate) trait BoringCipher {
    fn new() -> Algorithm;
    fn key_size() -> usize;
    fn extract_keys(key: cipher::AeadKey, iv: cipher::Iv) -> ConnectionTrafficSecrets;
}

pub(crate) trait BoringAead: BoringCipher + AeadCore + Send + Sync {}

pub(crate) struct BoringAeadCrypter<T: BoringAead> {
    crypter: aead2::Crypter,
    iv: Iv,
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
    pub fn new(iv: Iv, key: &[u8]) -> Result<Self, ErrorStack> {
        let cipher = <T as BoringCipher>::new();

        assert_eq!(
            cipher.nonce_len(),
            rustls::crypto::cipher::Nonce::new(&iv, 0).0.len()
        );

        let crypter = BoringAeadCrypter {
            crypter: aead2::Crypter::new(cipher, key)?,
            iv,
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
        let payload = m.payload_mut();

        // construct nonce
        let nonce = cipher::Nonce::new(&self.iv, seq);

        // construct the aad
        let aad = make_tls13_aad(payload.len());

        // decrypt on clone to ensure this can be done in parallel
        self.decrypt_in_place(Nonce::<T>::from_slice(&nonce.0), &aad, payload)
            .map_err(|_| rustls::Error::DecryptError)
            .and_then(|_| m.into_tls13_unpadded_message())
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
            BoringAeadCrypter::<T>::new(iv, key.as_ref()).expect("failed to create AEAD crypter"),
        )
    }

    fn decrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageDecrypter> {
        Box::new(
            BoringAeadCrypter::<T>::new(iv, key.as_ref()).expect("failed to create AEAD crypter"),
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
