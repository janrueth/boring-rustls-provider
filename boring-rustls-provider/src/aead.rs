use std::marker::PhantomData;

use aead::{AeadCore, AeadInPlace, Nonce, Tag};
use boring::error::ErrorStack;
use boring_additions::aead::Algorithm;
use rustls::crypto::cipher::{self, make_tls12_aad, make_tls13_aad, Iv};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

use crate::helper::log_and_map;

pub(crate) mod aes;
pub(crate) mod chacha20;

pub(crate) trait BoringCipher {
    /// The lengths of the explicit nonce. (Not the full nonce length, only the part that changes)
    /// See also [`BoringCipher::fixed_iv_len`]
    const EXPLICIT_NONCE_LEN: usize;
    /// The IV's fixed length (Not the full IV length, only the part that doesn't change).
    /// Together with [`BoringCipher::explicit_nonce_len`] it determines the total
    /// lengths of the used nonce.
    const FIXED_IV_LEN: usize;
    /// The key size in bytes
    const KEY_SIZE: usize;

    /// The length of the authentication tag
    const TAG_LEN: usize;

    /// Constructs a new instance of this cipher as an AEAD algorithm
    fn new_cipher() -> Algorithm;

    /// Extract keys
    fn extract_keys(key: cipher::AeadKey, iv: cipher::Iv) -> ConnectionTrafficSecrets;
}

pub(crate) trait QuicCipher: Send + Sync {
    /// The key size in bytes
    const KEY_SIZE: usize;

    /// the expected length of a sample
    const SAMPLE_LEN: usize;

    fn header_protection_mask(hp_key: &[u8], sample: &[u8]) -> [u8; 5];
}

pub(crate) trait BoringAead: BoringCipher + AeadCore + Send + Sync {}

pub(crate) struct BoringAeadCrypter<T: BoringAead> {
    crypter: boring_additions::aead::Crypter,
    iv: Iv,
    tls_version: ProtocolVersion,
    phantom: PhantomData<T>,
}

impl<T: BoringAead> AeadCore for BoringAeadCrypter<T> {
    // inherit all properties from the Algorithm

    type NonceSize = T::NonceSize;

    type TagSize = T::TagSize;

    type CiphertextOverhead = T::CiphertextOverhead;
}

impl<T: BoringAead> BoringAeadCrypter<T> {
    /// Creates a new aead crypter
    pub fn new(iv: Iv, key: &[u8], tls_version: ProtocolVersion) -> Result<Self, ErrorStack> {
        assert!(match tls_version {
            #[cfg(feature = "tls12")]
            ProtocolVersion::TLSv1_2 => true,
            ProtocolVersion::TLSv1_3 => true,
            _ => false,
        });

        let cipher = <T as BoringCipher>::new_cipher();

        assert_eq!(
            cipher.nonce_len(),
            rustls::crypto::cipher::Nonce::new(&iv, 0).0.len()
        );

        let crypter = BoringAeadCrypter {
            crypter: boring_additions::aead::Crypter::new(&cipher, key)?,
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
            .seal_in_place(nonce, associated_data, buffer, &mut tag)
            .map_err(|e| log_and_map("seal_in_place", e, aead::Error))?;

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
            .open_in_place(nonce, associated_data, buffer, tag)
            .map_err(|e| log_and_map("open_in_place", e, aead::Error))?;
        Ok(())
    }
}

impl<T> cipher::MessageEncrypter for BoringAeadCrypter<T>
where
    T: BoringAead,
{
    fn encrypt(
        &mut self,
        msg: cipher::BorrowedPlainMessage,
        seq: u64,
    ) -> Result<cipher::OpaqueMessage, rustls::Error> {
        let nonce = cipher::Nonce::new(&self.iv, seq);

        match self.tls_version {
            #[cfg(feature = "tls12")]
            ProtocolVersion::TLSv1_2 => {
                let fixed_iv_len = <T as BoringCipher>::FIXED_IV_LEN;
                let explicit_nonce_len = <T as BoringCipher>::EXPLICIT_NONCE_LEN;

                let total_len = self.encrypted_payload_len(msg.payload.len());

                let mut full_payload = Vec::with_capacity(total_len);
                full_payload.extend_from_slice(&nonce.0.as_ref()[fixed_iv_len..]);
                full_payload.extend_from_slice(msg.payload);
                full_payload.extend_from_slice(&vec![0u8; self.crypter.max_overhead()]);

                let (_, payload) = full_payload.split_at_mut(explicit_nonce_len);
                let (payload, tag) = payload.split_at_mut(msg.payload.len());
                let aad = cipher::make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
                self.crypter
                    .seal_in_place(&nonce.0, &aad, payload, tag)
                    .map_err(|_| rustls::Error::EncryptError)
                    .map(|_| cipher::OpaqueMessage::new(msg.typ, msg.version, full_payload))
            }

            ProtocolVersion::TLSv1_3 => {
                let total_len = self.encrypted_payload_len(msg.payload.len());

                let mut payload = Vec::with_capacity(total_len);
                payload.extend_from_slice(msg.payload);
                payload.push(msg.typ.get_u8());

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

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        match self.tls_version {
            ProtocolVersion::TLSv1_2 => {
                payload_len + self.crypter.max_overhead() + <T as BoringCipher>::EXPLICIT_NONCE_LEN
            }
            ProtocolVersion::TLSv1_3 => payload_len + 1 + self.crypter.max_overhead(),
            _ => unimplemented!(),
        }
    }
}

impl<T> cipher::MessageDecrypter for BoringAeadCrypter<T>
where
    T: BoringAead,
{
    fn decrypt(
        &mut self,
        mut m: cipher::OpaqueMessage,
        seq: u64,
    ) -> Result<cipher::PlainMessage, rustls::Error> {
        match self.tls_version {
            #[cfg(feature = "tls12")]
            ProtocolVersion::TLSv1_2 => {
                let explicit_nonce_len = <T as BoringCipher>::EXPLICIT_NONCE_LEN;

                // payload is: [nonce] | [ciphertext] | [auth tag]
                let actual_payload_length =
                    m.payload().len() - self.crypter.max_overhead() - explicit_nonce_len;

                let aad = make_tls12_aad(seq, m.typ, m.version, actual_payload_length);

                let payload = m.payload_mut();

                // get the nonce
                let (explicit_nonce, payload) = payload.split_at_mut(explicit_nonce_len);

                let nonce = {
                    let fixed_iv_len = <T as BoringCipher>::FIXED_IV_LEN;

                    assert_eq!(explicit_nonce_len + fixed_iv_len, 12);

                    // grab the IV by constructing a nonce, this is just an xor
                    let iv = cipher::Nonce::new(&self.iv, seq).0;
                    let mut nonce = [0u8; 12];
                    nonce[..fixed_iv_len].copy_from_slice(&iv[..fixed_iv_len]);
                    nonce[fixed_iv_len..].copy_from_slice(explicit_nonce);
                    nonce
                };

                // split off the authentication tag
                let (payload, tag) =
                    payload.split_at_mut(payload.len() - self.crypter.max_overhead());

                self.crypter
                    .open_in_place(&nonce, &aad, payload, tag)
                    .map_err(|e| log_and_map("open_in_place", e, rustls::Error::DecryptError))
                    .map(|_| {
                        // rotate the nonce to the end
                        m.payload_mut().rotate_left(explicit_nonce_len);

                        // truncate buffer to the actual payload
                        m.payload_mut().truncate(actual_payload_length);

                        m.into_plain_message()
                    })
            }
            ProtocolVersion::TLSv1_3 => {
                let nonce = cipher::Nonce::new(&self.iv, seq);
                let aad = make_tls13_aad(m.payload().len());
                self.decrypt_in_place(Nonce::<T>::from_slice(&nonce.0), &aad, m.payload_mut())
                    .map_err(|_| rustls::Error::DecryptError)
                    .and_then(|_| m.into_tls13_unpadded_message())
            }
            _ => unimplemented!(),
        }
    }
}

impl<T> rustls::quic::PacketKey for BoringAeadCrypter<T>
where
    T: QuicCipher + BoringAead,
{
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<rustls::quic::Tag, rustls::Error> {
        let associated_data = header;
        let nonce = cipher::Nonce::new(&self.iv, packet_number);
        let tag = self
            .encrypt_in_place_detached(Nonce::<T>::from_slice(&nonce.0), associated_data, payload)
            .map_err(|_| rustls::Error::EncryptError)?;

        Ok(rustls::quic::Tag::from(tag.as_ref()))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], rustls::Error> {
        let associated_data = header;
        let nonce = cipher::Nonce::new(&self.iv, packet_number);

        let (buffer, tag) = payload.split_at_mut(payload.len() - self.crypter.max_overhead());

        self.crypter
            .open_in_place(&nonce.0, associated_data, buffer, tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        Ok(buffer)
    }

    fn tag_len(&self) -> usize {
        <T as BoringCipher>::TAG_LEN
    }
}

pub(crate) struct Aead<T>(PhantomData<T>);

impl<T> Aead<T> {
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
        <T as BoringCipher>::KEY_SIZE
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
        extra: &[u8],
    ) -> Box<dyn cipher::MessageEncrypter> {
        let mut full_iv = Vec::with_capacity(iv.len() + extra.len());
        full_iv.extend_from_slice(iv);
        full_iv.extend_from_slice(extra);
        Box::new(
            BoringAeadCrypter::<T>::new(Iv::copy(&full_iv), key.as_ref(), ProtocolVersion::TLSv1_2)
                .expect("failed to create AEAD crypter"),
        )
    }

    fn decrypter(&self, key: cipher::AeadKey, iv: &[u8]) -> Box<dyn cipher::MessageDecrypter> {
        let mut pseudo_iv = Vec::with_capacity(iv.len() + <T as BoringCipher>::EXPLICIT_NONCE_LEN);
        pseudo_iv.extend_from_slice(iv);
        pseudo_iv.extend_from_slice(&vec![0u8; <T as BoringCipher>::EXPLICIT_NONCE_LEN]);
        Box::new(
            BoringAeadCrypter::<T>::new(
                Iv::copy(&pseudo_iv),
                key.as_ref(),
                ProtocolVersion::TLSv1_2,
            )
            .expect("failed to create AEAD crypter"),
        )
    }

    fn key_block_shape(&self) -> cipher::KeyBlockShape {
        cipher::KeyBlockShape {
            enc_key_len: <T as BoringCipher>::KEY_SIZE,
            fixed_iv_len: <T as BoringCipher>::FIXED_IV_LEN,
            explicit_nonce_len: <T as BoringCipher>::EXPLICIT_NONCE_LEN,
        }
    }

    fn extract_keys(
        &self,
        key: cipher::AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        let nonce = {
            let fixed_iv_len = <T as BoringCipher>::FIXED_IV_LEN;
            let explicit_nonce_len = <T as BoringCipher>::EXPLICIT_NONCE_LEN;
            assert_eq!(explicit_nonce_len + fixed_iv_len, 12);

            // grab the IV by constructing a nonce, this is just an xor

            let mut nonce = [0u8; 12];
            nonce[..fixed_iv_len].copy_from_slice(&iv[..fixed_iv_len]);
            nonce[fixed_iv_len..].copy_from_slice(explicit);
            nonce
        };
        Ok(<T as BoringCipher>::extract_keys(key, Iv::copy(&nonce)))
    }
}

struct QuicHeaderProtector<T: QuicCipher> {
    key: cipher::AeadKey,
    phantom: PhantomData<T>,
}

impl<T: QuicCipher> QuicHeaderProtector<T> {
    const MAX_PN_LEN: usize = 4;
    fn rfc9001_header_protection(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        remove: bool,
    ) {
        let mask = T::header_protection_mask(self.key.as_ref(), sample);

        const LONG_HEADER_FORMAT: u8 = 0x80;
        let bits_to_mask = if (*first & LONG_HEADER_FORMAT) == LONG_HEADER_FORMAT {
            // Long header: 4 bits masked
            0x0f
        } else {
            // Short header: 5 bits masked
            0x1f
        };

        let pn_length = if remove {
            // remove the mask on the first byte
            // then get length to get same as below
            *first ^= mask[0] & bits_to_mask;
            (*first & 0x03) as usize + 1
        } else {
            // calculate length than mask
            let pn_length = (*first & 0x03) as usize + 1;
            *first ^= mask[0] & bits_to_mask;
            pn_length
        };

        // mask the first `pn_length` bytes of the packet number with the mask
        for (pn_byte, m) in packet_number.iter_mut().zip(&mask[1..]).take(pn_length) {
            *pn_byte ^= m;
        }
    }
}

impl<T: QuicCipher> rustls::quic::HeaderProtectionKey for QuicHeaderProtector<T> {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        // We can only mask up to 4 bytes
        if packet_number.len() > Self::MAX_PN_LEN {
            return Err(rustls::Error::General("packet number too long".into()));
        }

        self.rfc9001_header_protection(sample, first, packet_number, false);

        Ok(())
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        if packet_number.len() > Self::MAX_PN_LEN {
            return Err(rustls::Error::General("packet number too long".into()));
        }

        self.rfc9001_header_protection(sample, first, packet_number, true);

        Ok(())
    }

    fn sample_len(&self) -> usize {
        T::SAMPLE_LEN
    }
}

impl<T> rustls::quic::Algorithm for Aead<T>
where
    T: QuicCipher + BoringAead + 'static,
{
    fn packet_key(&self, key: cipher::AeadKey, iv: Iv) -> Box<dyn rustls::quic::PacketKey> {
        Box::new(
            BoringAeadCrypter::<T>::new(iv, key.as_ref(), ProtocolVersion::TLSv1_3)
                .expect("failed to create AEAD crypter"),
        )
    }

    fn header_protection_key(
        &self,
        key: cipher::AeadKey,
    ) -> Box<dyn rustls::quic::HeaderProtectionKey> {
        Box::new(QuicHeaderProtector {
            key,
            phantom: PhantomData::<T>,
        })
    }

    fn aead_key_len(&self) -> usize {
        <T as QuicCipher>::KEY_SIZE
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rustls::crypto::cipher::{AeadKey, Iv};

    use crate::aead::BoringAeadCrypter;
    use rustls::quic::PacketKey;

    use super::{chacha20::ChaCha20Poly1305, QuicHeaderProtector};

    #[test]
    fn quic_header_protection_short() {
        // test vector from https://www.rfc-editor.org/rfc/rfc9001.html#name-chacha20-poly1305-short-hea
        let hp_key = hex!("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
        let sample = hex!("5e5cd55c41f69080575d7999c25a5bfb");
        let unprotected_header = hex!("4200bff4");
        let mut header = unprotected_header;
        let (first, packet_number) = header.split_at_mut(1);
        let protected_header = hex!("4cfe4189");

        let protector = QuicHeaderProtector {
            key: AeadKey::from(hp_key),
            phantom: std::marker::PhantomData::<ChaCha20Poly1305>,
        };

        protector.rfc9001_header_protection(&sample, &mut first[0], packet_number, false);
        assert_eq!(&header[..], &protected_header[..]);

        let (first, packet_number) = header.split_at_mut(1);
        protector.rfc9001_header_protection(&sample, &mut first[0], packet_number, true);
        assert_eq!(&header[..], &unprotected_header[..]);
    }

    #[test]
    fn quic_chacha20_crypt() {
        // test vector from https://www.rfc-editor.org/rfc/rfc9001.html#name-chacha20-poly1305-short-hea
        let expected_cleartext = hex!("01");

        let expected_ciphertext = hex!("655e5cd55c41f69080575d7999c25a5bfb");
        let key = hex!("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
        let iv = hex!("e0459b3474bdd0e44a41c144");
        let packet_number = 654360564;
        let unprotected_header = hex!("4200bff4");

        let protector = BoringAeadCrypter::<ChaCha20Poly1305>::new(
            Iv::new(iv),
            &key,
            rustls::ProtocolVersion::TLSv1_3,
        )
        .unwrap();

        let mut payload = expected_cleartext;

        let tag = protector
            .encrypt_in_place(packet_number, &unprotected_header, &mut payload)
            .unwrap();

        let mut ciphertext = [&payload, tag.as_ref()].concat();
        assert_eq!(ciphertext, expected_ciphertext);

        let cleartext = protector
            .decrypt_in_place(packet_number, &unprotected_header, &mut ciphertext)
            .unwrap();

        assert_eq!(cleartext, expected_cleartext);
    }
}
