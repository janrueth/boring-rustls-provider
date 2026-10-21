use std::{marker::PhantomData, sync::Mutex};

use boring::aead::{AeadCtx, Algorithm};
use boring::error::ErrorStack;
use rustls::ConnectionTrafficSecrets;
#[cfg(feature = "tls12")]
use rustls::crypto::cipher::make_tls12_aad;
use rustls::crypto::cipher::{
    self, EncodedMessage, InboundOpaque, Iv, OutboundOpaque, OutboundPlain, make_tls13_aad,
};
use rustls::enums::{ContentType, ProtocolVersion};
use rustls_pki_types::FipsStatus;

use crate::helper::log_and_map;

pub(crate) mod aes;
pub(crate) mod chacha20;

const QUIC_TAG_LEN: usize = 16;

pub(crate) trait BoringCipher {
    /// The lengths of the explicit nonce. (Not the full nonce length, only the part that changes)
    /// See also [`BoringCipher::fixed_iv_len`]
    const EXPLICIT_NONCE_LEN: usize;
    /// The IV's fixed length (Not the full IV length, only the part that doesn't change).
    /// Together with [`BoringCipher::explicit_nonce_len`] it determines the total
    /// lengths of the used nonce.
    /// Used only by TLS 1.2 code paths.
    #[cfg(feature = "tls12")]
    const FIXED_IV_LEN: usize;
    /// The amount of extra key-block material used to randomize the explicit nonce.
    ///
    /// BoringSSL's TLS 1.2 AEADs require a monotonically increasing explicit nonce,
    /// so this is deliberately separate from [`Self::EXPLICIT_NONCE_LEN`].
    #[cfg(feature = "tls12")]
    const KEY_BLOCK_EXTRA_LEN: usize = 0;
    /// The key size in bytes
    const KEY_SIZE: usize;

    /// The length of the authentication tag
    const TAG_LEN: usize;

    /// integrity limit
    const INTEGRITY_LIMIT: u64;

    /// confidentiality limit
    const CONFIDENTIALITY_LIMIT: u64;

    /// Whether this algorithm is FIPS-approved.
    const FIPS_APPROVED: bool;

    /// Constructs a new instance of this cipher as an AEAD algorithm
    fn new_cipher() -> Algorithm;

    /// Constructs the TLS 1.2 variant of this cipher.
    #[cfg(feature = "tls12")]
    fn new_tls12_cipher() -> Algorithm {
        Self::new_cipher()
    }

    /// Constructs the TLS 1.3 variant of this cipher.
    fn new_tls13_cipher() -> Algorithm {
        Self::new_cipher()
    }

    /// Extract keys
    fn extract_keys(key: cipher::AeadKey, iv: cipher::Iv) -> ConnectionTrafficSecrets;
}

pub(crate) trait QuicCipher: Send + Sync {
    /// The key size in bytes
    const KEY_SIZE: usize;

    /// the expected length of a sample
    const SAMPLE_LEN: usize;

    fn header_protection_mask(hp_key: &[u8], sample: &[u8]) -> Result<[u8; 5], rustls::Error>;
}

pub(crate) trait BoringAead: BoringCipher + Send + Sync {}

pub(crate) struct BoringAeadCrypter<T: BoringAead> {
    ctx: AeadCtx,
    max_overhead: usize,
    iv: Iv,
    tls_version: ProtocolVersion,
    phantom: PhantomData<T>,
}

pub(crate) struct BoringQuicPacketKey<T: BoringAead> {
    ctx: Mutex<AeadCtx>,
    max_overhead: usize,
    iv: Iv,
    phantom: PhantomData<T>,
}

impl<T: BoringAead> BoringAeadCrypter<T> {
    /// Creates a new aead crypter
    pub fn new(iv: Iv, key: &[u8], tls_version: ProtocolVersion) -> Result<Self, ErrorStack> {
        let tls_version_supported = match tls_version {
            #[cfg(feature = "tls12")]
            ProtocolVersion::TLSv1_2 => true,
            ProtocolVersion::TLSv1_3 => true,
            _ => false,
        };
        if !tls_version_supported {
            return Err(ErrorStack::get());
        }

        let cipher = match tls_version {
            #[cfg(feature = "tls12")]
            ProtocolVersion::TLSv1_2 => <T as BoringCipher>::new_tls12_cipher(),
            ProtocolVersion::TLSv1_3 => <T as BoringCipher>::new_tls13_cipher(),
            _ => return Err(ErrorStack::get()),
        };

        if cipher.nonce_len() != rustls::crypto::cipher::Nonce::new(&iv, 0).len() {
            return Err(ErrorStack::get());
        }

        let max_overhead = cipher.max_overhead();
        let crypter = BoringAeadCrypter {
            ctx: AeadCtx::new_default_tag(&cipher, key)?,
            max_overhead,
            iv,
            tls_version,
            phantom: PhantomData,
        };
        Ok(crypter)
    }
}

impl<T: BoringAead> BoringQuicPacketKey<T> {
    fn new(iv: Iv, key: &[u8]) -> Result<Self, ErrorStack> {
        let cipher = <T as BoringCipher>::new_cipher();
        if cipher.nonce_len() != rustls::crypto::cipher::Nonce::new(&iv, 0).len() {
            return Err(ErrorStack::get());
        }
        if cipher.max_overhead() != <T as BoringCipher>::TAG_LEN
            || <T as BoringCipher>::TAG_LEN != QUIC_TAG_LEN
        {
            return Err(ErrorStack::get());
        }

        Ok(Self {
            ctx: Mutex::new(AeadCtx::new_default_tag(&cipher, key)?),
            max_overhead: cipher.max_overhead(),
            iv,
            phantom: PhantomData,
        })
    }
}

impl<T> cipher::MessageEncrypter for BoringAeadCrypter<T>
where
    T: BoringAead,
{
    fn encrypt(
        &mut self,
        msg: EncodedMessage<OutboundPlain<'_>>,
        seq: u64,
    ) -> Result<EncodedMessage<OutboundOpaque>, rustls::Error> {
        let nonce = cipher::Nonce::new(&self.iv, seq);
        match self.tls_version {
            #[cfg(feature = "tls12")]
            ProtocolVersion::TLSv1_2 => {
                let fixed_iv_len = <T as BoringCipher>::FIXED_IV_LEN;
                let explicit_nonce_len = <T as BoringCipher>::EXPLICIT_NONCE_LEN;

                let payload_len = msg.payload.len();
                let total_len = self.encrypted_payload_len(payload_len);

                let mut full_payload = OutboundOpaque::with_capacity(total_len);
                full_payload.extend_from_slice(&nonce.as_ref()[fixed_iv_len..]);
                full_payload.extend_from_chunks(&msg.payload);
                full_payload.extend_from_slice(&vec![0u8; self.max_overhead]);

                let (_, payload) = full_payload.as_mut().split_at_mut(explicit_nonce_len);
                let (payload, tag) = payload.split_at_mut(payload_len);
                let aad = cipher::make_tls12_aad(seq, msg.typ, msg.version, payload_len);
                self.ctx
                    .seal_in_place_mut(nonce.as_ref(), payload, tag, &aad)
                    .map_err(|_| rustls::Error::EncryptError)?;

                Ok(EncodedMessage::new(msg.typ, msg.version, full_payload))
            }

            ProtocolVersion::TLSv1_3 => {
                let total_len = self.encrypted_payload_len(msg.payload.len());

                let mut payload = OutboundOpaque::with_capacity(total_len);
                payload.extend_from_chunks(&msg.payload);
                payload.extend_from_slice(&msg.typ.to_array());
                payload.extend_from_slice(&vec![0u8; self.max_overhead]);

                let aad = cipher::make_tls13_aad(total_len);
                let (plaintext, tag) = payload.as_mut().split_at_mut(total_len - self.max_overhead);
                self.ctx
                    .seal_in_place_mut(nonce.as_ref(), plaintext, tag, &aad)
                    .map_err(|e| {
                        log_and_map("seal_in_place_mut", e, rustls::Error::EncryptError)
                    })?;
                Ok(EncodedMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    payload,
                ))
            }
            _ => Err(rustls::Error::EncryptError),
        }
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        let per_record_overhead = match self.tls_version {
            ProtocolVersion::TLSv1_2 => self
                .max_overhead
                .saturating_add(<T as BoringCipher>::EXPLICIT_NONCE_LEN),
            ProtocolVersion::TLSv1_3 => 1usize.saturating_add(self.max_overhead),
            _ => return payload_len,
        };

        payload_len.saturating_add(per_record_overhead)
    }
}

impl<T> cipher::MessageDecrypter for BoringAeadCrypter<T>
where
    T: BoringAead,
{
    fn decrypt<'a>(
        &mut self,
        mut m: EncodedMessage<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<EncodedMessage<&'a [u8]>, rustls::Error> {
        match self.tls_version {
            #[cfg(feature = "tls12")]
            ProtocolVersion::TLSv1_2 => {
                let explicit_nonce_len = <T as BoringCipher>::EXPLICIT_NONCE_LEN;
                let tag_len = self.max_overhead;
                let min_payload_len = explicit_nonce_len
                    .checked_add(tag_len)
                    .ok_or(rustls::Error::DecryptError)?;

                if m.payload.len() < min_payload_len {
                    return Err(rustls::Error::DecryptError);
                }

                // payload is: [nonce] | [ciphertext] | [auth tag]
                let actual_payload_length = m.payload.len() - tag_len - explicit_nonce_len;

                let aad = make_tls12_aad(seq, m.typ, m.version, actual_payload_length);

                let payload = &mut m.payload;

                // get the nonce
                let (explicit_nonce, payload) = payload.split_at_mut(explicit_nonce_len);

                let nonce = {
                    let fixed_iv_len = <T as BoringCipher>::FIXED_IV_LEN;

                    if explicit_nonce_len + fixed_iv_len != 12 {
                        return Err(rustls::Error::DecryptError);
                    }

                    // grab the IV by constructing a nonce, this is just an xor
                    let nonce_val = cipher::Nonce::new(&self.iv, seq);
                    let iv: [u8; 12] = nonce_val
                        .to_array()
                        .map_err(|_| rustls::Error::DecryptError)?;
                    let mut nonce = [0u8; 12];
                    nonce[..fixed_iv_len].copy_from_slice(&iv[..fixed_iv_len]);
                    nonce[fixed_iv_len..].copy_from_slice(explicit_nonce);
                    nonce
                };

                // split off the authentication tag
                let (payload, tag) = payload.split_at_mut(payload.len() - tag_len);

                self.ctx
                    .open_in_place_mut(&nonce, payload, tag, &aad)
                    .map_err(|e| log_and_map("open_in_place_mut", e, rustls::Error::DecryptError))
                    .map(|_| {
                        // rotate the nonce to the end
                        m.payload.rotate_left(explicit_nonce_len);

                        // truncate buffer to the actual payload
                        m.payload.truncate(actual_payload_length);

                        m.into_plain_message()
                    })
            }
            ProtocolVersion::TLSv1_3 => {
                let nonce = cipher::Nonce::new(&self.iv, seq);
                let aad = make_tls13_aad(m.payload.len());
                if m.payload.len() < self.max_overhead {
                    return Err(rustls::Error::DecryptError);
                }

                let plaintext_len = m.payload.len() - self.max_overhead;
                let (payload, tag) = m.payload.split_at_mut(plaintext_len);
                self.ctx
                    .open_in_place_mut(nonce.as_ref(), payload, tag, &aad)
                    .map_err(|e| {
                        log_and_map("open_in_place_mut", e, rustls::Error::DecryptError)
                    })?;
                m.payload.truncate(plaintext_len);
                m.into_tls13_unpadded_message()
            }
            _ => Err(rustls::Error::DecryptError),
        }
    }
}

impl<T> rustls::quic::PacketKey for BoringQuicPacketKey<T>
where
    T: QuicCipher + BoringAead,
{
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
        path_id: Option<u32>,
    ) -> Result<rustls::quic::Tag, rustls::Error> {
        let associated_data = header;
        let nonce = cipher::Nonce::quic(path_id, &self.iv, packet_number);
        let mut tag = [0u8; QUIC_TAG_LEN];
        let mut ctx = self.ctx.lock().map_err(|_| rustls::Error::EncryptError)?;
        ctx.seal_in_place_mut(
            nonce.as_ref(),
            payload,
            &mut tag[..self.max_overhead],
            associated_data,
        )
        .map_err(|e| log_and_map("seal_in_place_mut", e, rustls::Error::EncryptError))?;

        Ok(rustls::quic::Tag::from(&tag[..self.max_overhead]))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
        path_id: Option<u32>,
    ) -> Result<&'a [u8], rustls::Error> {
        let associated_data = header;
        let nonce = cipher::Nonce::quic(path_id, &self.iv, packet_number);

        if payload.len() < self.max_overhead {
            return Err(rustls::Error::DecryptError);
        }

        let (buffer, tag) = payload.split_at_mut(payload.len() - self.max_overhead);

        let mut ctx = self.ctx.lock().map_err(|_| rustls::Error::DecryptError)?;
        ctx.open_in_place_mut(nonce.as_ref(), buffer, tag, associated_data)
            .map_err(|e| log_and_map("open_in_place_mut", e, rustls::Error::DecryptError))?;

        Ok(buffer)
    }

    fn tag_len(&self) -> usize {
        <T as BoringCipher>::TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        <T as BoringCipher>::CONFIDENTIALITY_LIMIT
    }

    fn integrity_limit(&self) -> u64 {
        <T as BoringCipher>::INTEGRITY_LIMIT
    }
}

struct InvalidMessageEncrypter;

impl cipher::MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(
        &mut self,
        _msg: EncodedMessage<OutboundPlain<'_>>,
        _seq: u64,
    ) -> Result<EncodedMessage<OutboundOpaque>, rustls::Error> {
        Err(rustls::Error::EncryptError)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }
}

struct InvalidMessageDecrypter;

impl cipher::MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        _msg: EncodedMessage<InboundOpaque<'a>>,
        _seq: u64,
    ) -> Result<EncodedMessage<&'a [u8]>, rustls::Error> {
        Err(rustls::Error::DecryptError)
    }
}

struct InvalidPacketKey<T>(PhantomData<T>);

impl<T: BoringCipher + QuicCipher> rustls::quic::PacketKey for InvalidPacketKey<T> {
    fn encrypt_in_place(
        &self,
        _packet_number: u64,
        _header: &[u8],
        _payload: &mut [u8],
        _path_id: Option<u32>,
    ) -> Result<rustls::quic::Tag, rustls::Error> {
        Err(rustls::Error::EncryptError)
    }

    fn decrypt_in_place<'a>(
        &self,
        _packet_number: u64,
        _header: &[u8],
        _payload: &'a mut [u8],
        _path_id: Option<u32>,
    ) -> Result<&'a [u8], rustls::Error> {
        Err(rustls::Error::DecryptError)
    }

    fn tag_len(&self) -> usize {
        <T as BoringCipher>::TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        0
    }

    fn integrity_limit(&self) -> u64 {
        0
    }
}

pub(crate) struct Aead<T>(PhantomData<T>);

impl<T> Aead<T> {
    pub const DEFAULT: Self = Self(PhantomData);
}

impl<T: BoringAead + 'static> cipher::Tls13AeadAlgorithm for Aead<T> {
    fn encrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageEncrypter> {
        match BoringAeadCrypter::<T>::new(iv, key.as_ref(), ProtocolVersion::TLSv1_3) {
            Ok(crypter) => Box::new(crypter),
            Err(err) => {
                log_and_map(
                    "Tls13AeadAlgorithm::encrypter BoringAeadCrypter::new",
                    err,
                    (),
                );
                Box::new(InvalidMessageEncrypter)
            }
        }
    }

    fn decrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageDecrypter> {
        match BoringAeadCrypter::<T>::new(iv, key.as_ref(), ProtocolVersion::TLSv1_3) {
            Ok(crypter) => Box::new(crypter),
            Err(err) => {
                log_and_map(
                    "Tls13AeadAlgorithm::decrypter BoringAeadCrypter::new",
                    err,
                    (),
                );
                Box::new(InvalidMessageDecrypter)
            }
        }
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

    fn fips(&self) -> FipsStatus {
        if cfg!(feature = "fips") && <T as BoringCipher>::FIPS_APPROVED {
            FipsStatus::Pending
        } else {
            FipsStatus::Unvalidated
        }
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
        let Some(iv) = tls12_iv::<T>(iv, extra) else {
            return Box::new(InvalidMessageEncrypter);
        };
        match BoringAeadCrypter::<T>::new(iv, key.as_ref(), ProtocolVersion::TLSv1_2) {
            Ok(crypter) => Box::new(crypter),
            Err(err) => {
                log_and_map(
                    "Tls12AeadAlgorithm::encrypter BoringAeadCrypter::new",
                    err,
                    (),
                );
                Box::new(InvalidMessageEncrypter)
            }
        }
    }

    fn decrypter(&self, key: cipher::AeadKey, iv: &[u8]) -> Box<dyn cipher::MessageDecrypter> {
        let Some(iv) = tls12_iv::<T>(iv, &[]) else {
            return Box::new(InvalidMessageDecrypter);
        };
        match BoringAeadCrypter::<T>::new(iv, key.as_ref(), ProtocolVersion::TLSv1_2) {
            Ok(crypter) => Box::new(crypter),
            Err(err) => {
                log_and_map(
                    "Tls12AeadAlgorithm::decrypter BoringAeadCrypter::new",
                    err,
                    (),
                );
                Box::new(InvalidMessageDecrypter)
            }
        }
    }

    fn key_block_shape(&self) -> cipher::KeyBlockShape {
        cipher::KeyBlockShape {
            enc_key_len: <T as BoringCipher>::KEY_SIZE,
            fixed_iv_len: <T as BoringCipher>::FIXED_IV_LEN,
            explicit_nonce_len: <T as BoringCipher>::KEY_BLOCK_EXTRA_LEN,
        }
    }

    fn extract_keys(
        &self,
        key: cipher::AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        let iv = tls12_iv::<T>(iv, explicit).ok_or(cipher::UnsupportedOperationError)?;
        Ok(<T as BoringCipher>::extract_keys(key, iv))
    }

    fn fips(&self) -> FipsStatus {
        if cfg!(feature = "fips") && <T as BoringCipher>::FIPS_APPROVED {
            FipsStatus::Pending
        } else {
            FipsStatus::Unvalidated
        }
    }
}

#[cfg(feature = "tls12")]
fn tls12_iv<T: BoringCipher>(fixed_iv: &[u8], extra: &[u8]) -> Option<Iv> {
    if fixed_iv.len() != T::FIXED_IV_LEN || extra.len() != T::KEY_BLOCK_EXTRA_LEN {
        return None;
    }
    if T::FIXED_IV_LEN.checked_add(T::EXPLICIT_NONCE_LEN)? != 12 {
        return None;
    }

    let mut iv = [0u8; 12];
    iv[..T::FIXED_IV_LEN].copy_from_slice(fixed_iv);
    Some(Iv::from(iv))
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
    ) -> Result<(), rustls::Error> {
        let mask = T::header_protection_mask(self.key.as_ref(), sample)?;

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

        Ok(())
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

        self.rfc9001_header_protection(sample, first, packet_number, false)?;

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

        self.rfc9001_header_protection(sample, first, packet_number, true)?;

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
        match BoringQuicPacketKey::<T>::new(iv, key.as_ref()) {
            Ok(crypter) => Box::new(crypter),
            Err(err) => {
                log_and_map(
                    "QuicAlgorithm::packet_key BoringQuicPacketKey::new",
                    err,
                    (),
                );
                Box::new(InvalidPacketKey::<T>(PhantomData))
            }
        }
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

    fn fips(&self) -> FipsStatus {
        if cfg!(feature = "fips") && <T as BoringCipher>::FIPS_APPROVED {
            FipsStatus::Pending
        } else {
            FipsStatus::Unvalidated
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rustls::crypto::cipher::{
        AeadKey, EncodedMessage, InboundOpaque, Iv, MessageEncrypter, OutboundPlain,
        Tls13AeadAlgorithm,
    };
    #[cfg(feature = "tls12")]
    use rustls::crypto::cipher::{MessageDecrypter, Tls12AeadAlgorithm};
    use rustls::enums::{ContentType, ProtocolVersion};
    use rustls::quic::Algorithm as QuicAlgorithm;
    use rustls::quic::HeaderProtectionKey;

    use crate::aead::{BoringAeadCrypter, BoringQuicPacketKey};
    use rustls::quic::PacketKey;

    use super::aes::Aes128;
    use super::{BoringCipher, QuicHeaderProtector, chacha20::ChaCha20Poly1305};

    fn outbound_message(
        payload: &[u8],
        version: ProtocolVersion,
    ) -> EncodedMessage<OutboundPlain<'_>> {
        EncodedMessage::new(
            ContentType::ApplicationData,
            version,
            OutboundPlain::Single(payload),
        )
    }

    #[test]
    fn tls13_aes_rejects_non_monotonic_sequence_numbers() {
        let mut encrypter = BoringAeadCrypter::<Aes128>::new(
            Iv::from([0u8; 12]),
            &[0u8; 16],
            ProtocolVersion::TLSv1_3,
        )
        .unwrap();

        encrypter
            .encrypt(outbound_message(b"first", ProtocolVersion::TLSv1_3), 0)
            .expect("initial sequence number should encrypt");
        encrypter
            .encrypt(outbound_message(b"second", ProtocolVersion::TLSv1_3), 1)
            .expect("increasing sequence number should encrypt");
        let err = encrypter
            .encrypt(outbound_message(b"repeat", ProtocolVersion::TLSv1_3), 1)
            .expect_err("reused sequence number must be rejected");

        assert!(matches!(err, rustls::Error::EncryptError));
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn tls12_aes_uses_monotonic_sequence_number_as_explicit_nonce() {
        let shape = Tls12AeadAlgorithm::key_block_shape(&super::Aead::<Aes128>::DEFAULT);
        assert_eq!(shape.explicit_nonce_len, 0);
        let iv = super::tls12_iv::<Aes128>(&[0u8; 4], &[]).unwrap();
        let mut encrypter =
            BoringAeadCrypter::<Aes128>::new(iv, &[0u8; 16], ProtocolVersion::TLSv1_2).unwrap();

        let first = encrypter
            .encrypt(outbound_message(b"first", ProtocolVersion::TLSv1_2), 0)
            .expect("initial sequence number should encrypt");
        assert_eq!(&first.payload.as_ref()[..8], &0u64.to_be_bytes());

        let second = encrypter
            .encrypt(outbound_message(b"second", ProtocolVersion::TLSv1_2), 1)
            .expect("increasing sequence number should encrypt");
        assert_eq!(&second.payload.as_ref()[..8], &1u64.to_be_bytes());

        let err = encrypter
            .encrypt(outbound_message(b"repeat", ProtocolVersion::TLSv1_2), 1)
            .expect_err("reused sequence number must be rejected");
        assert!(matches!(err, rustls::Error::EncryptError));
    }

    #[test]
    fn quic_aes_keeps_generic_non_monotonic_aead() {
        let key = [0u8; <Aes128 as BoringCipher>::KEY_SIZE];
        let packet_key = BoringQuicPacketKey::<Aes128>::new(Iv::from([0u8; 12]), &key).unwrap();
        let mut later = [1u8];
        let mut earlier = [2u8];

        packet_key
            .encrypt_in_place(5, &[], &mut later, None)
            .expect("generic QUIC AEAD should encrypt packet 5");
        packet_key
            .encrypt_in_place(3, &[], &mut earlier, None)
            .expect("generic QUIC AEAD should allow an earlier packet number");
    }

    #[test]
    fn quic_packet_key_preserves_path_id_in_nonce() {
        let key = [0u8; <Aes128 as BoringCipher>::KEY_SIZE];
        let packet_key = BoringQuicPacketKey::<Aes128>::new(Iv::from([0u8; 12]), &key).unwrap();
        let mut payload = [7u8];
        let mut other_path_payload = payload;

        let tag = packet_key
            .encrypt_in_place(1, &[], &mut payload, Some(42))
            .expect("QUIC multipath nonce should encrypt");
        let other_path_tag = packet_key
            .encrypt_in_place(1, &[], &mut other_path_payload, Some(43))
            .expect("another QUIC path should encrypt independently");
        assert_ne!(
            [&payload, tag.as_ref()].concat(),
            [&other_path_payload, other_path_tag.as_ref()].concat(),
            "path ID must affect the QUIC nonce"
        );

        let mut ciphertext = [&payload, tag.as_ref()].concat();

        let plaintext = packet_key
            .decrypt_in_place(1, &[], &mut ciphertext, Some(42))
            .expect("matching QUIC path ID should decrypt");
        assert_eq!(plaintext, &[7]);
    }

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

        protector
            .rfc9001_header_protection(&sample, &mut first[0], packet_number, false)
            .expect("valid sample should protect QUIC header");
        assert_eq!(&header[..], &protected_header[..]);

        let (first, packet_number) = header.split_at_mut(1);
        protector
            .rfc9001_header_protection(&sample, &mut first[0], packet_number, true)
            .expect("valid sample should unprotect QUIC header");
        assert_eq!(&header[..], &unprotected_header[..]);
    }

    #[test]
    fn quic_header_protection_rejects_invalid_sample_without_mutation() {
        let hp_key = hex!("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
        let sample = hex!("5e5cd55c41f69080575d7999c25a5bfb");
        let mut header = hex!("4200bff4");
        let original = header;
        let (first, packet_number) = header.split_at_mut(1);

        let protector = QuicHeaderProtector {
            key: AeadKey::from(hp_key),
            phantom: std::marker::PhantomData::<ChaCha20Poly1305>,
        };

        let err = protector
            .encrypt_in_place(&sample[..sample.len() - 1], &mut first[0], packet_number)
            .expect_err("short sample must be rejected");

        assert!(matches!(err, rustls::Error::General(_)));
        assert_eq!(header, original);
    }

    #[test]
    fn tls13_decrypter_constructor_failure_returns_erroring_decrypter() {
        let mut decrypter = Tls13AeadAlgorithm::decrypter(
            &super::Aead::<Aes128>::DEFAULT,
            AeadKey::from([0u8; 32]),
            Iv::from([0u8; 12]),
        );
        let mut payload = vec![0u8; 8];
        let msg = EncodedMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_3,
            InboundOpaque(&mut payload),
        );

        let err = decrypter
            .decrypt(msg, 0)
            .expect_err("invalid constructor inputs should produce decrypt errors");

        assert!(matches!(err, rustls::Error::DecryptError));
    }

    #[test]
    fn quic_packet_key_constructor_failure_returns_erroring_key() {
        let packet_key = super::Aead::<Aes128>::DEFAULT
            .packet_key(AeadKey::from([0u8; 32]), Iv::from([0u8; 12]));
        let mut payload = [0u8; 0];

        let enc_err = packet_key.encrypt_in_place(0, &[], &mut payload, None);
        assert!(matches!(enc_err, Err(rustls::Error::EncryptError)));

        let dec_err = packet_key
            .decrypt_in_place(0, &[], &mut payload, None)
            .expect_err("invalid constructor inputs should produce decrypt errors");
        assert!(matches!(dec_err, rustls::Error::DecryptError));
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn tls12_decrypter_constructor_failure_returns_erroring_decrypter() {
        let mut decrypter = Tls12AeadAlgorithm::decrypter(
            &super::Aead::<Aes128>::DEFAULT,
            AeadKey::from([0u8; 32]),
            &[0u8; 4],
        );
        let mut payload = vec![0u8; 8];
        let msg = EncodedMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            InboundOpaque(&mut payload),
        );

        let err = decrypter
            .decrypt(msg, 0)
            .expect_err("invalid constructor inputs should produce decrypt errors");

        assert!(matches!(err, rustls::Error::DecryptError));
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

        let protector = BoringQuicPacketKey::<ChaCha20Poly1305>::new(Iv::from(iv), &key).unwrap();

        let mut payload = expected_cleartext;

        let tag = protector
            .encrypt_in_place(packet_number, &unprotected_header, &mut payload, None)
            .unwrap();

        let mut ciphertext = [&payload, tag.as_ref()].concat();
        assert_eq!(ciphertext, expected_ciphertext);

        let cleartext = protector
            .decrypt_in_place(packet_number, &unprotected_header, &mut ciphertext, None)
            .unwrap();

        assert_eq!(cleartext, expected_cleartext);
    }

    #[test]
    fn quic_decrypt_rejects_truncated_payload() {
        let key = [0u8; <ChaCha20Poly1305 as BoringCipher>::KEY_SIZE];
        let iv = [0u8; 12];
        let crypter = BoringQuicPacketKey::<ChaCha20Poly1305>::new(Iv::from(iv), &key).unwrap();

        let mut payload = [0u8; <ChaCha20Poly1305 as BoringCipher>::TAG_LEN - 1];
        let err = crypter
            .decrypt_in_place(0, &[], &mut payload, None)
            .expect_err("truncated QUIC payload must fail decryption");

        assert!(matches!(err, rustls::Error::DecryptError));
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn tls12_decrypt_rejects_truncated_payload() {
        let key = [0u8; <Aes128 as BoringCipher>::KEY_SIZE];
        let iv = [0u8; 12];
        let mut decrypter =
            BoringAeadCrypter::<Aes128>::new(Iv::from(iv), &key, ProtocolVersion::TLSv1_2).unwrap();

        let min_payload_len =
            <Aes128 as BoringCipher>::EXPLICIT_NONCE_LEN + <Aes128 as BoringCipher>::TAG_LEN;
        let mut payload = vec![0u8; min_payload_len - 1];
        let msg = EncodedMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            InboundOpaque(&mut payload),
        );

        let err = decrypter
            .decrypt(msg, 0)
            .expect_err("truncated TLS1.2 payload must fail decryption");

        assert!(matches!(err, rustls::Error::DecryptError));
    }
}
