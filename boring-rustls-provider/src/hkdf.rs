use std::marker::PhantomData;

use boring::hash::MessageDigest;
use rustls::crypto::tls13::{self, Hkdf as RustlsHkdf};

use crate::helper::{cvt, cvt_p};

/// A trait that is required for a Hkdf function
pub trait BoringHash: Send + Sync {
    /// Instantiate a new digest using
    /// the hash function that this trait
    /// is implemented for.
    fn new_hash() -> MessageDigest;
}

/// SHA256-based for Hkdf
pub struct Sha256();
impl BoringHash for Sha256 {
    fn new_hash() -> MessageDigest {
        MessageDigest::sha256()
    }
}

/// SHA384-based for Hkdf
pub struct Sha384();
impl BoringHash for Sha384 {
    fn new_hash() -> MessageDigest {
        MessageDigest::sha384()
    }
}

/// A Hmac-based key derivation function
/// using T as the hash function
pub struct Hkdf<T: BoringHash>(PhantomData<T>);

impl<T: BoringHash> Hkdf<T> {
    /// A default Hkdf implementation
    pub const DEFAULT: Self = Self(PhantomData);
}

impl<T: BoringHash> RustlsHkdf for Hkdf<T> {
    /// `HKDF-Extract(salt, 0_HashLen)`
    ///
    /// `0_HashLen` is a string of `HashLen` zero bytes.
    ///
    /// A `salt` of `None` should be treated as a sequence of `HashLen` zero bytes.
    fn extract_from_zero_ikm(
        &self,
        salt: Option<&[u8]>,
    ) -> Box<dyn rustls::crypto::tls13::HkdfExpander> {
        let hash_size = T::new_hash().size();

        let secret = [0u8; boring_sys::EVP_MAX_MD_SIZE as usize];
        let secret_len = hash_size;

        self.extract_from_secret(salt, &secret[..secret_len])
    }

    /// `HKDF-Extract(salt, secret)`
    ///
    /// A `salt` of `None` should be treated as a sequence of `HashLen` zero bytes.
    fn extract_from_secret(
        &self,
        salt: Option<&[u8]>,
        secret: &[u8],
    ) -> Box<dyn rustls::crypto::tls13::HkdfExpander> {
        let digest = T::new_hash();
        let hash_size = digest.size();

        let mut prk = [0u8; boring_sys::EVP_MAX_MD_SIZE as usize];
        let mut prk_len = 0;

        // if salt isn't set we usen these bytes here as salt
        let salt_bytes = [0u8; boring_sys::EVP_MAX_MD_SIZE as usize];

        let salt = if let Some(salt) = salt {
            salt
        } else {
            &salt_bytes[..hash_size]
        };

        unsafe {
            cvt(boring_sys::HKDF_extract(
                prk.as_mut_ptr(),
                &mut prk_len,
                digest.as_ptr(),
                secret.as_ptr(),
                secret.len(),
                salt.as_ptr(),
                salt.len(),
            ))
            .expect("HKDF_extract failed");
        }
        Box::new(HkdfExpander {
            prk,
            prk_len,
            digest,
        })
    }

    fn expander_for_okm(
        &self,
        okm: &rustls::crypto::tls13::OkmBlock,
    ) -> Box<dyn rustls::crypto::tls13::HkdfExpander> {
        let okm = okm.as_ref();
        let mut prk = [0u8; boring_sys::EVP_MAX_MD_SIZE as usize];
        let prk_len = okm.len();

        prk[..prk_len].copy_from_slice(okm);

        Box::new(HkdfExpander {
            prk,
            prk_len,
            digest: T::new_hash(),
        })
    }

    fn hmac_sign(
        &self,
        key: &rustls::crypto::tls13::OkmBlock,
        message: &[u8],
    ) -> rustls::crypto::hmac::Tag {
        let digest = T::new_hash();
        let mut hash = [0u8; boring_sys::EVP_MAX_MD_SIZE as usize];
        let mut hash_len = 0u32;
        unsafe {
            cvt_p(boring_sys::HMAC(
                digest.as_ptr(),
                key.as_ref().as_ptr() as _,
                key.as_ref().len(),
                message.as_ptr(),
                message.len(),
                hash.as_mut_ptr(),
                &mut hash_len,
            ))
            .expect("HMAC failed");
        }
        rustls::crypto::hmac::Tag::new(&hash[..hash_len as usize])
    }
}

struct HkdfExpander {
    prk: [u8; boring_sys::EVP_MAX_MD_SIZE as usize],
    prk_len: usize,
    digest: MessageDigest,
}

impl tls13::HkdfExpander for HkdfExpander {
    /// `HKDF-Expand(PRK, info, L)` into a slice.
    ///
    /// Where:
    ///
    /// - `PRK` is the implicit key material represented by this instance.
    /// - `L` is `output.len()`.
    /// - `info` is a slice of byte slices, which should be processed sequentially
    ///   (or concatenated if that is not possible).
    ///
    /// Returns `Err(OutputLengthError)` if `L` is larger than `255 * HashLen`.
    /// Otherwise, writes to `output`.
    fn expand_slice(
        &self,
        info: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), tls13::OutputLengthError> {
        let info_concat = info.concat();
        unsafe {
            boring_sys::HKDF_expand(
                output.as_mut_ptr(),
                output.len(),
                self.digest.as_ptr(),
                self.prk.as_ptr(),
                self.prk_len,
                info_concat.as_ptr(),
                info_concat.len(),
            );
        };
        Ok(())
    }

    /// `HKDF-Expand(PRK, info, L=HashLen)` returned as a value.
    ///
    /// - `PRK` is the implicit key material represented by this instance.
    /// - `L := HashLen`.
    /// - `info` is a slice of byte slices, which should be processed sequentially
    ///   (or concatenated if that is not possible).
    ///
    /// This is infallible, because by definition `OkmBlock` is always exactly
    /// `HashLen` bytes long.
    fn expand_block(&self, info: &[&[u8]]) -> tls13::OkmBlock {
        let mut output = [0u8; boring_sys::EVP_MAX_MD_SIZE as usize];
        let output_len = self.hash_len();

        self.expand_slice(info, &mut output[..output_len])
            .expect("failed hkdf expand");

        tls13::OkmBlock::new(&output[..output_len])
    }

    fn hash_len(&self) -> usize {
        self.digest.size()
    }
}
