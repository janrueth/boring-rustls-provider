use std::ptr;

use boring::error::ErrorStack;
use foreign_types::ForeignType;

mod types;

use crate::helper::{cvt, cvt_p};

pub use self::types::*;

pub struct Algorithm(*const boring_sys::EVP_AEAD);

impl Algorithm {
    /// AES-128 in Galois Counter Mode.
    ///
    /// Note: AES-GCM should only be used with 12-byte (96-bit) nonces. Although it is specified to take a variable-length nonce, nonces with other lengths are effectively randomized, which means one must consider collisions. Unless implementing an existing protocol which has already specified incorrect parameters, only use 12-byte nonces.
    #[must_use]
    pub fn aes_128_gcm() -> Self {
        Self(unsafe { boring_sys::EVP_aead_aes_128_gcm() })
    }

    /// AES-256 in Galois Counter Mode.
    ///
    /// Note: AES-GCM should only be used with 12-byte (96-bit) nonces. Although it is specified to take a variable-length nonce, nonces with other lengths are effectively randomized, which means one must consider collisions. Unless implementing an existing protocol which has already specified incorrect parameters, only use 12-byte nonces.
    #[must_use]
    pub fn aes_256_gcm() -> Self {
        Self(unsafe { boring_sys::EVP_aead_aes_256_gcm() })
    }

    /// `ChaCha20` with `Poly1305` as described in RFC 8439.
    #[must_use]
    pub fn chacha20_poly1305() -> Self {
        Self(unsafe { boring_sys::EVP_aead_chacha20_poly1305() })
    }

    /// ChaCha20-Poly1305 with an extended nonce that makes random generation of nonces safe.
    #[allow(unused)]
    #[must_use]
    pub fn xchacha20_poly1305() -> Self {
        Self(unsafe { boring_sys::EVP_aead_xchacha20_poly1305() })
    }

    /// Returns the length, in bytes, of the keys used by aead
    #[must_use]
    pub fn key_length(&self) -> usize {
        unsafe { boring_sys::EVP_AEAD_key_length(self.0) }
    }

    /// Returns the maximum number of additional bytes added by the act of sealing data with aead.
    #[must_use]
    pub fn max_overhead(&self) -> usize {
        unsafe { boring_sys::EVP_AEAD_max_overhead(self.0) }
    }

    /// Returns the maximum tag length when using aead.
    #[allow(unused)]
    #[must_use]
    pub fn max_tag_len(&self) -> usize {
        unsafe { boring_sys::EVP_AEAD_max_tag_len(self.0) }
    }

    /// Returns the length, in bytes, of the per-message nonce for aead.
    #[must_use]
    pub fn nonce_len(&self) -> usize {
        unsafe { boring_sys::EVP_AEAD_nonce_length(self.0) }
    }
}

pub struct Crypter {
    ctx: EvpAeadCtx,
    max_overhead: usize,
    nonce_len: usize,
}

impl Crypter {
    /// Constructs a new AEAD crypter with the given algorithm and key
    ///
    /// # Errors
    /// Returns the `BoringSSL` error in case of an internal error
    ///
    /// # Panics
    /// * If the key length mismatches the `aead_alg` required key length
    pub fn new(aead_alg: &Algorithm, key: &[u8]) -> Result<Self, ErrorStack> {
        assert_eq!(aead_alg.key_length(), key.len());
        boring_sys::init();

        let this = unsafe {
            Self {
                ctx: EvpAeadCtx::from_ptr(cvt_p(boring_sys::EVP_AEAD_CTX_new(
                    aead_alg.0,
                    key.as_ptr(),
                    key.len(),
                    boring_sys::EVP_AEAD_DEFAULT_TAG_LENGTH as usize,
                ))?),
                max_overhead: aead_alg.max_overhead(),
                nonce_len: aead_alg.nonce_len(),
            }
        };

        Ok(this)
    }

    /// Returns the maximum required overhead in bytes
    /// that will be added to a ciphertext, e.g.,
    /// to hold an authentication tag.
    #[must_use]
    pub fn max_overhead(&self) -> usize {
        self.max_overhead
    }

    /// Encrypts and authenticates `buffer` and authenticates `associated_data`.
    /// It writes the ciphertext to `buffer` and the authentication tag to `tag`.
    /// `tag` needs to have sufficient space, see [`Self::max_overhead()`](fn@Self::max_overhead())
    /// On success, it returns the actual length of the `tag`
    ///
    /// # Errors
    /// In case of an error, returns the `BoringSSL` error
    ///
    /// # Panics
    /// * If the `nonce` is not the expected lenght
    /// * If the `tag` has not enough space
    pub fn seal_in_place(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) -> Result<usize, ErrorStack> {
        assert!(tag.len() >= self.max_overhead);
        assert_eq!(nonce.len(), self.nonce_len);

        let mut tag_len = tag.len();
        unsafe {
            cvt(boring_sys::EVP_AEAD_CTX_seal_scatter(
                self.ctx.as_ptr(),
                buffer.as_mut_ptr(),
                tag.as_mut_ptr(),
                &mut tag_len,
                tag.len(),
                nonce.as_ptr(),
                nonce.len(),
                buffer.as_ptr(),
                buffer.len(),
                ptr::null_mut(),
                0,
                associated_data.as_ptr(),
                associated_data.len(),
            ))?;
        }
        Ok(tag_len)
    }

    /// Decrypts and authenticates `buffer` and authenticates `associated_data`.
    /// It writes the cleartext to `buffer` and validates using `tag`.
    ///
    /// # Errors
    /// In case of an error, returns the `BoringSSL` error
    ///
    /// # Panics
    /// * if the nonce has the wrong lenght
    pub fn open_in_place(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), ErrorStack> {
        assert_eq!(nonce.len(), self.nonce_len);

        unsafe {
            cvt(boring_sys::EVP_AEAD_CTX_open_gather(
                self.ctx.as_ptr(),
                buffer.as_mut_ptr(),
                nonce.as_ptr(),
                nonce.len(),
                buffer.as_ptr(),
                buffer.len(),
                tag.as_ptr(),
                tag.len(),
                associated_data.as_ptr(),
                associated_data.len(),
            ))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Crypter;

    #[test]
    fn in_out() {
        let key = Crypter::new(&super::Algorithm::aes_128_gcm(), &[0u8; 16]).unwrap();
        let nonce = [0u8; 12];
        let associated_data = b"this is authenticated";
        let mut buffer = Vec::with_capacity(26);
        buffer.extend_from_slice(b"ABCDE");

        let mut tag = [0u8; 16];
        key.seal_in_place(&nonce, associated_data, buffer.as_mut_slice(), &mut tag)
            .unwrap();

        key.open_in_place(&nonce, associated_data, buffer.as_mut_slice(), &tag[..])
            .unwrap();

        assert_eq!(b"ABCDE", buffer.as_slice());
    }
}
