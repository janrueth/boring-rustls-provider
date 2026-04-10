use std::{os::raw::c_void, ptr};

use boring::hash::MessageDigest;
use boring_additions::hmac::HmacCtx;
use foreign_types::ForeignType;
use rustls::crypto;
use zeroize::Zeroizing;

use crate::helper::{cvt, cvt_p};

/// A SHA256-based Hmac
#[allow(unused)]
pub const SHA256: &dyn crypto::hmac::Hmac = &BoringHmac(boring::nid::Nid::SHA256);

/// A SHA384-based Hmac
#[allow(unused)]
pub const SHA384: &dyn crypto::hmac::Hmac = &BoringHmac(boring::nid::Nid::SHA384);

struct BoringHmac(pub boring::nid::Nid);

impl crypto::hmac::Hmac for BoringHmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        let md = MessageDigest::from_nid(self.0).expect("failed getting digest");

        Box::new(BoringHmacKey {
            md,
            key: Zeroizing::new(key.to_vec()),
        })
    }

    fn hash_output_len(&self) -> usize {
        MessageDigest::from_nid(self.0)
            .expect("failed getting digest")
            .size()
    }

    fn fips(&self) -> bool {
        cfg!(feature = "fips")
    }
}

struct BoringHmacKey {
    md: MessageDigest,
    key: Zeroizing<Vec<u8>>,
}

impl BoringHmacKey {
    fn init(ctx: &HmacCtx, key: &[u8], md: MessageDigest) {
        unsafe {
            cvt(boring_sys::HMAC_Init_ex(
                ctx.as_ptr(),
                key.as_ptr() as *const c_void,
                key.len(),
                md.as_ptr(),
                ptr::null_mut(),
            ))
        }
        .expect("failed initializing hmac");
    }

    fn update(ctx: &HmacCtx, bytes: &[u8]) {
        unsafe {
            cvt(boring_sys::HMAC_Update(
                ctx.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
            ))
        }
        .expect("failed updating hmac");
    }

    fn finish(ctx: &HmacCtx, out: &mut [u8]) -> usize {
        let mut out_len = 0;
        unsafe {
            cvt(boring_sys::HMAC_Final(
                ctx.as_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
            ))
        }
        .expect("failed hmac final");
        out_len as usize
    }

    fn new_ctx() -> HmacCtx {
        unsafe {
            HmacCtx::from_ptr(cvt_p(boring_sys::HMAC_CTX_new()).expect("failed creating HMAC_CTX"))
        }
    }
}

impl crypto::hmac::Key for BoringHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let ctx = Self::new_ctx();
        Self::init(&ctx, self.key.as_slice(), self.md);

        Self::update(&ctx, first);
        for m in middle {
            Self::update(&ctx, m);
        }

        Self::update(&ctx, last);

        let mut out = Zeroizing::new([0u8; boring_sys::EVP_MAX_MD_SIZE as usize]);
        let out_len = Self::finish(&ctx, &mut out[..]);

        crypto::hmac::Tag::new(&out[..out_len])
    }

    fn tag_len(&self) -> usize {
        self.md.size()
    }
}

#[cfg(test)]
mod tests {
    use super::{SHA256, SHA384};
    use hex_literal::hex;

    #[test]
    fn test_sha256_hmac() {
        let hasher = SHA256.with_key("Very Secret".as_bytes());

        let _tag = hasher.sign_concat(
            "yay".as_bytes(),
            &["this".as_bytes(), "works".as_bytes()],
            "well".as_bytes(),
        );

        let tag = hasher.sign_concat(
            &[],
            &[
                "yay".as_bytes(),
                "this".as_bytes(),
                "works".as_bytes(),
                "well".as_bytes(),
            ],
            &[],
        );

        assert_eq!(
            tag.as_ref(),
            hex!("11fa4a6ee97bebfad9e1087145c556fec9a786cad0659aa10702d21bd2968305")
        );
    }

    #[test]
    fn test_sha384_hmac_len() {
        let hasher = SHA384.with_key("Very Secret".as_bytes());

        let tag = hasher.sign_concat(
            &[],
            &[
                "yay".as_bytes(),
                "this".as_bytes(),
                "works".as_bytes(),
                "well".as_bytes(),
            ],
            &[],
        );

        assert_eq!(tag.as_ref().len(), hasher.tag_len());
        assert_eq!(tag.as_ref().len(), 48);
    }
}
