use std::{os::raw::c_void, ptr};

use boring::hash::MessageDigest;
use boring_additions::hmac::HmacCtx;
use foreign_types::ForeignType;
use rustls::crypto;

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
        let ctx = unsafe {
            HmacCtx::from_ptr(
                cvt_p(boring_sys::HMAC_CTX_new()).expect("failed getting hmac context"),
            )
        };

        let md = MessageDigest::from_nid(self.0).expect("failed getting digest");

        Box::new(BoringHmacKey {
            ctx,
            md,
            key: key.to_vec(),
        })
    }

    fn hash_output_len(&self) -> usize {
        MessageDigest::from_nid(self.0)
            .expect("failed getting digest")
            .size()
    }
}

#[derive(Clone)]
struct BoringHmacKey {
    ctx: HmacCtx,
    md: MessageDigest,
    key: Vec<u8>,
}

impl BoringHmacKey {
    fn init(&self) {
        unsafe {
            // initialize a new hmac
            cvt(boring_sys::HMAC_Init_ex(
                self.ctx.as_ptr(),
                self.key.as_ptr() as *const c_void,
                self.key.len(),
                self.md.as_ptr(),
                ptr::null_mut(),
            ))
        }
        .expect("failed initializing hmac");
    }

    fn update(&self, bytes: &[u8]) {
        unsafe {
            cvt(boring_sys::HMAC_Update(
                self.ctx.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
            ))
        }
        .expect("failed updating hmac");
    }

    fn finish(&self, out: &mut [u8]) -> usize {
        let mut out_len = 0;
        unsafe {
            cvt(boring_sys::HMAC_Final(
                self.ctx.as_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
            ))
        }
        .expect("failed hmac final");
        out_len as usize
    }
}

impl crypto::hmac::Key for BoringHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        self.init();

        self.update(first);
        for m in middle {
            self.update(m);
        }

        self.update(last);

        let mut out = [0u8; 32];
        let out_len = self.finish(&mut out);

        crypto::hmac::Tag::new(&out[..out_len])
    }

    fn tag_len(&self) -> usize {
        self.md.size()
    }
}

#[cfg(test)]
mod tests {
    use super::SHA256;
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
}
