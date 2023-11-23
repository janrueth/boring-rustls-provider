use std::{os::raw::c_void, ptr};

use boring::hash::MessageDigest;
use boring_additions::hmac::HmacCtx;
use foreign_types::ForeignType;
use rustls::crypto;

use crate::helper::{cvt, cvt_p};

#[allow(unused)]
pub const SHA256: &dyn crypto::hmac::Hmac = &BoringHmac(boring::nid::Nid::SHA256);
pub const SHA384: &dyn crypto::hmac::Hmac = &BoringHmac(boring::nid::Nid::SHA384);

pub struct BoringHmac(pub boring::nid::Nid);

impl crypto::hmac::Hmac for BoringHmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(unsafe {
            let ctx = HmacCtx::from_ptr(cvt_p(boring_sys::HMAC_CTX_new()).unwrap());

            let md = boring::hash::MessageDigest::from_nid(self.0).unwrap();

            BoringHmacKey {
                ctx,
                md,
                key: key.to_vec(),
            }
        })
    }

    fn hash_output_len(&self) -> usize {
        boring::hash::MessageDigest::from_nid(self.0)
            .unwrap()
            .size()
    }
}

#[derive(Clone)]
struct BoringHmacKey {
    ctx: HmacCtx,
    md: MessageDigest,
    key: Vec<u8>,
}

impl crypto::hmac::Key for BoringHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut out = [0u8; 32];

        crypto::hmac::Tag::new(unsafe {
            // initialize a new hmac
            cvt(boring_sys::HMAC_Init_ex(
                self.ctx.as_ptr(),
                self.key.as_ptr() as *const c_void,
                self.key.len(),
                self.md.as_ptr(),
                ptr::null_mut(),
            ))
            .unwrap();

            cvt(boring_sys::HMAC_Update(
                self.ctx.as_ptr(),
                first.as_ptr(),
                first.len(),
            ))
            .unwrap();

            for m in middle {
                cvt(boring_sys::HMAC_Update(
                    self.ctx.as_ptr(),
                    m.as_ptr(),
                    m.len(),
                ))
                .unwrap();
            }

            cvt(boring_sys::HMAC_Update(
                self.ctx.as_ptr(),
                last.as_ptr(),
                last.len(),
            ))
            .unwrap();

            let mut out_len = 0;
            cvt(boring_sys::HMAC_Final(
                self.ctx.as_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
            ))
            .unwrap();

            &out[..out_len as usize]
        })
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
