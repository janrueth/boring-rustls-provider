use boring::hash::MessageDigest;
use rustls::crypto;
use zeroize::Zeroizing;

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

    fn fips(&self) -> rustls_pki_types::FipsStatus {
        if cfg!(feature = "fips") {
            rustls_pki_types::FipsStatus::Pending
        } else {
            rustls_pki_types::FipsStatus::Unvalidated
        }
    }
}

struct BoringHmacKey {
    md: MessageDigest,
    key: Zeroizing<Vec<u8>>,
}

impl crypto::hmac::Key for BoringHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut hmac =
            boring::hmac::Hmac::init(&self.key, &self.md).expect("failed initializing hmac");

        hmac.update(first).expect("failed updating hmac");
        for m in middle {
            hmac.update(m).expect("failed updating hmac");
        }
        hmac.update(last).expect("failed updating hmac");

        let out = hmac.finalize().expect("failed finalizing hmac");
        crypto::hmac::Tag::new(&out)
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
