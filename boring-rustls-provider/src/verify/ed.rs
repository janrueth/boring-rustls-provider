use std::ptr;

use foreign_types::ForeignType;
use rustls::SignatureScheme;
use rustls_pki_types::{InvalidSignature, SignatureVerificationAlgorithm};

use crate::helper::cvt_p;

pub struct BoringEdVerifier(SignatureScheme);

impl BoringEdVerifier {
    pub const ED25519: Self = Self(SignatureScheme::ED25519);
    pub const ED448: Self = Self(SignatureScheme::ED448);
}

impl SignatureVerificationAlgorithm for BoringEdVerifier {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), rustls_pki_types::InvalidSignature> {
        let public_key = ed_public_key_for_scheme(public_key, self.0)?;
        let mut verifier = ed_verifier_from_params(public_key.as_ref());

        verifier.verify_oneshot(signature, message).map_or_else(
            |_| Err(InvalidSignature),
            |res| if res { Ok(()) } else { Err(InvalidSignature) },
        )
    }

    fn public_key_alg_id(&self) -> rustls_pki_types::AlgorithmIdentifier {
        // for ed those are the same
        self.signature_alg_id()
    }

    fn signature_alg_id(&self) -> rustls_pki_types::AlgorithmIdentifier {
        match self.0 {
            SignatureScheme::ED25519 => webpki::alg_id::ED25519,
            SignatureScheme::ED448 => {
                // rfc8410#section-3: 1.3.101.113: -> DER: 06 03 2B 65 71
                rustls_pki_types::AlgorithmIdentifier::from_slice(&[0x06, 0x03, 0x2B, 0x65, 0x71])
            }
            _ => unimplemented!(),
        }
    }
}

fn ed_verifier_from_params(
    key: &boring::pkey::PKeyRef<boring::pkey::Public>,
) -> boring::sign::Verifier {
    let verifier =
        boring::sign::Verifier::new_without_digest(key).expect("failed getting verifier");

    verifier
}

fn ed_public_key_for_scheme(
    spki_spk: &[u8],
    scheme: SignatureScheme,
) -> Result<boring::pkey::PKey<boring::pkey::Public>, InvalidSignature> {
    let nid = boring::nid::Nid::from_raw(match scheme {
        SignatureScheme::ED25519 => boring_sys::EVP_PKEY_ED25519,
        SignatureScheme::ED448 => boring_sys::EVP_PKEY_ED448,
        _ => unimplemented!(),
    });
    ed_public_key(spki_spk, nid)
}

pub fn ed_public_key(
    spki_spk: &[u8],
    nid: boring::nid::Nid,
) -> Result<boring::pkey::PKey<boring::pkey::Public>, InvalidSignature> {
    Ok(unsafe {
        let pkey = cvt_p(boring_sys::EVP_PKEY_new_raw_public_key(
            nid.as_raw(),
            ptr::null_mut(),
            spki_spk.as_ptr(),
            spki_spk.len(),
        ))
        .map_err(|_| InvalidSignature)?;

        boring::pkey::PKey::from_ptr(pkey)
    })
}
