use boring::{error::ErrorStack, hash::MessageDigest};
use rustls::SignatureScheme;
use rustls_pki_types::{InvalidSignature, SignatureVerificationAlgorithm};

pub struct BoringEcVerifier(SignatureScheme);

impl BoringEcVerifier {
    pub const ECDSA_NISTP256_SHA256: Self = Self(SignatureScheme::ECDSA_NISTP256_SHA256);
    pub const ECDSA_NISTP384_SHA384: Self = Self(SignatureScheme::ECDSA_NISTP384_SHA384);
    pub const ECDSA_NISTP521_SHA512: Self = Self(SignatureScheme::ECDSA_NISTP521_SHA512);
}

impl SignatureVerificationAlgorithm for BoringEcVerifier {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), rustls_pki_types::InvalidSignature> {
        let (group, mut bn_ctx) = setup_ec_key(self.0);
        let ec_point =
            ec_point(group.as_ref(), bn_ctx.as_mut(), public_key).map_err(|_| InvalidSignature)?;
        let public_key =
            ec_public_key(group.as_ref(), ec_point.as_ref()).map_err(|_| InvalidSignature)?;
        let mut verifier = match self.0 {
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                ec_verifier_from_params(public_key.as_ref(), MessageDigest::sha256())
            }
            SignatureScheme::ECDSA_NISTP384_SHA384 => {
                ec_verifier_from_params(public_key.as_ref(), MessageDigest::sha384())
            }
            SignatureScheme::ECDSA_NISTP521_SHA512 => {
                ec_verifier_from_params(public_key.as_ref(), MessageDigest::sha512())
            }

            _ => unimplemented!(),
        };
        verifier.verify_oneshot(signature, message).map_or_else(
            |_| Err(InvalidSignature),
            |res| if res { Ok(()) } else { Err(InvalidSignature) },
        )
    }

    fn public_key_alg_id(&self) -> rustls_pki_types::AlgorithmIdentifier {
        match self.0 {
            SignatureScheme::ECDSA_NISTP256_SHA256 => webpki::alg_id::ECDSA_P256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => webpki::alg_id::ECDSA_P384,
            SignatureScheme::ECDSA_NISTP521_SHA512 => {
                // See rfc5480 appendix-A (secp521r1): 1.3.132.0.35
                rustls_pki_types::AlgorithmIdentifier::from_slice(&[
                    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
                    0x04, 0x00, 0x23,
                ])
            }
            _ => unimplemented!(),
        }
    }

    fn signature_alg_id(&self) -> rustls_pki_types::AlgorithmIdentifier {
        match self.0 {
            SignatureScheme::ECDSA_NISTP256_SHA256 => webpki::alg_id::ECDSA_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => webpki::alg_id::ECDSA_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512 => {
                // See rfc5480 appendix-A (ecdsa-with-SHA512): 1.2.840.10045.4.3.4
                rustls_pki_types::AlgorithmIdentifier::from_slice(&[
                    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04,
                ])
            }
            _ => unimplemented!(),
        }
    }
}

fn ec_verifier_from_params(
    key: &boring::pkey::PKeyRef<boring::pkey::Public>,
    digest: MessageDigest,
) -> boring::sign::Verifier {
    let verifier =
        boring::sign::Verifier::new(digest.clone(), key).expect("failed getting verifier");

    verifier
}

fn group_for_scheme(scheme: SignatureScheme) -> boring::ec::EcGroup {
    let nid = match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => boring::nid::Nid::X9_62_PRIME256V1,
        SignatureScheme::ECDSA_NISTP384_SHA384 => boring::nid::Nid::SECP384R1,
        SignatureScheme::ECDSA_NISTP521_SHA512 => boring::nid::Nid::SECP521R1,
        _ => unimplemented!(),
    };
    boring::ec::EcGroup::from_curve_name(nid).expect("failed getting verify curve")
}

fn setup_ec_key(scheme: SignatureScheme) -> (boring::ec::EcGroup, boring::bn::BigNumContext) {
    (
        group_for_scheme(scheme),
        boring::bn::BigNumContext::new().unwrap(),
    )
}

pub(crate) fn ec_point(
    group: &boring::ec::EcGroupRef,
    bignum_ctx: &mut boring::bn::BigNumContextRef,
    spki_spk: &[u8],
) -> Result<boring::ec::EcPoint, ErrorStack> {
    boring::ec::EcPoint::from_bytes(group, spki_spk, bignum_ctx)
}

pub(crate) fn ec_public_key(
    group: &boring::ec::EcGroupRef,
    ec_point: &boring::ec::EcPointRef,
) -> Result<boring::pkey::PKey<boring::pkey::Public>, ErrorStack> {
    boring::pkey::PKey::from_ec_key(boring::ec::EcKey::from_public_key(group, ec_point)?)
}
