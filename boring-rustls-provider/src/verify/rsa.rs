use boring::{
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    sign::RsaPssSaltlen,
};
use rustls::{pki_types::alg_id, SignatureScheme};
use rustls_pki_types::{InvalidSignature, SignatureVerificationAlgorithm};
use spki::der::Reader;

use crate::helper::log_and_map;

#[derive(Debug)]
pub struct BoringRsaVerifier(SignatureScheme);

impl BoringRsaVerifier {
    pub const RSA_PKCS1_SHA256: Self = Self(SignatureScheme::RSA_PKCS1_SHA256);
    pub const RSA_PKCS1_SHA384: Self = Self(SignatureScheme::RSA_PKCS1_SHA384);
    pub const RSA_PKCS1_SHA512: Self = Self(SignatureScheme::RSA_PKCS1_SHA512);
    pub const RSA_PSS_SHA256: Self = Self(SignatureScheme::RSA_PSS_SHA256);
    pub const RSA_PSS_SHA384: Self = Self(SignatureScheme::RSA_PSS_SHA384);
    pub const RSA_PSS_SHA512: Self = Self(SignatureScheme::RSA_PSS_SHA512);
}

impl SignatureVerificationAlgorithm for BoringRsaVerifier {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), rustls_pki_types::InvalidSignature> {
        let public_key = decode_spki_spk(public_key)?;
        let mut verifier = match self.0 {
            SignatureScheme::RSA_PKCS1_SHA256 => rsa_verifier_from_params(
                public_key.as_ref(),
                MessageDigest::sha256(),
                Padding::PKCS1,
            ),
            SignatureScheme::RSA_PKCS1_SHA384 => rsa_verifier_from_params(
                public_key.as_ref(),
                MessageDigest::sha384(),
                Padding::PKCS1,
            ),
            SignatureScheme::RSA_PKCS1_SHA512 => rsa_verifier_from_params(
                public_key.as_ref(),
                MessageDigest::sha512(),
                Padding::PKCS1,
            ),

            SignatureScheme::RSA_PSS_SHA256 => rsa_verifier_from_params(
                public_key.as_ref(),
                MessageDigest::sha256(),
                Padding::PKCS1_PSS,
            ),
            SignatureScheme::RSA_PSS_SHA384 => rsa_verifier_from_params(
                public_key.as_ref(),
                MessageDigest::sha384(),
                Padding::PKCS1_PSS,
            ),
            SignatureScheme::RSA_PSS_SHA512 => rsa_verifier_from_params(
                public_key.as_ref(),
                MessageDigest::sha512(),
                Padding::PKCS1_PSS,
            ),

            _ => unimplemented!(),
        };
        verifier.verify_oneshot(signature, message).map_or_else(
            |_| Err(InvalidSignature),
            |res| if res { Ok(()) } else { Err(InvalidSignature) },
        )
    }

    fn public_key_alg_id(&self) -> rustls_pki_types::AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> rustls_pki_types::AlgorithmIdentifier {
        match self.0 {
            SignatureScheme::RSA_PKCS1_SHA256 => alg_id::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => alg_id::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => alg_id::RSA_PKCS1_SHA512,

            SignatureScheme::RSA_PSS_SHA256 => alg_id::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => alg_id::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => alg_id::RSA_PSS_SHA512,

            _ => unimplemented!(),
        }
    }
}

fn rsa_verifier_from_params(
    key: &boring::pkey::PKeyRef<boring::pkey::Public>,
    digest: MessageDigest,
    padding: Padding,
) -> boring::sign::Verifier<'_> {
    let mut verifier = boring::sign::Verifier::new(digest, key).expect("failed getting verifier");
    verifier
        .set_rsa_padding(padding)
        .expect("failed setting padding");
    if padding == Padding::PKCS1_PSS {
        verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .expect("failed setting rsa_pss salt lengths");
        verifier
            .set_rsa_mgf1_md(digest)
            .expect("failed setting mgf1 digest");
    }

    verifier
}

pub(crate) fn decode_spki_spk(
    spki_spk: &[u8],
) -> Result<PKey<boring::pkey::Public>, InvalidSignature> {
    // public_key: unfortunately this is not a whole SPKI, but just the key material.
    // decode the two integers manually.

    let mut reader = spki::der::SliceReader::new(spki_spk)
        .map_err(|e| log_and_map("SliceReader::new", e, InvalidSignature))?;
    let ne: [spki::der::asn1::UintRef; 2] = reader
        .decode()
        .map_err(|e| log_and_map("SliceReader::decode", e, InvalidSignature))?;

    let n = BigNum::from_slice(ne[0].as_bytes())
        .map_err(|e| log_and_map("BigNum::from_slice", e, InvalidSignature))?;
    let e = BigNum::from_slice(ne[1].as_bytes())
        .map_err(|e| log_and_map("BigNum::from_slice", e, InvalidSignature))?;

    PKey::from_rsa(
        Rsa::from_public_components(n, e)
            .map_err(|e| log_and_map("Rsa::from_public_components", e, InvalidSignature))?,
    )
    .map_err(|e| log_and_map("Pkey::from_rsa", e, InvalidSignature))
}
