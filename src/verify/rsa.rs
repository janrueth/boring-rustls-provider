use boring::{
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    sign::RsaPssSaltlen,
};
use rustls::{crypto::SignatureScheme, pki_types::alg_id};
use rustls_pki_types::{InvalidSignature, SignatureVerificationAlgorithm};

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

            _ => return Err(InvalidSignature),
        }?;
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

            _ => unreachable!("BoringRsaVerifier only supports configured RSA schemes"),
        }
    }

    fn fips(&self) -> bool {
        cfg!(feature = "fips")
    }
}

fn rsa_verifier_from_params(
    key: &boring::pkey::PKeyRef<boring::pkey::Public>,
    digest: MessageDigest,
    padding: Padding,
) -> Result<boring::sign::Verifier<'_>, InvalidSignature> {
    let mut verifier = boring::sign::Verifier::new(digest, key)
        .map_err(|e| log_and_map("Verifier::new", e, InvalidSignature))?;
    verifier
        .set_rsa_padding(padding)
        .map_err(|e| log_and_map("set_rsa_padding", e, InvalidSignature))?;
    if padding == Padding::PKCS1_PSS {
        verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| log_and_map("set_rsa_pss_saltlen", e, InvalidSignature))?;
        verifier
            .set_rsa_mgf1_md(digest)
            .map_err(|e| log_and_map("set_rsa_mgf1_md", e, InvalidSignature))?;
    }

    Ok(verifier)
}

pub(crate) fn decode_spki_spk(
    spki_spk: &[u8],
) -> Result<PKey<boring::pkey::Public>, InvalidSignature> {
    // public_key: unfortunately this is not a whole SPKI, but just the key material.
    // decode the two integers manually.

    use spki::der::{Decode, Reader, SliceReader};

    let mut reader = SliceReader::new(spki_spk)
        .map_err(|e| log_and_map("SliceReader::new", e, InvalidSignature))?;
    let (n_ref, e_ref) = reader
        .sequence(|inner: &mut spki::der::SliceReader<'_>| {
            let n = spki::der::asn1::UintRef::decode(inner)?;
            let e = spki::der::asn1::UintRef::decode(inner)?;
            Ok((n, e))
        })
        .map_err(|e: spki::der::Error| log_and_map("sequence decode", e, InvalidSignature))?;

    let n = BigNum::from_slice(n_ref.as_bytes())
        .map_err(|e| log_and_map("BigNum::from_slice", e, InvalidSignature))?;
    let e = BigNum::from_slice(e_ref.as_bytes())
        .map_err(|e| log_and_map("BigNum::from_slice", e, InvalidSignature))?;

    PKey::from_rsa(
        Rsa::from_public_components(n, e)
            .map_err(|e| log_and_map("Rsa::from_public_components", e, InvalidSignature))?,
    )
    .map_err(|e| log_and_map("Pkey::from_rsa", e, InvalidSignature))
}
