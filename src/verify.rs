use rustls::crypto::{SignatureScheme, WebPkiSupportedAlgorithms};
use rustls_pki_types::SignatureVerificationAlgorithm;

pub(crate) mod ec;
pub(crate) mod ed;
pub(crate) mod rsa;

const fn supported_algorithms(
    all: &'static [&'static dyn SignatureVerificationAlgorithm],
    mapping: &'static [(
        SignatureScheme,
        &'static [&'static dyn SignatureVerificationAlgorithm],
    )],
) -> WebPkiSupportedAlgorithms {
    match WebPkiSupportedAlgorithms::new(all, mapping) {
        Ok(algorithms) => algorithms,
        Err(_) => panic!("static signature algorithm mappings must be valid"),
    }
}

/// All supported signature verification algorithms.
///
/// Includes RSA (PKCS#1 v1.5 and PSS), ECDSA (P-256, P-384, P-521),
/// Ed25519, and Ed448.
///
/// For the FIPS-restricted subset see [`ALL_FIPS_ALGORITHMS`].
#[allow(unused)]
pub static ALL_ALGORITHMS: WebPkiSupportedAlgorithms = supported_algorithms(
    &[
        &rsa::BoringRsaVerifier::RSA_PKCS1_SHA256,
        &rsa::BoringRsaVerifier::RSA_PKCS1_SHA384,
        &rsa::BoringRsaVerifier::RSA_PKCS1_SHA512,
        &rsa::BoringRsaVerifier::RSA_PSS_SHA256,
        &rsa::BoringRsaVerifier::RSA_PSS_SHA384,
        &rsa::BoringRsaVerifier::RSA_PSS_SHA512,
        &ec::BoringEcVerifier::ECDSA_NISTP256_SHA256,
        &ec::BoringEcVerifier::ECDSA_NISTP384_SHA384,
        &ec::BoringEcVerifier::ECDSA_NISTP521_SHA512,
        &ed::BoringEdVerifier::ED25519,
        &ed::BoringEdVerifier::ED448,
    ],
    &[
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[&rsa::BoringRsaVerifier::RSA_PKCS1_SHA256],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[&rsa::BoringRsaVerifier::RSA_PKCS1_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[&rsa::BoringRsaVerifier::RSA_PKCS1_SHA512],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[&rsa::BoringRsaVerifier::RSA_PSS_SHA256],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[&rsa::BoringRsaVerifier::RSA_PSS_SHA384],
        ),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[&rsa::BoringRsaVerifier::RSA_PSS_SHA512],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[&ec::BoringEcVerifier::ECDSA_NISTP256_SHA256],
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[&ec::BoringEcVerifier::ECDSA_NISTP384_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP521_SHA512,
            &[&ec::BoringEcVerifier::ECDSA_NISTP521_SHA512],
        ),
        (SignatureScheme::ED25519, &[&ed::BoringEdVerifier::ED25519]),
        (SignatureScheme::ED448, &[&ed::BoringEdVerifier::ED448]),
    ],
);

/// FIPS-approved signature verification algorithms per SP 800-52r2.
///
/// Aligned with boring's `fips202205` compliance policy:
///   - RSA: PKCS#1 v1.5 and PSS with SHA-256/384/512
///   - ECDSA: P-256 with SHA-256 and P-384 with SHA-384 only
///     (SP 800-52r2 Table 4.1: "The curve should be P-256 or P-384")
///   - No P-521, Ed25519, or Ed448
#[allow(unused)]
pub static ALL_FIPS_ALGORITHMS: WebPkiSupportedAlgorithms = supported_algorithms(
    &[
        &rsa::BoringRsaVerifier::RSA_PKCS1_SHA256,
        &rsa::BoringRsaVerifier::RSA_PKCS1_SHA384,
        &rsa::BoringRsaVerifier::RSA_PKCS1_SHA512,
        &rsa::BoringRsaVerifier::RSA_PSS_SHA256,
        &rsa::BoringRsaVerifier::RSA_PSS_SHA384,
        &rsa::BoringRsaVerifier::RSA_PSS_SHA512,
        &ec::BoringEcVerifier::ECDSA_NISTP256_SHA256,
        &ec::BoringEcVerifier::ECDSA_NISTP384_SHA384,
    ],
    &[
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[&rsa::BoringRsaVerifier::RSA_PKCS1_SHA256],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[&rsa::BoringRsaVerifier::RSA_PKCS1_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[&rsa::BoringRsaVerifier::RSA_PKCS1_SHA512],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[&rsa::BoringRsaVerifier::RSA_PSS_SHA256],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[&rsa::BoringRsaVerifier::RSA_PSS_SHA384],
        ),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[&rsa::BoringRsaVerifier::RSA_PSS_SHA512],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[&ec::BoringEcVerifier::ECDSA_NISTP256_SHA256],
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[&ec::BoringEcVerifier::ECDSA_NISTP384_SHA384],
        ),
    ],
);
