use rustls::{SignatureScheme, crypto::WebPkiSupportedAlgorithms};

pub(crate) mod ec;
pub(crate) mod ed;
#[cfg(feature = "mldsa")]
pub(crate) mod mldsa;
pub(crate) mod rsa;

/// All supported signature verification algorithms.
///
/// Includes ML-DSA when enabled, RSA (PKCS#1 v1.5 and PSS), ECDSA
/// (P-256, P-384, P-521), Ed25519, and Ed448.
///
/// For the FIPS-restricted subset see [`ALL_FIPS_ALGORITHMS`].
#[allow(unused)]
pub static ALL_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        #[cfg(feature = "mldsa")]
        &mldsa::BoringMlDsaVerifier::ML_DSA_44,
        #[cfg(feature = "mldsa")]
        &mldsa::BoringMlDsaVerifier::ML_DSA_65,
        #[cfg(feature = "mldsa")]
        &mldsa::BoringMlDsaVerifier::ML_DSA_87,
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
    mapping: &[
        #[cfg(feature = "mldsa")]
        (
            SignatureScheme::ML_DSA_44,
            &[&mldsa::BoringMlDsaVerifier::ML_DSA_44],
        ),
        #[cfg(feature = "mldsa")]
        (
            SignatureScheme::ML_DSA_65,
            &[&mldsa::BoringMlDsaVerifier::ML_DSA_65],
        ),
        #[cfg(feature = "mldsa")]
        (
            SignatureScheme::ML_DSA_87,
            &[&mldsa::BoringMlDsaVerifier::ML_DSA_87],
        ),
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
};

/// Signature verification algorithms exposed by the FIPS configuration.
///
/// The classical subset follows SP 800-52r2. ML-DSA implements FIPS 204, but
/// algorithm support does not by itself establish cryptographic-module or
/// application compliance:
///   - ML-DSA: ML-DSA-44, ML-DSA-65, and ML-DSA-87 (FIPS 204)
///   - RSA: PKCS#1 v1.5 and PSS with SHA-256/384/512
///   - ECDSA: P-256 with SHA-256 and P-384 with SHA-384 only
///     (SP 800-52r2 Table 4.1: "The curve should be P-256 or P-384")
///   - No P-521, Ed25519, or Ed448
#[allow(unused)]
pub static ALL_FIPS_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        #[cfg(feature = "mldsa")]
        &mldsa::BoringMlDsaVerifier::ML_DSA_44,
        #[cfg(feature = "mldsa")]
        &mldsa::BoringMlDsaVerifier::ML_DSA_65,
        #[cfg(feature = "mldsa")]
        &mldsa::BoringMlDsaVerifier::ML_DSA_87,
        &rsa::BoringRsaVerifier::RSA_PKCS1_SHA256,
        &rsa::BoringRsaVerifier::RSA_PKCS1_SHA384,
        &rsa::BoringRsaVerifier::RSA_PKCS1_SHA512,
        &rsa::BoringRsaVerifier::RSA_PSS_SHA256,
        &rsa::BoringRsaVerifier::RSA_PSS_SHA384,
        &rsa::BoringRsaVerifier::RSA_PSS_SHA512,
        &ec::BoringEcVerifier::ECDSA_NISTP256_SHA256,
        &ec::BoringEcVerifier::ECDSA_NISTP384_SHA384,
    ],
    mapping: &[
        #[cfg(feature = "mldsa")]
        (
            SignatureScheme::ML_DSA_44,
            &[&mldsa::BoringMlDsaVerifier::ML_DSA_44],
        ),
        #[cfg(feature = "mldsa")]
        (
            SignatureScheme::ML_DSA_65,
            &[&mldsa::BoringMlDsaVerifier::ML_DSA_65],
        ),
        #[cfg(feature = "mldsa")]
        (
            SignatureScheme::ML_DSA_87,
            &[&mldsa::BoringMlDsaVerifier::ML_DSA_87],
        ),
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
};
