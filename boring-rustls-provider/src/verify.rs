use rustls::{SignatureScheme, WebPkiSupportedAlgorithms};

pub(crate) mod ec;
mod ed;
pub(crate) mod rsa;

#[allow(unused)]
pub static ALL_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
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

#[allow(unused)]
pub static ALL_FIPS_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        &rsa::BoringRsaVerifier::RSA_PKCS1_SHA256,
        &rsa::BoringRsaVerifier::RSA_PKCS1_SHA384,
        &rsa::BoringRsaVerifier::RSA_PKCS1_SHA512,
        &rsa::BoringRsaVerifier::RSA_PSS_SHA256,
        &rsa::BoringRsaVerifier::RSA_PSS_SHA384,
        &rsa::BoringRsaVerifier::RSA_PSS_SHA512,
        &ec::BoringEcVerifier::ECDSA_NISTP256_SHA256,
        &ec::BoringEcVerifier::ECDSA_NISTP384_SHA384,
        &ec::BoringEcVerifier::ECDSA_NISTP521_SHA512,
        //&ed::BoringEdVerifier::ED25519, // FIPS 186-5: requires SHA512 but boring doesn't want us to set a digest, correct?
        //&ed::BoringEdVerifier::ED448, // FIPS 186-5: requires SHAKE256 but boring doesn't want us to set a digest, correct?
    ],
    mapping: &[
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
        // (SignatureScheme::ED25519, &[&ed::BoringEdVerifier::ED25519]),
        // (SignatureScheme::ED448, &[&ed::BoringEdVerifier::ED448]),
    ],
};
