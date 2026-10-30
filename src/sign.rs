use std::sync::Arc;

#[cfg(feature = "mldsa")]
use boring::mldsa::{Algorithm as MlDsaAlgorithm, MlDsaPrivateKey, MlDsaPrivateKeySeed};
use boring::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKeyRef, Private},
    rsa::Padding,
    sign::{RsaPssSaltlen, Signer},
};
use rustls::crypto::{SignatureScheme, SigningKey};
#[cfg(feature = "mldsa")]
use rustls::{crypto::public_key_to_spki, pki_types::alg_id};
use rustls_pki_types::PrivateKeyDer;

use crate::helper::log_and_map;

const ALL_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

const EC_P256_SCHEMES: &[SignatureScheme] = &[SignatureScheme::ECDSA_NISTP256_SHA256];
const EC_P384_SCHEMES: &[SignatureScheme] = &[SignatureScheme::ECDSA_NISTP384_SHA384];
const EC_P521_SCHEMES: &[SignatureScheme] = &[SignatureScheme::ECDSA_NISTP521_SHA512];

#[cfg(feature = "mldsa")]
const ML_DSA_PKCS8_PREFIX: &[u8] = &[
    0x30, 0x34, // OneAsymmetricKey SEQUENCE
    0x02, 0x01, 0x00, // version v1
    0x30, 0x0b, // AlgorithmIdentifier SEQUENCE
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
];
#[cfg(feature = "mldsa")]
const ML_DSA_PKCS8_SUFFIX: &[u8] = &[
    0x04, 0x22, // privateKey OCTET STRING
    0x80, 0x20, // seed [0] IMPLICIT OCTET STRING (SIZE (32))
];
#[cfg(feature = "mldsa")]
const ML_DSA_44_OID_FINAL_OCTET: u8 = 0x11;
#[cfg(feature = "mldsa")]
const ML_DSA_65_OID_FINAL_OCTET: u8 = 0x12;
#[cfg(feature = "mldsa")]
const ML_DSA_87_OID_FINAL_OCTET: u8 = 0x13;

#[derive(Debug, Clone, Copy)]
enum EcCurve {
    P256,
    P384,
    P521,
}

#[derive(Debug, Clone, Copy)]
enum KeyKind {
    Rsa,
    Ec(EcCurve),
    Ed25519,
    Ed448,
    #[cfg(feature = "mldsa")]
    MlDsa(MlDsaAlgorithm),
}

#[derive(Debug)]
enum PrivateKey {
    Classical(Arc<boring::pkey::PKey<Private>>),
    #[cfg(feature = "mldsa")]
    MlDsa(Arc<MlDsaPrivateKey>),
}

/// An abstraction over a boringssl private key used for signing.
#[derive(Debug)]
pub struct BoringPrivateKey(PrivateKey, KeyKind);

#[cfg(feature = "mldsa")]
fn mldsa_private_key_from_pkcs8(der: &[u8]) -> Result<MlDsaPrivateKey, rustls::Error> {
    let expected_len = ML_DSA_PKCS8_PREFIX.len()
        + 1
        + ML_DSA_PKCS8_SUFFIX.len()
        + boring::mldsa::PRIVATE_KEY_SEED_BYTES;
    if der.len() != expected_len
        || !der.starts_with(ML_DSA_PKCS8_PREFIX)
        || der[ML_DSA_PKCS8_PREFIX.len() + 1..].get(..ML_DSA_PKCS8_SUFFIX.len())
            != Some(ML_DSA_PKCS8_SUFFIX)
    {
        return Err(rustls::Error::General(
            "invalid ML-DSA seed-only PKCS#8 private key".into(),
        ));
    }

    let algorithm = match der[ML_DSA_PKCS8_PREFIX.len()] {
        ML_DSA_44_OID_FINAL_OCTET => MlDsaAlgorithm::MlDsa44,
        ML_DSA_65_OID_FINAL_OCTET => MlDsaAlgorithm::MlDsa65,
        ML_DSA_87_OID_FINAL_OCTET => MlDsaAlgorithm::MlDsa87,
        _ => {
            return Err(rustls::Error::General(
                "unsupported ML-DSA private key algorithm".into(),
            ));
        }
    };
    let seed_offset = ML_DSA_PKCS8_PREFIX.len() + 1 + ML_DSA_PKCS8_SUFFIX.len();
    let seed: MlDsaPrivateKeySeed = der[seed_offset..]
        .try_into()
        .map_err(|_| rustls::Error::General("invalid ML-DSA private key seed".into()))?;

    MlDsaPrivateKey::from_seed(algorithm, &seed).map_err(|e| {
        log_and_map(
            "MlDsaPrivateKey::from_seed",
            e,
            rustls::Error::General("failed loading ML-DSA private key".into()),
        )
    })
}

impl TryFrom<PrivateKeyDer<'static>> for BoringPrivateKey {
    type Error = rustls::Error;

    fn try_from(value: PrivateKeyDer<'static>) -> Result<Self, Self::Error> {
        #[cfg(feature = "mldsa")]
        if let PrivateKeyDer::Pkcs8(der) = &value {
            let bytes = der.secret_pkcs8_der();
            if bytes.starts_with(ML_DSA_PKCS8_PREFIX) {
                let key = mldsa_private_key_from_pkcs8(bytes)?;
                let kind = KeyKind::MlDsa(key.algorithm());
                return Ok(Self(PrivateKey::MlDsa(Arc::new(key)), kind));
            }
        }

        let pkey = match value {
            PrivateKeyDer::Pkcs8(der) => {
                boring::pkey::PKey::private_key_from_pkcs8(der.secret_pkcs8_der()).map_err(|e| {
                    log_and_map(
                        "private_key_from_pkcs8",
                        e,
                        rustls::Error::General("failed loading private key".into()),
                    )
                })
            }
            PrivateKeyDer::Pkcs1(der) => {
                boring::pkey::PKey::private_key_from_der(der.secret_pkcs1_der()).map_err(|e| {
                    log_and_map(
                        "private_key_from_der_pkcs1",
                        e,
                        rustls::Error::General("failed loading private key".into()),
                    )
                })
            }
            PrivateKeyDer::Sec1(der) => {
                boring::pkey::PKey::private_key_from_der(der.secret_sec1_der()).map_err(|e| {
                    log_and_map(
                        "private_key_from_der_sec1",
                        e,
                        rustls::Error::General("failed loading private key".into()),
                    )
                })
            }
            _ => {
                return Err(rustls::Error::General(
                    "unsupported private key encoding".into(),
                ));
            }
        }?;

        let kind = match pkey.id() {
            Id::RSA => KeyKind::Rsa,
            Id::EC => {
                let ec_key = pkey.ec_key().map_err(|e| {
                    log_and_map(
                        "ec_key",
                        e,
                        rustls::Error::General("failed loading EC private key".into()),
                    )
                })?;

                let curve_nid = ec_key.group().curve_name().ok_or_else(|| {
                    rustls::Error::General("unsupported EC key without named curve".into())
                })?;

                let curve = match curve_nid {
                    Nid::X9_62_PRIME256V1 => EcCurve::P256,
                    Nid::SECP384R1 => EcCurve::P384,
                    Nid::SECP521R1 => EcCurve::P521,
                    _ => {
                        return Err(rustls::Error::General(
                            "unsupported EC private key curve".into(),
                        ));
                    }
                };

                KeyKind::Ec(curve)
            }
            Id::ED25519 => KeyKind::Ed25519,
            Id::ED448 => KeyKind::Ed448,
            _ => return Err(rustls::Error::General("unsupported key format".into())),
        };

        #[cfg(feature = "fips")]
        match kind {
            KeyKind::Rsa => {
                let rsa = pkey.rsa().map_err(|e| {
                    log_and_map(
                        "rsa",
                        e,
                        rustls::Error::General("failed inspecting RSA private key".into()),
                    )
                })?;
                let rsa_bits = rsa.n().num_bits();
                if rsa_bits < 2048 {
                    return Err(rustls::Error::General(format!(
                        "RSA key too small for FIPS mode ({rsa_bits}-bit, minimum 2048)"
                    )));
                }
            }
            KeyKind::Ec(EcCurve::P256 | EcCurve::P384) => {}
            KeyKind::Ec(EcCurve::P521) | KeyKind::Ed25519 | KeyKind::Ed448 => {
                return Err(rustls::Error::General(
                    "key type is not allowed in FIPS mode".into(),
                ));
            }
            #[cfg(feature = "mldsa")]
            KeyKind::MlDsa(_) => {}
        }

        Ok(Self(PrivateKey::Classical(Arc::new(pkey)), kind))
    }
}

fn rsa_signer_from_params(
    key: &PKeyRef<Private>,
    digest: MessageDigest,
    padding: Padding,
) -> Result<Signer<'_>, rustls::Error> {
    let mut signer = Signer::new(digest, key).map_err(|e| {
        log_and_map(
            "Signer::new",
            e,
            rustls::Error::General("failed preparing signer".into()),
        )
    })?;

    signer.set_rsa_padding(padding).map_err(|e| {
        log_and_map(
            "set_rsa_padding",
            e,
            rustls::Error::General("failed preparing signer".into()),
        )
    })?;

    if padding == Padding::PKCS1_PSS {
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| {
                log_and_map(
                    "set_rsa_pss_saltlen",
                    e,
                    rustls::Error::General("failed preparing signer".into()),
                )
            })?;

        signer.set_rsa_mgf1_md(digest).map_err(|e| {
            log_and_map(
                "set_rsa_mgf1_md",
                e,
                rustls::Error::General("failed preparing signer".into()),
            )
        })?;
    }

    Ok(signer)
}

fn ec_signer_from_params(
    key: &PKeyRef<Private>,
    digest: MessageDigest,
) -> Result<Signer<'_>, rustls::Error> {
    Signer::new(digest, key).map_err(|e| {
        log_and_map(
            "Signer::new",
            e,
            rustls::Error::General("failed preparing signer".into()),
        )
    })
}

impl SigningKey for BoringPrivateKey {
    fn choose_scheme(
        &self,
        offered: &[SignatureScheme],
    ) -> Option<Box<dyn rustls::crypto::Signer>> {
        let scheme = match self.1 {
            KeyKind::Rsa => ALL_RSA_SCHEMES
                .iter()
                .find(|scheme| offered.contains(scheme))
                .copied(),
            KeyKind::Ec(EcCurve::P256) => EC_P256_SCHEMES
                .iter()
                .find(|scheme| offered.contains(scheme))
                .copied(),
            KeyKind::Ec(EcCurve::P384) => EC_P384_SCHEMES
                .iter()
                .find(|scheme| offered.contains(scheme))
                .copied(),
            KeyKind::Ec(EcCurve::P521) => EC_P521_SCHEMES
                .iter()
                .find(|scheme| offered.contains(scheme))
                .copied(),
            KeyKind::Ed25519 if offered.contains(&SignatureScheme::ED25519) => {
                Some(SignatureScheme::ED25519)
            }
            KeyKind::Ed448 if offered.contains(&SignatureScheme::ED448) => {
                Some(SignatureScheme::ED448)
            }
            #[cfg(feature = "mldsa")]
            KeyKind::MlDsa(algorithm) => {
                let scheme = mldsa_scheme(algorithm);
                offered.contains(&scheme).then_some(scheme)
            }
            _ => None,
        }?;

        match (&self.0, scheme) {
            (PrivateKey::Classical(key), scheme) => {
                Some(Box::new(BoringSigner(key.clone(), scheme)))
            }
            #[cfg(feature = "mldsa")]
            (PrivateKey::MlDsa(key), scheme) => Some(Box::new(MlDsaSigner(key.clone(), scheme))),
        }
    }

    fn public_key(&self) -> Option<rustls_pki_types::SubjectPublicKeyInfoDer<'_>> {
        match &self.0 {
            PrivateKey::Classical(key) => Some(rustls_pki_types::SubjectPublicKeyInfoDer::from(
                key.public_key_to_der().ok()?,
            )),
            #[cfg(feature = "mldsa")]
            PrivateKey::MlDsa(key) => {
                let public_key = key.public_key().ok()?.to_bytes().ok()?;
                let algorithm_identifier = match key.algorithm() {
                    MlDsaAlgorithm::MlDsa44 => alg_id::ML_DSA_44,
                    MlDsaAlgorithm::MlDsa65 => alg_id::ML_DSA_65,
                    MlDsaAlgorithm::MlDsa87 => alg_id::ML_DSA_87,
                };
                Some(public_key_to_spki(&algorithm_identifier, public_key))
            }
        }
    }
}

#[cfg(feature = "mldsa")]
fn mldsa_scheme(algorithm: MlDsaAlgorithm) -> SignatureScheme {
    match algorithm {
        MlDsaAlgorithm::MlDsa44 => SignatureScheme::ML_DSA_44,
        MlDsaAlgorithm::MlDsa65 => SignatureScheme::ML_DSA_65,
        MlDsaAlgorithm::MlDsa87 => SignatureScheme::ML_DSA_87,
    }
}

#[cfg(feature = "mldsa")]
#[derive(Debug)]
struct MlDsaSigner(Arc<MlDsaPrivateKey>, SignatureScheme);

#[cfg(feature = "mldsa")]
impl rustls::crypto::Signer for MlDsaSigner {
    fn sign(self: Box<Self>, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.0.sign(message).map_err(|e| {
            log_and_map(
                "MlDsaPrivateKey::sign",
                e,
                rustls::Error::General("failed signing with ML-DSA private key".into()),
            )
        })
    }

    fn scheme(&self) -> SignatureScheme {
        self.1
    }
}

/// A boringssl-based Signer.
#[derive(Debug)]
pub struct BoringSigner(Arc<boring::pkey::PKey<Private>>, SignatureScheme);

impl BoringSigner {
    fn get_signer(&self) -> Result<Signer<'_>, rustls::Error> {
        match self.1 {
            SignatureScheme::RSA_PKCS1_SHA256 => {
                rsa_signer_from_params(self.0.as_ref(), MessageDigest::sha256(), Padding::PKCS1)
            }
            SignatureScheme::RSA_PKCS1_SHA384 => {
                rsa_signer_from_params(self.0.as_ref(), MessageDigest::sha384(), Padding::PKCS1)
            }
            SignatureScheme::RSA_PKCS1_SHA512 => {
                rsa_signer_from_params(self.0.as_ref(), MessageDigest::sha512(), Padding::PKCS1)
            }
            SignatureScheme::RSA_PSS_SHA256 => {
                rsa_signer_from_params(self.0.as_ref(), MessageDigest::sha256(), Padding::PKCS1_PSS)
            }
            SignatureScheme::RSA_PSS_SHA384 => {
                rsa_signer_from_params(self.0.as_ref(), MessageDigest::sha384(), Padding::PKCS1_PSS)
            }
            SignatureScheme::RSA_PSS_SHA512 => {
                rsa_signer_from_params(self.0.as_ref(), MessageDigest::sha512(), Padding::PKCS1_PSS)
            }
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                ec_signer_from_params(self.0.as_ref(), MessageDigest::sha256())
            }
            SignatureScheme::ECDSA_NISTP384_SHA384 => {
                ec_signer_from_params(self.0.as_ref(), MessageDigest::sha384())
            }
            SignatureScheme::ECDSA_NISTP521_SHA512 => {
                ec_signer_from_params(self.0.as_ref(), MessageDigest::sha512())
            }
            SignatureScheme::ED25519 | SignatureScheme::ED448 => {
                Signer::new_without_digest(self.0.as_ref()).map_err(|e| {
                    log_and_map(
                        "Signer::new_without_digest",
                        e,
                        rustls::Error::General("failed preparing signer".into()),
                    )
                })
            }
            _ => Err(rustls::Error::General(
                "unsupported signature scheme for private key".into(),
            )),
        }
    }
}

impl rustls::crypto::Signer for BoringSigner {
    fn sign(self: Box<Self>, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut signer = self.get_signer()?;
        let max_sig_len = signer
            .len()
            .map_err(|e| log_and_map("len", e, rustls::Error::General("failed signing".into())))?;
        let mut sig = vec![0u8; max_sig_len];

        let sig_len = signer.sign_oneshot(&mut sig[..], message).map_err(|e| {
            log_and_map(
                "sign_oneshot",
                e,
                rustls::Error::General("failed signing".into()),
            )
        })?;
        sig.truncate(sig_len);
        Ok(sig)
    }

    fn scheme(&self) -> SignatureScheme {
        self.1
    }
}

#[cfg(test)]
mod tests {
    use boring::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::{PKey, Private},
        rsa::Rsa,
    };
    use rustls::crypto::{SignatureScheme, SigningKey};
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

    #[cfg(feature = "mldsa")]
    use boring::mldsa::{Algorithm as MlDsaAlgorithm, MlDsaPrivateKey};
    #[cfg(feature = "mldsa")]
    use rustls_pki_types::SignatureVerificationAlgorithm;

    use super::BoringPrivateKey;
    #[cfg(feature = "mldsa")]
    use super::{
        ML_DSA_44_OID_FINAL_OCTET, ML_DSA_65_OID_FINAL_OCTET, ML_DSA_87_OID_FINAL_OCTET,
        ML_DSA_PKCS8_PREFIX, ML_DSA_PKCS8_SUFFIX,
    };

    fn p256_private_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        PKey::from_ec_key(ec_key).unwrap()
    }

    #[cfg(feature = "mldsa")]
    fn mldsa_pkcs8(algorithm: MlDsaAlgorithm, seed: &[u8; 32]) -> Vec<u8> {
        let oid_last = match algorithm {
            MlDsaAlgorithm::MlDsa44 => ML_DSA_44_OID_FINAL_OCTET,
            MlDsaAlgorithm::MlDsa65 => ML_DSA_65_OID_FINAL_OCTET,
            MlDsaAlgorithm::MlDsa87 => ML_DSA_87_OID_FINAL_OCTET,
        };
        let mut der = ML_DSA_PKCS8_PREFIX.to_vec();
        der.push(oid_last);
        der.extend_from_slice(ML_DSA_PKCS8_SUFFIX);
        der.extend_from_slice(seed);
        der
    }

    #[cfg(feature = "mldsa")]
    fn mldsa44_expanded_pkcs8() -> Vec<u8> {
        let mut der = vec![
            0x30, 0x82, 0x0a, 0x18, // OneAsymmetricKey SEQUENCE (2584 bytes)
            0x02, 0x01, 0x00, // version v1
            0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11, 0x04,
            0x82, 0x0a, 0x04, // privateKey OCTET STRING (2564 bytes)
            0x04, 0x82, 0x0a, 0x00, // expandedKey OCTET STRING (2560 bytes)
        ];
        der.resize(2588, 0);
        der
    }

    #[cfg(feature = "mldsa")]
    #[test]
    fn mldsa_keys_sign_with_all_parameter_sets() {
        use crate::verify::mldsa::BoringMlDsaVerifier;

        for (algorithm, scheme, verifier) in [
            (
                MlDsaAlgorithm::MlDsa44,
                SignatureScheme::ML_DSA_44,
                &BoringMlDsaVerifier::ML_DSA_44,
            ),
            (
                MlDsaAlgorithm::MlDsa65,
                SignatureScheme::ML_DSA_65,
                &BoringMlDsaVerifier::ML_DSA_65,
            ),
            (
                MlDsaAlgorithm::MlDsa87,
                SignatureScheme::ML_DSA_87,
                &BoringMlDsaVerifier::ML_DSA_87,
            ),
        ] {
            let seed_byte = match algorithm {
                MlDsaAlgorithm::MlDsa44 => 44,
                MlDsaAlgorithm::MlDsa65 => 65,
                MlDsaAlgorithm::MlDsa87 => 87,
            };
            let seed = [seed_byte; 32];
            let der = mldsa_pkcs8(algorithm, &seed);
            let key =
                BoringPrivateKey::try_from(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
                    .unwrap();
            let signer = key.choose_scheme(&[scheme]).unwrap();
            let message = b"complete TLS 1.3 CertificateVerify input";
            assert_eq!(signer.scheme(), scheme);
            let signature = signer.sign(message).unwrap();
            let private_key = MlDsaPrivateKey::from_seed(algorithm, &seed).unwrap();
            let public_key = private_key.public_key().unwrap().to_bytes().unwrap();

            verifier
                .verify_signature(&public_key, message, &signature)
                .unwrap();
        }
    }

    #[cfg(feature = "mldsa")]
    #[test]
    fn mldsa_key_selects_only_its_parameter_set() {
        let der = mldsa_pkcs8(MlDsaAlgorithm::MlDsa65, &[7; 32]);
        let key = BoringPrivateKey::try_from(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
            .unwrap();

        assert!(key.choose_scheme(&[SignatureScheme::ML_DSA_44]).is_none());
        assert_eq!(
            key.choose_scheme(&[SignatureScheme::ML_DSA_87, SignatureScheme::ML_DSA_65,])
                .unwrap()
                .scheme(),
            SignatureScheme::ML_DSA_65
        );
    }

    #[cfg(feature = "mldsa")]
    #[test]
    fn rejects_non_seed_only_mldsa_pkcs8() {
        let valid = mldsa_pkcs8(MlDsaAlgorithm::MlDsa44, &[9; 32]);
        let seed_tag_offset = ML_DSA_PKCS8_PREFIX.len() + 1 + 2;
        let cases = [
            {
                let mut der = valid.clone();
                der[seed_tag_offset] = 0x04;
                der
            },
            {
                let mut der = valid.clone();
                der.push(0);
                der
            },
            {
                let mut der = valid.clone();
                der[4] = 1;
                der
            },
            {
                let mut der = valid.clone();
                der[ML_DSA_PKCS8_PREFIX.len()] = 0x14;
                der
            },
            mldsa44_expanded_pkcs8(),
            valid[..valid.len() - 1].to_vec(),
        ];

        for der in cases {
            assert!(
                BoringPrivateKey::try_from(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
                    .is_err()
            );
        }
    }

    #[test]
    fn loads_sec1_ec_private_key() {
        let pkey = p256_private_key();
        let sec1_der = pkey.private_key_to_der().unwrap();
        let key_der = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(sec1_der));

        let key = BoringPrivateKey::try_from(key_der).expect("SEC1 private key should load");

        assert!(key.public_key().is_some());
    }

    #[test]
    fn p256_key_chooses_only_p256_scheme() {
        let pkey = p256_private_key();
        let pkcs8_der = pkey.private_key_to_der_pkcs8().unwrap();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));

        let key = BoringPrivateKey::try_from(key_der).expect("P-256 private key should load");

        let offered = [
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ];
        let signer = key
            .choose_scheme(&offered)
            .expect("P-256 key should select P-256 scheme");
        assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP256_SHA256);

        assert!(
            key.choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
                .is_none()
        );
    }

    #[test]
    fn rsa_key_prefers_pss_when_available() {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let pkcs8_der = pkey.private_key_to_der_pkcs8().unwrap();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));

        let key = BoringPrivateKey::try_from(key_der).expect("RSA private key should load");
        let signer = key
            .choose_scheme(&[
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
            ])
            .expect("RSA key should select an offered scheme");

        assert_eq!(signer.scheme(), SignatureScheme::RSA_PSS_SHA256);
    }

    #[test]
    #[cfg(feature = "fips")]
    fn fips_rejects_rsa_key_below_2048_bits() {
        let rsa = Rsa::generate(1024).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let pkcs8_der = pkey.private_key_to_der_pkcs8().unwrap();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));

        let err = BoringPrivateKey::try_from(key_der)
            .expect_err("1024-bit RSA key should be rejected in FIPS mode");
        assert!(
            err.to_string().contains("too small for FIPS mode"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(feature = "fips")]
    fn fips_accepts_2048_bit_rsa_key() {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let pkcs8_der = pkey.private_key_to_der_pkcs8().unwrap();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));

        BoringPrivateKey::try_from(key_der).expect("2048-bit RSA key should load in FIPS mode");
    }
}
