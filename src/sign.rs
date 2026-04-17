use std::sync::Arc;

use boring::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKeyRef, Private},
    rsa::Padding,
    sign::{RsaPssSaltlen, Signer},
};
use rustls::{SignatureScheme, sign::SigningKey};
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
}

/// An abstraction over a boringssl private key used for signing.
#[derive(Debug)]
pub struct BoringPrivateKey(Arc<boring::pkey::PKey<Private>>, KeyKind);

impl TryFrom<PrivateKeyDer<'static>> for BoringPrivateKey {
    type Error = rustls::Error;

    fn try_from(value: PrivateKeyDer<'static>) -> Result<Self, Self::Error> {
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
            KeyKind::Rsa | KeyKind::Ec(EcCurve::P256 | EcCurve::P384) => {}
            KeyKind::Ec(EcCurve::P521) | KeyKind::Ed25519 | KeyKind::Ed448 => {
                return Err(rustls::Error::General(
                    "key type is not allowed in FIPS mode".into(),
                ));
            }
        }

        Ok(Self(Arc::new(pkey), kind))
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
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        let scheme = match self.1 {
            KeyKind::Rsa => ALL_RSA_SCHEMES
                .iter()
                .find(|scheme| offered.contains(scheme)),
            KeyKind::Ec(EcCurve::P256) => EC_P256_SCHEMES
                .iter()
                .find(|scheme| offered.contains(scheme)),
            KeyKind::Ec(EcCurve::P384) => EC_P384_SCHEMES
                .iter()
                .find(|scheme| offered.contains(scheme)),
            KeyKind::Ec(EcCurve::P521) => EC_P521_SCHEMES
                .iter()
                .find(|scheme| offered.contains(scheme)),
            KeyKind::Ed25519 if offered.contains(&rustls::SignatureScheme::ED25519) => {
                Some(&rustls::SignatureScheme::ED25519)
            }
            KeyKind::Ed448 if offered.contains(&rustls::SignatureScheme::ED448) => {
                Some(&rustls::SignatureScheme::ED448)
            }
            _ => None,
        }?;

        Some(Box::new(BoringSigner(self.0.clone(), *scheme)))
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        match self.1 {
            KeyKind::Rsa => rustls::SignatureAlgorithm::RSA,
            KeyKind::Ec(_) => rustls::SignatureAlgorithm::ECDSA,
            KeyKind::Ed25519 => rustls::SignatureAlgorithm::ED25519,
            KeyKind::Ed448 => rustls::SignatureAlgorithm::ED448,
        }
    }
}

/// A boringssl-based Signer.
#[derive(Debug)]
pub struct BoringSigner(Arc<boring::pkey::PKey<Private>>, rustls::SignatureScheme);

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

impl rustls::sign::Signer for BoringSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
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

    fn scheme(&self) -> rustls::SignatureScheme {
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
    use rustls::sign::SigningKey;
    use rustls::{SignatureAlgorithm, SignatureScheme};
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

    use super::BoringPrivateKey;

    fn p256_private_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        PKey::from_ec_key(ec_key).unwrap()
    }

    #[test]
    fn loads_sec1_ec_private_key() {
        let pkey = p256_private_key();
        let sec1_der = pkey.private_key_to_der().unwrap();
        let key_der = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(sec1_der));

        let key = BoringPrivateKey::try_from(key_der).expect("SEC1 private key should load");

        assert_eq!(key.algorithm(), SignatureAlgorithm::ECDSA);
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
}
