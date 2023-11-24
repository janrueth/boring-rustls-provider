use std::sync::Arc;

use boring::{
    hash::MessageDigest,
    pkey::{Id, PKeyRef, Private},
    rsa::Padding,
    sign::{RsaPssSaltlen, Signer},
};
use rustls::{sign::SigningKey, SignatureScheme};
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

const ALL_EC_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
];

/// An abstraction over a boringssl private key
/// used for signing
#[derive(Debug)]
pub struct BoringPrivateKey(Arc<boring::pkey::PKey<Private>>, rustls::SignatureAlgorithm);

impl TryFrom<PrivateKeyDer<'static>> for BoringPrivateKey {
    type Error = rustls::Error;

    fn try_from(value: PrivateKeyDer<'static>) -> Result<Self, Self::Error> {
        let pkey = match value {
            PrivateKeyDer::Pkcs8(der) => {
                boring::pkey::PKey::private_key_from_pkcs8(der.secret_pkcs8_der())
                    .map_err(|e| log_and_map("private_key_from_pkcs8", e, ()))
            }
            PrivateKeyDer::Pkcs1(der) => {
                boring::pkey::PKey::private_key_from_der(der.secret_pkcs1_der())
                    .map_err(|e| log_and_map("private_key_from_der", e, ()))
            }
            _ => Err(()),
        }
        .map_err(|_| rustls::Error::General("failed loading private key".into()))?;

        let sig = match pkey.id() {
            Id::RSA => rustls::SignatureAlgorithm::RSA,
            Id::EC => rustls::SignatureAlgorithm::ECDSA,
            Id::ED25519 => rustls::SignatureAlgorithm::ED25519,
            Id::ED448 => rustls::SignatureAlgorithm::ED448,
            _ => return Err(rustls::Error::General("unsupported key format".into())),
        };
        Ok(Self(Arc::new(pkey), sig))
    }
}

fn rsa_signer_from_params(
    key: &PKeyRef<Private>,
    digest: MessageDigest,
    padding: Padding,
) -> Signer {
    let mut signer = Signer::new(digest, key).expect("failed getting signer");
    signer
        .set_rsa_padding(padding)
        .expect("failed setting padding");
    if padding == Padding::PKCS1_PSS {
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .expect("failed setting rsa_pss salt lengths");
        signer
            .set_rsa_mgf1_md(digest)
            .expect("failed setting mgf1 digest");
    }

    signer
}

fn ec_signer_from_params(key: &PKeyRef<Private>, digest: MessageDigest) -> Signer {
    let signer = Signer::new(digest, key).expect("failed getting signer");
    signer
}

impl BoringPrivateKey {}

impl SigningKey for BoringPrivateKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        match self.1 {
            rustls::SignatureAlgorithm::RSA => ALL_RSA_SCHEMES
                .iter()
                .find(|scheme| offered.contains(scheme))
                .map(|&scheme| Box::new(BoringSigner(self.0.clone(), scheme)) as _),
            rustls::SignatureAlgorithm::ECDSA => ALL_EC_SCHEMES
                .iter()
                .find(|scheme| offered.contains(scheme))
                .map(|&scheme| Box::new(BoringSigner(self.0.clone(), scheme)) as _),
            rustls::SignatureAlgorithm::ED25519
                if offered.contains(&rustls::SignatureScheme::ED25519) =>
            {
                Some(Box::new(BoringSigner(
                    self.0.clone(),
                    rustls::SignatureScheme::ED25519,
                )))
            }
            rustls::SignatureAlgorithm::ED448
                if offered.contains(&rustls::SignatureScheme::ED448) =>
            {
                Some(Box::new(BoringSigner(
                    self.0.clone(),
                    rustls::SignatureScheme::ED448,
                )))
            }
            _ => None,
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.1
    }
}

/// A boringssl-based Signer
#[derive(Debug)]
pub struct BoringSigner(Arc<boring::pkey::PKey<Private>>, rustls::SignatureScheme);

impl BoringSigner {
    fn get_signer(&self) -> Signer {
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
                Signer::new_without_digest(self.0.as_ref()).expect("failed getting signer")
            }

            _ => unimplemented!(),
        }
    }
}

impl rustls::sign::Signer for BoringSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let signer = self.get_signer();
        let mut msg_with_sig =
            Vec::<u8>::with_capacity(message.len() + boring_sys::EVP_MAX_MD_SIZE as usize);
        msg_with_sig.extend_from_slice(message);
        msg_with_sig.extend_from_slice(&[0u8; boring_sys::EVP_MAX_MD_SIZE as usize]);

        let toatl_len = signer
            .sign(&mut msg_with_sig[..])
            .map_err(|e| log_and_map("sign", e, rustls::Error::General("failed signing".into())))?;
        msg_with_sig.truncate(toatl_len);
        Ok(msg_with_sig)
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        self.1
    }
}
