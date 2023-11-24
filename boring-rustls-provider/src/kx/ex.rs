use std::{
    mem::MaybeUninit,
    ptr::{self},
};

use boring::{
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    nid::Nid,
    pkey::{PKey, PKeyRef, Private},
};
use boring_additions::evp::EvpPkeyCtx;
use foreign_types::ForeignType;
use rustls::crypto;
use spki::der::Decode;

use crate::helper::{cvt, cvt_p, log_and_map};

use super::DhKeyType;

/// This type can be used to perform an
/// Eliptic Curve or Edwards Curve key
/// exchange.
pub struct KeyExchange {
    own_key: PKey<Private>,
    pub_bytes: Vec<u8>,
    key_type: DhKeyType,
}

impl KeyExchange {
    /// Creates a new `KeyExchange` using a random
    /// private key for the `X25519` Edwards curve
    pub fn with_x25519() -> Result<Self, ErrorStack> {
        Self::ed_from_curve(Nid::from_raw(boring_sys::NID_X25519))
    }

    /// Creates a new `KeyExchange` using a random
    /// private key for the `X448` Edwards curve
    pub fn with_x448() -> Result<Self, ErrorStack> {
        Self::ed_from_curve(Nid::from_raw(boring_sys::NID_X448))
    }

    /// Creates a new `KeyExchange` using a random
    /// private key for `sepc256r1` curve
    /// Also known as `X9_62_PRIME256V1`
    pub fn with_secp256r1() -> Result<Self, ErrorStack> {
        Self::ec_from_curve(Nid::X9_62_PRIME256V1)
    }

    /// Creates a new `KeyExchange` using a random
    /// private key for `sepc384r1` curve
    pub fn with_secp384r1() -> Result<Self, ErrorStack> {
        Self::ec_from_curve(Nid::SECP384R1)
    }

    /// Creates a new `KeyExchange` using a random
    /// private key for `sep521r1` curve
    pub fn with_secp521r1() -> Result<Self, ErrorStack> {
        Self::ec_from_curve(Nid::SECP521R1)
    }

    /// Allows getting a new `KeyExchange` using Eliptic Curves
    /// on the specified curve
    fn ec_from_curve(nid: Nid) -> Result<Self, ErrorStack> {
        let ec_group = EcGroup::from_curve_name(nid)?;
        let ec_key = EcKey::generate(&ec_group)?;

        let own_key = PKey::from_ec_key(ec_key)?;
        let pub_bytes = Self::raw_public_key(&own_key)?;
        Ok(Self {
            own_key,
            pub_bytes,
            key_type: DhKeyType::EC((ec_group, nid.as_raw())),
        })
    }

    /// Allows getting a new `KeyExchange` using Edwards Curves
    /// on the specified curve
    fn ed_from_curve(nid: Nid) -> Result<Self, ErrorStack> {
        let pkey_ctx = unsafe {
            EvpPkeyCtx::from_ptr(cvt_p(boring_sys::EVP_PKEY_CTX_new_id(
                nid.as_raw(),
                ptr::null_mut(),
            ))?)
        };

        let own_key: PKey<Private> = unsafe {
            cvt(boring_sys::EVP_PKEY_keygen_init(pkey_ctx.as_ptr()))?;

            let mut pkey =
                MaybeUninit::<*mut boring_sys::EVP_PKEY>::new(ptr::null_mut()).assume_init();
            cvt(boring_sys::EVP_PKEY_keygen(pkey_ctx.as_ptr(), &mut pkey))?;

            PKey::from_ptr(pkey)
        };

        let pub_bytes = Self::raw_public_key(&own_key)?;

        Ok(Self {
            own_key,
            pub_bytes,
            key_type: DhKeyType::ED(nid.as_raw()),
        })
    }

    /// Decodes a SPKI public key to it's raw public key component
    fn raw_public_key(pkey: &PKeyRef<Private>) -> Result<Vec<u8>, ErrorStack> {
        let spki = pkey.public_key_to_der()?;

        // parse the key
        let pkey = spki::SubjectPublicKeyInfoRef::from_der(spki.as_ref())
            .expect("failed parsing spki bytes");

        // return the raw public key as a new vec
        Ok(Vec::from(
            pkey.subject_public_key
                .as_bytes()
                .expect("failed getting raw spki bytes"),
        ))
    }

    /// Derives a shared secret using the peer's raw public key
    fn diffie_hellman(&self, peer_pub_key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let peerkey = match &self.key_type {
            DhKeyType::EC((group, _)) => {
                let mut bn_ctx = boring::bn::BigNumContext::new()?;

                let point = crate::verify::ec::get_ec_point(group, &mut bn_ctx, peer_pub_key)?;

                crate::verify::ec::create_public_key(group, point.as_ref())?
            }
            DhKeyType::ED(nid) => crate::verify::ed::public_key(peer_pub_key, Nid::from_raw(*nid))?,
            _ => unimplemented!(),
        };

        let mut deriver = boring::derive::Deriver::new(&self.own_key)?;

        deriver.set_peer(&peerkey)?;

        deriver.derive_to_vec()
    }
}

impl crypto::ActiveKeyExchange for KeyExchange {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        self.diffie_hellman(peer_pub_key)
            .map(|x| crypto::SharedSecret::from(x.as_slice()))
            .map_err(|e| {
                log_and_map(
                    "ex::KeyExchange::diffie_hellman",
                    e,
                    rustls::Error::PeerMisbehaved(rustls::PeerMisbehaved::InvalidKeyShare),
                )
            })
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_bytes
    }

    fn group(&self) -> rustls::NamedGroup {
        match self.key_type {
            DhKeyType::ED(boring_sys::NID_X25519) => rustls::NamedGroup::X25519,
            DhKeyType::ED(boring_sys::NID_X448) => rustls::NamedGroup::X448,
            DhKeyType::EC((_, boring_sys::NID_X9_62_prime256v1)) => rustls::NamedGroup::secp256r1,
            DhKeyType::EC((_, boring_sys::NID_secp384r1)) => rustls::NamedGroup::secp384r1,
            DhKeyType::EC((_, boring_sys::NID_secp521r1)) => rustls::NamedGroup::secp521r1,
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::KeyExchange;
    use rustls::crypto::ActiveKeyExchange;

    #[test]
    fn test_derive_ec() {
        let alice = Box::new(KeyExchange::with_secp256r1().unwrap());
        let bob = KeyExchange::with_secp256r1().unwrap();

        assert_eq!(
            alice.diffie_hellman(bob.pub_key()).unwrap(),
            bob.diffie_hellman(alice.pub_key()).unwrap()
        );
    }

    #[test]
    fn test_derive_ed() {
        let alice = Box::new(KeyExchange::with_x25519().unwrap());
        let bob = KeyExchange::with_x25519().unwrap();

        assert_eq!(
            alice.diffie_hellman(bob.pub_key()).unwrap(),
            bob.diffie_hellman(alice.pub_key()).unwrap()
        );
    }
}
