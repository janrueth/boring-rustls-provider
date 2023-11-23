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

use crate::helper::{cvt, cvt_p};

use super::DhKeyType;

pub struct ExKeyExchange {
    own_key: PKey<Private>,
    pub_bytes: Vec<u8>,
    key_type: DhKeyType,
}

impl ExKeyExchange {
    pub fn with_x25519() -> Result<Self, ErrorStack> {
        Self::ed_from_curve(Nid::from_raw(boring_sys::NID_X25519))
    }

    pub fn with_x448() -> Result<Self, ErrorStack> {
        Self::ed_from_curve(Nid::from_raw(boring_sys::NID_X448))
    }

    pub fn with_secp256r1() -> Result<Self, ErrorStack> {
        Self::ec_from_curve(Nid::X9_62_PRIME256V1)
    }

    pub fn with_secp384r1() -> Result<Self, ErrorStack> {
        Self::ec_from_curve(Nid::SECP384R1)
    }

    pub fn with_secp521r1() -> Result<Self, ErrorStack> {
        Self::ec_from_curve(Nid::SECP521R1)
    }

    fn ec_from_curve(nid: Nid) -> Result<Self, ErrorStack> {
        let ec_group = EcGroup::from_curve_name(nid)?;
        let ec_key = EcKey::generate(&ec_group)?;

        let own_key = PKey::from_ec_key(ec_key)?;
        let pub_bytes = Self::raw_public_key(&own_key);
        Ok(Self {
            own_key,
            pub_bytes,
            key_type: DhKeyType::EC((ec_group, nid.as_raw())),
        })
    }

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

        let pub_bytes = Self::raw_public_key(&own_key);

        Ok(Self {
            own_key,
            pub_bytes,
            key_type: DhKeyType::ED(nid.as_raw()),
        })
    }

    fn raw_public_key(pkey: &PKeyRef<Private>) -> Vec<u8> {
        let spki = pkey.public_key_to_der().unwrap();

        // parse the key
        let key = spki::SubjectPublicKeyInfoRef::from_der(spki.as_ref()).unwrap();

        // return the raw public key as a new vec
        Vec::from(key.subject_public_key.as_bytes().unwrap())
    }
}

impl crypto::ActiveKeyExchange for ExKeyExchange {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let peerkey = match &self.key_type {
            DhKeyType::EC((group, _)) => {
                let mut bn_ctx = boring::bn::BigNumContext::new()
                    .map_err(|x| rustls::Error::General(x.to_string()))?;

                let point = crate::verify::ec::ec_point(group, &mut bn_ctx, peer_pub_key)
                    .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;

                crate::verify::ec::ec_public_key(group, point.as_ref())
                    .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?
            }
            DhKeyType::ED(nid) => {
                crate::verify::ed::ed_public_key(peer_pub_key, Nid::from_raw(*nid))
                    .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?
            }
            _ => unimplemented!(),
        };

        let mut deriver = boring::derive::Deriver::new(&self.own_key).unwrap();

        deriver
            .set_peer(&peerkey)
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;

        Ok(crypto::SharedSecret::from(
            deriver.derive_to_vec().unwrap().as_slice(),
        ))
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
    use super::ExKeyExchange;
    use rustls::crypto::ActiveKeyExchange;

    #[test]
    fn test_derive_ec() {
        let kx = Box::new(ExKeyExchange::with_secp256r1().unwrap());
        let kx1 = ExKeyExchange::with_secp256r1().unwrap();

        kx.group();
        kx.complete(kx1.pub_key()).unwrap();
    }

    #[test]
    fn test_derive_ed() {
        let kx = Box::new(ExKeyExchange::with_x25519().unwrap());
        let kx1 = ExKeyExchange::with_x25519().unwrap();

        kx.group();
        kx.complete(kx1.pub_key()).unwrap();
    }
}
