use boring::{
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    nid::Nid,
    pkey::Id,
    pkey::{PKey, PKeyRef, Private},
};
use rustls::crypto::kx::{ActiveKeyExchange, NamedGroup, SharedSecret};
use rustls::error::PeerMisbehaved;

use crate::helper::log_and_map;

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
    #[cfg(not(feature = "fips"))]
    pub fn with_x25519() -> Result<Self, ErrorStack> {
        Self::ed_from_curve(Nid::from_raw(boring_sys::NID_X25519))
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
    #[cfg(not(feature = "fips"))]
    fn ed_from_curve(nid: Nid) -> Result<Self, ErrorStack> {
        let own_key = PKey::generate(Id::from_raw(nid.as_raw()))?;
        let pub_bytes = Self::raw_public_key(&own_key)?;

        Ok(Self {
            own_key,
            pub_bytes,
            key_type: DhKeyType::ED(nid.as_raw()),
        })
    }

    /// Decodes a SPKI public key to it's raw public key component
    fn raw_public_key(pkey: &PKeyRef<Private>) -> Result<Vec<u8>, ErrorStack> {
        if pkey.id() == Id::EC {
            let ec_key = pkey.ec_key()?;
            let mut bn_ctx = boring::bn::BigNumContext::new()?;

            return ec_key.public_key().to_bytes(
                ec_key.group(),
                boring::ec::PointConversionForm::UNCOMPRESSED,
                &mut bn_ctx,
            );
        }

        let mut output = vec![0u8; pkey.raw_public_key_len()?];
        let used_len = {
            let used = pkey.raw_public_key(&mut output)?;
            used.len()
        };
        output.truncate(used_len);
        Ok(output)
    }

    /// Derives a shared secret using the peer's raw public key
    fn diffie_hellman(&self, peer_pub_key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let peerkey = match &self.key_type {
            DhKeyType::EC((group, _)) => {
                let mut bn_ctx = boring::bn::BigNumContext::new()?;

                let point = crate::verify::ec::get_ec_point(group, &mut bn_ctx, peer_pub_key)?;

                crate::verify::ec::create_public_key(group, point.as_ref())?
            }
            #[cfg(not(feature = "fips"))]
            DhKeyType::ED(nid) => crate::verify::ed::public_key(peer_pub_key, Nid::from_raw(*nid))?,
        };

        let mut deriver = boring::derive::Deriver::new(&self.own_key)?;

        deriver.set_peer(&peerkey)?;

        deriver.derive_to_vec()
    }
}

impl ActiveKeyExchange for KeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        self.diffie_hellman(peer_pub_key)
            .map(SharedSecret::from)
            .map_err(|e| {
                log_and_map(
                    "ex::KeyExchange::diffie_hellman",
                    e,
                    rustls::Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare),
                )
            })
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_bytes
    }

    fn group(&self) -> NamedGroup {
        match self.key_type {
            #[cfg(not(feature = "fips"))]
            DhKeyType::ED(boring_sys::NID_X25519) => NamedGroup::X25519,
            DhKeyType::EC((_, boring_sys::NID_X9_62_prime256v1)) => NamedGroup::secp256r1,
            DhKeyType::EC((_, boring_sys::NID_secp384r1)) => NamedGroup::secp384r1,
            _ => unreachable!("unsupported key type"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::KeyExchange;
    use rustls::crypto::kx::ActiveKeyExchange;

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
    #[cfg(not(feature = "fips"))]
    fn test_derive_ed() {
        let alice = Box::new(KeyExchange::with_x25519().unwrap());
        let bob = KeyExchange::with_x25519().unwrap();

        assert_eq!(
            alice.diffie_hellman(bob.pub_key()).unwrap(),
            bob.diffie_hellman(alice.pub_key()).unwrap()
        );
    }
}
