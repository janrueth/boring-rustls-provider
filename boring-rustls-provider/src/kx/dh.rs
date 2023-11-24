use boring::{dh::Dh, error::ErrorStack, pkey::Private};
use foreign_types::ForeignType;
use rustls::crypto;

use crate::helper::{cvt, cvt_p, log_and_map};

use super::DhKeyType;

/// This type can be used to perform a
/// Diffie-Hellman key exchange.
pub struct KeyExchange {
    dh: Dh<Private>,
    pub_bytes: Vec<u8>,
    key_type: DhKeyType,
}

impl KeyExchange {
    // Generate a new KeyExchange with a random FFDHE_2048 private key
    pub fn generate_ffdhe_2048() -> Result<Self, ErrorStack> {
        let mut me = Self {
            dh: unsafe { Dh::from_ptr(cvt_p(boring_sys::DH_get_rfc7919_2048())?) },
            pub_bytes: Vec::new(),
            key_type: DhKeyType::FFDHE2048,
        };

        me.pub_bytes = unsafe {
            // generate a new key pair
            cvt(boring_sys::DH_generate_key(me.dh.as_ptr()))?;

            // get a reference to the pub key
            let pubkey = boring_sys::DH_get0_pub_key(me.dh.as_ptr());

            // figure out how many bytes we need, round up to the next full byte
            let size = (boring_sys::BN_num_bits(pubkey) as usize + 7) / 8;

            // alloc a vector with enough capacity
            let mut v = Vec::with_capacity(size);

            // convert to binary representation
            let after_size = boring_sys::BN_bn2bin(pubkey, v.as_mut_ptr());
            // size should be what we calculated before
            assert_eq!(size, after_size);

            // ensure those bytes are accessible in the vec
            v.set_len(size);
            v
        };

        Ok(me)
    }

    /// Generate a shared secret with the other's raw public key
    fn diffie_hellman(&self, raw_public_key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let peer = boring::bn::BigNum::from_slice(raw_public_key)?;

        let secret_len = unsafe { cvt(boring_sys::DH_size(self.dh.as_ptr()))? } as usize;
        let mut secret = vec![0u8; secret_len];

        let secret_len = unsafe {
            cvt(boring_sys::DH_compute_key_padded(
                secret.as_mut_ptr(),
                peer.as_ptr(),
                self.dh.as_ptr(),
            ))?
        } as usize;

        secret.truncate(secret_len);
        Ok(secret)
    }
}

impl crypto::ActiveKeyExchange for KeyExchange {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let expected_len = self.pub_bytes.len();

        if peer_pub_key.len() != expected_len {
            return Err(rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare));
        }

        Ok(crypto::SharedSecret::from(
            self.diffie_hellman(peer_pub_key)
                .map_err(|e| {
                    log_and_map(
                        "dh::KeyExchange::diffie_hellman",
                        e,
                        rustls::PeerMisbehaved::InvalidKeyShare,
                    )
                })?
                .as_ref(),
        ))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_bytes.as_ref()
    }

    fn group(&self) -> rustls::NamedGroup {
        match self.key_type {
            DhKeyType::FFDHE2048 => rustls::NamedGroup::FFDHE2048,
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::kx::dh::KeyExchange;
    use rustls::crypto::ActiveKeyExchange;

    #[test]
    fn test_derive_dh() {
        let alice = KeyExchange::generate_ffdhe_2048().unwrap();
        let bob = KeyExchange::generate_ffdhe_2048().unwrap();

        let shared_secret1 = alice.diffie_hellman(bob.pub_key()).unwrap();
        let shared_secret2 = bob.diffie_hellman(alice.pub_key()).unwrap();

        assert_eq!(shared_secret1, shared_secret2)
    }
}
