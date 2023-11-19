use boring::error::ErrorStack;
use foreign_types::ForeignType;
use rustls::crypto;

use crate::helper::{cvt, cvt_p};

use super::DhKeyType;

pub struct BoringDhKey {
    dh: boring::dh::Dh<boring::pkey::Private>,
    pub_bytes: Vec<u8>,
    key_type: DhKeyType,
}

impl BoringDhKey {
    pub fn generate_ffdhe_2048() -> Result<Self, ErrorStack> {
        let mut me = Self {
            dh: unsafe { boring::dh::Dh::from_ptr(cvt_p(boring_sys::DH_get_rfc7919_2048())?) },
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

    pub fn diffie_hellman(&self, raw_public_key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let peer = boring::bn::BigNum::from_slice(raw_public_key).unwrap();
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

    #[allow(unused)]
    fn pub_key(&self) -> &[u8] {
        self.pub_bytes.as_ref()
    }
}

impl crypto::ActiveKeyExchange for BoringDhKey {
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
                .map_err(|x| rustls::Error::General(x.to_string()))?
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
