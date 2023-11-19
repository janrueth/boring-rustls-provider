use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    ptr::{self, NonNull},
};

use boring::error::ErrorStack;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use rustls::crypto;
use spki::der::Decode;

use crate::helper::{cvt, cvt_p};

use super::DhKeyType;

pub struct BoringEvpPkeyCtxRef(Opaque);

unsafe impl ForeignTypeRef for BoringEvpPkeyCtxRef {
    type CType = boring_sys::EVP_PKEY_CTX;
}

unsafe impl Sync for BoringEvpPkeyCtxRef {}
unsafe impl Send for BoringEvpPkeyCtxRef {}

unsafe impl Sync for BoringEvpPkeyCtx {}
unsafe impl Send for BoringEvpPkeyCtx {}

pub struct BoringEvpPkeyCtx(NonNull<boring_sys::EVP_PKEY_CTX>);
unsafe impl ForeignType for BoringEvpPkeyCtx {
    type CType = boring_sys::EVP_PKEY_CTX;

    type Ref = BoringEvpPkeyCtxRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}
impl Drop for BoringEvpPkeyCtx {
    fn drop(&mut self) {
        unsafe {
            boring_sys::EVP_PKEY_CTX_free(self.0.as_ptr());
        }
    }
}

impl core::fmt::Debug for BoringEvpPkeyCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BoringEvpPkeyCtx").field(&self.0).finish()
    }
}

impl Deref for BoringEvpPkeyCtx {
    type Target = BoringEvpPkeyCtxRef;

    fn deref(&self) -> &BoringEvpPkeyCtxRef {
        unsafe { BoringEvpPkeyCtxRef::from_ptr(self.as_ptr()) }
    }
}

impl DerefMut for BoringEvpPkeyCtx {
    fn deref_mut(&mut self) -> &mut BoringEvpPkeyCtxRef {
        unsafe { BoringEvpPkeyCtxRef::from_ptr_mut(self.as_ptr()) }
    }
}

#[derive(Debug)]
pub struct BoringEvpKey {
    /// the private key context for deriving shared secrets
    dctx: BoringEvpPkeyCtx,

    key_type: DhKeyType,

    pub_bytes: Vec<u8>,
}

unsafe impl Sync for BoringEvpKey {}
unsafe impl Send for BoringEvpKey {}

impl BoringEvpKey {
    pub fn generate_x25519() -> Result<Self, ErrorStack> {
        unsafe {
            Self::generate_with_ctx(
                DhKeyType::ED(boring_sys::NID_X25519),
                Self::generate_ctx_from_nid(boring_sys::NID_X25519)?,
            )
        }
    }

    pub fn generate_x448() -> Result<Self, ErrorStack> {
        unsafe {
            Self::generate_with_ctx(
                DhKeyType::ED(boring_sys::NID_X448),
                Self::generate_ctx_from_nid(boring_sys::NID_X448)?,
            )
        }
    }

    pub fn generate_secp256r1() -> Result<Self, ErrorStack> {
        unsafe {
            let pctx = Self::generate_ctx_with_ec_curve(boring_sys::NID_X9_62_prime256v1)?;
            Self::generate_with_ctx(DhKeyType::EC(boring_sys::NID_X9_62_prime256v1), pctx)
        }
    }
    pub fn generate_secp384r1() -> Result<Self, ErrorStack> {
        unsafe {
            let pctx = Self::generate_ctx_with_ec_curve(boring_sys::NID_secp384r1)?;
            Self::generate_with_ctx(DhKeyType::EC(boring_sys::NID_secp384r1), pctx)
        }
    }
    pub fn generate_secp521r1() -> Result<Self, ErrorStack> {
        unsafe {
            let pctx = Self::generate_ctx_with_ec_curve(boring_sys::NID_secp521r1)?;
            Self::generate_with_ctx(DhKeyType::EC(boring_sys::NID_secp521r1), pctx)
        }
    }

    unsafe fn generate_ctx_with_ec_curve(curve_nid: i32) -> Result<BoringEvpPkeyCtx, ErrorStack> {
        boring_sys::init();

        let pctx = BoringEvpPkeyCtx::from_ptr(cvt_p(boring_sys::EVP_PKEY_CTX_new_id(
            boring_sys::EVP_PKEY_EC,
            ptr::null_mut(),
        ))?);

        // The following function is for generating parameters
        cvt(boring_sys::EVP_PKEY_paramgen_init(pctx.as_ptr()))?;

        // Set the curve
        cvt(boring_sys::EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
            pctx.as_ptr(),
            curve_nid,
        ))?;

        // Used a named curve which has max compatiblity according man page
        cvt(boring_sys::EVP_PKEY_CTX_set_ec_param_enc(
            pctx.as_ptr(),
            boring_sys::OPENSSL_EC_NAMED_CURVE,
        ))?;

        // generate parameters
        let mut pkey = MaybeUninit::<*mut boring_sys::EVP_PKEY>::new(ptr::null_mut()).assume_init();
        cvt(boring_sys::EVP_PKEY_paramgen(pctx.as_ptr(), &mut pkey))?;
        let pkey: boring::pkey::PKey<boring::pkey::Params> = boring::pkey::PKey::from_ptr(pkey);

        Ok(BoringEvpPkeyCtx::from_ptr(
            // ctx will take ownership of pkey
            cvt_p(boring_sys::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut())).expect("failed"),
        ))
    }

    fn generate_ctx_from_nid(nid: i32) -> Result<BoringEvpPkeyCtx, ErrorStack> {
        boring_sys::init();
        Ok(unsafe {
            BoringEvpPkeyCtx::from_ptr(cvt_p(boring_sys::EVP_PKEY_CTX_new_id(
                nid,
                ptr::null_mut(),
            ))?)
        })
    }

    unsafe fn generate_with_ctx(
        key_type: DhKeyType,
        pctx: BoringEvpPkeyCtx,
    ) -> Result<Self, ErrorStack> {
        let mut pkey = MaybeUninit::<*mut boring_sys::EVP_PKEY>::new(ptr::null_mut()).assume_init();

        cvt(boring_sys::EVP_PKEY_keygen_init(pctx.as_ptr()))?;

        cvt(boring_sys::EVP_PKEY_keygen(pctx.as_ptr(), &mut pkey))?;
        let pkey: boring::pkey::PKey<boring::pkey::Private> = boring::pkey::PKey::from_ptr(pkey);

        let dctx = BoringEvpPkeyCtx::from_ptr(
            // dctx will take ownership of pkey, we can safely drop it
            cvt_p(boring_sys::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut()))?,
        );

        let pub_bytes = Self::raw_public_key(pkey.as_ref())?;

        Ok(Self {
            dctx,
            key_type,
            pub_bytes,
        })
    }

    fn raw_public_key(
        pkey: &boring::pkey::PKeyRef<boring::pkey::Private>,
    ) -> Result<Vec<u8>, ErrorStack> {
        let key_len = unsafe {
            // figure out how many bytes we need for the key
            cvt(boring_sys::i2d_PUBKEY(pkey.as_ptr(), ptr::null_mut()))? as usize
        };
        let mut spki = vec![0u8; key_len];
        unsafe {
            // write the key to spki
            cvt(boring_sys::i2d_PUBKEY(
                pkey.as_ptr(),
                &mut spki.as_mut_ptr(),
            ))?;
        }
        // parse the key
        let key = spki::SubjectPublicKeyInfoRef::from_der(spki.as_ref()).unwrap();

        // return the raw public key as a new vec
        Ok(Vec::from(key.subject_public_key.as_bytes().unwrap()))
    }

    pub fn diffie_hellman(&self, raw_public_key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        match self.key_type {
            DhKeyType::EC(nid) => self.diffie_hellman_ec(nid, raw_public_key),
            DhKeyType::ED(nid) => self.diffie_hellman_ed(nid, raw_public_key),
            _ => unimplemented!(),
        }
    }

    fn diffie_hellman_ec(&self, nid: i32, raw_public_key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        // this is only the key data not the algo identifier etc
        let group = boring::ec::EcGroup::from_curve_name(boring::nid::Nid::from_raw(nid))?;
        let mut bn_ctx = boring::bn::BigNumContext::new()?;
        let point =
            crate::verify::ec::ec_point(group.as_ref(), &mut bn_ctx, raw_public_key).unwrap();

        let peerkey = crate::verify::ec::ec_public_key(group.as_ref(), point.as_ref()).unwrap();

        self.diffie_hellman_common(peerkey.as_ptr())
    }

    fn diffie_hellman_ed(&self, nid: i32, raw_public_key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let peerkey: boring::pkey::PKey<boring::pkey::Public> = unsafe {
            boring::pkey::PKey::from_ptr(cvt_p(boring_sys::EVP_PKEY_new_raw_public_key(
                nid,
                ptr::null_mut(),
                raw_public_key.as_ptr(),
                raw_public_key.len(),
            ))?)
        };

        self.diffie_hellman_common(peerkey.as_ptr())
    }

    fn diffie_hellman_common(
        &self,
        peerkey: *mut boring_sys::EVP_PKEY,
    ) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            // Initialize
            cvt(boring_sys::EVP_PKEY_derive_init(self.dctx.as_ptr()))?;

            // Provide the peer public key
            cvt(boring_sys::EVP_PKEY_derive_set_peer(
                self.dctx.as_ptr(),
                peerkey,
            ))?;
        }

        // Determine buffer length for shared secret
        let mut secret_len = unsafe {
            let mut secret_len = 0;
            cvt(boring_sys::EVP_PKEY_derive(
                self.dctx.as_ptr(),
                ptr::null_mut(),
                &mut secret_len,
            ))?;
            secret_len
        };

        let mut secret = vec![0u8; secret_len];
        unsafe {
            cvt(boring_sys::EVP_PKEY_derive(
                self.dctx.as_ptr(),
                secret.as_mut_ptr(),
                &mut secret_len,
            ))?;
        }
        Ok(secret)
    }
}

impl crypto::ActiveKeyExchange for BoringEvpKey {
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
            DhKeyType::ED(boring_sys::NID_X25519) => rustls::NamedGroup::X25519,
            DhKeyType::ED(boring_sys::NID_X448) => rustls::NamedGroup::X448,
            DhKeyType::EC(boring_sys::NID_X9_62_prime256v1) => rustls::NamedGroup::secp256r1,
            DhKeyType::EC(boring_sys::NID_secp384r1) => rustls::NamedGroup::secp384r1,
            DhKeyType::EC(boring_sys::NID_secp521r1) => rustls::NamedGroup::secp521r1,
            _ => unimplemented!(),
        }
    }
}
