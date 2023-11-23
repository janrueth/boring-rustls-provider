use std::{
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

use foreign_types::{ForeignType, ForeignTypeRef, Opaque};

pub struct EvpPkeyCtxRef(Opaque);

unsafe impl ForeignTypeRef for EvpPkeyCtxRef {
    type CType = boring_sys::EVP_PKEY_CTX;
}

unsafe impl Sync for EvpPkeyCtxRef {}
unsafe impl Send for EvpPkeyCtxRef {}

unsafe impl Sync for EvpPkeyCtx {}
unsafe impl Send for EvpPkeyCtx {}

pub struct EvpPkeyCtx(NonNull<boring_sys::EVP_PKEY_CTX>);
unsafe impl ForeignType for EvpPkeyCtx {
    type CType = boring_sys::EVP_PKEY_CTX;

    type Ref = EvpPkeyCtxRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}
impl Drop for EvpPkeyCtx {
    fn drop(&mut self) {
        unsafe {
            boring_sys::EVP_PKEY_CTX_free(self.0.as_ptr());
        }
    }
}

impl core::fmt::Debug for EvpPkeyCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("EvpPkeyCtx").field(&self.0).finish()
    }
}

impl Deref for EvpPkeyCtx {
    type Target = EvpPkeyCtxRef;

    fn deref(&self) -> &EvpPkeyCtxRef {
        unsafe { EvpPkeyCtxRef::from_ptr(self.as_ptr()) }
    }
}

impl DerefMut for EvpPkeyCtx {
    fn deref_mut(&mut self) -> &mut EvpPkeyCtxRef {
        unsafe { EvpPkeyCtxRef::from_ptr_mut(self.as_ptr()) }
    }
}
