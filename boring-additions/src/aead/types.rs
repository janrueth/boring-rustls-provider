use std::{
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

use foreign_types::{ForeignType, ForeignTypeRef, Opaque};

pub struct EvpAeadCtxRef(Opaque);

unsafe impl ForeignTypeRef for EvpAeadCtxRef {
    type CType = boring_sys::EVP_AEAD_CTX;
}

unsafe impl Sync for EvpAeadCtxRef {}
unsafe impl Send for EvpAeadCtxRef {}

pub struct EvpAeadCtx(NonNull<boring_sys::EVP_AEAD_CTX>);

unsafe impl Sync for EvpAeadCtx {}
unsafe impl Send for EvpAeadCtx {}

unsafe impl ForeignType for EvpAeadCtx {
    type CType = boring_sys::EVP_AEAD_CTX;

    type Ref = EvpAeadCtxRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}

impl Drop for EvpAeadCtx {
    fn drop(&mut self) {
        unsafe {
            boring_sys::EVP_AEAD_CTX_free(self.0.as_ptr());
        }
    }
}

impl Deref for EvpAeadCtx {
    type Target = EvpAeadCtxRef;

    fn deref(&self) -> &EvpAeadCtxRef {
        unsafe { EvpAeadCtxRef::from_ptr(self.as_ptr()) }
    }
}

impl DerefMut for EvpAeadCtx {
    fn deref_mut(&mut self) -> &mut EvpAeadCtxRef {
        unsafe { EvpAeadCtxRef::from_ptr_mut(self.as_ptr()) }
    }
}
