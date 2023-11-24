use std::{
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

use foreign_types::{ForeignType, ForeignTypeRef, Opaque};

use crate::helper::{cvt, cvt_p};

pub struct HmacCtxRef(Opaque);

unsafe impl ForeignTypeRef for HmacCtxRef {
    type CType = boring_sys::HMAC_CTX;
}

unsafe impl Sync for HmacCtxRef {}
unsafe impl Send for HmacCtxRef {}

pub struct HmacCtx(NonNull<boring_sys::HMAC_CTX>);

unsafe impl Sync for HmacCtx {}
unsafe impl Send for HmacCtx {}

unsafe impl ForeignType for HmacCtx {
    type CType = boring_sys::HMAC_CTX;

    type Ref = HmacCtxRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}

impl Clone for HmacCtx {
    fn clone(&self) -> Self {
        unsafe {
            cvt_p(boring_sys::HMAC_CTX_new())
                .map(|ctx| HmacCtx::from_ptr(ctx))
                .and_then(|ctx| {
                    cvt(boring_sys::HMAC_CTX_copy(ctx.as_ptr(), self.0.as_ptr()))?;
                    Ok(ctx)
                })
        }
        .expect("failed cloning hmac ctx")
    }
}

impl Drop for HmacCtx {
    fn drop(&mut self) {
        unsafe {
            boring_sys::HMAC_CTX_free(self.0.as_ptr());
        }
    }
}

impl Deref for HmacCtx {
    type Target = HmacCtxRef;

    fn deref(&self) -> &HmacCtxRef {
        unsafe { Self::Target::from_ptr(self.as_ptr()) }
    }
}

impl DerefMut for HmacCtx {
    fn deref_mut(&mut self) -> &mut HmacCtxRef {
        unsafe { HmacCtxRef::from_ptr_mut(self.as_ptr()) }
    }
}
