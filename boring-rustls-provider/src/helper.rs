use std::os::raw::c_int;

use boring::error::ErrorStack;
#[cfg(feature = "log")]
use log::trace;

/// Check the value returned from a `BoringSSL` ffi call
/// that returns a pointer.
///
/// If the pointer is null, this method returns the
/// [`boring::error::ErrorStack`] as Err, the pointer otherwise.
pub(crate) fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

/// Check the value returned from a `BoringSSL` ffi call that
/// returns a integer.
///
/// Returns the [`boring::error::ErrorStack`] when the result is <= 0.
/// And forwards the return code otherwise
pub(crate) fn cvt(r: c_int) -> Result<i32, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[cfg(feature = "log")]
#[inline(always)]
pub(crate) fn log_and_map<E: core::fmt::Display, T>(func: &'static str, e: E, mapped: T) -> T {
    trace!("failed {}, error: {}", func, e);
    mapped
}

#[cfg(not(feature = "log"))]
pub(crate) fn log_and_map<E: core::fmt::Display, T>(func: &'static str, e: E, mapped: T) -> T {
    mapped
}
