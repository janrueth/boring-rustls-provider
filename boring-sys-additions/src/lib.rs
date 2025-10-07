use std::ffi;

extern "C" {
    /// Calculates `out_len` bytes of the TLS PRF, using `digest`, and
    /// writes them to `out`. It returns one on success and zero on error.
    ///
    /// This isn't part of the public headers in `BoringSSL` but it is exported
    /// in `crypto/fipsmodule/tls/internal.h` :)
    pub fn CRYPTO_tls1_prf(
        digest: *const boring_sys::EVP_MD,
        out: *mut u8,
        out_len: usize,
        secret: *const u8,
        secret_len: usize,
        label: *const u8,
        label_len: usize,
        seed1: *const u8,
        seed1_len: usize,
        seed2: *const u8,
        seed2_len: usize,
    ) -> ffi::c_int;
}
