# boring-rustls-provider

[![Build Status](https://github.com/janrueth/boring-rustls-provider/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/janrueth/boring-rustls-provider/actions/workflows/ci.yml?query=branch%3Amain)

A [BoringSSL](https://github.com/cloudflare/boring)-based [rustls](https://github.com/rustls/rustls) crypto provider.

Built on `boring` v5 and `rustls` 0.23.

## Features

No features are enabled by default. The provider ships with TLS 1.3 support
out of the box; additional capabilities are opt-in.

| Feature | Description |
|---|---|
| `fips` | Build against FIPS-validated BoringSSL and restrict the provider to FIPS-approved algorithms only (SP 800-52r2). See [FIPS mode](#fips-mode) below. |
| `fips-precompiled` | Deprecated alias for `fips`. Matches the `boring` crate's feature name. |
| `tls12` | Enable TLS 1.2 cipher suites (`ECDHE-ECDSA` and `ECDHE-RSA` with AES-GCM and ChaCha20-Poly1305). Without this only TLS 1.3 is available. |
| `logging` | Enable debug logging of BoringSSL errors and provider internals via the `log` crate. |

## Supported Algorithms

### Cipher Suites

TLS 1.3 (always available):
```
AES_128_GCM_SHA256
AES_256_GCM_SHA384
CHACHA20_POLY1305_SHA256
```

TLS 1.2 (requires `tls12` feature):
```
ECDHE_ECDSA_AES128_GCM_SHA256
ECDHE_RSA_AES128_GCM_SHA256
ECDHE_ECDSA_AES256_GCM_SHA384
ECDHE_RSA_AES256_GCM_SHA384
ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
```

### Key Exchange Groups

ECDHE:
```
X25519
X448
secp256r1 (P-256)
secp384r1 (P-384)
secp521r1 (P-521)
```

FFDHE:
```
ffdhe2048
```

### Signature Algorithms

```
RSA_PKCS1_SHA256
RSA_PKCS1_SHA384
RSA_PKCS1_SHA512
RSA_PSS_SHA256
RSA_PSS_SHA384
RSA_PSS_SHA512
ECDSA_NISTP256_SHA256
ECDSA_NISTP384_SHA384
ECDSA_NISTP521_SHA512
ED25519
ED448
```

## FIPS Mode

When the `fips` feature is enabled the provider builds against a FIPS-validated
version of BoringSSL and restricts all algorithm selections to those approved
under [SP 800-52r2](https://doi.org/10.6028/NIST.SP.800-52r2), aligned with
boring's `fips202205` compliance policy:

- **Cipher suites**: AES-GCM only (no ChaCha20-Poly1305).
- **Key exchange groups**: P-256 and P-384 only (no X25519, X448, P-521, or FFDHE).
- **Signature algorithms**: RSA PKCS#1 / PSS and ECDSA with P-256 or P-384 only
  (no P-521, Ed25519, or Ed448).

Post-quantum hybrid key exchange (`P256Kyber768Draft00`) is planned for the
FIPS group set but not yet implemented.

## Workspace Structure

| Crate | Purpose |
|---|---|
| `boring-rustls-provider` | The main rustls crypto provider. |
| `boring-additions` | Safe Rust wrappers for BoringSSL APIs not yet exposed by the `boring` crate (AEAD, EVP_PKEY_CTX, HMAC_CTX). Intended for upstreaming. |
| `boring-sys-additions` | Raw FFI binding for `CRYPTO_tls1_prf` (internal BoringSSL symbol used for FIPS-compliant TLS 1.2 PRF). Intended for upstreaming. |
| `examples` | Example client binary. |

## License

MIT
