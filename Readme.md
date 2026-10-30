# boring-rustls-provider

[![Crates.io Version](https://img.shields.io/crates/v/boring-rustls-provider)](https://crates.io/crates/boring-rustls-provider/)
[![docs.rs](https://img.shields.io/docsrs/boring-rustls-provider)](https://docs.rs/boring-rustls-provider/latest/boring_rustls_provider/)
[![Build Status](https://github.com/janrueth/boring-rustls-provider/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/janrueth/boring-rustls-provider/actions/workflows/ci.yml?query=branch%3Amain)


A [BoringSSL](https://github.com/cloudflare/boring)-based [rustls](https://github.com/rustls/rustls) crypto provider.

Built on `boring` v5 and `rustls` 0.23.

## Versioning

Version 5 was the first release of this crate, version-matched to `boring` v5.
Going forward, major versions track **rustls** breaking changes rather than
`boring` versions:

| `boring-rustls-provider` | `rustls` | `boring` / `boring-sys` | Branch |
|--------------------------|----------|-------------------------|--------|
| v5 | 0.23 | v5 | `v5` |
| v6 | 0.24 | v5 | `main` |

All versions continue to depend on `boring` v5 / `boring-sys` v5 unless those
crates themselves introduce a breaking change.

### Branch strategy

- **`main`** always tracks the latest (or next) major version.
- When work on a new major version begins, a maintenance branch (e.g., `v5`)
  is created from `main` for the prior release series.
- Bugfixes for older versions go to their maintenance branch and are released
  as patch versions.

## Features

The `mldsa` feature is enabled by default. The provider ships with TLS 1.3
support out of the box; other capabilities are opt-in.

| Feature | Description |
|---|---|
| `fips` | Build BoringSSL in FIPS mode and apply the provider's classical algorithm restrictions (SP 800-52r2). Implies `mlkem` and `mldsa`. See [FIPS mode](#fips-mode) below. |
| `fips-precompiled` | Deprecated alias for `fips`. Matches the `boring` crate's feature name. |
| `mldsa` | Enable ML-DSA-44, ML-DSA-65, and ML-DSA-87 certificate verification and TLS 1.3 authentication. Enabled by default; use `--no-default-features` to omit it. |
| `mlkem` | Enable the X25519MLKEM768 post-quantum hybrid key exchange group (`draft-ietf-tls-ecdhe-mlkem-00`). Uses ML-KEM-768 (FIPS 203) combined with X25519. See [Post-quantum key exchange](#post-quantum-key-exchange). |
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

The provider implements the following BoringSSL key exchange groups:

```
X25519MLKEM768 (0x11ec, requires mlkem feature, TLS 1.3 only)
X25519
secp256r1 (P-256)
secp384r1 (P-384)
```

When `mlkem` is enabled, X25519MLKEM768 is the preferred (first) group in both
FIPS and non-FIPS configurations.

### Signature Algorithms

```
ML_DSA_44 (TLS 1.3 only; requires mldsa feature)
ML_DSA_65 (TLS 1.3 only; requires mldsa feature)
ML_DSA_87 (TLS 1.3 only; requires mldsa feature)
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

ML-DSA uses the pure signature form from
[FIPS 204](https://doi.org/10.6028/NIST.FIPS.204), with an empty ML-DSA context,
as specified for TLS 1.3 by
[draft-ietf-tls-mldsa](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/).
ML-DSA public keys and certificate signatures use the identifiers and encodings
from [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881). Private-key loading
accepts RFC 9881's canonical seed-only PKCS#8 form; expanded and combined
private-key forms are not accepted.

## Post-Quantum Key Exchange

The `mlkem` feature enables the **X25519MLKEM768** hybrid key exchange group
per `draft-ietf-tls-ecdhe-mlkem-00`. This combines classical X25519
Diffie-Hellman with ML-KEM-768 (FIPS 203) post-quantum key encapsulation,
ensuring that connections are secure against both classical and quantum
adversaries.

The `fips` feature implies `mlkem`, so X25519MLKEM768 is always available
in FIPS mode.

Wire format (ML-KEM component first in all encodings):
- Client key share: `mlkem_pk(1184) || x25519_pk(32)` = 1216 bytes
- Server key share: `mlkem_ct(1088) || x25519_pk(32)` = 1120 bytes
- Shared secret: `mlkem_ss(32) || x25519_ss(32)` = 64 bytes

Interoperability has been verified against Cloudflare's PQ endpoints
(`pq.cloudflareresearch.com`).

## FIPS Mode

When the `fips` feature is enabled, the provider builds BoringSSL in FIPS mode
and restricts its algorithm selections according to
[SP 800-52r2](https://doi.org/10.6028/NIST.SP.800-52r2):

- **Cipher suites**: AES-GCM only (no ChaCha20-Poly1305).
- **Key exchange groups**: X25519MLKEM768 (preferred), P-256, and P-384 only
  (no standalone X25519).
- **Signature algorithms and keys**: ML-DSA-44/65/87 remain available. Classical
  signatures are restricted to RSA PKCS#1 / PSS with keys of at least 2048 bits
  and ECDSA with P-256 or P-384 only (no P-521, Ed25519, or Ed448).

This crate integrates BoringSSL cryptographic primitives with rustls. It does
not construct a BoringSSL TLS context, so TLS policy is enforced through the
algorithm lists and key provider in the returned rustls `CryptoProvider`.
`provider_with_ciphers` accepts only this crate's canonical FIPS cipher-suite
implementations when the `fips` feature is enabled.

The restrictions above apply to the provider's built-in configuration and key
loading. Applications that replace rustls components—particularly custom
credential resolvers or signing keys—must independently ensure those
components select only approved algorithms and key sizes. Running BoringSSL in
FIPS mode is necessary for this configuration, but does not by itself establish
compliance for an application as a whole.

ML-DSA is standardized by FIPS 204. Its FIPS 140 validation status depends on
the exact BoringSSL module and its validation certificate.

## License

MIT
