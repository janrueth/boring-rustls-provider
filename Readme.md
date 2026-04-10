# boring-rustls-provider

[![Build Status](https://github.com/janrueth/boring-rustls-provider/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/janrueth/boring-rustls-provider/actions/workflows/ci.yml?query=branch%3Amain)

A [BoringSSL](https://github.com/cloudflare/boring)-based [rustls](https://github.com/rustls/rustls) crypto provider.

Built on `boring` v5 and `rustls` 0.23.

## Features

No features are enabled by default. The provider ships with TLS 1.3 support
out of the box; additional capabilities are opt-in.

| Feature | Description |
|---|---|
| `fips` | Build against FIPS-validated BoringSSL and restrict the provider to FIPS-approved algorithms only (SP 800-52r2). Implies `mlkem`. See [FIPS mode](#fips-mode) below. |
| `fips-precompiled` | Deprecated alias for `fips`. Matches the `boring` crate's feature name. |
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

Matches boring's default supported group list:

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

When the `fips` feature is enabled the provider builds against a FIPS-validated
version of BoringSSL and restricts all algorithm selections to those approved
under [SP 800-52r2](https://doi.org/10.6028/NIST.SP.800-52r2), aligned with
boring's `fips202205` compliance policy:

- **Cipher suites**: AES-GCM only (no ChaCha20-Poly1305).
- **Key exchange groups**: X25519MLKEM768 (preferred), P-256, and P-384 only
  (no standalone X25519).
- **Signature algorithms**: RSA PKCS#1 / PSS and ECDSA with P-256 or P-384 only
  (no P-521, Ed25519, or Ed448).

## Workspace Structure

| Crate | Purpose |
|---|---|
| `boring-rustls-provider` | The main rustls crypto provider. |
| `boring-additions` | Safe Rust wrappers for BoringSSL APIs not yet exposed by the `boring` crate (AEAD, EVP_PKEY_CTX, HMAC_CTX). Intended for upstreaming. |
| `boring-sys-additions` | Raw FFI binding for `CRYPTO_tls1_prf` (internal BoringSSL symbol used for FIPS-compliant TLS 1.2 PRF). Intended for upstreaming. |
| `examples` | Example client binary. |

## License

MIT
