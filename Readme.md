# boring-rustls-provider

This is supposed to be the start to a [boringssl](https://github.com/cloudflare/boring)-based [rustls](https://github.com/rustls/rustls) crypto provider.

## Status
This is just a dump of me figuring out how to interface with boring and rustls.
It works to establish a connection and exchange data but I haven't written real tests yet, nor did I cleanup the code or made the effort to make it look nice.
There is probably some code in here that should rather live in the `boring` crate.

Further, the rustls crypto provider API is still not stable it seems. This works currently with `rustls = 0.22.0-alpha.4`.

### Supported ciphers
Currently, supports only TLS 1.3:
```
AES_128_GCM_SHA256
AES_256_GCM_SHA384
CHACHA20_POLY1305_SHA256
```

TLS 1.2 prepared for (doesn't work yet):
```
ECDHE_ECDSA_AES128_GCM_SHA256
ECDHE_RSA_AES128_GCM_SHA256

ECDHE_ECDSA_AES256_GCM_SHA384
ECDHE_RSA_AES256_GCM_SHA384

ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
```

### Key Exchange Algorithms
 
`ECDHE` with curves:
```
X25519
X448
secp256r1
secp384r1
secp521r1
```


`FFDHE` with:
```
ffdhe2048
```

### Signature Generation / Verification

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


## License
MIT
