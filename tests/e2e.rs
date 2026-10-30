use rcgen::CertificateParams;
use std::sync::Arc;
#[cfg(feature = "mldsa")]
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use boring_rustls_provider::tls13;
#[cfg(feature = "tls12")]
use rustls::version::TLS12;
use rustls::{ClientConfig, ServerConfig, SupportedCipherSuite, version::TLS13};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[cfg(feature = "mldsa")]
#[derive(Debug)]
struct MlDsa44HandshakeVerifier {
    verified_tls13_signature: Arc<AtomicBool>,
}

#[cfg(feature = "mldsa")]
impl rustls::client::danger::ServerCertVerifier for MlDsa44HandshakeVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "ML-DSA is not supported in TLS 1.2".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        assert_eq!(dss.scheme, rustls::SignatureScheme::ML_DSA_44);
        let provider = boring_rustls_provider::provider();
        let verified = rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )?;
        self.verified_tls13_signature.store(true, Ordering::Relaxed);
        Ok(verified)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ML_DSA_44]
    }
}

#[cfg(feature = "mldsa")]
fn rfc9881_mldsa44_credentials() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = CertificateDer::from(
        include_bytes!("fixtures/mldsa44-rfc9881.der")
            .as_slice()
            .to_vec(),
    );
    let mut key = vec![
        0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x03, 0x11, 0x04, 0x22, 0x80, 0x20,
    ];
    key.extend(0u8..32);
    (cert, PrivatePkcs8KeyDer::from(key).into())
}

fn tls13_provider_suites() -> Vec<SupportedCipherSuite> {
    boring_rustls_provider::provider()
        .cipher_suites
        .into_iter()
        .filter(|suite| matches!(suite, SupportedCipherSuite::Tls13(_)))
        .collect()
}

#[cfg(feature = "tls12")]
fn tls12_provider_suites_for_ecdsa() -> Vec<SupportedCipherSuite> {
    boring_rustls_provider::provider()
        .cipher_suites
        .into_iter()
        .filter(|suite| {
            let SupportedCipherSuite::Tls12(suite) = suite else {
                return false;
            };

            suite.sign.iter().any(|scheme| {
                matches!(
                    scheme,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256
                        | rustls::SignatureScheme::ECDSA_NISTP384_SHA384
                        | rustls::SignatureScheme::ECDSA_NISTP521_SHA512
                        | rustls::SignatureScheme::ED25519
                        | rustls::SignatureScheme::ED448
                )
            })
        })
        .collect()
}

#[cfg(feature = "tls12")]
fn tls12_provider_suites_for_rsa() -> Vec<SupportedCipherSuite> {
    boring_rustls_provider::provider()
        .cipher_suites
        .into_iter()
        .filter(|suite| {
            let SupportedCipherSuite::Tls12(suite) = suite else {
                return false;
            };

            suite.sign.iter().any(|scheme| {
                matches!(
                    scheme,
                    rustls::SignatureScheme::RSA_PKCS1_SHA256
                        | rustls::SignatureScheme::RSA_PKCS1_SHA384
                        | rustls::SignatureScheme::RSA_PKCS1_SHA512
                        | rustls::SignatureScheme::RSA_PSS_SHA256
                        | rustls::SignatureScheme::RSA_PSS_SHA384
                        | rustls::SignatureScheme::RSA_PSS_SHA512
                )
            })
        })
        .collect()
}

#[tokio::test]
async fn test_tls13_crypto() {
    let pki = TestPki::new(&rcgen::PKCS_ECDSA_P256_SHA256);

    let root_store = pki.client_root_store();
    let server_config = pki.server_config();

    let ciphers = tls13_provider_suites();

    for cipher in ciphers {
        let config = ClientConfig::builder_with_provider(Arc::new(
            boring_rustls_provider::provider_with_ciphers([cipher].to_vec()),
        ))
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(root_store.clone())
        .with_no_client_auth();

        do_exchange(config, server_config.clone()).await;
    }
}

#[test]
fn provider_kx_groups_reject_invalid_peer_keys_without_panicking() {
    for group in boring_rustls_provider::provider().kx_groups {
        let kx = group.start().expect("provider KX group should initialize");

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| kx.complete(&[])));
        assert!(outcome.is_ok(), "KX group {:?} panicked", group.name());
        assert!(
            outcome.expect("already checked for panic").is_err(),
            "KX group {:?} accepted an invalid key share",
            group.name()
        );
    }
}

#[test]
fn provider_verifiers_reject_malformed_inputs_without_panicking() {
    let provider = boring_rustls_provider::provider();

    for (index, verifier) in provider
        .signature_verification_algorithms
        .all
        .iter()
        .enumerate()
    {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verifier.verify_signature(&[], b"message", &[])
        }));

        assert!(outcome.is_ok(), "verifier #{index} panicked");
        assert!(
            outcome.expect("already checked for panic").is_err(),
            "verifier #{index} accepted malformed inputs"
        );
    }
}

#[test]
#[cfg(feature = "mldsa")]
fn provider_exposes_all_mldsa_schemes_first() {
    use rustls::SignatureScheme;

    let provider = boring_rustls_provider::provider();
    let schemes = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .map(|(scheme, _)| *scheme)
        .collect::<Vec<_>>();

    assert_eq!(
        &schemes[..3],
        &[
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ]
    );
}

#[tokio::test]
#[cfg(feature = "mldsa")]
async fn mldsa44_completes_tls13_handshake() {
    let (cert, key) = rfc9881_mldsa44_credentials();
    let server_config =
        ServerConfig::builder_with_provider(Arc::new(boring_rustls_provider::provider()))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();

    let verified = Arc::new(AtomicBool::new(false));
    let verifier = MlDsa44HandshakeVerifier {
        verified_tls13_signature: verified.clone(),
    };
    let client_config =
        ClientConfig::builder_with_provider(Arc::new(boring_rustls_provider::provider()))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

    do_exchange(client_config, Arc::new(server_config)).await;
    assert!(verified.load(Ordering::Relaxed));
}

#[tokio::test]
#[cfg(all(feature = "mldsa", feature = "tls12"))]
async fn mldsa_is_not_negotiated_for_tls12() {
    let (cert, key) = rfc9881_mldsa44_credentials();
    let server_config =
        ServerConfig::builder_with_provider(Arc::new(boring_rustls_provider::provider()))
            .with_protocol_versions(&[&TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
    let verifier = MlDsa44HandshakeVerifier {
        verified_tls13_signature: Arc::new(AtomicBool::new(false)),
    };
    let client_config =
        ClientConfig::builder_with_provider(Arc::new(boring_rustls_provider::provider()))
            .with_protocol_versions(&[&TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        TlsAcceptor::from(Arc::new(server_config))
            .accept(stream)
            .await
    });
    let stream = TcpStream::connect(addr).await.unwrap();
    let client_result = TlsConnector::from(Arc::new(client_config))
        .connect(
            rustls_pki_types::ServerName::try_from("localhost").unwrap(),
            stream,
        )
        .await;

    assert!(client_result.is_err());
    assert!(server.await.unwrap().is_err());
}

/// Self-to-self TLS 1.3 handshake using only the X25519MLKEM768 PQ hybrid group.
#[cfg(feature = "mlkem")]
#[tokio::test]
async fn test_tls13_pq_x25519_mlkem768() {
    use rustls::NamedGroup;

    let pki = TestPki::new(&rcgen::PKCS_ECDSA_P256_SHA256);

    let root_store = pki.client_root_store();

    // Build server with only X25519MLKEM768
    let server_provider =
        boring_rustls_provider::provider_with_ciphers(vec![SupportedCipherSuite::Tls13(
            &tls13::AES_256_GCM_SHA384,
        )]);
    let server_config = {
        let mut cfg = ServerConfig::builder_with_provider(Arc::new(server_provider))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![pki.server_cert_der.clone()],
                pki.server_key_der.clone_key(),
            )
            .unwrap();
        cfg.key_log = Arc::new(rustls::KeyLogFile::new());
        Arc::new(cfg)
    };

    // Build client with only X25519MLKEM768
    let client_provider =
        boring_rustls_provider::provider_with_ciphers(vec![SupportedCipherSuite::Tls13(
            &tls13::AES_256_GCM_SHA384,
        )]);
    let config = ClientConfig::builder_with_provider(Arc::new(client_provider))
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let negotiated_group = do_exchange(config, server_config).await;
    assert_eq!(negotiated_group, Some(NamedGroup::X25519MLKEM768));
}

/// Connect to Cloudflare's PQ test endpoint and verify X25519MLKEM768
/// was actually negotiated by checking the `/cdn-cgi/trace` response.
/// Marked `#[ignore]` because it depends on an external service.
#[cfg(feature = "mlkem")]
#[ignore]
#[tokio::test]
async fn test_pq_interop_cloudflare() {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = boring_rustls_provider::provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect("pq.cloudflareresearch.com:443")
        .await
        .unwrap();

    let mut stream = connector
        .connect(
            rustls_pki_types::ServerName::try_from("pq.cloudflareresearch.com").unwrap(),
            stream,
        )
        .await
        .expect("TLS handshake with pq.cloudflareresearch.com failed");

    // Hit the trace endpoint which reports negotiated TLS parameters
    stream
        .write_all(
            b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: pq.cloudflareresearch.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);

    // Verify TLS 1.3 was used
    assert!(
        response.contains("tls=TLSv1.3"),
        "expected TLSv1.3, got: {response}"
    );

    // Verify X25519MLKEM768 was negotiated as the key exchange
    assert!(
        response.contains("kex=X25519MLKEM768"),
        "expected kex=X25519MLKEM768, got: {response}"
    );
}

/// Connect to Cloudflare with TLS 1.2 forced and verify that a classical
/// key exchange is used (PQ groups are TLS 1.3 only).
/// Marked `#[ignore]` because it depends on an external service.
#[cfg(all(feature = "mlkem", feature = "tls12"))]
#[ignore]
#[tokio::test]
async fn test_tls12_interop_cloudflare_no_pq() {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = boring_rustls_provider::provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS12])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect("pq.cloudflareresearch.com:443")
        .await
        .unwrap();

    let mut stream = connector
        .connect(
            rustls_pki_types::ServerName::try_from("pq.cloudflareresearch.com").unwrap(),
            stream,
        )
        .await
        .expect("TLS handshake with pq.cloudflareresearch.com (TLS 1.2) failed");

    stream
        .write_all(
            b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: pq.cloudflareresearch.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);

    // Verify TLS 1.2 was used
    assert!(
        response.contains("tls=TLSv1.2"),
        "expected TLSv1.2, got: {response}"
    );

    // Verify a classical key exchange was used (not PQ)
    assert!(
        !response.contains("kex=X25519MLKEM768"),
        "TLS 1.2 should not use PQ key exchange, got: {response}"
    );
}

#[test]
#[cfg(feature = "fips")]
fn is_fips_enabled() {
    assert!(boring::fips::enabled());
}

#[test]
#[cfg(feature = "fips")]
fn fips_provider_excludes_chacha20_cipher_suites() {
    use rustls::CipherSuite;

    let provider = boring_rustls_provider::provider();
    let disallowed = [
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    for suite in provider.cipher_suites {
        let selected = suite.suite();
        assert!(
            !disallowed.contains(&selected),
            "FIPS provider exposed disallowed cipher suite: {selected:?}"
        );
    }
}

#[test]
#[cfg(feature = "fips")]
fn fips_provider_with_ciphers_filters_non_fips_input() {
    use rustls::CipherSuite;

    let provider = boring_rustls_provider::provider_with_ciphers(vec![
        SupportedCipherSuite::Tls13(&tls13::CHACHA20_POLY1305_SHA256),
        SupportedCipherSuite::Tls13(&tls13::AES_128_GCM_SHA256),
    ]);

    let suites = provider
        .cipher_suites
        .iter()
        .map(|suite| suite.suite())
        .collect::<Vec<_>>();

    assert_eq!(suites, vec![CipherSuite::TLS13_AES_128_GCM_SHA256]);
}

#[test]
#[cfg(feature = "fips")]
fn fips_provider_rejects_noncanonical_suite_with_approved_codepoint() {
    let canonical = &tls13::AES_128_GCM_SHA256;
    let noncanonical = Box::leak(Box::new(rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: canonical.common.suite,
            hash_provider: canonical.common.hash_provider,
            confidentiality_limit: canonical.common.confidentiality_limit,
        },
        hkdf_provider: canonical.hkdf_provider,
        aead_alg: canonical.aead_alg,
        quic: canonical.quic,
    }));

    // rustls compares suites by codepoint, so these are equal despite carrying
    // distinct implementation objects.
    assert_eq!(canonical, noncanonical);

    let provider = boring_rustls_provider::provider_with_ciphers(vec![
        SupportedCipherSuite::Tls13(noncanonical),
        SupportedCipherSuite::Tls13(canonical),
    ]);

    assert_eq!(provider.cipher_suites.len(), 1);
    let SupportedCipherSuite::Tls13(selected) = provider.cipher_suites[0] else {
        panic!("expected a TLS 1.3 cipher suite");
    };
    assert!(std::ptr::eq(selected, canonical));
}

#[test]
#[cfg(feature = "fips")]
fn fips_provider_restricts_kx_groups() {
    use rustls::NamedGroup;

    let provider = boring_rustls_provider::provider();
    let groups = provider
        .kx_groups
        .iter()
        .map(|group| group.name())
        .collect::<Vec<_>>();

    // fips implies mlkem, so X25519MLKEM768 must be present and preferred
    assert_eq!(
        groups[0],
        NamedGroup::X25519MLKEM768,
        "X25519MLKEM768 should be the first (preferred) FIPS KX group"
    );
    assert!(groups.contains(&NamedGroup::secp256r1));
    assert!(groups.contains(&NamedGroup::secp384r1));
    for group in &groups {
        assert!(
            matches!(
                group,
                NamedGroup::X25519MLKEM768 | NamedGroup::secp256r1 | NamedGroup::secp384r1
            ),
            "FIPS provider exposed disallowed KX group: {group:?}"
        );
    }
}

#[test]
#[cfg(feature = "fips")]
fn fips_provider_excludes_disallowed_signature_schemes() {
    use rustls::SignatureScheme;

    let provider = boring_rustls_provider::provider();
    let schemes = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .map(|(scheme, _)| *scheme)
        .collect::<Vec<_>>();

    assert!(schemes.contains(&SignatureScheme::RSA_PSS_SHA256));
    assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
    assert!(schemes.contains(&SignatureScheme::ML_DSA_44));
    assert!(schemes.contains(&SignatureScheme::ML_DSA_65));
    assert!(schemes.contains(&SignatureScheme::ML_DSA_87));

    for disallowed in [
        SignatureScheme::ECDSA_NISTP521_SHA512,
        SignatureScheme::ED25519,
        SignatureScheme::ED448,
    ] {
        assert!(
            !schemes.contains(&disallowed),
            "FIPS provider exposed disallowed signature scheme: {disallowed:?}"
        );
    }
}

#[test]
#[cfg(all(feature = "fips", feature = "tls12"))]
fn fips_tls12_suites_exclude_disallowed_signature_schemes() {
    use rustls::{CipherSuite, SignatureScheme};

    let provider = boring_rustls_provider::provider();
    let mut checked_suites = 0;
    for suite in provider.cipher_suites {
        let SupportedCipherSuite::Tls12(suite) = suite else {
            continue;
        };
        if !matches!(
            suite.common.suite,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        ) {
            continue;
        }

        checked_suites += 1;
        assert_eq!(
            suite.sign,
            &[
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
            ]
        );
    }
    assert_eq!(checked_suites, 2);
}

#[test]
#[cfg(not(feature = "fips"))]
fn is_fips_disabled() {
    assert!(!boring::fips::enabled());
}

#[test]
#[cfg(not(feature = "fips"))]
fn non_fips_provider_keeps_non_fips_algorithms() {
    use rustls::{CipherSuite, NamedGroup};

    let provider = boring_rustls_provider::provider();

    assert!(
        provider
            .cipher_suites
            .iter()
            .any(|suite| { suite.suite() == CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 })
    );

    assert!(
        provider
            .kx_groups
            .iter()
            .any(|group| group.name() == NamedGroup::X25519)
    );
}

#[test]
#[cfg(not(feature = "fips"))]
fn non_fips_provider_components_report_non_fips() {
    let provider = boring_rustls_provider::provider();

    assert!(!provider.secure_random.fips());
    assert!(!provider.key_provider.fips());
}

#[test]
#[cfg(not(feature = "fips"))]
fn non_fips_provider_with_ciphers_keeps_requested_suites() {
    use rustls::CipherSuite;

    let provider = boring_rustls_provider::provider_with_ciphers(vec![
        SupportedCipherSuite::Tls13(&tls13::CHACHA20_POLY1305_SHA256),
        SupportedCipherSuite::Tls13(&tls13::AES_128_GCM_SHA256),
    ]);

    let suites = provider
        .cipher_suites
        .iter()
        .map(|suite| suite.suite())
        .collect::<Vec<_>>();

    assert_eq!(
        suites,
        vec![
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
        ]
    );
}

#[test]
#[cfg(all(not(feature = "fips"), feature = "mlkem"))]
fn non_fips_provider_includes_pq_group() {
    use rustls::NamedGroup;

    let provider = boring_rustls_provider::provider();
    let groups = provider
        .kx_groups
        .iter()
        .map(|group| group.name())
        .collect::<Vec<_>>();

    assert_eq!(
        groups[0],
        NamedGroup::X25519MLKEM768,
        "X25519MLKEM768 should be the first (preferred) KX group"
    );
    assert_eq!(
        groups[1],
        NamedGroup::X25519,
        "X25519 should be the first classical fallback"
    );
    assert_eq!(
        groups[2],
        NamedGroup::secp256r1,
        "P-256 should follow X25519, matching boring's default order"
    );
}

#[cfg(feature = "tls12")]
#[tokio::test]
async fn test_tls12_ec_crypto() {
    let pki = TestPki::new(&rcgen::PKCS_ECDSA_P256_SHA256);

    let root_store = pki.client_root_store();
    let server_config = pki.server_config();

    let ciphers = tls12_provider_suites_for_ecdsa();

    for cipher in ciphers {
        let config = ClientConfig::builder_with_provider(Arc::new(
            boring_rustls_provider::provider_with_ciphers([cipher].to_vec()),
        ))
        .with_protocol_versions(&[&TLS12])
        .unwrap()
        .with_root_certificates(root_store.clone())
        .with_no_client_auth();

        do_exchange(config, server_config.clone()).await;
    }
}

#[cfg(feature = "tls12")]
#[tokio::test]
async fn test_tls12_rsa_crypto() {
    let pki = TestPki::new(&rcgen::PKCS_RSA_SHA256);

    let root_store = pki.client_root_store();
    let server_config = pki.server_config();

    let ciphers = tls12_provider_suites_for_rsa();

    for cipher in ciphers {
        let config = ClientConfig::builder_with_provider(Arc::new(
            boring_rustls_provider::provider_with_ciphers([cipher].to_vec()),
        ))
        .with_protocol_versions(&[&TLS12])
        .unwrap()
        .with_root_certificates(root_store.clone())
        .with_no_client_auth();

        do_exchange(config, server_config.clone()).await;
    }
}

async fn new_listener() -> TcpListener {
    TcpListener::bind("localhost:0").await.unwrap()
}

async fn do_exchange(
    config: ClientConfig,
    server_config: Arc<ServerConfig>,
) -> Option<rustls::NamedGroup> {
    let listener = new_listener().await;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(spawn_echo_server(listener, server_config.clone()));

    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(&addr).await.unwrap();

    let mut stream = connector
        .connect(
            rustls_pki_types::ServerName::try_from("localhost").unwrap(),
            stream,
        )
        .await
        .unwrap();

    let negotiated_group = stream
        .get_ref()
        .1
        .negotiated_key_exchange_group()
        .map(|group| group.name());

    stream.write_all(b"HELLO").await.unwrap();
    let mut buf = Vec::new();
    let bytes = stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(&buf[..bytes], b"HELLO");

    negotiated_group
}

async fn spawn_echo_server(listener: TcpListener, config: Arc<ServerConfig>) {
    let acceptor = TlsAcceptor::from(config);

    let (stream, _) = listener.accept().await.unwrap();
    let acceptor = acceptor.clone();
    let mut stream = acceptor.accept(stream).await.unwrap();

    let mut buf = vec![0u8; 5];
    let bytes = stream.read_exact(buf.as_mut_slice()).await.unwrap();
    stream.write_all(&buf[..bytes]).await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();
}

struct TestPki {
    ca_cert_der: CertificateDer<'static>,
    server_cert_der: CertificateDer<'static>,
    server_key_der: PrivateKeyDer<'static>,
}

impl TestPki {
    fn new(alg: &'static rcgen::SignatureAlgorithm) -> Self {
        let mut ca_params = rcgen::CertificateParams::new(Vec::new());
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Provider Server Example");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        keypair_for_alg(&mut ca_params, alg);
        ca_params.alg = alg;
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        let ca_cert_der = CertificateDer::from(ca_cert.serialize_der().unwrap());
        // Create a server end entity cert issued by the CA.
        let mut server_ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        server_ee_params.alg = alg;
        keypair_for_alg(&mut server_ee_params, alg);
        let server_cert = rcgen::Certificate::from_params(server_ee_params).unwrap();
        let server_cert_der =
            CertificateDer::from(server_cert.serialize_der_with_signer(&ca_cert).unwrap());
        let server_key_der =
            PrivatePkcs8KeyDer::from(server_cert.serialize_private_key_der()).into();
        Self {
            ca_cert_der,
            server_cert_der,
            server_key_der,
        }
    }

    fn server_config(self) -> Arc<ServerConfig> {
        #[cfg(feature = "tls12")]
        let versions: &[&'static rustls::SupportedProtocolVersion] = &[&TLS12, &TLS13];
        #[cfg(not(feature = "tls12"))]
        let versions: &[&'static rustls::SupportedProtocolVersion] = &[&TLS13];

        let mut server_config =
            ServerConfig::builder_with_provider(Arc::new(boring_rustls_provider::provider()))
                .with_protocol_versions(versions)
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![self.server_cert_der], self.server_key_der)
                .unwrap();

        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(server_config)
    }

    fn client_root_store(&self) -> rustls::RootCertStore {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(self.ca_cert_der.clone()).unwrap();
        root_store
    }
}

fn gen_rsa_key(bits: u32) -> rcgen::KeyPair {
    let rsa = boring::rsa::Rsa::generate(bits).unwrap();

    let der_pkcs8 = boring::pkey::PKey::from_rsa(rsa)
        .unwrap()
        .private_key_to_der_pkcs8()
        .unwrap();
    rcgen::KeyPair::from_der(&der_pkcs8).unwrap()
}

fn keypair_for_alg(params: &mut CertificateParams, alg: &rcgen::SignatureAlgorithm) {
    if alg == &rcgen::PKCS_RSA_SHA256 {
        params.key_pair = Some(gen_rsa_key(2048));
    } else if alg == &rcgen::PKCS_RSA_SHA384 {
        params.key_pair = Some(gen_rsa_key(3072));
    } else if alg == &rcgen::PKCS_RSA_SHA512 {
        params.key_pair = Some(gen_rsa_key(4096));
    }
}
