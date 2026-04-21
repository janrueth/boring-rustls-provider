use std::sync::Arc;

use boring_rustls_provider::tls13;
#[cfg(any(feature = "tls12", feature = "fips"))]
use rustls::crypto::SignatureScheme;
use rustls::crypto::kx::NamedGroup;
use rustls::crypto::{CipherSuite, Identity};
use rustls::{ClientConfig, ServerConfig, SupportedCipherSuite};
#[cfg(not(feature = "fips"))]
use rustls_pki_types::FipsStatus;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn all_tls13_suites() -> Vec<&'static rustls::Tls13CipherSuite> {
    boring_rustls_provider::provider()
        .tls13_cipher_suites
        .to_vec()
}

#[cfg(feature = "tls12")]
fn all_tls12_suites() -> Vec<&'static rustls::Tls12CipherSuite> {
    boring_rustls_provider::provider()
        .tls12_cipher_suites
        .to_vec()
}

#[cfg(feature = "tls12")]
fn tls12_suites_for_ecdsa() -> Vec<&'static rustls::Tls12CipherSuite> {
    all_tls12_suites()
        .into_iter()
        .filter(|suite| {
            suite.sign.iter().any(|scheme| {
                matches!(
                    scheme,
                    SignatureScheme::ECDSA_NISTP256_SHA256
                        | SignatureScheme::ECDSA_NISTP384_SHA384
                        | SignatureScheme::ECDSA_NISTP521_SHA512
                        | SignatureScheme::ED25519
                        | SignatureScheme::ED448
                )
            })
        })
        .collect()
}

#[cfg(feature = "tls12")]
fn tls12_suites_for_rsa() -> Vec<&'static rustls::Tls12CipherSuite> {
    all_tls12_suites()
        .into_iter()
        .filter(|suite| {
            suite.sign.iter().any(|scheme| {
                matches!(
                    scheme,
                    SignatureScheme::RSA_PKCS1_SHA256
                        | SignatureScheme::RSA_PKCS1_SHA384
                        | SignatureScheme::RSA_PKCS1_SHA512
                        | SignatureScheme::RSA_PSS_SHA256
                        | SignatureScheme::RSA_PSS_SHA384
                        | SignatureScheme::RSA_PSS_SHA512
                )
            })
        })
        .collect()
}

/// Perform a full TLS handshake and data exchange between a client and server
/// in memory (no network). Returns the negotiated key exchange group.
fn do_handshake(
    client_config: ClientConfig,
    server_config: Arc<ServerConfig>,
) -> Option<NamedGroup> {
    let mut client =
        rustls::ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
            .unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();

    // Drive the handshake to completion
    let mut buf = Vec::new();
    loop {
        // client -> server
        buf.clear();
        if client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            server.read_tls(&mut &buf[..]).unwrap();
            server.process_new_packets().unwrap();
        }

        // server -> client
        buf.clear();
        if server.wants_write() {
            server.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            client.read_tls(&mut &buf[..]).unwrap();
            client.process_new_packets().unwrap();
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }

    // Exchange application data
    use std::io::{Read, Write};
    client.writer().write_all(b"HELLO").unwrap();

    buf.clear();
    client.write_tls(&mut buf).unwrap();
    server.read_tls(&mut &buf[..]).unwrap();
    server.process_new_packets().unwrap();

    let mut app_buf = [0u8; 5];
    server.reader().read_exact(&mut app_buf).unwrap();
    assert_eq!(&app_buf, b"HELLO");

    client
        .negotiated_key_exchange_group()
        .map(|group| group.name())
}

struct TestPki {
    ca_cert_der: rustls_pki_types::CertificateDer<'static>,
    server_cert_der: rustls_pki_types::CertificateDer<'static>,
    server_key_der: rustls_pki_types::PrivateKeyDer<'static>,
}

impl TestPki {
    fn new(alg: &'static rcgen::SignatureAlgorithm) -> Self {
        let ca_key = keypair_for_alg(alg);
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
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
        let ca = rcgen::CertifiedIssuer::self_signed(ca_params, &ca_key).unwrap();
        let ca_cert_der = ca.der().clone();

        let server_key = keypair_for_alg(alg);
        let mut server_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_params.is_ca = rcgen::IsCa::NoCa;
        server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = server_params.signed_by(&server_key, &ca).unwrap();
        let server_cert_der = server_cert.der().clone();
        let server_key_der =
            rustls_pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()).into();

        Self {
            ca_cert_der,
            server_cert_der,
            server_key_der,
        }
    }

    fn client_root_store(&self) -> rustls::RootCertStore {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(self.ca_cert_der.clone()).unwrap();
        root_store
    }

    fn server_identity(&self) -> Arc<Identity<'static>> {
        Arc::new(
            Identity::from_cert_chain(vec![self.server_cert_der.clone()])
                .expect("valid cert chain"),
        )
    }

    fn server_config(&self) -> Arc<ServerConfig> {
        let mut cfg = ServerConfig::builder(Arc::new(boring_rustls_provider::provider()))
            .with_no_client_auth()
            .with_single_cert(self.server_identity(), self.server_key_der.clone_key())
            .unwrap();
        cfg.key_log = Arc::new(rustls::KeyLogFile::new());
        Arc::new(cfg)
    }
}

fn keypair_for_alg(alg: &'static rcgen::SignatureAlgorithm) -> rcgen::KeyPair {
    if alg == &rcgen::PKCS_RSA_SHA256 {
        gen_rsa_key(alg, 2048)
    } else if alg == &rcgen::PKCS_RSA_SHA384 {
        gen_rsa_key(alg, 3072)
    } else if alg == &rcgen::PKCS_RSA_SHA512 {
        gen_rsa_key(alg, 4096)
    } else {
        rcgen::KeyPair::generate_for(alg).unwrap()
    }
}

fn gen_rsa_key(alg: &'static rcgen::SignatureAlgorithm, bits: u32) -> rcgen::KeyPair {
    let rsa = boring::rsa::Rsa::generate(bits).unwrap();
    let der_pkcs8 = boring::pkey::PKey::from_rsa(rsa)
        .unwrap()
        .private_key_to_der_pkcs8()
        .unwrap();
    let key_der: rustls_pki_types::PrivateKeyDer<'static> =
        rustls_pki_types::PrivatePkcs8KeyDer::from(der_pkcs8).into();
    rcgen::KeyPair::from_der_and_sign_algo(&key_der, alg).unwrap()
}

// ---------------------------------------------------------------------------
// TLS handshake tests
// ---------------------------------------------------------------------------

#[test]
fn test_tls13_crypto() {
    let pki = TestPki::new(&rcgen::PKCS_ECDSA_P256_SHA256);
    let root_store = pki.client_root_store();
    let server_config = pki.server_config();

    for suite in all_tls13_suites() {
        let config = ClientConfig::builder(Arc::new(
            boring_rustls_provider::provider_with_ciphers(vec![SupportedCipherSuite::Tls13(suite)]),
        ))
        .with_root_certificates(root_store.clone())
        .with_no_client_auth()
        .unwrap();

        do_handshake(config, server_config.clone());
    }
}

#[cfg(feature = "mlkem")]
#[test]
fn test_tls13_pq_x25519_mlkem768() {
    let pki = TestPki::new(&rcgen::PKCS_ECDSA_P256_SHA256);
    let root_store = pki.client_root_store();

    let server_provider =
        boring_rustls_provider::provider_with_ciphers(vec![SupportedCipherSuite::Tls13(
            &tls13::AES_256_GCM_SHA384,
        )]);
    let server_config = {
        let mut cfg = ServerConfig::builder(Arc::new(server_provider))
            .with_no_client_auth()
            .with_single_cert(pki.server_identity(), pki.server_key_der.clone_key())
            .unwrap();
        cfg.key_log = Arc::new(rustls::KeyLogFile::new());
        Arc::new(cfg)
    };

    let client_provider =
        boring_rustls_provider::provider_with_ciphers(vec![SupportedCipherSuite::Tls13(
            &tls13::AES_256_GCM_SHA384,
        )]);
    let config = ClientConfig::builder(Arc::new(client_provider))
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .unwrap();

    let negotiated_group = do_handshake(config, server_config);
    assert_eq!(negotiated_group, Some(NamedGroup::X25519MLKEM768));
}

#[cfg(feature = "tls12")]
#[test]
fn test_tls12_ec_crypto() {
    let pki = TestPki::new(&rcgen::PKCS_ECDSA_P256_SHA256);
    let root_store = pki.client_root_store();
    let server_config = pki.server_config();

    for suite in tls12_suites_for_ecdsa() {
        let config = ClientConfig::builder(Arc::new(
            boring_rustls_provider::provider_with_ciphers(vec![SupportedCipherSuite::Tls12(suite)]),
        ))
        .with_root_certificates(root_store.clone())
        .with_no_client_auth()
        .unwrap();

        do_handshake(config, server_config.clone());
    }
}

#[cfg(feature = "tls12")]
#[test]
fn test_tls12_rsa_crypto() {
    let pki = TestPki::new(&rcgen::PKCS_RSA_SHA256);
    let root_store = pki.client_root_store();
    let server_config = pki.server_config();

    for suite in tls12_suites_for_rsa() {
        let config = ClientConfig::builder(Arc::new(
            boring_rustls_provider::provider_with_ciphers(vec![SupportedCipherSuite::Tls12(suite)]),
        ))
        .with_root_certificates(root_store.clone())
        .with_no_client_auth()
        .unwrap();

        do_handshake(config, server_config.clone());
    }
}

// ---------------------------------------------------------------------------
// Provider unit tests
// ---------------------------------------------------------------------------

#[test]
fn provider_kx_groups_reject_invalid_peer_keys_without_panicking() {
    for group in boring_rustls_provider::provider().kx_groups.iter() {
        let kx = group.start().expect("provider KX group should initialize");

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            kx.into_single().complete(&[])
        }));
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

// ---------------------------------------------------------------------------
// FIPS tests
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "fips")]
fn is_fips_enabled() {
    assert!(boring::fips::enabled());
}

#[test]
#[cfg(feature = "fips")]
fn fips_provider_excludes_chacha20_cipher_suites() {
    let provider = boring_rustls_provider::provider();
    let disallowed = [
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    for suite in provider.tls13_cipher_suites.iter() {
        let selected = suite.common.suite;
        assert!(
            !disallowed.contains(&selected),
            "FIPS provider exposed disallowed TLS 1.3 cipher suite: {selected:?}"
        );
    }
    for suite in provider.tls12_cipher_suites.iter() {
        let selected = suite.common.suite;
        assert!(
            !disallowed.contains(&selected),
            "FIPS provider exposed disallowed TLS 1.2 cipher suite: {selected:?}"
        );
    }
}

#[test]
#[cfg(feature = "fips")]
fn fips_provider_with_ciphers_filters_non_fips_input() {
    let provider = boring_rustls_provider::provider_with_ciphers(vec![
        SupportedCipherSuite::Tls13(&tls13::CHACHA20_POLY1305_SHA256),
        SupportedCipherSuite::Tls13(&tls13::AES_128_GCM_SHA256),
    ]);

    let suites: Vec<_> = provider
        .tls13_cipher_suites
        .iter()
        .map(|suite| suite.common.suite)
        .collect();

    assert_eq!(suites, vec![CipherSuite::TLS13_AES_128_GCM_SHA256]);
}

#[test]
#[cfg(feature = "fips")]
fn fips_provider_restricts_kx_groups() {
    let provider = boring_rustls_provider::provider();
    let groups: Vec<_> = provider
        .kx_groups
        .iter()
        .map(|group| group.name())
        .collect();

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
    let provider = boring_rustls_provider::provider();
    let schemes: Vec<_> = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .map(|(scheme, _)| *scheme)
        .collect();

    assert!(schemes.contains(&SignatureScheme::RSA_PSS_SHA256));
    assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));

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

// ---------------------------------------------------------------------------
// Non-FIPS tests
// ---------------------------------------------------------------------------

#[test]
#[cfg(not(feature = "fips"))]
fn is_fips_disabled() {
    assert!(!boring::fips::enabled());
}

#[test]
#[cfg(not(feature = "fips"))]
fn non_fips_provider_keeps_non_fips_algorithms() {
    let provider = boring_rustls_provider::provider();

    assert!(
        provider
            .tls13_cipher_suites
            .iter()
            .any(|suite| suite.common.suite == CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
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

    assert_eq!(provider.secure_random.fips(), FipsStatus::Unvalidated);
    assert_eq!(provider.key_provider.fips(), FipsStatus::Unvalidated);
}

#[test]
#[cfg(not(feature = "fips"))]
fn non_fips_provider_with_ciphers_keeps_requested_suites() {
    let provider = boring_rustls_provider::provider_with_ciphers(vec![
        SupportedCipherSuite::Tls13(&tls13::CHACHA20_POLY1305_SHA256),
        SupportedCipherSuite::Tls13(&tls13::AES_128_GCM_SHA256),
    ]);

    let suites: Vec<_> = provider
        .tls13_cipher_suites
        .iter()
        .map(|suite| suite.common.suite)
        .collect();

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
    let provider = boring_rustls_provider::provider();
    let groups: Vec<_> = provider
        .kx_groups
        .iter()
        .map(|group| group.name())
        .collect();

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
