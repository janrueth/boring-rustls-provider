use rcgen::CertificateParams;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use boring_rustls_provider::{tls12, tls13};
use rustls::{
    version::{TLS12, TLS13},
    ClientConfig, ServerConfig, SupportedCipherSuite,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test]
async fn test_tls13_crypto() {
    let pki = TestPki::new(&rcgen::PKCS_ECDSA_P256_SHA256);

    let root_store = pki.client_root_store();
    let server_config = pki.server_config();

    let ciphers = [
        SupportedCipherSuite::Tls13(&tls13::AES_128_GCM_SHA256),
        SupportedCipherSuite::Tls13(&tls13::AES_256_GCM_SHA384),
        SupportedCipherSuite::Tls13(&tls13::CHACHA20_POLY1305_SHA256),
    ];

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
#[cfg(any(feature = "fips", feature = "fips-only"))]
fn is_fips_enabled() {
    assert!(boring::fips::enabled());
}

#[test]
#[cfg(not(any(feature = "fips", feature = "fips-only")))]
fn is_fips_disabled() {
    assert!(!boring::fips::enabled());
}

#[tokio::test]
async fn test_tls12_ec_crypto() {
    let pki = TestPki::new(&rcgen::PKCS_ECDSA_P256_SHA256);

    let root_store = pki.client_root_store();
    let server_config = pki.server_config();

    let ciphers = [
        SupportedCipherSuite::Tls12(&tls12::ECDHE_ECDSA_AES128_GCM_SHA256),
        SupportedCipherSuite::Tls12(&tls12::ECDHE_ECDSA_AES256_GCM_SHA384),
        SupportedCipherSuite::Tls12(&tls12::ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
    ];

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

#[tokio::test]
async fn test_tls12_rsa_crypto() {
    let pki = TestPki::new(&rcgen::PKCS_RSA_SHA256);

    let root_store = pki.client_root_store();
    let server_config = pki.server_config();

    let ciphers = [
        SupportedCipherSuite::Tls12(&tls12::ECDHE_RSA_AES128_GCM_SHA256),
        SupportedCipherSuite::Tls12(&tls12::ECDHE_RSA_AES256_GCM_SHA384),
        SupportedCipherSuite::Tls12(&tls12::ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
    ];

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

async fn do_exchange(config: ClientConfig, server_config: Arc<ServerConfig>) {
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

    stream.write_all(b"HELLO").await.unwrap();
    let mut buf = Vec::new();
    let bytes = stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(&buf[..bytes], b"HELLO");
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
        let mut server_config =
            ServerConfig::builder_with_provider(Arc::new(boring_rustls_provider::provider()))
                .with_protocol_versions(&[&TLS12, &TLS13])
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
