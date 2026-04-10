use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config =
        rustls::ClientConfig::builder_with_provider(boring_rustls_provider::provider().into())
            .with_safe_default_protocol_versions()
            .map_err(|_| std::io::Error::other("failed selecting protocol versions"))?
            .with_root_certificates(root_store)
            .with_no_client_auth();

    let server_name = "www.rust-lang.org"
        .try_into()
        .map_err(|_| std::io::Error::other("invalid server name"))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
    let mut sock = TcpStream::connect("www.rust-lang.org:443")?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: www.rust-lang.org\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )?;
    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .ok_or_else(|| std::io::Error::other("no negotiated ciphersuite"))?;
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )?;
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext)?;
    stdout().write_all(&plaintext)?;

    Ok(())
}
