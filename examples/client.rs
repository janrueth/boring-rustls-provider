use std::io::{Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder(boring_rustls_provider::provider().into())
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .map_err(|e| std::io::Error::other(format!("failed building client config: {e}")))?;

    let server_name = "www.rust-lang.org"
        .try_into()
        .map_err(|_| std::io::Error::other("invalid server name"))?;
    let config = Arc::new(config);
    let mut tls_out = Vec::new();
    let mut conn = config.connect(server_name).build(&mut tls_out)?;
    let mut sock = TcpStream::connect("www.rust-lang.org:443")?;
    let mut tls_in = rustls::VecInput::default();

    while conn.is_handshaking() {
        sock.write_all(&tls_out)?;
        tls_out.clear();

        tls_in.read(&mut sock)?;
        let mut plaintext = Vec::new();
        conn.read_tls(&mut tls_in, &mut tls_out)
            .handle_all(&mut plaintext)?;
    }

    let request = concat!(
        "GET / HTTP/1.1\r\n",
        "Host: www.rust-lang.org\r\n",
        "Connection: close\r\n",
        "Accept-Encoding: identity\r\n",
        "\r\n"
    );
    conn.write(
        rustls::crypto::cipher::OutboundPlain::Single(request.as_bytes()),
        &mut tls_out,
    )?;
    sock.write_all(&tls_out)?;
    tls_out.clear();

    let ciphersuite = conn
        .negotiated_cipher_suite()
        .ok_or_else(|| std::io::Error::other("no negotiated ciphersuite"))?;
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )?;
    let mut plaintext = Vec::new();
    loop {
        let read = tls_in.read(&mut sock)?;
        conn.read_tls(&mut tls_in, &mut tls_out)
            .handle_all(&mut plaintext)?;
        sock.write_all(&tls_out)?;
        tls_out.clear();
        if read == 0 {
            break;
        }
    }
    stdout().write_all(&plaintext)?;

    Ok(())
}
