//! X25519MLKEM768 post-quantum hybrid key exchange.
//!
//! Implements the X25519MLKEM768 hybrid key agreement per
//! `draft-ietf-tls-ecdhe-mlkem-00`. Composes ML-KEM-768 (FIPS 203)
//! with X25519, with the ML-KEM component first in all wire encodings.
//!
//! Wire format:
//!   - Client key share: `mlkem_pk(1184) || x25519_pk(32)` = 1216 bytes
//!   - Server key share: `mlkem_ct(1088) || x25519_pk(32)` = 1120 bytes
//!   - Shared secret:    `mlkem_ss(32)   || x25519_ss(32)` = 64 bytes

use boring::mlkem::{Algorithm, MlKemPrivateKey, MlKemPublicKey};
use rustls::Error;
use rustls::crypto::{
    self,
    kx::{
        ActiveKeyExchange, CompletedKeyExchange, HybridKeyExchange, NamedGroup, SharedSecret,
        StartedKeyExchange, SupportedKxGroup,
    },
};
use rustls::error::PeerMisbehaved;
use rustls_pki_types::FipsStatus;
use zeroize::Zeroizing;

const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
const MLKEM768_CIPHERTEXT_BYTES: usize = 1088;
const X25519_PUBLIC_KEY_BYTES: usize = 32;
const X25519_PRIVATE_KEY_BYTES: usize = 32;
const X25519_SHARED_SECRET_BYTES: usize = 32;

const CLIENT_SHARE_LEN: usize = MLKEM768_PUBLIC_KEY_BYTES + X25519_PUBLIC_KEY_BYTES; // 1216
const SERVER_SHARE_LEN: usize = MLKEM768_CIPHERTEXT_BYTES + X25519_PUBLIC_KEY_BYTES; // 1120

/// X25519MLKEM768 post-quantum hybrid key exchange group.
#[derive(Debug)]
pub struct X25519MlKem768;

impl SupportedKxGroup for X25519MlKem768 {
    /// Client-side: generate ML-KEM-768 + X25519 keypairs.
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        let (mlkem_pub, mlkem_priv) =
            MlKemPrivateKey::generate(Algorithm::MlKem768).map_err(|e| {
                crate::helper::log_and_map(
                    "X25519MlKem768::start mlkem generate",
                    e,
                    crypto::GetRandomFailed,
                )
            })?;

        let mut x25519_pub = [0u8; X25519_PUBLIC_KEY_BYTES];
        let mut x25519_priv = Zeroizing::new([0u8; X25519_PRIVATE_KEY_BYTES]);
        // SAFETY: X25519_keypair writes exactly 32 bytes to each output buffer.
        unsafe {
            boring_sys::X25519_keypair(x25519_pub.as_mut_ptr(), x25519_priv.as_mut_ptr());
        }

        // Wire format: mlkem_pk || x25519_pk
        let mut pub_key = Vec::with_capacity(CLIENT_SHARE_LEN);
        pub_key.extend_from_slice(mlkem_pub.as_bytes());
        pub_key.extend_from_slice(&x25519_pub);

        Ok(StartedKeyExchange::Hybrid(Box::new(ActiveX25519MlKem768 {
            mlkem_priv,
            x25519_priv,
            x25519_pub,
            pub_key,
        })))
    }

    /// Server-side: one-shot encapsulate + DH.
    ///
    /// Must be overridden for KEMs because the server's output (ciphertext)
    /// depends on the client's input (encapsulation key).
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != CLIENT_SHARE_LEN {
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
        }

        // Split client share: mlkem_pk(1184) || x25519_pk(32)
        let (client_mlkem_pk_bytes, client_x25519_pk) =
            client_share.split_at(MLKEM768_PUBLIC_KEY_BYTES);

        // ML-KEM encapsulate
        let client_mlkem_pk =
            MlKemPublicKey::from_slice(Algorithm::MlKem768, client_mlkem_pk_bytes).map_err(
                |e| {
                    crate::helper::log_and_map(
                        "X25519MlKem768::start_and_complete mlkem parse",
                        e,
                        Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare),
                    )
                },
            )?;

        let (mlkem_ct, mlkem_ss) = client_mlkem_pk.encapsulate().map_err(|e| {
            crate::helper::log_and_map(
                "X25519MlKem768::start_and_complete mlkem encap",
                e,
                Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare),
            )
        })?;
        let mlkem_ss = Zeroizing::new(mlkem_ss);

        // X25519 key exchange
        let mut x25519_server_pub = [0u8; X25519_PUBLIC_KEY_BYTES];
        let mut x25519_server_priv = Zeroizing::new([0u8; X25519_PRIVATE_KEY_BYTES]);
        let mut x25519_ss = Zeroizing::new([0u8; X25519_SHARED_SECRET_BYTES]);

        // SAFETY: X25519_keypair writes exactly 32 bytes to each buffer.
        // X25519 returns 1 on success, 0 on failure (e.g., low-order point).
        unsafe {
            boring_sys::X25519_keypair(
                x25519_server_pub.as_mut_ptr(),
                x25519_server_priv.as_mut_ptr(),
            );
            let rc = boring_sys::X25519(
                x25519_ss.as_mut_ptr(),
                x25519_server_priv.as_ptr(),
                client_x25519_pk.as_ptr(),
            );
            if rc != 1 {
                return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
            }
        }

        // Server share: mlkem_ct(1088) || x25519_pk(32)
        let mut server_share = Vec::with_capacity(SERVER_SHARE_LEN);
        server_share.extend_from_slice(&mlkem_ct);
        server_share.extend_from_slice(&x25519_server_pub);

        // Shared secret: mlkem_ss(32) || x25519_ss(32)
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(&mlkem_ss[..]);
        secret.extend_from_slice(&x25519_ss[..]);

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: server_share,
            secret: SharedSecret::from(secret),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn fips(&self) -> FipsStatus {
        if cfg!(feature = "fips") {
            FipsStatus::Pending
        } else {
            FipsStatus::Unvalidated
        }
    }
}

/// Client-side active hybrid key exchange state.
///
/// Holds the ML-KEM private key and X25519 private key generated
/// during [`X25519MlKem768::start`], waiting for the server's response.
struct ActiveX25519MlKem768 {
    mlkem_priv: MlKemPrivateKey,
    x25519_priv: Zeroizing<[u8; X25519_PRIVATE_KEY_BYTES]>,
    x25519_pub: [u8; X25519_PUBLIC_KEY_BYTES],
    pub_key: Vec<u8>,
}

impl HybridKeyExchange for ActiveX25519MlKem768 {
    fn component(&self) -> (NamedGroup, &[u8]) {
        (NamedGroup::X25519, &self.x25519_pub)
    }

    fn complete_component(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != X25519_PUBLIC_KEY_BYTES {
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
        }

        let mut x25519_ss = Zeroizing::new([0u8; X25519_SHARED_SECRET_BYTES]);

        // SAFETY: X25519 reads 32 bytes from each input and writes 32 to output.
        unsafe {
            let rc = boring_sys::X25519(
                x25519_ss.as_mut_ptr(),
                self.x25519_priv.as_ptr(),
                peer_pub_key.as_ptr(),
            );
            if rc != 1 {
                return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
            }
        }

        Ok(SharedSecret::from(Vec::from(&x25519_ss[..])))
    }

    fn as_key_exchange(&self) -> &(dyn ActiveKeyExchange + 'static) {
        self
    }

    fn into_key_exchange(self: Box<Self>) -> Box<dyn ActiveKeyExchange> {
        self
    }
}

impl ActiveKeyExchange for ActiveX25519MlKem768 {
    /// Client-side: decapsulate ML-KEM + derive X25519.
    fn complete(self: Box<Self>, server_share: &[u8]) -> Result<SharedSecret, Error> {
        if server_share.len() != SERVER_SHARE_LEN {
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
        }

        // Split server share: mlkem_ct(1088) || x25519_pk(32)
        let (mlkem_ct, server_x25519_pk) = server_share.split_at(MLKEM768_CIPHERTEXT_BYTES);

        // ML-KEM decapsulate
        let mlkem_ss = self.mlkem_priv.decapsulate(mlkem_ct).map_err(|e| {
            crate::helper::log_and_map(
                "ActiveX25519MlKem768::complete mlkem decap",
                e,
                Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare),
            )
        })?;
        let mlkem_ss = Zeroizing::new(mlkem_ss);

        // X25519 derive
        let mut x25519_ss = Zeroizing::new([0u8; X25519_SHARED_SECRET_BYTES]);
        // SAFETY: X25519 reads 32 bytes from each input and writes 32 to output.
        unsafe {
            let rc = boring_sys::X25519(
                x25519_ss.as_mut_ptr(),
                self.x25519_priv.as_ptr(),
                server_x25519_pk.as_ptr(),
            );
            if rc != 1 {
                return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
            }
        }

        // Shared secret: mlkem_ss(32) || x25519_ss(32)
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(&mlkem_ss[..]);
        secret.extend_from_slice(&x25519_ss[..]);

        Ok(SharedSecret::from(secret))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::kx::SupportedKxGroup;

    fn unwrap_hybrid(started: StartedKeyExchange) -> Box<dyn HybridKeyExchange> {
        match started {
            StartedKeyExchange::Hybrid(h) => h,
            _ => panic!("expected Hybrid variant"),
        }
    }

    #[test]
    fn hybrid_round_trip() {
        let group = X25519MlKem768;

        // Client generates keypair
        let client = unwrap_hybrid(group.start().unwrap());
        assert_eq!(client.pub_key().len(), CLIENT_SHARE_LEN);
        assert_eq!(client.group(), NamedGroup::X25519MLKEM768);

        // Server encapsulates + derives
        let server = group.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(server.pub_key.len(), SERVER_SHARE_LEN);
        assert_eq!(server.group, NamedGroup::X25519MLKEM768);

        // Client decapsulates + derives
        let client_secret = client
            .into_key_exchange()
            .complete(&server.pub_key)
            .unwrap();

        // Shared secrets must match
        assert_eq!(
            client_secret.secret_bytes(),
            server.secret.secret_bytes(),
            "client and server shared secrets differ"
        );
        assert_eq!(client_secret.secret_bytes().len(), 64);
    }

    #[test]
    fn rejects_invalid_client_share() {
        let group = X25519MlKem768;
        let result = group.start_and_complete(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_server_share() {
        let group = X25519MlKem768;
        let client = unwrap_hybrid(group.start().unwrap());
        let result = client.into_key_exchange().complete(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn exposes_x25519_hybrid_component() {
        let group = X25519MlKem768;
        let client = unwrap_hybrid(group.start().unwrap());

        let (component_group, component_pub_key) = client.component();

        assert_eq!(component_group, NamedGroup::X25519);
        assert_eq!(component_pub_key.len(), X25519_PUBLIC_KEY_BYTES);
        assert_eq!(
            component_pub_key,
            &client.pub_key()[MLKEM768_PUBLIC_KEY_BYTES..CLIENT_SHARE_LEN]
        );
    }

    #[test]
    fn complete_hybrid_component_matches_x25519() {
        let group = X25519MlKem768;
        let client = unwrap_hybrid(group.start().unwrap());
        let (_, client_x25519_pub) = client.component();
        let client_x25519_pub = client_x25519_pub.to_vec();

        let mut server_x25519_pub = [0u8; X25519_PUBLIC_KEY_BYTES];
        let mut server_x25519_priv = [0u8; X25519_PRIVATE_KEY_BYTES];
        let mut server_x25519_ss = [0u8; X25519_SHARED_SECRET_BYTES];

        // SAFETY: X25519_keypair writes 32-byte buffers. X25519 returns 1 on success.
        unsafe {
            boring_sys::X25519_keypair(
                server_x25519_pub.as_mut_ptr(),
                server_x25519_priv.as_mut_ptr(),
            );
            let rc = boring_sys::X25519(
                server_x25519_ss.as_mut_ptr(),
                server_x25519_priv.as_ptr(),
                client_x25519_pub.as_ptr(),
            );
            assert_eq!(rc, 1);
        }

        let client_secret = client.complete_component(&server_x25519_pub).unwrap();
        assert_eq!(client_secret.secret_bytes(), &server_x25519_ss);
    }

    #[test]
    #[cfg(feature = "fips")]
    fn reports_fips() {
        assert_eq!(X25519MlKem768.fips(), FipsStatus::Pending);
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn reports_non_fips() {
        assert_eq!(X25519MlKem768.fips(), FipsStatus::Unvalidated);
    }
}
