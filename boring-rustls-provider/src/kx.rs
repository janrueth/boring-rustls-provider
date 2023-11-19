use rustls::crypto::{self, ActiveKeyExchange};

mod dh;
mod evp;

#[derive(Debug)]
enum DhKeyType {
    EC(i32),
    ED(i32),
    FFDHE2048,
}

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(
            evp::BoringEvpKey::generate_x25519().map_err(|_| crypto::GetRandomFailed)?,
        ))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

#[derive(Debug)]
pub struct X448;

impl crypto::SupportedKxGroup for X448 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(
            evp::BoringEvpKey::generate_x448().map_err(|_| crypto::GetRandomFailed)?,
        ))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X448
    }
}

#[derive(Debug)]
pub struct Secp256r1;

impl crypto::SupportedKxGroup for Secp256r1 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(
            evp::BoringEvpKey::generate_secp256r1().map_err(|_| crypto::GetRandomFailed)?,
        ))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp256r1
    }
}

#[derive(Debug)]
pub struct Secp384r1;

impl crypto::SupportedKxGroup for Secp384r1 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(
            evp::BoringEvpKey::generate_secp384r1().map_err(|_| crypto::GetRandomFailed)?,
        ))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp384r1
    }
}

#[derive(Debug)]
pub struct Secp521r1;

impl crypto::SupportedKxGroup for Secp521r1 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(
            evp::BoringEvpKey::generate_secp521r1().map_err(|_| crypto::GetRandomFailed)?,
        ))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp521r1
    }
}

#[derive(Debug)]
pub struct FfDHe2048;

impl crypto::SupportedKxGroup for FfDHe2048 {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange + 'static)>, rustls::Error> {
        Ok(Box::new(
            dh::BoringDhKey::generate_ffdhe_2048().map_err(|_| crypto::GetRandomFailed)?,
        ))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::FFDHE2048
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::ActiveKeyExchange;

    #[test]
    fn test_derive_ed() {
        let alice = super::evp::BoringEvpKey::generate_x25519().unwrap();
        let bob = super::evp::BoringEvpKey::generate_x25519().unwrap();

        let shared_secret1 = alice.diffie_hellman(&bob.pub_key()).unwrap();
        let shared_secret2 = bob.diffie_hellman(&alice.pub_key()).unwrap();

        assert_eq!(shared_secret1, shared_secret2)
    }

    #[test]
    fn test_derive_ec() {
        let alice = super::evp::BoringEvpKey::generate_secp256r1().unwrap();
        let bob = super::evp::BoringEvpKey::generate_secp256r1().unwrap();

        let shared_secret1 = alice.diffie_hellman(&bob.pub_key()).unwrap();
        let shared_secret2 = bob.diffie_hellman(&alice.pub_key()).unwrap();

        assert_eq!(shared_secret1, shared_secret2)
    }

    #[test]
    fn test_derive_dh() {
        let alice = super::dh::BoringDhKey::generate_ffdhe_2048().unwrap();
        let bob = super::dh::BoringDhKey::generate_ffdhe_2048().unwrap();

        let shared_secret1 = alice.diffie_hellman(&bob.pub_key()).unwrap();
        let shared_secret2 = bob.diffie_hellman(&alice.pub_key()).unwrap();

        assert_eq!(shared_secret1, shared_secret2)
    }
}
