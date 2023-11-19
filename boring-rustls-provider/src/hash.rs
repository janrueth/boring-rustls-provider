use rustls::crypto::hash;

pub const SHA256: &dyn hash::Hash = &Hash(boring::nid::Nid::SHA256);

pub struct Hash(pub boring::nid::Nid);

impl hash::Hash for Hash {
    fn start(&self) -> Box<dyn hash::Context> {
        let digest = boring::hash::MessageDigest::from_nid(self.0).unwrap();
        let hasher = boring::hash::Hasher::new(digest).unwrap();
        Box::new(HasherContext(hasher))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        let mut hasher = self.start();
        hasher.update(data);
        hasher.finish()
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        match self.0 {
            boring::nid::Nid::SHA256 => hash::HashAlgorithm::SHA256,
            _ => unimplemented!(),
        }
    }

    fn output_len(&self) -> usize {
        boring::hash::MessageDigest::from_nid(self.0)
            .unwrap()
            .size()
    }
}

struct HasherContext(boring::hash::Hasher);

impl hash::Context for HasherContext {
    fn fork_finish(&self) -> hash::Output {
        let mut cloned = self.0.clone();

        hash::Output::new(&cloned.finish().unwrap()[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(HasherContext(self.0.clone()))
    }

    fn finish(mut self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finish().unwrap()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::SHA256;
    use hex_literal::hex;

    #[test]
    fn test_sha256() {
        let hash = SHA256.hash("test".as_bytes());

        assert_eq!(
            hash.as_ref(),
            hex!("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        );
    }
}
