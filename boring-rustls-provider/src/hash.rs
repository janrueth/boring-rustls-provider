use boring::hash::{Hasher, MessageDigest};
use rustls::crypto::hash;

pub const SHA256: &dyn hash::Hash = &Hash(boring::nid::Nid::SHA256);
pub const SHA384: &dyn hash::Hash = &Hash(boring::nid::Nid::SHA384);

pub struct Hash(pub boring::nid::Nid);

impl hash::Hash for Hash {
    fn start(&self) -> Box<dyn hash::Context> {
        let digest = MessageDigest::from_nid(self.0).expect("failed getting hash digest");
        let hasher = Hasher::new(digest).expect("failed getting hasher");
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
            boring::nid::Nid::SHA384 => hash::HashAlgorithm::SHA384,
            boring::nid::Nid::SHA512 => hash::HashAlgorithm::SHA512,
            _ => unimplemented!(),
        }
    }

    fn output_len(&self) -> usize {
        MessageDigest::from_nid(self.0)
            .expect("failed getting digest")
            .size()
    }
}

struct HasherContext(Hasher);

impl hash::Context for HasherContext {
    fn fork_finish(&self) -> hash::Output {
        let mut cloned = self.0.clone();

        hash::Output::new(&cloned.finish().expect("failed finishing hash")[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(HasherContext(self.0.clone()))
    }

    fn finish(mut self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finish().expect("failed finishing hash")[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data).expect("failed adding data to hash");
    }
}

#[cfg(test)]
mod tests {
    use super::SHA256;
    use hex_literal::hex;

    #[test]
    fn test_context() {
        let mut hash = SHA256.start();
        hash.update(b"ABCDE");
        let abcde = hash.fork_finish();
        hash.update(b"FGHIJ");
        let abcdefghij = hash.finish();

        assert_eq!(
            abcde.as_ref(),
            hex!("f0393febe8baaa55e32f7be2a7cc180bf34e52137d99e056c817a9c07b8f239a")
        );
        assert_eq!(
            abcdefghij.as_ref(),
            hex!("261305762671a58cae5b74990bcfc236c2336fb04a0fbac626166d9491d2884c")
        );
    }

    #[test]
    fn test_sha256() {
        let hash = SHA256.hash("test".as_bytes());

        assert_eq!(
            hash.as_ref(),
            hex!("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        );
    }
}
