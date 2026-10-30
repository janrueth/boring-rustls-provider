use boring::mldsa::{Algorithm, MlDsaPublicKey};
use rustls::pki_types::alg_id;
use rustls_pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};

use crate::helper;

#[derive(Debug)]
pub struct BoringMlDsaVerifier(Algorithm);

impl BoringMlDsaVerifier {
    pub const ML_DSA_44: Self = Self(Algorithm::MlDsa44);
    pub const ML_DSA_65: Self = Self(Algorithm::MlDsa65);
    pub const ML_DSA_87: Self = Self(Algorithm::MlDsa87);

    fn algorithm_identifier(&self) -> AlgorithmIdentifier {
        match self.0 {
            Algorithm::MlDsa44 => alg_id::ML_DSA_44,
            Algorithm::MlDsa65 => alg_id::ML_DSA_65,
            Algorithm::MlDsa87 => alg_id::ML_DSA_87,
        }
    }
}

impl SignatureVerificationAlgorithm for BoringMlDsaVerifier {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let public_key = MlDsaPublicKey::from_slice(self.0, public_key)
            .map_err(|e| helper::log_and_map("MlDsaPublicKey::from_slice", e, InvalidSignature))?;

        public_key
            .verify(message, signature)
            .map_err(|e| helper::log_and_map("MlDsaPublicKey::verify", e, InvalidSignature))
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.algorithm_identifier()
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.algorithm_identifier()
    }

    fn fips(&self) -> bool {
        cfg!(feature = "fips")
    }
}

#[cfg(test)]
mod tests {
    use boring::mldsa::{Algorithm, MlDsaPrivateKey};
    use rustls_pki_types::SignatureVerificationAlgorithm;

    use super::BoringMlDsaVerifier;

    #[test]
    fn verifies_all_parameter_sets() {
        for (algorithm, verifier) in [
            (Algorithm::MlDsa44, &BoringMlDsaVerifier::ML_DSA_44),
            (Algorithm::MlDsa65, &BoringMlDsaVerifier::ML_DSA_65),
            (Algorithm::MlDsa87, &BoringMlDsaVerifier::ML_DSA_87),
        ] {
            let (public_key, private_key) = MlDsaPrivateKey::generate(algorithm).unwrap();
            let message = b"ML-DSA verifier test";
            let signature = private_key.sign(message).unwrap();
            let public_key = public_key.to_bytes().unwrap();

            verifier
                .verify_signature(&public_key, message, &signature)
                .unwrap();
            assert!(
                verifier
                    .verify_signature(&public_key, b"wrong message", &signature)
                    .is_err()
            );
        }
    }
}
