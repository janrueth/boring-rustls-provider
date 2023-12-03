use std::ptr;

use boring::error::ErrorStack;
use rustls::crypto;

use crate::helper::{cvt, log_and_map};

pub struct PrfTls1WithDigest(pub boring::nid::Nid);

impl crypto::tls12::Prf for PrfTls1WithDigest {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn crypto::ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        let digest = boring::hash::MessageDigest::from_nid(self.0)
            .ok_or(rustls::Error::General("invalid digest for prf".into()))?;

        let secret = kx.complete(peer_pub_key)?;

        prf(digest, output, secret.secret_bytes(), label, seed)
            .map_err(|e| log_and_map("prf", e, rustls::Error::General("failed on prf".into())))
    }

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        let digest = boring::hash::MessageDigest::from_nid(self.0).expect("failed getting digest");
        prf(digest, output, secret, label, seed).expect("failed calculating prf")
    }
}

fn prf(
    digest: boring::hash::MessageDigest,
    output: &mut [u8],
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
) -> Result<(), ErrorStack> {
    unsafe {
        // seed is already concatenated from the randoms, so we
        // can simply pass it in as a single seed
        cvt(boring_sys_additions::CRYPTO_tls1_prf(
            digest.as_ptr(),
            output.as_mut_ptr(),
            output.len(),
            secret.as_ptr(),
            secret.len(),
            label.as_ptr(),
            label.len(),
            seed.as_ptr(),
            seed.len(),
            ptr::null(),
            0,
        ))
    }
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::prf::prf;

    #[test]
    fn test_tls12_prf() {
        struct TestVector {
            test_name: &'static str,
            digest: boring::nid::Nid,
            secret: &'static [u8],
            label: &'static [u8],
            seed: &'static [u8],
            expected_output: &'static [u8],
        }

        // test vectors taken from https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/
        let inputs = &[
            TestVector {
                test_name: "88 bytes of pseudo-randomness using TLS1.2PRF-SHA224",
                digest: boring::nid::Nid::SHA224,
                secret: &hex!("e1 88 28 74 03 52 b5 30 d6 9b 34 c6 59 7d ea 2e"),
                label: b"test label",
                seed: &hex!("f5 a3 fe 6d 34 e2 e2 85 60 fd ca f6 82 3f 90 91"),
                expected_output: &hex!(
                    "
                    22 4d 8a f3 c0 45 33 93
                    a9 77 97 89 d2 1c f7 da
                    5e e6 2a e6 b6 17 87 3d
                    48 94 28 ef c8 dd 58 d1
                    56 6e 70 29 e2 ca 3a 5e
                    cd 35 5d c6 4d 4d 92 7e
                    2f bd 78 c4 23 3e 86 04
                    b1 47 49 a7 7a 92 a7 0f
                    dd f6 14 bc 0d f6 23 d7
                    98 60 4e 4c a5 51 27 94
                    d8 02 a2 58 e8 2f 86 cf
                    "
                ),
            },
            TestVector {
                test_name: "100 bytes of pseudo-randomness using TLS1.2PRF-SHA256",
                digest: boring::nid::Nid::SHA256,
                secret: &hex!("9b be 43 6b a9 40 f0 17 b1 76 52 84 9a 71 db 35"),
                label: b"test label",
                seed: &hex!("a0 ba 9f 93 6c da 31 18 27 a6 f7 96 ff d5 19 8c"),

                expected_output: &hex!(
                    "
                    e3 f2 29 ba 72 7b e1 7b
                    8d 12 26 20 55 7c d4 53
                    c2 aa b2 1d 07 c3 d4 95
                    32 9b 52 d4 e6 1e db 5a
                    6b 30 17 91 e9 0d 35 c9
                    c9 a4 6b 4e 14 ba f9 af
                    0f a0 22 f7 07 7d ef 17
                    ab fd 37 97 c0 56 4b ab
                    4f bc 91 66 6e 9d ef 9b
                    97 fc e3 4f 79 67 89 ba
                    a4 80 82 d1 22 ee 42 c5
                    a7 2e 5a 51 10 ff f7 01
                    87 34 7b 66
                    "
                ),
            },
            TestVector {
                test_name: "196 bytes of pseudo-randomness using TLS1.2PRF-SHA512",
                digest: boring::nid::Nid::SHA512,
                secret: &hex!("b0 32 35 23 c1 85 35 99 58 4d 88 56 8b bb 05 eb"),
                label: b"test label",
                seed: &hex!("d4 64 0e 12 e4 bc db fb 43 7f 03 e6 ae 41 8e e5"),
                expected_output: &hex!(
                    "
                    12 61 f5 88 c7 98 c5 c2
                    01 ff 03 6e 7a 9c b5 ed
                    cd 7f e3 f9 4c 66 9a 12
                    2a 46 38 d7 d5 08 b2 83
                    04 2d f6 78 98 75 c7 14
                    7e 90 6d 86 8b c7 5c 45
                    e2 0e b4 0c 1c f4 a1 71
                    3b 27 37 1f 68 43 25 92
                    f7 dc 8e a8 ef 22 3e 12
                    ea 85 07 84 13 11 bf 68
                    65 3d 0c fc 40 56 d8 11
                    f0 25 c4 5d df a6 e6 fe
                    c7 02 f0 54 b4 09 d6 f2
                    8d d0 a3 23 3e 49 8d a4
                    1a 3e 75 c5 63 0e ed be
                    22 fe 25 4e 33 a1 b0 e9
                    f6 b9 82 66 75 be c7 d0
                    1a 84 56 58 dc 9c 39 75
                    45 40 1d 40 b9 f4 6c 7a
                    40 0e e1 b8 f8 1c a0 a6
                    0d 1a 39 7a 10 28 bf f5
                    d2 ef 50 66 12 68 42 fb
                    8d a4 19 76 32 bd b5 4f
                    f6 63 3f 86 bb c8 36 e6
                    40 d4 d8 98
                    "
                ),
            },
            TestVector {
                test_name: "148 bytes of pseudo-randomness using TLS1.2PRF-SHA384",
                digest: boring::nid::Nid::SHA384,
                secret: &hex!("b8 0b 73 3d 6c ee fc dc 71 56 6e a4 8e 55 67 df"),
                label: b"test label",
                seed: &hex!("cd 66 5c f6 a8 44 7d d6 ff 8b 27 55 5e db 74 65"),
                expected_output: &hex!(
                    "
                    7b 0c 18 e9 ce d4 10 ed
                    18 04 f2 cf a3 4a 33 6a
                    1c 14 df fb 49 00 bb 5f
                    d7 94 21 07 e8 1c 83 cd
                    e9 ca 0f aa 60 be 9f e3
                    4f 82 b1 23 3c 91 46 a0
                    e5 34 cb 40 0f ed 27 00
                    88 4f 9d c2 36 f8 0e dd
                    8b fa 96 11 44 c9 e8 d7
                    92 ec a7 22 a7 b3 2f c3
                    d4 16 d4 73 eb c2 c5 fd
                    4a bf da d0 5d 91 84 25
                    9b 5b f8 cd 4d 90 fa 0d
                    31 e2 de c4 79 e4 f1 a2
                    60 66 f2 ee a9 a6 92 36
                    a3 e5 26 55 c9 e9 ae e6
                    91 c8 f3 a2 68 54 30 8d
                    5e aa 3b e8 5e 09 90 70
                    3d 73 e5 6f
                    "
                ),
            },
        ];

        for input in inputs {
            let digest = boring::hash::MessageDigest::from_nid(input.digest).unwrap();
            let mut calculated_output = vec![0u8; input.expected_output.len()];
            prf(
                digest,
                calculated_output.as_mut(),
                input.secret,
                input.label,
                input.seed,
            )
            .unwrap();

            assert_eq!(
                calculated_output.as_slice(),
                input.expected_output,
                "test: {} failed",
                input.test_name
            );
        }
    }
}
