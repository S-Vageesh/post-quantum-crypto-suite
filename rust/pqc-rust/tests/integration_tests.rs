use pqc_rust::{
    DigitalSignature, Dilithium, Falcon, Kem, KemAlgorithm, Kyber, SigAlgorithm, SphincsPlus,
};

/// A simple seedable mock RNG implementing `RngCore` and `CryptoRng` for unit testing.
struct MockRng {
    state: u64,
}

impl MockRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

impl rand_core::RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.state >> 32) as u32
    }

    fn next_u64(&mut self) -> u64 {
        let low = self.next_u32() as u64;
        let high = self.next_u32() as u64;
        (high << 32) | low
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            let rand = self.next_u32();
            let bytes = rand.to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for MockRng {}

#[test]
fn test_kyber_flow() {
    let mut rng = MockRng::new(1);
    let algorithms = [
        KemAlgorithm::Kyber512,
        KemAlgorithm::Kyber768,
        KemAlgorithm::Kyber1024,
    ];

    for algo in algorithms {
        let kyber = Kyber::new(algo).unwrap();
        assert_eq!(kyber.algorithm(), algo);

        // Key generation
        let (pk, sk) = kyber.generate_keypair(&mut rng).unwrap();
        assert_eq!(pk.as_bytes().len(), algo.public_key_len());
        assert_eq!(sk.expose_secret().len(), algo.secret_key_len());

        // Encapsulation
        let (ct, ss_alice) = kyber.encapsulate(&pk, &mut rng).unwrap();
        assert_eq!(ct.as_bytes().len(), algo.ciphertext_len());
        assert_eq!(ss_alice.expose_secret().len(), algo.shared_secret_len());

        // Decapsulation
        let ss_bob = kyber.decapsulate(&ct, &sk).unwrap();
        assert_eq!(ss_bob.expose_secret().len(), algo.shared_secret_len());

        // Validate shared secrets match
        assert_eq!(ss_alice.expose_secret(), ss_bob.expose_secret());
    }
}

#[test]
fn test_dilithium_flow() {
    let mut rng = MockRng::new(2);
    let algorithms = [
        SigAlgorithm::Dilithium2,
        SigAlgorithm::Dilithium3,
        SigAlgorithm::Dilithium5,
    ];
    let message = b"Alice signs this post-quantum document.";

    for algo in algorithms {
        let dilithium = Dilithium::new(algo).unwrap();
        assert_eq!(dilithium.algorithm(), algo);

        // Key generation
        let (pk, sk) = dilithium.generate_keypair(&mut rng).unwrap();
        assert_eq!(pk.as_bytes().len(), algo.public_key_len());
        assert_eq!(sk.expose_secret().len(), algo.secret_key_len());

        // Signing
        let sig = dilithium.sign(message, &sk, &mut rng).unwrap();
        assert!(sig.as_bytes().len() <= algo.signature_len());

        // Verification
        assert!(dilithium.verify(message, &sig, &pk).is_ok());

        // Verification failure with modified message
        let tampered = b"Alice signs this post-quantum document!";
        assert!(dilithium.verify(tampered, &sig, &pk).is_err());
    }
}

#[test]
fn test_falcon_flow() {
    let mut rng = MockRng::new(3);
    let algorithms = [SigAlgorithm::Falcon512, SigAlgorithm::Falcon1024];
    let message = b"Sign with Falcon.";

    for algo in algorithms {
        let falcon = Falcon::new(algo).unwrap();
        assert_eq!(falcon.algorithm(), algo);

        // Key generation
        let (pk, sk) = falcon.generate_keypair(&mut rng).unwrap();
        assert_eq!(pk.as_bytes().len(), algo.public_key_len());

        // Signing
        let sig = falcon.sign(message, &sk, &mut rng).unwrap();
        assert!(sig.as_bytes().len() <= algo.signature_len());

        // Verification
        assert!(falcon.verify(message, &sig, &pk).is_ok());

        // Verification failure with modified message
        let tampered = b"Sign with Falcon!";
        assert!(falcon.verify(tampered, &sig, &pk).is_err());
    }
}

#[test]
fn test_sphincs_flow() {
    let mut rng = MockRng::new(4);
    let algorithms = [SigAlgorithm::SphincsPlus128s, SigAlgorithm::SphincsPlus256s];
    let message = b"Sign with SPHINCS+.";

    for algo in algorithms {
        let sphincs = SphincsPlus::new(algo).unwrap();
        assert_eq!(sphincs.algorithm(), algo);

        // Key generation
        let (pk, sk) = sphincs.generate_keypair(&mut rng).unwrap();
        assert_eq!(pk.as_bytes().len(), algo.public_key_len());

        // Signing
        let sig = sphincs.sign(message, &sk, &mut rng).unwrap();
        assert!(sig.as_bytes().len() <= algo.signature_len());

        // Verification
        assert!(sphincs.verify(message, &sig, &pk).is_ok());

        // Verification failure with modified message
        let tampered = b"Sign with SPHINCS+!";
        assert!(sphincs.verify(tampered, &sig, &pk).is_err());
    }
}
