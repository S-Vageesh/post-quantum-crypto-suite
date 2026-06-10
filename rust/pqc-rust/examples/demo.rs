use pqc_rust::{
    DigitalSignature, Dilithium, Falcon, Kem, KemAlgorithm, Kyber, PqcError, SigAlgorithm,
    SphincsPlus,
};

/// A simple seedable mock RNG implementing `RngCore` and `CryptoRng`
/// to provide reproducible and dependency-free random bytes for stubs.
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

fn main() -> Result<(), PqcError> {
    println!("=== Post-Quantum Cryptography Suite Demo ===\n");

    let mut rng = MockRng::new(42);

    // -------------------------------------------------------------
    // KEM Demo (Kyber-768)
    // -------------------------------------------------------------
    println!("--- KEM: Kyber-768 Demo ---");
    let kem_algo = KemAlgorithm::Kyber768;
    let kyber = Kyber::new(kem_algo)?;

    println!("1. Generating keypair...");
    let (pk, sk) = kyber.generate_keypair(&mut rng)?;
    println!("   Public Key Size: {} bytes", pk.as_bytes().len());
    println!(
        "   Secret Key Size: {} bytes (Memory scrubbed on Drop)",
        sk.expose_secret().len()
    );

    println!("2. Encapsulating shared secret (Alice)...");
    let (ct, ss_alice) = kyber.encapsulate(&pk, &mut rng)?;
    println!("   Ciphertext Size: {} bytes", ct.as_bytes().len());
    println!(
        "   Shared Secret (Alice): {:x?}...",
        &ss_alice.expose_secret()[0..8]
    );

    println!("3. Decapsulating shared secret (Bob)...");
    let ss_bob = kyber.decapsulate(&ct, &sk)?;
    println!(
        "   Shared Secret (Bob):   {:x?}...",
        &ss_bob.expose_secret()[0..8]
    );

    assert_eq!(ss_alice.expose_secret(), ss_bob.expose_secret());
    println!("   Status: Success (Shared secrets match!)\n");

    // -------------------------------------------------------------
    // Signature Demo (Dilithium3)
    // -------------------------------------------------------------
    println!("--- Signature: Dilithium3 Demo ---");
    let sig_algo = SigAlgorithm::Dilithium3;
    let dilithium = Dilithium::new(sig_algo)?;

    println!("1. Generating keypair...");
    let (spk, ssk) = dilithium.generate_keypair(&mut rng)?;
    println!("   Public Key Size: {} bytes", spk.as_bytes().len());
    println!("   Secret Key Size: {} bytes", ssk.expose_secret().len());

    let message = b"Post-quantum security is the future.";
    println!("2. Signing message: {:?}", String::from_utf8_lossy(message));
    let signature = dilithium.sign(message, &ssk, &mut rng)?;
    println!("   Signature Size: {} bytes", signature.as_bytes().len());

    println!("3. Verifying signature...");
    match dilithium.verify(message, &signature, &spk) {
        Ok(()) => println!("   Status: Success (Signature verified!)"),
        Err(e) => println!("   Status: Failed ({})", e),
    }

    println!("4. Verifying signature with tampered message...");
    let tampered_message = b"Post-quantum security is the future!";
    match dilithium.verify(tampered_message, &signature, &spk) {
        Ok(()) => println!("   Status: Unexpected Success!"),
        Err(_) => println!("   Status: Success (Rejected tampered message as expected)"),
    }
    println!();

    // -------------------------------------------------------------
    // Signature Demo (Falcon-512)
    // -------------------------------------------------------------
    println!("--- Signature: Falcon-512 Demo ---");
    let falcon_algo = SigAlgorithm::Falcon512;
    let falcon = Falcon::new(falcon_algo)?;

    println!("1. Generating keypair...");
    let (fpk, fsk) = falcon.generate_keypair(&mut rng)?;
    println!("   Public Key Size: {} bytes", fpk.as_bytes().len());

    println!("2. Signing message...");
    let f_sig = falcon.sign(message, &fsk, &mut rng)?;
    println!("   Signature Size: {} bytes", f_sig.as_bytes().len());

    println!("3. Verifying signature...");
    match falcon.verify(message, &f_sig, &fpk) {
        Ok(()) => println!("   Status: Success (Signature verified!)"),
        Err(e) => println!("   Status: Failed ({})", e),
    }
    println!();

    // -------------------------------------------------------------
    // Signature Demo (SPHINCS+-128s)
    // -------------------------------------------------------------
    println!("--- Signature: SPHINCS+-128s Demo ---");
    let sphincs_algo = SigAlgorithm::SphincsPlus128s;
    let sphincs = SphincsPlus::new(sphincs_algo)?;

    println!("1. Generating keypair...");
    let (sspk, sssk) = sphincs.generate_keypair(&mut rng)?;
    println!("   Public Key Size: {} bytes", sspk.as_bytes().len());

    println!("2. Signing message...");
    let s_sig = sphincs.sign(message, &sssk, &mut rng)?;
    println!("   Signature Size: {} bytes", s_sig.as_bytes().len());

    println!("3. Verifying signature...");
    match sphincs.verify(message, &s_sig, &sspk) {
        Ok(()) => println!("   Status: Success (Signature verified!)"),
        Err(e) => println!("   Status: Failed ({})", e),
    }

    Ok(())
}
