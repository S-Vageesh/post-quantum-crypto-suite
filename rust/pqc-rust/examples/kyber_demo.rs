use pqc_rust::{Kem, KemAlgorithm, Kyber, PqcError};
use rand_core::OsRng;

fn main() -> Result<(), PqcError> {
    println!("==================================================");
    println!("        Kyber Post-Quantum KEM Demonstration");
    println!("==================================================");

    // 1. Initialize Kyber-768
    let algorithm = KemAlgorithm::Kyber768;
    println!("* Instantiating Kyber KEM with variant: {:?}", algorithm);
    let kyber = Kyber::new(algorithm)?;

    // 2. Generate Key Pair
    println!("\n[Step 1] Generating key pair (Bob)...");
    let mut rng = OsRng;
    let (public_key, secret_key) = kyber.generate_keypair(&mut rng)?;
    println!(
        " -> Bob's Public Key length: {} bytes",
        public_key.as_bytes().len()
    );
    println!(
        " -> Bob's Secret Key length: {} bytes",
        secret_key.expose_secret().len()
    );

    // 3. Encapsulation (Alice)
    println!("\n[Step 2] Encapsulating shared secret using Bob's Public Key (Alice)...");
    let (ciphertext, alice_secret) = kyber.encapsulate(&public_key, &mut rng)?;
    println!(
        " -> Ciphertext length: {} bytes",
        ciphertext.as_bytes().len()
    );
    println!(
        " -> Alice's Derived Secret: {:x?}...",
        &alice_secret.expose_secret()[0..12]
    );

    // 4. Decapsulation (Bob)
    println!("\n[Step 3] Decapsulating ciphertext using Bob's Secret Key (Bob)...");
    let bob_secret = kyber.decapsulate(&ciphertext, &secret_key)?;
    println!(
        " -> Bob's Derived Secret:   {:x?}...",
        &bob_secret.expose_secret()[0..12]
    );

    // 5. Verification
    println!("\n[Step 4] Verifying derived shared secrets...");
    if alice_secret.expose_secret() == bob_secret.expose_secret() {
        println!(" -> SUCCESS: Both parties derived the exact same shared secret!");
    } else {
        println!(" -> FAILURE: Shared secrets do not match.");
        return Err(PqcError::DecapsulationError(
            "Shared secret mismatch".to_string(),
        ));
    }
    println!("==================================================");

    Ok(())
}
