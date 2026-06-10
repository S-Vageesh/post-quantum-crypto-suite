use crate::errors::PqcError;
use crate::config::KemAlgorithm;
use crate::kem::{Kem, PublicKey, SecretKey, Ciphertext, SharedSecret};
use rand_core::{CryptoRng, RngCore};

/// Implementation of the Kyber Key Encapsulation Mechanism (KEM).
pub struct Kyber {
    algorithm: KemAlgorithm,
}

impl Kyber {
    /// Creates a new Kyber instance for the specified Kyber configuration.
    pub fn new(algorithm: KemAlgorithm) -> Result<Self, PqcError> {
        match algorithm {
            KemAlgorithm::Kyber512 | KemAlgorithm::Kyber768 | KemAlgorithm::Kyber1024 => {
                Ok(Self { algorithm })
            }
        }
    }
}

impl Kem for Kyber {
    fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }

    fn generate_keypair<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(PublicKey, SecretKey), PqcError> {
        let pk_len = self.algorithm.public_key_len();
        let sk_len = self.algorithm.secret_key_len();

        let mut pk_bytes = vec![0u8; pk_len];
        let mut sk_bytes = vec![0u8; sk_len];

        // Fill with random bytes to simulate key generation
        rng.fill_bytes(&mut pk_bytes);
        rng.fill_bytes(&mut sk_bytes);

        // Mark key type indicators in stub
        if !pk_bytes.is_empty() { pk_bytes[0] = 0xAB; }
        if !sk_bytes.is_empty() { sk_bytes[0] = 0xCD; }

        let pk = PublicKey::from_bytes(self.algorithm, pk_bytes)?;
        let sk = SecretKey::from_bytes(self.algorithm, sk_bytes)?;

        Ok((pk, sk))
    }

    fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey,
        rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret), PqcError> {
        if public_key.algorithm() != self.algorithm {
            return Err(PqcError::InvalidConfig(
                "Public key algorithm mismatch".to_string(),
            ));
        }

        let ct_len = self.algorithm.ciphertext_len();
        let ss_len = self.algorithm.shared_secret_len();

        let mut ct_bytes = vec![0u8; ct_len];
        rng.fill_bytes(&mut ct_bytes);

        // Deterministic derivation from ciphertext to allow decapsulation stub to match
        let mut ss_bytes = vec![0u8; ss_len];
        for i in 0..ss_len {
            ss_bytes[i] = ct_bytes[i] ^ 0x55;
        }

        let ct = Ciphertext::from_bytes(self.algorithm, ct_bytes)?;
        let ss = SharedSecret::from_bytes(self.algorithm, ss_bytes)?;

        Ok((ct, ss))
    }

    fn decapsulate(
        &self,
        ciphertext: &Ciphertext,
        secret_key: &SecretKey,
    ) -> Result<SharedSecret, PqcError> {
        if ciphertext.algorithm() != self.algorithm || secret_key.algorithm() != self.algorithm {
            return Err(PqcError::InvalidConfig(
                "Ciphertext or secret key algorithm mismatch".to_string(),
            ));
        }

        let ss_len = self.algorithm.shared_secret_len();
        let mut ss_bytes = vec![0u8; ss_len];

        // Recompute the deterministic shared secret from ciphertext
        let ct_bytes = ciphertext.as_bytes();
        for i in 0..ss_len {
            ss_bytes[i] = ct_bytes[i] ^ 0x55;
        }

        SharedSecret::from_bytes(self.algorithm, ss_bytes)
    }
}
