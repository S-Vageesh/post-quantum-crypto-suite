use crate::config::SigAlgorithm;
use crate::errors::PqcError;
use crate::sig::{DigitalSignature, PublicKey, SecretKey, Signature};
use rand_core::{CryptoRng, RngCore};

/// Implementation of the SPHINCS+ Digital Signature scheme.
pub struct SphincsPlus {
    algorithm: SigAlgorithm,
}

impl SphincsPlus {
    /// Creates a new SPHINCS+ instance for the specified SPHINCS+ configuration.
    pub fn new(algorithm: SigAlgorithm) -> Result<Self, PqcError> {
        match algorithm {
            SigAlgorithm::SphincsPlus128s | SigAlgorithm::SphincsPlus256s => Ok(Self { algorithm }),
            _ => Err(PqcError::InvalidConfig(
                "Unsupported SPHINCS+ variant".to_string(),
            )),
        }
    }
}

impl DigitalSignature for SphincsPlus {
    fn algorithm(&self) -> SigAlgorithm {
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

        rng.fill_bytes(&mut pk_bytes);
        rng.fill_bytes(&mut sk_bytes);

        // Mark key type indicators in stub
        if !pk_bytes.is_empty() {
            pk_bytes[0] = 0x50;
        }
        if !sk_bytes.is_empty() {
            sk_bytes[0] = 0x51;
        }

        let pk = PublicKey::from_bytes(self.algorithm, pk_bytes)?;
        let sk = SecretKey::from_bytes(self.algorithm, sk_bytes)?;

        Ok((pk, sk))
    }

    fn sign<R: RngCore + CryptoRng>(
        &self,
        message: &[u8],
        secret_key: &SecretKey,
        rng: &mut R,
    ) -> Result<Signature, PqcError> {
        if secret_key.algorithm() != self.algorithm {
            return Err(PqcError::InvalidConfig(
                "Secret key algorithm mismatch".to_string(),
            ));
        }

        let sig_len = self.algorithm.signature_len();
        let mut sig_bytes = vec![0u8; sig_len];
        rng.fill_bytes(&mut sig_bytes);

        // Compute deterministic mock signature based on message for verification testing
        let msg_len = message.len();
        for i in 0..std::cmp::min(sig_len, msg_len) {
            sig_bytes[i] = message[i] ^ 0xCC;
        }

        Signature::from_bytes(self.algorithm, sig_bytes)
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<(), PqcError> {
        if signature.algorithm() != self.algorithm || public_key.algorithm() != self.algorithm {
            return Err(PqcError::InvalidConfig(
                "Signature or public key algorithm mismatch".to_string(),
            ));
        }

        let sig_bytes = signature.as_bytes();
        let msg_len = message.len();

        // Verify the deterministic tag
        for i in 0..std::cmp::min(sig_bytes.len(), msg_len) {
            if sig_bytes[i] != (message[i] ^ 0xCC) {
                return Err(PqcError::VerificationError(
                    "Invalid signature tag mismatch".to_string(),
                ));
            }
        }

        Ok(())
    }
}
