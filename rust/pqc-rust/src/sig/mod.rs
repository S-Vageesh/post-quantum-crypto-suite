use crate::errors::PqcError;
use crate::config::SigAlgorithm;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::{CryptoRng, RngCore};

pub mod dilithium;
pub mod falcon;
pub mod sphincs;

/// Represents a signature public key wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    algorithm: SigAlgorithm,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Creates a public key from raw bytes.
    pub fn from_bytes(algorithm: SigAlgorithm, bytes: Vec<u8>) -> Result<Self, PqcError> {
        if bytes.len() != algorithm.public_key_len() {
            return Err(PqcError::SerializationError(format!(
                "Invalid public key length. Expected {} bytes, got {}",
                algorithm.public_key_len(),
                bytes.len()
            )));
        }
        Ok(Self { algorithm, bytes })
    }

    /// Returns the raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the signature algorithm variant.
    pub fn algorithm(&self) -> SigAlgorithm {
        self.algorithm
    }
}

/// Represents a signature secret key wrapper, zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[zeroize(skip)]
    algorithm: SigAlgorithm,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("algorithm", &self.algorithm)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl SecretKey {
    /// Creates a secret key from raw bytes.
    pub fn from_bytes(algorithm: SigAlgorithm, bytes: Vec<u8>) -> Result<Self, PqcError> {
        if bytes.len() != algorithm.secret_key_len() {
            return Err(PqcError::SerializationError(format!(
                "Invalid secret key length. Expected {} bytes, got {}",
                algorithm.secret_key_len(),
                bytes.len()
            )));
        }
        Ok(Self { algorithm, bytes })
    }

    /// Returns the raw bytes of the secret key.
    /// Use with caution to avoid memory leaks.
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the signature algorithm variant.
    pub fn algorithm(&self) -> SigAlgorithm {
        self.algorithm
    }
}

/// Represents a generated signature wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    algorithm: SigAlgorithm,
    bytes: Vec<u8>,
}

impl Signature {
    /// Creates a signature from raw bytes.
    pub fn from_bytes(algorithm: SigAlgorithm, bytes: Vec<u8>) -> Result<Self, PqcError> {
        // Some signature schemes can produce variable-length signatures,
        // so we treat algorithm.signature_len() as the upper limit.
        if bytes.len() > algorithm.signature_len() {
            return Err(PqcError::SerializationError(format!(
                "Signature size exceeds maximum limit of {} bytes, got {}",
                algorithm.signature_len(),
                bytes.len()
            )));
        }
        Ok(Self { algorithm, bytes })
    }

    /// Returns the raw bytes of the signature.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the signature algorithm variant.
    pub fn algorithm(&self) -> SigAlgorithm {
        self.algorithm
    }
}

/// The core Digital Signature trait.
pub trait DigitalSignature {
    /// Returns the algorithm configuration for this instance.
    fn algorithm(&self) -> SigAlgorithm;

    /// Generates a public/secret keypair using the provided cryptographically secure RNG.
    fn generate_keypair<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(PublicKey, SecretKey), PqcError>;

    /// Signs a message using a secret key and the provided RNG.
    fn sign<R: RngCore + CryptoRng>(
        &self,
        message: &[u8],
        secret_key: &SecretKey,
        rng: &mut R,
    ) -> Result<Signature, PqcError>;

    /// Verifies a signature against a message and public key.
    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<(), PqcError>;
}
