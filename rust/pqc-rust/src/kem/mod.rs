use crate::config::KemAlgorithm;
use crate::errors::PqcError;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod kyber;

/// Represents a KEM public key wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    algorithm: KemAlgorithm,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Creates a public key from raw bytes.
    pub fn from_bytes(algorithm: KemAlgorithm, bytes: Vec<u8>) -> Result<Self, PqcError> {
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

    /// Returns the KEM algorithm variant.
    pub fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }
}

/// Represents a KEM secret key wrapper, zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[zeroize(skip)]
    algorithm: KemAlgorithm,
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
    pub fn from_bytes(algorithm: KemAlgorithm, bytes: Vec<u8>) -> Result<Self, PqcError> {
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

    /// Returns the KEM algorithm variant.
    pub fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }
}

/// Represents a KEM ciphertext wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    algorithm: KemAlgorithm,
    bytes: Vec<u8>,
}

impl Ciphertext {
    /// Creates a ciphertext from raw bytes.
    pub fn from_bytes(algorithm: KemAlgorithm, bytes: Vec<u8>) -> Result<Self, PqcError> {
        if bytes.len() != algorithm.ciphertext_len() {
            return Err(PqcError::SerializationError(format!(
                "Invalid ciphertext length. Expected {} bytes, got {}",
                algorithm.ciphertext_len(),
                bytes.len()
            )));
        }
        Ok(Self { algorithm, bytes })
    }

    /// Returns the raw bytes of the ciphertext.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the KEM algorithm variant.
    pub fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }
}

/// Represents a shared secret, zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    #[zeroize(skip)]
    algorithm: KemAlgorithm,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("algorithm", &self.algorithm)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl SharedSecret {
    /// Creates a shared secret from raw bytes.
    pub fn from_bytes(algorithm: KemAlgorithm, bytes: Vec<u8>) -> Result<Self, PqcError> {
        if bytes.len() != algorithm.shared_secret_len() {
            return Err(PqcError::SerializationError(format!(
                "Invalid shared secret length. Expected {} bytes, got {}",
                algorithm.shared_secret_len(),
                bytes.len()
            )));
        }
        Ok(Self { algorithm, bytes })
    }

    /// Returns the raw bytes of the shared secret.
    /// Use with caution to avoid memory leaks.
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the KEM algorithm variant.
    pub fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }
}

/// The core Key Encapsulation Mechanism (KEM) trait.
pub trait Kem {
    /// Returns the algorithm configuration for this instance.
    fn algorithm(&self) -> KemAlgorithm;

    /// Generates a public/secret keypair using the provided cryptographically secure RNG.
    fn generate_keypair<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(PublicKey, SecretKey), PqcError>;

    /// Encapsulates a shared secret using a public key and the provided RNG.
    fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey,
        rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret), PqcError>;

    /// Decapsulates a ciphertext using a secret key, returning the shared secret.
    fn decapsulate(
        &self,
        ciphertext: &Ciphertext,
        secret_key: &SecretKey,
    ) -> Result<SharedSecret, PqcError>;
}
