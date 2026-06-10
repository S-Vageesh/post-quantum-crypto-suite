use thiserror::Error;

/// Custom error type for Post-Quantum Cryptography Suite operations.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum PqcError {
    /// Error generated when key generation fails.
    #[error("Key generation failed: {0}")]
    KeyGenError(String),

    /// Error generated when serialization or deserialization fails.
    #[error("Serialization or deserialization failed: {0}")]
    SerializationError(String),

    /// Error generated during key encapsulation.
    #[error("Encapsulation failed: {0}")]
    EncapsulationError(String),

    /// Error generated when decapsulation fails (e.g. invalid ciphertext or secret key mismatch).
    #[error("Decapsulation failed: {0}")]
    DecapsulationError(String),

    /// Error generated when digital signature signing fails.
    #[error("Signature signing failed: {0}")]
    SigningError(String),

    /// Error generated when signature verification fails.
    #[error("Signature verification failed: {0}")]
    VerificationError(String),

    /// Error generated when an invalid parameter or configuration is provided.
    #[error("Invalid algorithm configuration or parameters: {0}")]
    InvalidConfig(String),
}
