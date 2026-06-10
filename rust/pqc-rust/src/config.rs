/// Represents the supported configurations for Key Encapsulation Mechanisms (KEM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KemAlgorithm {
    /// Kyber-512 (NIST Security Level 1)
    Kyber512,
    /// Kyber-768 (NIST Security Level 3)
    Kyber768,
    /// Kyber-1024 (NIST Security Level 5)
    Kyber1024,
}

impl KemAlgorithm {
    /// Returns the public key length in bytes for the configuration.
    pub const fn public_key_len(&self) -> usize {
        match self {
            Self::Kyber512 => 800,
            Self::Kyber768 => 1184,
            Self::Kyber1024 => 1568,
        }
    }

    /// Returns the secret key length in bytes for the configuration.
    pub const fn secret_key_len(&self) -> usize {
        match self {
            Self::Kyber512 => 1632,
            Self::Kyber768 => 2400,
            Self::Kyber1024 => 3168,
        }
    }

    /// Returns the ciphertext length in bytes for the configuration.
    pub const fn ciphertext_len(&self) -> usize {
        match self {
            Self::Kyber512 => 768,
            Self::Kyber768 => 1088,
            Self::Kyber1024 => 1568,
        }
    }

    /// Returns the shared secret length in bytes (usually 32 bytes for Kyber).
    pub const fn shared_secret_len(&self) -> usize {
        32
    }
}

/// Represents the supported configurations for Digital Signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigAlgorithm {
    /// Dilithium2 (NIST Security Level 2)
    Dilithium2,
    /// Dilithium3 (NIST Security Level 3)
    Dilithium3,
    /// Dilithium5 (NIST Security Level 5)
    Dilithium5,
    /// Falcon-512 (NIST Security Level 1)
    Falcon512,
    /// Falcon-1024 (NIST Security Level 5)
    Falcon1024,
    /// SPHINCS+-128s (Simple/Robust, Level 1)
    SphincsPlus128s,
    /// SPHINCS+-256s (Simple/Robust, Level 5)
    SphincsPlus256s,
}

impl SigAlgorithm {
    /// Returns the public key length in bytes for the signature scheme.
    pub const fn public_key_len(&self) -> usize {
        match self {
            Self::Dilithium2 => 1312,
            Self::Dilithium3 => 1952,
            Self::Dilithium5 => 2592,
            Self::Falcon512 => 897,
            Self::Falcon1024 => 1793,
            Self::SphincsPlus128s => 32,
            Self::SphincsPlus256s => 64,
        }
    }

    /// Returns the secret key length in bytes for the signature scheme.
    pub const fn secret_key_len(&self) -> usize {
        match self {
            Self::Dilithium2 => 2528,
            Self::Dilithium3 => 4000,
            Self::Dilithium5 => 4864,
            Self::Falcon512 => 1281,
            Self::Falcon1024 => 2305,
            Self::SphincsPlus128s => 64,
            Self::SphincsPlus256s => 128,
        }
    }

    /// Returns the maximum signature length in bytes for the signature scheme.
    pub const fn signature_len(&self) -> usize {
        match self {
            Self::Dilithium2 => 2420,
            Self::Dilithium3 => 3300,
            Self::Dilithium5 => 4595,
            Self::Falcon512 => 666,
            Self::Falcon1024 => 1280,
            Self::SphincsPlus128s => 7856,
            Self::SphincsPlus256s => 29792,
        }
    }
}
