//! # Post-Quantum Cryptography (PQC) Suite
//!
//! A clean, modular toolkit in Rust designed to support next-generation post-quantum
//! cryptographic algorithms, including Kyber for Key Encapsulation (KEM) and
//! Dilithium, Falcon, and SPHINCS+ for Digital Signatures.
//!
//! This crate provides robust trait interfaces for general KEM and signature schemes,
//! safe key handling via zeroization, configuration-based instantiation, and unified error handling.

pub mod config;
pub mod errors;
pub mod kem;
pub mod sig;

// Re-export core items for simpler usage
pub use config::{KemAlgorithm, SigAlgorithm};
pub use errors::PqcError;
pub use kem::{
    Ciphertext, Kem, PublicKey as KemPublicKey, SecretKey as KemSecretKey, SharedSecret,
};
pub use sig::{DigitalSignature, PublicKey as SigPublicKey, SecretKey as SigSecretKey, Signature};

// Re-export algorithm implementations
pub use kem::kyber::Kyber;
pub use sig::dilithium::Dilithium;
pub use sig::falcon::Falcon;
pub use sig::sphincs::SphincsPlus;
