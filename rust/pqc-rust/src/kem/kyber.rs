use crate::errors::PqcError;
use crate::config::KemAlgorithm;
use crate::kem::{Kem, PublicKey, SecretKey, Ciphertext, SharedSecret};
use rand_core::{CryptoRng, RngCore};
use pqcrypto_traits::kem::{
    PublicKey as _, SecretKey as _, Ciphertext as _, SharedSecret as _,
};

/// Implementation of the Kyber Key Encapsulation Mechanism (KEM) using the pqcrypto ecosystem.
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
        _rng: &mut R,
    ) -> Result<(PublicKey, SecretKey), PqcError> {
        let (pk_bytes, sk_bytes) = match self.algorithm {
            KemAlgorithm::Kyber512 => {
                let (pk, sk) = pqcrypto_kyber::kyber512::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            KemAlgorithm::Kyber768 => {
                let (pk, sk) = pqcrypto_kyber::kyber768::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            KemAlgorithm::Kyber1024 => {
                let (pk, sk) = pqcrypto_kyber::kyber1024::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
        };

        let pk = PublicKey::from_bytes(self.algorithm, pk_bytes)?;
        let sk = SecretKey::from_bytes(self.algorithm, sk_bytes)?;

        Ok((pk, sk))
    }

    fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey,
        _rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret), PqcError> {
        if public_key.algorithm() != self.algorithm {
            return Err(PqcError::InvalidConfig(
                "Public key algorithm mismatch".to_string(),
            ));
        }

        let (ct_bytes, ss_bytes) = match self.algorithm {
            KemAlgorithm::Kyber512 => {
                let pk = pqcrypto_kyber::kyber512::PublicKey::from_bytes(public_key.as_bytes())
                    .map_err(|e| PqcError::SerializationError(format!("Invalid public key bytes: {:?}", e)))?;
                let (ss, ct) = pqcrypto_kyber::kyber512::encapsulate(&pk);
                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            KemAlgorithm::Kyber768 => {
                let pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(public_key.as_bytes())
                    .map_err(|e| PqcError::SerializationError(format!("Invalid public key bytes: {:?}", e)))?;
                let (ss, ct) = pqcrypto_kyber::kyber768::encapsulate(&pk);
                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            KemAlgorithm::Kyber1024 => {
                let pk = pqcrypto_kyber::kyber1024::PublicKey::from_bytes(public_key.as_bytes())
                    .map_err(|e| PqcError::SerializationError(format!("Invalid public key bytes: {:?}", e)))?;
                let (ss, ct) = pqcrypto_kyber::kyber1024::encapsulate(&pk);
                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
        };

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

        let ss_bytes = match self.algorithm {
            KemAlgorithm::Kyber512 => {
                let ct = pqcrypto_kyber::kyber512::Ciphertext::from_bytes(ciphertext.as_bytes())
                    .map_err(|e| PqcError::SerializationError(format!("Invalid ciphertext bytes: {:?}", e)))?;
                let sk = pqcrypto_kyber::kyber512::SecretKey::from_bytes(secret_key.expose_secret())
                    .map_err(|e| PqcError::SerializationError(format!("Invalid secret key bytes: {:?}", e)))?;
                let ss = pqcrypto_kyber::kyber512::decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            }
            KemAlgorithm::Kyber768 => {
                let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ciphertext.as_bytes())
                    .map_err(|e| PqcError::SerializationError(format!("Invalid ciphertext bytes: {:?}", e)))?;
                let sk = pqcrypto_kyber::kyber768::SecretKey::from_bytes(secret_key.expose_secret())
                    .map_err(|e| PqcError::SerializationError(format!("Invalid secret key bytes: {:?}", e)))?;
                let ss = pqcrypto_kyber::kyber768::decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            }
            KemAlgorithm::Kyber1024 => {
                let ct = pqcrypto_kyber::kyber1024::Ciphertext::from_bytes(ciphertext.as_bytes())
                    .map_err(|e| PqcError::SerializationError(format!("Invalid ciphertext bytes: {:?}", e)))?;
                let sk = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(secret_key.expose_secret())
                    .map_err(|e| PqcError::SerializationError(format!("Invalid secret key bytes: {:?}", e)))?;
                let ss = pqcrypto_kyber::kyber1024::decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            }
        };

        SharedSecret::from_bytes(self.algorithm, ss_bytes)
    }
}
