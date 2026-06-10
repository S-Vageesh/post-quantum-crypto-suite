# Post-Quantum Cryptography Toolkit

A Rust-based toolkit for experimenting with modern post-quantum cryptographic algorithms and building familiarity with NIST-standardized quantum-resistant primitives.

## Overview

This project explores practical post-quantum cryptography through a modular and extensible architecture. The current implementation integrates CRYSTALS-Kyber, a NIST-standardized Key Encapsulation Mechanism (KEM), using the pqcrypto ecosystem.

The codebase is designed to allow future expansion to additional post-quantum algorithms such as Dilithium, Falcon, and SPHINCS+.

## Features

### Implemented

* Modular cryptographic architecture in Rust
* CRYSTALS-Kyber KEM integration
* Key generation
* Encapsulation
* Decapsulation
* Shared secret verification example
* Integration tests and example programs
* Benchmarking infrastructure

### Planned

* Dilithium digital signatures
* Falcon digital signatures
* SPHINCS+ digital signatures
* Performance benchmarking across algorithms
* Additional cryptographic demonstrations

## Project Structure

```text
src/
├── kem/
│   └── kyber.rs
│
├── sig/
│   ├── dilithium.rs
│   ├── falcon.rs
│   └── sphincs.rs
│
├── config.rs
├── errors.rs
├── lib.rs
└── main.rs
```

## Example

Generate a keypair, perform encapsulation, and verify that both parties derive the same shared secret:

```bash
cargo run --example kyber_demo
```

## Technology Stack

* Rust
* pqcrypto-kyber
* pqcrypto-traits
* Cargo
* Git & GitHub

## Learning Goals

* Post-Quantum Cryptography
* Key Encapsulation Mechanisms (KEMs)
* Secure software architecture
* Rust cryptography ecosystem
* Cryptographic API design

## Status

Current Stage: Kyber Integration Complete

This repository is actively evolving toward a broader post-quantum cryptography toolkit.
