use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pqc_rust::{
    DigitalSignature, Dilithium, Falcon, Kem, KemAlgorithm, Kyber, SigAlgorithm, SphincsPlus,
};

/// A simple seedable mock RNG implementing `RngCore` and `CryptoRng` for benchmarking.
struct MockRng {
    state: u64,
}

impl MockRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

impl rand_core::RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.state >> 32) as u32
    }

    fn next_u64(&mut self) -> u64 {
        let low = self.next_u32() as u64;
        let high = self.next_u32() as u64;
        (high << 32) | low
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            let rand = self.next_u32();
            let bytes = rand.to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for MockRng {}

fn bench_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM");
    let mut rng = MockRng::new(123);
    let algos = [
        KemAlgorithm::Kyber512,
        KemAlgorithm::Kyber768,
        KemAlgorithm::Kyber1024,
    ];

    for algo in algos {
        let kem = Kyber::new(algo).unwrap();
        let algo_name = format!("{:?}", algo);

        // Keygen Benchmark
        group.bench_function(BenchmarkId::new("KeyGen", &algo_name), |b| {
            b.iter(|| {
                let _ = kem.generate_keypair(&mut rng).unwrap();
            })
        });

        // Encapsulate Benchmark
        let (pk, sk) = kem.generate_keypair(&mut rng).unwrap();
        group.bench_function(BenchmarkId::new("Encapsulate", &algo_name), |b| {
            b.iter(|| {
                let _ = kem.encapsulate(&pk, &mut rng).unwrap();
            })
        });

        // Decapsulate Benchmark
        let (ct, _) = kem.encapsulate(&pk, &mut rng).unwrap();
        group.bench_function(BenchmarkId::new("Decapsulate", &algo_name), |b| {
            b.iter(|| {
                let _ = kem.decapsulate(&ct, &sk).unwrap();
            })
        });
    }
    group.finish();
}

fn bench_sig(c: &mut Criterion) {
    let mut group = c.benchmark_group("Signature");
    let mut rng = MockRng::new(456);
    let message = b"Benchmarking PQC digital signatures with standard input sizes.";

    // Dilithium
    let dilithium_algos = [
        SigAlgorithm::Dilithium2,
        SigAlgorithm::Dilithium3,
        SigAlgorithm::Dilithium5,
    ];
    for algo in dilithium_algos {
        let sig_scheme = Dilithium::new(algo).unwrap();
        let algo_name = format!("{:?}", algo);

        group.bench_function(BenchmarkId::new("KeyGen", &algo_name), |b| {
            b.iter(|| {
                let _ = sig_scheme.generate_keypair(&mut rng).unwrap();
            })
        });

        let (pk, sk) = sig_scheme.generate_keypair(&mut rng).unwrap();
        group.bench_function(BenchmarkId::new("Sign", &algo_name), |b| {
            b.iter(|| {
                let _ = sig_scheme.sign(message, &sk, &mut rng).unwrap();
            })
        });

        let signature = sig_scheme.sign(message, &sk, &mut rng).unwrap();
        group.bench_function(BenchmarkId::new("Verify", &algo_name), |b| {
            b.iter(|| {
                let _ = sig_scheme.verify(message, &signature, &pk).unwrap();
            })
        });
    }

    // Falcon
    let falcon_algos = [SigAlgorithm::Falcon512, SigAlgorithm::Falcon1024];
    for algo in falcon_algos {
        let sig_scheme = Falcon::new(algo).unwrap();
        let algo_name = format!("{:?}", algo);

        group.bench_function(BenchmarkId::new("KeyGen", &algo_name), |b| {
            b.iter(|| {
                let _ = sig_scheme.generate_keypair(&mut rng).unwrap();
            })
        });

        let (pk, sk) = sig_scheme.generate_keypair(&mut rng).unwrap();
        group.bench_function(BenchmarkId::new("Sign", &algo_name), |b| {
            b.iter(|| {
                let _ = sig_scheme.sign(message, &sk, &mut rng).unwrap();
            })
        });

        let signature = sig_scheme.sign(message, &sk, &mut rng).unwrap();
        group.bench_function(BenchmarkId::new("Verify", &algo_name), |b| {
            b.iter(|| {
                let _ = sig_scheme.verify(message, &signature, &pk).unwrap();
            })
        });
    }

    // SPHINCS+
    let sphincs_algos = [SigAlgorithm::SphincsPlus128s, SigAlgorithm::SphincsPlus256s];
    for algo in sphincs_algos {
        let sig_scheme = SphincsPlus::new(algo).unwrap();
        let algo_name = format!("{:?}", algo);

        group.bench_function(BenchmarkId::new("KeyGen", &algo_name), |b| {
            b.iter(|| {
                let _ = sig_scheme.generate_keypair(&mut rng).unwrap();
            })
        });

        let (pk, sk) = sig_scheme.generate_keypair(&mut rng).unwrap();
        group.bench_function(BenchmarkId::new("Sign", &algo_name), |b| {
            b.iter(|| {
                let _ = sig_scheme.sign(message, &sk, &mut rng).unwrap();
            })
        });

        let signature = sig_scheme.sign(message, &sk, &mut rng).unwrap();
        group.bench_function(BenchmarkId::new("Verify", &algo_name), |b| {
            b.iter(|| {
                let _ = sig_scheme.verify(message, &signature, &pk).unwrap();
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_kem, bench_sig);
criterion_main!(benches);
