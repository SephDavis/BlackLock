//! Benchmarks for BlackLock operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use blacklock::{KeyPair, SecurityLevel};

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("Key Generation");
    
    for level in [SecurityLevel::Low, SecurityLevel::Medium, SecurityLevel::High] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", level)),
            &level,
            |b, &level| {
                b.iter(|| KeyPair::generate(black_box(level)).unwrap())
            },
        );
    }
    
    group.finish();
}

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encryption");
    let message = b"Hello, Post-Quantum World! This is a test message.";
    
    for level in [SecurityLevel::Low, SecurityLevel::Medium, SecurityLevel::High] {
        let keypair = KeyPair::generate(level).unwrap();
        
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", level)),
            &keypair,
            |b, keypair| {
                b.iter(|| keypair.public_key().encrypt(black_box(message)).unwrap())
            },
        );
    }
    
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decryption");
    let message = b"Hello, Post-Quantum World! This is a test message.";
    
    for level in [SecurityLevel::Low, SecurityLevel::Medium, SecurityLevel::High] {
        let keypair = KeyPair::generate(level).unwrap();
        let ciphertext = keypair.public_key().encrypt(message).unwrap();
        
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", level)),
            &(keypair, ciphertext),
            |b, (keypair, ciphertext)| {
                b.iter(|| keypair.secret_key().decrypt(black_box(ciphertext)).unwrap())
            },
        );
    }
    
    group.finish();
}

fn bench_full_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("Full Cycle (keygen + encrypt + decrypt)");
    let message = b"Hello, Post-Quantum World!";
    
    for level in [SecurityLevel::Low, SecurityLevel::Medium, SecurityLevel::High] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", level)),
            &level,
            |b, &level| {
                b.iter(|| {
                    let keypair = KeyPair::generate(level).unwrap();
                    let ciphertext = keypair.public_key().encrypt(black_box(message)).unwrap();
                    keypair.secret_key().decrypt(&ciphertext).unwrap()
                })
            },
        );
    }
    
    group.finish();
}

criterion_group!(benches, bench_keygen, bench_encrypt, bench_decrypt, bench_full_cycle);
criterion_main!(benches);
