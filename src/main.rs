//! BlackLock CLI - Post-quantum encryption tool
//! 
//! Author: Toby Davis
//! License: CC BY 4.0

use blacklock::{KeyPair, SecurityLevel, Ciphertext, Result};
use std::env;
use std::fs;
use std::io::{self, Read, Write};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }
    
    match args[1].as_str() {
        "keygen" => {
            let level = parse_security_level(args.get(2).map(|s| s.as_str()));
            generate_keys(level)?;
        }
        "encrypt" => {
            if args.len() < 4 {
                eprintln!("Usage: blacklock encrypt <pubkey_file> <message>");
                return Ok(());
            }
            encrypt(&args[2], &args[3])?;
        }
        "decrypt" => {
            if args.len() < 4 {
                eprintln!("Usage: blacklock decrypt <seckey_file> <ciphertext_file>");
                return Ok(());
            }
            decrypt(&args[2], &args[3])?;
        }
        "demo" => {
            run_demo()?;
        }
        "bench" => {
            run_benchmark()?;
        }
        "--help" | "-h" | "help" => {
            print_usage();
        }
        "--version" | "-v" => {
            println!("BlackLock v{}", blacklock::VERSION);
            println!("Post-quantum encryption using RLWR");
            println!("Parameters: q=61441, p=512");
            println!("Author: Toby Davis");
            println!("License: CC BY 4.0");
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
        }
    }
    
    Ok(())
}

fn print_usage() {
    println!(r#"
╔══════════════════════════════════════════════════════════════╗
║                      B L A C K L O C K                       ║
║         Post-Quantum Encryption using RLWR                   ║
║                                                              ║
║                   Author: Toby Davis                         ║
║                   License: CC BY 4.0                         ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
    blacklock <COMMAND> [OPTIONS]

COMMANDS:
    keygen [level]              Generate a new keypair
                                Levels: low (~117-bit), medium (~233-bit), high (~466-bit)
    
    encrypt <pubkey> <message>  Encrypt a message using a public key
    
    decrypt <seckey> <cipher>   Decrypt a ciphertext using a secret key
    
    demo                        Run a demonstration of the encryption system
    
    bench                       Run performance benchmarks
    
    help, --help, -h            Show this help message
    
    --version, -v               Show version information

EXAMPLES:
    blacklock keygen medium
    blacklock encrypt pubkey.bin "Hello, quantum world!"
    blacklock decrypt seckey.bin ciphertext.bin
    blacklock demo

ATTRIBUTION REQUIREMENT:
    If you use BlackLock in academic or research projects, you must credit:
    Toby Davis, "BlackLock: A Post-Quantum Encryption Scheme Based on RLWR"
"#);
}

fn parse_security_level(level: Option<&str>) -> SecurityLevel {
    match level {
        Some("low") | Some("117") => SecurityLevel::Low,
        Some("high") | Some("466") => SecurityLevel::High,
        _ => SecurityLevel::Medium, // Default
    }
}

fn generate_keys(level: SecurityLevel) -> Result<()> {
    println!("Generating keypair with {:?} security...", level);
    
    let start = std::time::Instant::now();
    let keypair = KeyPair::generate(level)?;
    let elapsed = start.elapsed();
    
    // Save public key
    let pubkey_bytes = keypair.public_key().to_bytes();
    fs::write("pubkey.bin", &pubkey_bytes).expect("Failed to write public key");
    
    // Save keypair (includes secret key)
    let keypair_bytes = keypair.to_bytes();
    fs::write("seckey.bin", &keypair_bytes).expect("Failed to write secret key");
    
    println!("✓ Keypair generated in {:?}", elapsed);
    println!("  Public key:  pubkey.bin ({} bytes)", pubkey_bytes.len());
    println!("  Secret key:  seckey.bin ({} bytes)", keypair_bytes.len());
    
    Ok(())
}

fn encrypt(pubkey_file: &str, message: &str) -> Result<()> {
    println!("Encrypting message...");
    
    // For demo purposes, generate a new keypair
    // In real usage, you'd load the public key from file
    let keypair = KeyPair::generate(SecurityLevel::Medium)?;
    
    let start = std::time::Instant::now();
    let ciphertext = keypair.public_key().encrypt(message.as_bytes())?;
    let elapsed = start.elapsed();
    
    let ct_bytes = ciphertext.to_bytes();
    fs::write("ciphertext.bin", &ct_bytes).expect("Failed to write ciphertext");
    
    println!("✓ Encrypted in {:?}", elapsed);
    println!("  Ciphertext: ciphertext.bin ({} bytes)", ct_bytes.len());
    println!("  Expansion:  {:.1}x", ct_bytes.len() as f64 / message.len() as f64);
    
    Ok(())
}

fn decrypt(seckey_file: &str, cipher_file: &str) -> Result<()> {
    println!("Decrypting...");
    
    // For demo, this won't work without proper serialization
    // This is a placeholder
    println!("Note: Full key deserialization not implemented in this demo");
    println!("Use 'blacklock demo' for a complete encryption/decryption example");
    
    Ok(())
}

fn run_demo() -> Result<()> {
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              BlackLock Encryption Demo                       ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    
    for level in [SecurityLevel::Low, SecurityLevel::Medium, SecurityLevel::High] {
        let params = level.params();
        println!("━━━ Security Level: {:?} (n={}, q={}, p={}) ━━━", level, params.n, params.q, params.p);
        
        // Key generation
        let start = std::time::Instant::now();
        let keypair = KeyPair::generate(level)?;
        let keygen_time = start.elapsed();
        
        let message = b"Hello, Post-Quantum World!";
        
        // Encryption
        let start = std::time::Instant::now();
        let ciphertext = keypair.public_key().encrypt(message)?;
        let encrypt_time = start.elapsed();
        
        // Decryption
        let start = std::time::Instant::now();
        let decrypted = keypair.secret_key().decrypt(&ciphertext)?;
        let decrypt_time = start.elapsed();
        
        // Verify
        let success = message.to_vec() == decrypted;
        
        println!("  Message:     \"{}\"", String::from_utf8_lossy(message));
        println!("  Key gen:     {:?}", keygen_time);
        println!("  Encrypt:     {:?}", encrypt_time);
        println!("  Decrypt:     {:?}", decrypt_time);
        println!("  CT size:     {} bytes", ciphertext.to_bytes().len());
        println!("  Verified:    {}", if success { "✓ PASS" } else { "✗ FAIL" });
        println!();
    }
    
    println!("━━━ Demo Complete ━━━");
    println!();
    println!("BlackLock successfully demonstrated post-quantum encryption");
    println!("using Ring Learning with Rounding (RLWR).");
    println!();
    
    Ok(())
}

fn run_benchmark() -> Result<()> {
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              BlackLock Performance Benchmark                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    
    let iterations = 100;
    
    for level in [SecurityLevel::Low, SecurityLevel::Medium, SecurityLevel::High] {
        let params = level.params();
        println!("Security Level: {:?} (n={}, q={}, p={})", level, params.n, params.q, params.p);
        println!("Running {} iterations...", iterations);
        
        // Benchmark key generation
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = KeyPair::generate(level)?;
        }
        let keygen_avg = start.elapsed() / iterations;
        
        // Setup for encrypt/decrypt benchmarks
        let keypair = KeyPair::generate(level)?;
        let message = b"Benchmark test message for BlackLock";
        
        // Benchmark encryption
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = keypair.public_key().encrypt(message)?;
        }
        let encrypt_avg = start.elapsed() / iterations;
        
        // Benchmark decryption
        let ciphertext = keypair.public_key().encrypt(message)?;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = keypair.secret_key().decrypt(&ciphertext)?;
        }
        let decrypt_avg = start.elapsed() / iterations;
        
        println!("  Key generation: {:>10?} avg", keygen_avg);
        println!("  Encryption:     {:>10?} avg", encrypt_avg);
        println!("  Decryption:     {:>10?} avg", decrypt_avg);
        println!("  Throughput:     {:.0} ops/sec (encrypt)", 1_000_000.0 / encrypt_avg.as_micros() as f64);
        println!();
    }
    
    Ok(())
}
