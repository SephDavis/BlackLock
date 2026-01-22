# BlackLock

Post-quantum secure encryption using Ring Learning with Rounding (RLWR).

```
╔══════════════════════════════════════════════════════════════╗
║                      B L A C K L O C K                       ║
║         Post-Quantum Encryption using RLWR                   ║
╚══════════════════════════════════════════════════════════════╝
```

## About

Developed by **Toby Davis**, BlackLock is a conceptual project designed to explore innovative applications of RLWR in post-quantum cryptography. While this is not a fully working production algorithm, it provides a foundation for research into secure communication technologies resistant to the threats posed by quantum computing.

### Features

- **Ring Learning with Rounding (RLWR)** - Deterministic rounding provides efficiency over Ring-LWE
- **Number Theoretic Transform (NTT)** - O(n log n) polynomial multiplication
- **Multiple Security Levels** - 128-bit, 192-bit, and 256-bit security options
- **Memory Safe** - Written in Rust with `#![forbid(unsafe_code)]`
- **Zeroization** - Secret keys are securely wiped from memory on drop

## Installation

```bash
# Clone the repository
git clone https://github.com/SephDavis/BlackLock.git
cd blacklock

# Build in release mode
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

## Usage

### Command Line Interface

```bash
# Generate a keypair (default: medium security)
blacklock keygen medium

# Encrypt a message
blacklock encrypt pubkey.bin "Hello, quantum world!"

# Decrypt a ciphertext
blacklock decrypt seckey.bin ciphertext.bin

# Run demo
blacklock demo

# Run benchmarks
blacklock bench
```

### Library Usage

```rust
use blacklock::{KeyPair, SecurityLevel};

fn main() -> blacklock::Result<()> {
    // Generate a keypair
    let keypair = KeyPair::generate(SecurityLevel::Medium)?;
    
    // Encrypt a message
    let message = b"Hello, Post-Quantum World!";
    let ciphertext = keypair.public_key().encrypt(message)?;
    
    // Decrypt the ciphertext
    let decrypted = keypair.secret_key().decrypt(&ciphertext)?;
    
    assert_eq!(message.to_vec(), decrypted);
    println!("Success!");
    
    Ok(())
}
```

## Security Levels

| Level  | Ring Dimension | Security | Key Size | CT Size |
|--------|---------------|----------|----------|---------|
| Low    | n = 512       | ~128-bit | ~8 KB    | ~8 KB   |
| Medium | n = 1024      | ~192-bit | ~16 KB   | ~16 KB  |
| High   | n = 2048      | ~256-bit | ~32 KB   | ~32 KB  |

## Technical Details

### RLWR Parameters

- **Modulus q**: 12289 (NTT-friendly prime)
- **Rounding modulus p**: 256
- **Error distribution**: Centered binomial (η = 2)

### Algorithm Overview

1. **Key Generation**:
   - Sample random polynomial `a ∈ R_q`
   - Sample secret `s` with small coefficients
   - Compute `b = ⌊a·s⌉_p` (round to mod p)
   - Public key: `(a, b)`, Secret key: `s`

2. **Encryption**:
   - Sample ephemeral secret `r`
   - Compute `c₁ = ⌊a·r⌉_p`
   - Compute `c₂ = ⌊b·r⌉_p + encode(m)`
   - Ciphertext: `(c₁, c₂)`

3. **Decryption**:
   - Compute `m' = c₂ - ⌊c₁·s⌉_p`
   - Decode message from `m'`

## Attribution Requirement

If you use BlackLock in any academic or research project, publication, or derivative work, **you are required to credit the author**. Please include the following citation:

```
Toby Davis, "BlackLock: A Post-Quantum Encryption Algorithm Leveraging RLWR,"
GitHub Repository: https://github.com/SephDavis/BlackLock
```

### How to Acknowledge

- Include the citation in the "Acknowledgments" or "References" section of your research paper
- Provide a link to this repository in your documentation or project page

## License

This project is licensed under the **Creative Commons Attribution 4.0 International (CC BY 4.0)** license.

You are free to:
- **Share**: Copy and redistribute the material in any medium or format
- **Adapt**: Remix, transform, and build upon the material for any purpose, even commercially

Under the following terms:
- **Attribution**: You must give appropriate credit, provide a link to the license, and indicate if changes were made

For more details: [CC BY 4.0 License](https://creativecommons.org/licenses/by/4.0/)

## Disclaimer

BlackLock is a **conceptual project** designed for educational and exploratory purposes. It is **not a fully implemented or production-ready encryption algorithm**. 

⚠️ **Do not use this for actual security-critical applications without extensive peer review and security auditing.**

### Why Not Published as a Paper?

BlackLock has not undergone the rigorous testing and validation necessary for academic publication or production use. By sharing it in its current form, I aim to inspire collaboration and further research while ensuring its limitations are understood.

## Contributions

Contributions to BlackLock are welcome! Please ensure you:
1. Follow the terms of the license
2. Provide proper attribution to the original author
3. Run tests before submitting PRs: `cargo test`

## Contact

For questions or feedback:
- Open an issue on this repository
- Email: [your email here]

---

**BlackLock** - Exploring the quantum-resistant frontier 🔐
