//! # BlackLock
//! 
//! Post-quantum secure encryption using Ring Learning with Rounding (RLWR).
//! 
//! Developed by Toby Davis
//! 
//! ## Attribution Requirement
//! If you use BlackLock in any academic or research project, you are required to credit the author.
//! 
//! ## License
//! Creative Commons Attribution 4.0 International (CC BY 4.0)

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ntt;
pub mod rlwr;
pub mod params;
pub mod error;

pub use error::BlackLockError;
pub use rlwr::{KeyPair, PublicKey, SecretKey, Ciphertext};
pub use params::SecurityLevel;

/// Result type for BlackLock operations
pub type Result<T> = std::result::Result<T, BlackLockError>;

/// BlackLock version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_encryption_cycle() {
        let keypair = KeyPair::generate(SecurityLevel::Medium).unwrap();
        let message = b"Hello, Post-Quantum World!";
        
        let ciphertext = keypair.public_key().encrypt(message).unwrap();
        let decrypted = keypair.secret_key().decrypt(&ciphertext).unwrap();
        
        assert_eq!(message.to_vec(), decrypted);
    }

    #[test]
    fn test_different_security_levels() {
        for level in [SecurityLevel::Low, SecurityLevel::Medium, SecurityLevel::High] {
            let keypair = KeyPair::generate(level).unwrap();
            let message = b"Testing security levels";
            
            let ciphertext = keypair.public_key().encrypt(message).unwrap();
            let decrypted = keypair.secret_key().decrypt(&ciphertext).unwrap();
            
            assert_eq!(message.to_vec(), decrypted);
        }
    }
}
