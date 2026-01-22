//! Error types for BlackLock operations

use thiserror::Error;

/// Errors that can occur during BlackLock operations
#[derive(Error, Debug)]
pub enum BlackLockError {
    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    /// Invalid parameter
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Message too long for encryption
    #[error("Message too long: max {max} bytes, got {actual}")]
    MessageTooLong { max: usize, actual: usize },

    /// Invalid ciphertext format
    #[error("Invalid ciphertext format")]
    InvalidCiphertext,

    /// RNG error
    #[error("Random number generation failed")]
    RngError,
}
