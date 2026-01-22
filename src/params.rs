//! Security parameters for BlackLock RLWR

/// Security level selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// ~128-bit security (faster, smaller keys)
    Low,
    /// ~192-bit security (balanced)
    Medium,
    /// ~256-bit security (maximum security)
    High,
}

/// RLWR parameters for a given security level
#[derive(Debug, Clone, Copy)]
pub struct Parameters {
    /// Polynomial ring dimension (power of 2)
    pub n: usize,
    /// Modulus q
    pub q: u64,
    /// Rounding modulus p
    pub p: u64,
    /// Number of bits to round off
    pub rounding_bits: u32,
    /// Error distribution parameter
    pub eta: u32,
    /// Maximum message bytes
    pub max_message_bytes: usize,
}

impl SecurityLevel {
    /// Get the parameters for this security level
    pub fn params(self) -> Parameters {
        match self {
            SecurityLevel::Low => Parameters {
                n: 512,
                q: 12289,          // NTT-friendly prime
                p: 256,
                rounding_bits: 6,
                eta: 2,
                max_message_bytes: 32,
            },
            SecurityLevel::Medium => Parameters {
                n: 1024,
                q: 12289,
                p: 256,
                rounding_bits: 6,
                eta: 2,
                max_message_bytes: 64,
            },
            SecurityLevel::High => Parameters {
                n: 2048,
                q: 12289,
                p: 256,
                rounding_bits: 6,
                eta: 2,
                max_message_bytes: 128,
            },
        }
    }
}

impl Parameters {
    /// Calculate the rounding shift value
    #[inline]
    pub fn round_shift(&self) -> u64 {
        self.q / self.p
    }

    /// Round a value from mod q to mod p
    #[inline]
    pub fn round(&self, x: u64) -> u64 {
        let shift = self.round_shift();
        ((x + shift / 2) / shift) % self.p
    }

    /// Unround (scale) a value from mod p back to mod q
    #[inline]
    pub fn unround(&self, x: u64) -> u64 {
        (x * self.round_shift()) % self.q
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rounding() {
        let params = SecurityLevel::Medium.params();
        
        // Test round-trip (approximate)
        for val in [0u64, 100, 1000, 5000, 10000] {
            let rounded = params.round(val);
            let unrounded = params.unround(rounded);
            // Should be within rounding error
            let diff = if val > unrounded { val - unrounded } else { unrounded - val };
            assert!(diff < params.round_shift(), "Rounding error too large");
        }
    }
}
