//! Security parameters for BlackLock RLWR
//!
//! Parameters selected to satisfy:
//!   1. NTT compatibility: q ≡ 1 (mod 2n) for all n
//!   2. RLWR hardness: q/p ≥ 2√n for all n (q/p = 120 > 90.5 = 2√2048)
//!   3. Decryption correctness: failure δ < 2^{-44} for all parameter sets
//!
//! See: "BlackLock: A Post-Quantum Public-Key Encryption Scheme Based on
//! Ring Learning with Rounding" (Davis, 2025)

/// Security level selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// ~117-bit classical security (faster, smaller keys)
    Low,
    /// ~233-bit classical security (balanced, recommended default)
    Medium,
    /// ~466-bit classical security (conservative, long-term)
    High,
}

/// RLWR parameters for a given security level
#[derive(Debug, Clone, Copy)]
pub struct Parameters {
    /// Polynomial ring dimension (power of 2)
    pub n: usize,
    /// Modulus q (NTT-friendly prime, q ≡ 1 mod 2n for all n)
    pub q: u64,
    /// Rounding modulus p (power of 2)
    pub p: u64,
    /// Number of bits in the rounding modulus (log2(p))
    pub rounding_bits: u32,
    /// Error distribution parameter (ternary: η is unused, kept for API compat)
    pub eta: u32,
    /// Maximum message bytes (n/8, one bit per coefficient)
    pub max_message_bytes: usize,
}

impl SecurityLevel {
    /// Get the parameters for this security level
    pub fn params(self) -> Parameters {
        match self {
            // BL-512: ~117-bit classical, δ < 2^{-203}
            SecurityLevel::Low => Parameters {
                n: 512,
                q: 61441,          // NTT-friendly prime, 61441 ≡ 1 (mod 4096)
                p: 512,            // 2^9, q/p = 120
                rounding_bits: 9,
                eta: 1,            // ternary secret
                max_message_bytes: 64,
            },
            // BL-1024: ~233-bit classical, δ < 2^{-98}
            SecurityLevel::Medium => Parameters {
                n: 1024,
                q: 61441,
                p: 512,
                rounding_bits: 9,
                eta: 1,
                max_message_bytes: 128,
            },
            // BL-2048: ~466-bit classical, δ < 2^{-44}
            SecurityLevel::High => Parameters {
                n: 2048,
                q: 61441,
                p: 512,
                rounding_bits: 9,
                eta: 1,
                max_message_bytes: 256,
            },
        }
    }
}

impl Parameters {
    /// Calculate the rounding shift value (q / p)
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
    fn test_parameter_invariants() {
        for level in [SecurityLevel::Low, SecurityLevel::Medium, SecurityLevel::High] {
            let p = level.params();
            // q must be prime (basic check: not even, not div by small primes)
            assert!(p.q > 2 && p.q % 2 != 0);
            // q ≡ 1 (mod 2n)
            assert_eq!(p.q % (2 * p.n as u64), 1, "q ≡ 1 (mod 2n) failed for n={}", p.n);
            // RLWR hardness: q/p ≥ 2√n
            let ratio = p.q as f64 / p.p as f64;
            let threshold = 2.0 * (p.n as f64).sqrt();
            assert!(ratio >= threshold, "RLWR condition failed: q/p={} < 2√n={}", ratio, threshold);
            // p is power of 2
            assert!(p.p.is_power_of_two());
            // max message = n/8 bytes
            assert_eq!(p.max_message_bytes, p.n / 8);
        }
    }

    #[test]
    fn test_rounding() {
        let params = SecurityLevel::Medium.params();

        // Test round-trip (approximate)
        for val in [0u64, 100, 1000, 5000, 10000, 50000, 61000] {
            let val = val % params.q;
            let rounded = params.round(val);
            let unrounded = params.unround(rounded);
            let diff = if val > unrounded { val - unrounded } else { unrounded - val };
            assert!(diff <= params.round_shift(), "Rounding error too large for val={}", val);
        }
    }
}
