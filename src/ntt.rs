//! Number Theoretic Transform (NTT) for efficient polynomial multiplication
//! 
//! This NTT implements negacyclic convolution for the ring Z_q[x]/(x^n + 1),
//! which is required for Ring-LWE based cryptography.
//!
//! For q = 61441: primitive root g = 17
//!   n=512:  ψ = 421,   ψ⁻¹ = 46701
//!   n=1024: ψ = 16290, ψ⁻¹ = 58269
//!   n=2048: ψ = 39003, ψ⁻¹ = 24658

use crate::params::Parameters;

/// Precomputed NTT tables for a given parameter set
#[derive(Clone)]
pub struct NttTables {
    /// Powers of psi (2n-th root of unity) for forward transform
    psi_powers: Vec<u64>,
    /// Powers of psi^(-1) for inverse transform
    psi_inv_powers: Vec<u64>,
    /// Modulus
    q: u64,
    /// Dimension
    n: usize,
    /// n^(-1) mod q
    n_inv: u64,
}

impl NttTables {
    /// Create new NTT tables for the given parameters
    pub fn new(params: &Parameters) -> Self {
        let n = params.n;
        let q = params.q;
        
        // For negacyclic NTT, we need a primitive 2n-th root of unity (psi)
        // such that psi^(2n) = 1 and psi^n = -1
        // For q = 61441, we have q - 1 = 61440 = 2^12 * 3 * 5
        // We need 2n | (q-1), which is satisfied for n = 512, 1024, 2048
        
        let g = find_generator(q);
        // psi = g^((q-1)/(2n)) is a primitive 2n-th root of unity
        let psi = mod_exp(g, (q - 1) / (2 * n as u64), q);
        let psi_inv = mod_inverse(psi, q);
        let n_inv = mod_inverse(n as u64, q);
        
        // Verify psi is a primitive 2n-th root of unity
        debug_assert_eq!(mod_exp(psi, 2 * n as u64, q), 1, "ψ^(2n) ≠ 1");
        debug_assert_eq!(mod_exp(psi, n as u64, q), q - 1, "ψ^n ≠ -1");
        
        // Precompute powers of psi in bit-reversed order for the NTT
        let psi_powers = compute_powers_bitrev(psi, n, q);
        let psi_inv_powers = compute_powers_bitrev(psi_inv, n, q);
        
        Self {
            psi_powers,
            psi_inv_powers,
            q,
            n,
            n_inv,
        }
    }
    
    /// Forward NTT: transforms polynomial to NTT domain
    /// Input: polynomial coefficients a[0], a[1], ..., a[n-1]
    /// Output: NTT(a) for negacyclic convolution
    pub fn forward(&self, a: &mut [u64]) {
        debug_assert_eq!(a.len(), self.n);
        
        let n = self.n;
        let q = self.q;
        
        let mut t = n;
        let mut m = 1;
        
        while m < n {
            t /= 2;
            for i in 0..m {
                let j1 = 2 * i * t;
                let j2 = j1 + t;
                let s = self.psi_powers[m + i];
                
                for j in j1..j2 {
                    let u = a[j];
                    let v = mul_mod(a[j + t], s, q);
                    a[j] = add_mod(u, v, q);
                    a[j + t] = sub_mod(u, v, q);
                }
            }
            m *= 2;
        }
    }
    
    /// Inverse NTT: transforms from NTT domain back to coefficient domain
    pub fn inverse(&self, a: &mut [u64]) {
        debug_assert_eq!(a.len(), self.n);
        
        let n = self.n;
        let q = self.q;
        
        let mut t = 1;
        let mut m = n;
        
        while m > 1 {
            let h = m / 2;
            let mut j1 = 0;
            
            for i in 0..h {
                let j2 = j1 + t;
                let s = self.psi_inv_powers[h + i];
                
                for j in j1..j2 {
                    let u = a[j];
                    let v = a[j + t];
                    a[j] = add_mod(u, v, q);
                    a[j + t] = mul_mod(sub_mod(u, v, q), s, q);
                }
                j1 += 2 * t;
            }
            t *= 2;
            m = h;
        }
        
        // Scale by n^(-1)
        for coeff in a.iter_mut() {
            *coeff = mul_mod(*coeff, self.n_inv, q);
        }
    }
    
    /// Pointwise multiplication in NTT domain
    pub fn pointwise_mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        debug_assert_eq!(a.len(), self.n);
        debug_assert_eq!(b.len(), self.n);
        
        a.iter()
            .zip(b.iter())
            .map(|(&x, &y)| mul_mod(x, y, self.q))
            .collect()
    }
    
    /// Add two polynomials
    pub fn poly_add(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        a.iter()
            .zip(b.iter())
            .map(|(&x, &y)| add_mod(x, y, self.q))
            .collect()
    }
    
    /// Subtract two polynomials
    pub fn poly_sub(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        a.iter()
            .zip(b.iter())
            .map(|(&x, &y)| sub_mod(x, y, self.q))
            .collect()
    }
}

/// Compute powers of w in bit-reversed order
fn compute_powers_bitrev(w: u64, n: usize, q: u64) -> Vec<u64> {
    let mut powers = vec![0u64; n];
    powers[0] = 1;
    
    for i in 1..n {
        powers[i] = mul_mod(powers[i - 1], w, q);
    }
    
    // Bit-reverse the array
    bit_reverse_array(&mut powers);
    powers
}

/// Bit-reverse permutation of an array
fn bit_reverse_array(a: &mut [u64]) {
    let n = a.len();
    let log_n = (n as f64).log2() as u32;
    
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            a.swap(i, j);
        }
    }
}

/// Reverse the bits of x, considering only 'bits' number of bits
fn bit_reverse(x: usize, bits: u32) -> usize {
    let mut result = 0;
    let mut x = x;
    for _ in 0..bits {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    result
}

/// Modular addition
#[inline(always)]
fn add_mod(a: u64, b: u64, q: u64) -> u64 {
    let sum = a + b;
    if sum >= q { sum - q } else { sum }
}

/// Modular subtraction
#[inline(always)]
fn sub_mod(a: u64, b: u64, q: u64) -> u64 {
    if a >= b { a - b } else { a + q - b }
}

/// Modular multiplication using u128 to avoid overflow
#[inline(always)]
fn mul_mod(a: u64, b: u64, q: u64) -> u64 {
    ((a as u128 * b as u128) % q as u128) as u64
}

/// Modular exponentiation using binary method
pub fn mod_exp(base: u64, mut exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    
    let mut result = 1u64;
    let mut base = base % modulus;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = mul_mod(result, base, modulus);
        }
        exp >>= 1;
        base = mul_mod(base, base, modulus);
    }
    
    result
}

/// Extended Euclidean algorithm for modular inverse
pub fn mod_inverse(a: u64, m: u64) -> u64 {
    let mut mn = (m as i128, a as i128);
    let mut xy = (0i128, 1i128);
    
    while mn.1 != 0 {
        let q = mn.0 / mn.1;
        mn = (mn.1, mn.0 - q * mn.1);
        xy = (xy.1, xy.0 - q * xy.1);
    }
    
    ((xy.0 % m as i128 + m as i128) % m as i128) as u64
}

/// Find a generator of Z_q^* (primitive root modulo q)
fn find_generator(q: u64) -> u64 {
    // Known generators for BlackLock primes
    match q {
        12289 => return 11,  // legacy (original parameters)
        61441 => return 17,  // current BlackLock parameters
        _ => {}
    }
    
    // General case: find a generator by trial
    let phi = q - 1;
    let factors = factorize(phi);
    
    for g in 2..q {
        let mut is_generator = true;
        for &f in &factors {
            if mod_exp(g, phi / f, q) == 1 {
                is_generator = false;
                break;
            }
        }
        if is_generator {
            return g;
        }
    }
    
    panic!("No generator found for q = {}", q);
}

/// Factorize n into its prime factors (just the factors, not multiplicities)
fn factorize(mut n: u64) -> Vec<u64> {
    let mut factors = Vec::new();
    let mut d = 2;
    
    while d * d <= n {
        if n % d == 0 {
            factors.push(d);
            while n % d == 0 {
                n /= d;
            }
        }
        d += 1;
    }
    
    if n > 1 {
        factors.push(n);
    }
    
    factors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SecurityLevel;
    
    #[test]
    fn test_generator() {
        let q = 61441u64;
        let g = find_generator(q);
        assert_eq!(g, 17);
        // Verify: g^(q-1) = 1, g^((q-1)/2) = q-1
        assert_eq!(mod_exp(g, q - 1, q), 1);
        assert_eq!(mod_exp(g, (q - 1) / 2, q), q - 1);
    }
    
    #[test]
    fn test_psi_values() {
        let q = 61441u64;
        let g = 17u64;
        
        // n=512: ψ = g^((q-1)/(2*512)) = g^60
        let psi_512 = mod_exp(g, (q - 1) / (2 * 512), q);
        assert_eq!(psi_512, 421);
        assert_eq!(mod_exp(psi_512, 1024, q), 1);   // ψ^(2n) = 1
        assert_eq!(mod_exp(psi_512, 512, q), q - 1); // ψ^n = -1
        
        // n=1024: ψ = g^((q-1)/(2*1024)) = g^30
        let psi_1024 = mod_exp(g, (q - 1) / (2 * 1024), q);
        assert_eq!(psi_1024, 16290);
        assert_eq!(mod_exp(psi_1024, 2048, q), 1);
        assert_eq!(mod_exp(psi_1024, 1024, q), q - 1);
        
        // n=2048: ψ = g^((q-1)/(2*2048)) = g^15
        let psi_2048 = mod_exp(g, (q - 1) / (2 * 2048), q);
        assert_eq!(psi_2048, 39003);
        assert_eq!(mod_exp(psi_2048, 4096, q), 1);
        assert_eq!(mod_exp(psi_2048, 2048, q), q - 1);
    }
    
    #[test]
    fn test_ntt_roundtrip() {
        let params = SecurityLevel::Low.params();
        let tables = NttTables::new(&params);
        
        let original: Vec<u64> = (0..params.n as u64).map(|x| x % params.q).collect();
        let mut poly = original.clone();
        
        tables.forward(&mut poly);
        tables.inverse(&mut poly);
        
        assert_eq!(original, poly);
    }
    
    #[test]
    fn test_ntt_roundtrip_all_levels() {
        for level in [SecurityLevel::Low, SecurityLevel::Medium, SecurityLevel::High] {
            let params = level.params();
            let tables = NttTables::new(&params);
            
            let original: Vec<u64> = (0..params.n as u64).map(|x| x % params.q).collect();
            let mut poly = original.clone();
            
            tables.forward(&mut poly);
            tables.inverse(&mut poly);
            
            assert_eq!(original, poly, "NTT roundtrip failed for {:?}", level);
        }
    }
    
    #[test]
    fn test_ntt_multiplication() {
        // Test that NTT multiplication gives negacyclic convolution
        let params = SecurityLevel::Low.params();
        let tables = NttTables::new(&params);
        let n = params.n;
        
        // Simple test: (1 + x) * (1 + x) = 1 + 2x + x^2
        let mut a = vec![0u64; n];
        let mut b = vec![0u64; n];
        a[0] = 1;
        a[1] = 1;
        b[0] = 1;
        b[1] = 1;
        
        tables.forward(&mut a);
        tables.forward(&mut b);
        let mut c = tables.pointwise_mul(&a, &b);
        tables.inverse(&mut c);
        
        assert_eq!(c[0], 1);
        assert_eq!(c[1], 2);
        assert_eq!(c[2], 1);
        for i in 3..n {
            assert_eq!(c[i], 0);
        }
    }
    
    #[test]
    fn test_negacyclic() {
        // Test that x^n = -1 in the ring
        let params = SecurityLevel::Low.params();
        let tables = NttTables::new(&params);
        let n = params.n;
        let q = params.q;
        
        // a = x^(n-1)
        let mut a = vec![0u64; n];
        a[n - 1] = 1;
        
        // b = x
        let mut b = vec![0u64; n];
        b[1] = 1;
        
        tables.forward(&mut a);
        tables.forward(&mut b);
        let mut c = tables.pointwise_mul(&a, &b);
        tables.inverse(&mut c);
        
        // Result should be x^n = -1 = q-1 in constant term
        assert_eq!(c[0], q - 1);
        for i in 1..n {
            assert_eq!(c[i], 0);
        }
    }
    
    #[test]
    fn test_mod_exp() {
        assert_eq!(mod_exp(2, 10, 1000), 24);
        assert_eq!(mod_exp(3, 7, 13), 3);
    }
    
    #[test]
    fn test_mod_inverse() {
        let p = 61441u64;
        for a in [1, 2, 100, 1000, 12288, 61440] {
            let inv = mod_inverse(a, p);
            assert_eq!(mul_mod(a, inv, p), 1, "mod_inverse failed for a={}", a);
        }
    }
}
