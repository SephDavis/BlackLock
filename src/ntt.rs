//! Number Theoretic Transform (NTT) for efficient polynomial multiplication
//! 
//! NTT is the finite field analogue of FFT, enabling O(n log n) polynomial
//! multiplication instead of O(n²).

use crate::params::Parameters;

/// Precomputed NTT tables for a given parameter set
#[derive(Clone)]
pub struct NttTables {
    /// Root of unity
    root: u64,
    /// Inverse root of unity
    root_inv: u64,
    /// Twiddle factors for forward NTT
    twiddles: Vec<u64>,
    /// Twiddle factors for inverse NTT
    twiddles_inv: Vec<u64>,
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
        
        // Find primitive 2n-th root of unity
        // For q = 12289, a primitive root is 11
        let g = find_primitive_root(q);
        let root = mod_exp(g, (q - 1) / (2 * n as u64), q);
        let root_inv = mod_inverse(root, q);
        let n_inv = mod_inverse(n as u64, q);
        
        // Precompute twiddle factors
        let mut twiddles = vec![0u64; n];
        let mut twiddles_inv = vec![0u64; n];
        
        twiddles[0] = 1;
        twiddles_inv[0] = 1;
        
        for i in 1..n {
            twiddles[i] = (twiddles[i - 1] * root) % q;
            twiddles_inv[i] = (twiddles_inv[i - 1] * root_inv) % q;
        }
        
        // Bit-reverse the twiddle factors for in-place NTT
        let twiddles = bit_reverse_vec(&twiddles);
        let twiddles_inv = bit_reverse_vec(&twiddles_inv);
        
        Self {
            root,
            root_inv,
            twiddles,
            twiddles_inv,
            q,
            n,
            n_inv,
        }
    }
    
    /// Forward NTT (in-place, Cooley-Tukey butterfly)
    pub fn forward(&self, poly: &mut [u64]) {
        assert_eq!(poly.len(), self.n);
        
        let n = self.n;
        let q = self.q;
        
        // Bit-reverse copy
        bit_reverse_inplace(poly);
        
        // Cooley-Tukey iterative NTT
        let mut m = 1;
        while m < n {
            let w_m = mod_exp(self.root, (n / (2 * m)) as u64, q);
            
            for k in (0..n).step_by(2 * m) {
                let mut w = 1u64;
                for j in 0..m {
                    let t = (w * poly[k + j + m]) % q;
                    let u = poly[k + j];
                    poly[k + j] = (u + t) % q;
                    poly[k + j + m] = (u + q - t) % q;
                    w = (w * w_m) % q;
                }
            }
            m *= 2;
        }
    }
    
    /// Inverse NTT (in-place, Gentleman-Sande butterfly)
    pub fn inverse(&self, poly: &mut [u64]) {
        assert_eq!(poly.len(), self.n);
        
        let n = self.n;
        let q = self.q;
        
        // Gentleman-Sande iterative inverse NTT
        let mut m = n / 2;
        while m >= 1 {
            let w_m = mod_exp(self.root_inv, (n / (2 * m)) as u64, q);
            
            for k in (0..n).step_by(2 * m) {
                let mut w = 1u64;
                for j in 0..m {
                    let u = poly[k + j];
                    let v = poly[k + j + m];
                    poly[k + j] = (u + v) % q;
                    poly[k + j + m] = (w * ((u + q - v) % q)) % q;
                    w = (w * w_m) % q;
                }
            }
            m /= 2;
        }
        
        // Bit-reverse and scale by n^(-1)
        bit_reverse_inplace(poly);
        for coeff in poly.iter_mut() {
            *coeff = (*coeff * self.n_inv) % q;
        }
    }
    
    /// Multiply two polynomials in NTT domain (pointwise)
    pub fn pointwise_mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), self.n);
        assert_eq!(b.len(), self.n);
        
        a.iter()
            .zip(b.iter())
            .map(|(&x, &y)| (x * y) % self.q)
            .collect()
    }
    
    /// Add two polynomials
    pub fn poly_add(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        a.iter()
            .zip(b.iter())
            .map(|(&x, &y)| (x + y) % self.q)
            .collect()
    }
    
    /// Subtract two polynomials
    pub fn poly_sub(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        a.iter()
            .zip(b.iter())
            .map(|(&x, &y)| (x + self.q - y) % self.q)
            .collect()
    }
}

/// Modular exponentiation using binary method
pub fn mod_exp(base: u64, mut exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    
    let mut result = 1u128;
    let mut base = (base as u128) % (modulus as u128);
    let modulus = modulus as u128;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    
    result as u64
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
    
    while xy.0 < 0 {
        xy.0 += m as i128;
    }
    
    (xy.0 % m as i128) as u64
}

/// Find a primitive root modulo p (p must be prime)
fn find_primitive_root(p: u64) -> u64 {
    // For q = 12289, the primitive root is 11
    if p == 12289 {
        return 11;
    }
    
    // General case: find smallest primitive root
    let phi = p - 1;
    let mut factors = Vec::new();
    let mut n = phi;
    
    for i in 2..=((n as f64).sqrt() as u64 + 1) {
        if n % i == 0 {
            factors.push(i);
            while n % i == 0 {
                n /= i;
            }
        }
    }
    if n > 1 {
        factors.push(n);
    }
    
    for g in 2..p {
        let mut is_primitive = true;
        for &factor in &factors {
            if mod_exp(g, phi / factor, p) == 1 {
                is_primitive = false;
                break;
            }
        }
        if is_primitive {
            return g;
        }
    }
    
    panic!("No primitive root found for {}", p);
}

/// Bit-reverse permutation in-place
fn bit_reverse_inplace(data: &mut [u64]) {
    let n = data.len();
    let bits = (n as f64).log2() as u32;
    
    for i in 0..n {
        let j = bit_reverse(i as u32, bits) as usize;
        if i < j {
            data.swap(i, j);
        }
    }
}

/// Bit-reverse a vector (returns new vector)
fn bit_reverse_vec(data: &[u64]) -> Vec<u64> {
    let n = data.len();
    let bits = (n as f64).log2() as u32;
    
    let mut result = vec![0u64; n];
    for i in 0..n {
        let j = bit_reverse(i as u32, bits) as usize;
        result[j] = data[i];
    }
    result
}

/// Reverse bits of an integer
fn bit_reverse(mut x: u32, bits: u32) -> u32 {
    let mut result = 0u32;
    for _ in 0..bits {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SecurityLevel;
    
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
    fn test_mod_exp() {
        assert_eq!(mod_exp(2, 10, 1000), 24);
        assert_eq!(mod_exp(3, 7, 13), 3);
    }
    
    #[test]
    fn test_mod_inverse() {
        let p = 12289u64;
        for a in [1, 2, 100, 1000, 12288] {
            let inv = mod_inverse(a, p);
            assert_eq!((a * inv) % p, 1);
        }
    }
}
