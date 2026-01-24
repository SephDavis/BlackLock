//! Ring Learning with Rounding (RLWR) encryption scheme
//! 
//! RLWR is a variant of Ring-LWE that uses deterministic rounding instead of
//! random error sampling, providing similar security with improved efficiency.
//! 
//! Key insight: Instead of adding small random error e, we round coefficients
//! from Z_q to Z_p where p < q. The rounding "noise" replaces explicit error.

use crate::error::BlackLockError;
use crate::ntt::NttTables;
use crate::params::{Parameters, SecurityLevel};
use crate::Result;

use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A complete keypair for BlackLock encryption
#[derive(Clone)]
pub struct KeyPair {
    public_key: PublicKey,
    secret_key: SecretKey,
}

/// Public key for encryption
#[derive(Clone)]
pub struct PublicKey {
    /// Public polynomial a (stored in NTT domain)
    a_ntt: Vec<u64>,
    /// Public polynomial b = round_p(a * s) (stored in coefficient domain, mod p)
    b: Vec<u64>,
    /// NTT tables
    ntt: NttTables,
    /// Parameters
    params: Parameters,
}

/// Secret key for decryption (zeroized on drop for security)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    /// Secret polynomial s (stored in NTT domain)
    s_ntt: Vec<u64>,
    /// Parameters (not sensitive, but included for convenience)
    #[zeroize(skip)]
    params: Parameters,
    /// NTT tables
    #[zeroize(skip)]
    ntt: NttTables,
}

/// Encrypted ciphertext
#[derive(Clone)]
pub struct Ciphertext {
    /// First component: c1 = round_p(a * r) (mod p)
    c1: Vec<u64>,
    /// Second component: c2 = round_p(scale(b) * r) + encode(m) (mod p)
    c2: Vec<u64>,
    /// Original message length
    msg_len: usize,
    /// Parameters used
    params: Parameters,
}

/// Round from Z_q to Z_p: round_p(x) = floor((p * x + q/2) / q) mod p
#[inline]
fn round_to_p(x: u64, q: u64, p: u64) -> u64 {
    // This computes floor((p * x + q/2) / q)
    let scaled = (p as u128) * (x as u128) + (q as u128 / 2);
    ((scaled / (q as u128)) % (p as u128)) as u64
}

/// Scale from Z_p back to Z_q: scale(x) = floor(q * x / p)
#[inline]
fn scale_to_q(x: u64, q: u64, p: u64) -> u64 {
    (((q as u128) * (x as u128)) / (p as u128)) as u64
}

impl KeyPair {
    /// Generate a new keypair with the specified security level
    pub fn generate(level: SecurityLevel) -> Result<Self> {
        let params = level.params();
        Self::generate_with_params(params)
    }
    
    /// Generate a keypair with custom parameters
    pub fn generate_with_params(params: Parameters) -> Result<Self> {
        let ntt = NttTables::new(&params);
        let mut rng = StdRng::from_entropy();
        let q = params.q;
        let p = params.p;
        let n = params.n;
        
        // Generate random public polynomial a ∈ R_q
        let mut a: Vec<u64> = (0..n)
            .map(|_| rng.next_u64() % q)
            .collect();
        
        // Generate secret polynomial s with small coefficients
        let mut s: Vec<u64> = sample_ternary_secret(&mut rng, n, q);
        
        // Compute a * s in NTT domain
        ntt.forward(&mut a);
        ntt.forward(&mut s);
        let as_ntt = ntt.pointwise_mul(&a, &s);
        
        // Transform back to coefficient domain
        let mut as_poly = as_ntt;
        ntt.inverse(&mut as_poly);
        
        // Round to Z_p: b = round_p(a * s)
        let b: Vec<u64> = as_poly.iter()
            .map(|&x| round_to_p(x, q, p))
            .collect();
        
        Ok(Self {
            public_key: PublicKey { a_ntt: a, b, ntt: ntt.clone(), params },
            secret_key: SecretKey { s_ntt: s, params, ntt },
        })
    }
    
    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    
    /// Get the secret key
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
    
    /// Serialize the keypair to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.public_key.to_bytes());
        
        // Store secret in coefficient form
        let mut s = self.secret_key.s_ntt.clone();
        self.secret_key.ntt.inverse(&mut s);
        for &coeff in &s {
            bytes.extend(&coeff.to_le_bytes());
        }
        
        bytes
    }
}

impl PublicKey {
    /// Encrypt a message using this public key
    pub fn encrypt(&self, message: &[u8]) -> Result<Ciphertext> {
        if message.len() > self.params.max_message_bytes {
            return Err(BlackLockError::MessageTooLong {
                max: self.params.max_message_bytes,
                actual: message.len(),
            });
        }
        
        let q = self.params.q;
        let p = self.params.p;
        let n = self.params.n;
        
        // Derive randomness using SHAKE256
        let mut hasher = Shake256::default();
        hasher.update(message);
        hasher.update(&rand::random::<[u8; 32]>());
        let mut reader = hasher.finalize_xof();
        
        // Generate ephemeral secret r with small coefficients
        let mut r = sample_ternary_secret_from_xof(&mut reader, n, q);
        
        // Compute c1 = round_p(a * r)
        self.ntt.forward(&mut r);
        let ar_ntt = self.ntt.pointwise_mul(&self.a_ntt, &r);
        let mut ar = ar_ntt;
        self.ntt.inverse(&mut ar);
        
        let c1: Vec<u64> = ar.iter()
            .map(|&x| round_to_p(x, q, p))
            .collect();
        
        // Compute c2 = round_p(scale(b) * r) + encode(m)
        // First scale b back to Z_q
        let b_scaled: Vec<u64> = self.b.iter()
            .map(|&x| scale_to_q(x, q, p))
            .collect();
        
        let mut b_ntt = b_scaled;
        self.ntt.forward(&mut b_ntt);
        let br_ntt = self.ntt.pointwise_mul(&b_ntt, &r);
        let mut br = br_ntt;
        self.ntt.inverse(&mut br);
        
        // Round to Z_p
        let mut c2: Vec<u64> = br.iter()
            .map(|&x| round_to_p(x, q, p))
            .collect();
        
        // Encode message and add to c2
        // Each bit is encoded as 0 or p/2
        let half_p = p / 2;
        for (i, &byte) in message.iter().enumerate() {
            for bit_idx in 0..8 {
                let coeff_idx = i * 8 + bit_idx;
                if coeff_idx < n {
                    let bit = (byte >> bit_idx) & 1;
                    if bit == 1 {
                        c2[coeff_idx] = (c2[coeff_idx] + half_p) % p;
                    }
                }
            }
        }
        
        Ok(Ciphertext {
            c1,
            c2,
            msg_len: message.len(),
            params: self.params,
        })
    }
    
    /// Serialize public key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Security level indicator
        bytes.push(match self.params.n {
            512 => 0,
            1024 => 1,
            2048 => 2,
            _ => 255,
        });
        
        // Store a in coefficient form
        let mut a = self.a_ntt.clone();
        self.ntt.inverse(&mut a);
        
        for &coeff in &a {
            bytes.extend(&coeff.to_le_bytes());
        }
        // b is already in coefficient form (mod p), but we store as u64
        for &coeff in &self.b {
            bytes.extend(&coeff.to_le_bytes());
        }
        
        bytes
    }
}

impl SecretKey {
    /// Decrypt a ciphertext using this secret key
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Vec<u8>> {
        let q = self.params.q;
        let p = self.params.p;
        
        // Scale c1 back to Z_q and compute c1 * s
        let c1_scaled: Vec<u64> = ciphertext.c1.iter()
            .map(|&x| scale_to_q(x, q, p))
            .collect();
        
        let mut c1_ntt = c1_scaled;
        self.ntt.forward(&mut c1_ntt);
        let c1s_ntt = self.ntt.pointwise_mul(&c1_ntt, &self.s_ntt);
        let mut c1s = c1s_ntt;
        self.ntt.inverse(&mut c1s);
        
        // Round c1*s to Z_p
        let c1s_rounded: Vec<u64> = c1s.iter()
            .map(|&x| round_to_p(x, q, p))
            .collect();
        
        // Compute c2 - round_p(c1 * s) mod p
        let noisy_msg: Vec<u64> = ciphertext.c2.iter()
            .zip(c1s_rounded.iter())
            .map(|(&c2, &c1s)| (c2 + p - c1s) % p)
            .collect();
        
        // Decode message using threshold
        decode_message(&noisy_msg, ciphertext.msg_len, p)
    }
}

impl Ciphertext {
    /// Serialize ciphertext to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        bytes.extend(&(self.msg_len as u32).to_le_bytes());
        
        bytes.push(match self.params.n {
            512 => 0,
            1024 => 1,
            2048 => 2,
            _ => 255,
        });
        
        for &coeff in &self.c1 {
            bytes.extend(&coeff.to_le_bytes());
        }
        for &coeff in &self.c2 {
            bytes.extend(&coeff.to_le_bytes());
        }
        
        bytes
    }
    
    /// Deserialize ciphertext from bytes
    pub fn from_bytes(bytes: &[u8], level: SecurityLevel) -> Result<Self> {
        if bytes.len() < 5 {
            return Err(BlackLockError::InvalidCiphertext);
        }
        
        let params = level.params();
        let msg_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        
        let expected_len = 5 + params.n * 8 * 2;
        if bytes.len() != expected_len {
            return Err(BlackLockError::InvalidCiphertext);
        }
        
        let mut offset = 5;
        let mut c1 = Vec::with_capacity(params.n);
        let mut c2 = Vec::with_capacity(params.n);
        
        for _ in 0..params.n {
            let coeff = u64::from_le_bytes([
                bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
                bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
            ]);
            c1.push(coeff);
            offset += 8;
        }
        
        for _ in 0..params.n {
            let coeff = u64::from_le_bytes([
                bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
                bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
            ]);
            c2.push(coeff);
            offset += 8;
        }
        
        Ok(Self { c1, c2, msg_len, params })
    }
}

/// Sample a ternary secret polynomial with coefficients in {-1, 0, 1}
fn sample_ternary_secret(rng: &mut impl RngCore, n: usize, q: u64) -> Vec<u64> {
    (0..n)
        .map(|_| {
            let r = rng.next_u32() % 3;
            match r {
                0 => 0,
                1 => 1,
                2 => q - 1, // -1 mod q
                _ => unreachable!(),
            }
        })
        .collect()
}

/// Sample ternary secret from XOF
fn sample_ternary_secret_from_xof(reader: &mut impl XofReader, n: usize, q: u64) -> Vec<u64> {
    let mut buf = [0u8; 1];
    (0..n)
        .map(|_| {
            loop {
                reader.read(&mut buf);
                let r = buf[0] % 4;
                if r < 3 {
                    return match r {
                        0 => 0,
                        1 => 1,
                        2 => q - 1,
                        _ => unreachable!(),
                    };
                }
                // Rejection sampling for uniformity
            }
        })
        .collect()
}

/// Decode message using threshold decoding in Z_p
fn decode_message(coeffs: &[u64], msg_len: usize, p: u64) -> Result<Vec<u8>> {
    let mut message = vec![0u8; msg_len];
    let quarter_p = p / 4;
    let three_quarter_p = (3 * p) / 4;
    
    for (i, byte) in message.iter_mut().enumerate() {
        for bit_idx in 0..8 {
            let coeff_idx = i * 8 + bit_idx;
            if coeff_idx < coeffs.len() {
                let val = coeffs[coeff_idx];
                // Values in [p/4, 3p/4) decode as 1
                let bit = if val >= quarter_p && val < three_quarter_p {
                    1u8
                } else {
                    0u8
                };
                *byte |= bit << bit_idx;
            }
        }
    }
    
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_round_scale_inverse() {
        let q = 12289u64;
        let p = 256u64;
        
        // Test that scale(round(x)) ≈ x
        for x in [0, 100, 1000, 6000, 12000] {
            let rounded = round_to_p(x, q, p);
            let scaled = scale_to_q(rounded, q, p);
            let diff = if x > scaled { x - scaled } else { scaled - x };
            assert!(diff < q / p + 1, "Round-scale error too large");
        }
    }
    
    #[test]
    fn test_encrypt_decrypt() {
        let keypair = KeyPair::generate(SecurityLevel::Medium).unwrap();
        let message = b"Test RLWR encryption!";
        
        let ciphertext = keypair.public_key().encrypt(message).unwrap();
        let decrypted = keypair.secret_key().decrypt(&ciphertext).unwrap();
        
        assert_eq!(message.to_vec(), decrypted);
    }
    
    #[test]
    fn test_all_security_levels() {
        for level in [SecurityLevel::Low, SecurityLevel::Medium, SecurityLevel::High] {
            let keypair = KeyPair::generate(level).unwrap();
            let message = b"Testing all levels";
            
            let ct = keypair.public_key().encrypt(message).unwrap();
            let dec = keypair.secret_key().decrypt(&ct).unwrap();
            
            assert_eq!(message.to_vec(), dec, "Failed at {:?}", level);
        }
    }
    
    #[test]
    fn test_ciphertext_serialization() {
        let keypair = KeyPair::generate(SecurityLevel::Low).unwrap();
        let message = b"Serialize me";
        
        let ciphertext = keypair.public_key().encrypt(message).unwrap();
        let bytes = ciphertext.to_bytes();
        let restored = Ciphertext::from_bytes(&bytes, SecurityLevel::Low).unwrap();
        
        let decrypted = keypair.secret_key().decrypt(&restored).unwrap();
        assert_eq!(message.to_vec(), decrypted);
    }
}
