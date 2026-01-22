//! Ring Learning with Rounding (RLWR) encryption scheme
//! 
//! RLWR is a variant of Ring-LWE that uses deterministic rounding instead of
//! random error sampling, providing similar security with improved efficiency.

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
    /// Public polynomial a (shared)
    a: Vec<u64>,
    /// Public polynomial b = round(a * s)
    b: Vec<u64>,
    /// NTT tables
    ntt: NttTables,
    /// Parameters
    params: Parameters,
}

/// Secret key for decryption (zeroized on drop for security)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    /// Secret polynomial s
    s: Vec<u64>,
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
    /// First component: c1 = round(a * r)
    c1: Vec<u64>,
    /// Second component: c2 = round(b * r) + encoded_message
    c2: Vec<u64>,
    /// Original message length
    msg_len: usize,
    /// Parameters used
    params: Parameters,
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
        
        // Generate random public polynomial a
        let a: Vec<u64> = (0..params.n)
            .map(|_| rng.next_u64() % params.q)
            .collect();
        
        // Generate secret polynomial s with small coefficients
        let s: Vec<u64> = sample_secret(&mut rng, params.n, params.eta, params.q);
        
        // Compute b = round(a * s) in NTT domain
        let mut a_ntt = a.clone();
        let mut s_ntt = s.clone();
        ntt.forward(&mut a_ntt);
        ntt.forward(&mut s_ntt);
        
        let mut as_ntt = ntt.pointwise_mul(&a_ntt, &s_ntt);
        ntt.inverse(&mut as_ntt);
        
        // Round the result
        let b: Vec<u64> = as_ntt.iter().map(|&x| params.round(x)).collect();
        
        Ok(Self {
            public_key: PublicKey { a, b, ntt: ntt.clone(), params },
            secret_key: SecretKey { s, params, ntt },
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
        
        // Serialize public key
        bytes.extend(self.public_key.to_bytes());
        
        // Serialize secret key
        for &coeff in &self.secret_key.s {
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
        
        // Use SHAKE256 to derive randomness from message (for deterministic encryption)
        // In practice, you'd want to add random nonce for CCA security
        let mut hasher = Shake256::default();
        hasher.update(message);
        hasher.update(&rand::random::<[u8; 32]>()); // Random nonce
        let mut reader = hasher.finalize_xof();
        
        // Generate ephemeral secret r
        let r = sample_secret_from_xof(&mut reader, self.params.n, self.params.eta, self.params.q);
        
        // Compute c1 = round(a * r)
        let mut a_ntt = self.a.clone();
        let mut r_ntt = r.clone();
        self.ntt.forward(&mut a_ntt);
        self.ntt.forward(&mut r_ntt);
        
        let mut ar_ntt = self.ntt.pointwise_mul(&a_ntt, &r_ntt);
        self.ntt.inverse(&mut ar_ntt);
        
        let c1: Vec<u64> = ar_ntt.iter().map(|&x| self.params.round(x)).collect();
        
        // Compute c2 = round(b * r) + encode(message)
        // First, unround b to approximate the original value
        let b_unrounded: Vec<u64> = self.b.iter().map(|&x| self.params.unround(x)).collect();
        
        let mut b_ntt = b_unrounded;
        self.ntt.forward(&mut b_ntt);
        
        let mut br_ntt = self.ntt.pointwise_mul(&b_ntt, &r_ntt);
        self.ntt.inverse(&mut br_ntt);
        
        let mut c2: Vec<u64> = br_ntt.iter().map(|&x| self.params.round(x)).collect();
        
        // Encode message into polynomial coefficients
        let encoded = encode_message(message, self.params.n, self.params.p);
        
        // Add encoded message to c2
        for (c, &m) in c2.iter_mut().zip(encoded.iter()) {
            *c = (*c + m) % self.params.p;
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
        
        for &coeff in &self.a {
            bytes.extend(&coeff.to_le_bytes());
        }
        for &coeff in &self.b {
            bytes.extend(&coeff.to_le_bytes());
        }
        
        bytes
    }
}

impl SecretKey {
    /// Decrypt a ciphertext using this secret key
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Vec<u8>> {
        // Compute c1 * s
        let c1_unrounded: Vec<u64> = ciphertext.c1.iter()
            .map(|&x| self.params.unround(x))
            .collect();
        
        let mut c1_ntt = c1_unrounded;
        let mut s_ntt = self.s.clone();
        self.ntt.forward(&mut c1_ntt);
        self.ntt.forward(&mut s_ntt);
        
        let mut c1s_ntt = self.ntt.pointwise_mul(&c1_ntt, &s_ntt);
        self.ntt.inverse(&mut c1s_ntt);
        
        // Round and compute c2 - round(c1 * s)
        let c1s_rounded: Vec<u64> = c1s_ntt.iter().map(|&x| self.params.round(x)).collect();
        
        let decoded: Vec<u64> = ciphertext.c2.iter()
            .zip(c1s_rounded.iter())
            .map(|(&c2, &c1s)| (c2 + self.params.p - c1s) % self.params.p)
            .collect();
        
        // Decode message from polynomial
        decode_message(&decoded, ciphertext.msg_len, self.params.p)
    }
}

impl Ciphertext {
    /// Serialize ciphertext to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Message length
        bytes.extend(&(self.msg_len as u32).to_le_bytes());
        
        // Security level indicator
        bytes.push(match self.params.n {
            512 => 0,
            1024 => 1,
            2048 => 2,
            _ => 255,
        });
        
        // c1 coefficients
        for &coeff in &self.c1 {
            bytes.extend(&coeff.to_le_bytes());
        }
        
        // c2 coefficients
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

/// Sample a secret polynomial with small coefficients from centered binomial distribution
fn sample_secret(rng: &mut impl RngCore, n: usize, eta: u32, q: u64) -> Vec<u64> {
    (0..n)
        .map(|_| {
            let mut a = 0i64;
            let mut b = 0i64;
            for _ in 0..eta {
                a += (rng.next_u32() & 1) as i64;
                b += (rng.next_u32() & 1) as i64;
            }
            let val = a - b;
            if val < 0 {
                (q as i64 + val) as u64
            } else {
                val as u64
            }
        })
        .collect()
}

/// Sample secret from XOF (for deterministic randomness)
fn sample_secret_from_xof(reader: &mut impl XofReader, n: usize, eta: u32, q: u64) -> Vec<u64> {
    let mut buf = [0u8; 4];
    (0..n)
        .map(|_| {
            let mut a = 0i64;
            let mut b = 0i64;
            for _ in 0..eta {
                reader.read(&mut buf);
                a += (buf[0] & 1) as i64;
                b += (buf[1] & 1) as i64;
            }
            let val = a - b;
            if val < 0 {
                (q as i64 + val) as u64
            } else {
                val as u64
            }
        })
        .collect()
}

/// Encode a message into polynomial coefficients
fn encode_message(message: &[u8], n: usize, p: u64) -> Vec<u64> {
    let mut encoded = vec![0u64; n];
    let bits_per_coeff = (p as f64).log2() as usize;
    let mask = (1u64 << bits_per_coeff) - 1;
    
    let mut bit_idx = 0;
    for &byte in message {
        for i in 0..8 {
            let coeff_idx = bit_idx / bits_per_coeff;
            let bit_pos = bit_idx % bits_per_coeff;
            
            if coeff_idx < n {
                let bit = ((byte >> i) & 1) as u64;
                encoded[coeff_idx] |= bit << bit_pos;
                encoded[coeff_idx] &= mask;
            }
            bit_idx += 1;
        }
    }
    
    encoded
}

/// Decode a message from polynomial coefficients
fn decode_message(coeffs: &[u64], msg_len: usize, p: u64) -> Result<Vec<u8>> {
    let bits_per_coeff = (p as f64).log2() as usize;
    let mut message = vec![0u8; msg_len];
    
    let mut bit_idx = 0;
    for byte_idx in 0..msg_len {
        let mut byte = 0u8;
        for i in 0..8 {
            let coeff_idx = bit_idx / bits_per_coeff;
            let bit_pos = bit_idx % bits_per_coeff;
            
            if coeff_idx < coeffs.len() {
                let bit = ((coeffs[coeff_idx] >> bit_pos) & 1) as u8;
                byte |= bit << i;
            }
            bit_idx += 1;
        }
        message[byte_idx] = byte;
    }
    
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encode_decode() {
        let message = b"Hello!";
        let p = 256u64;
        let n = 512;
        
        let encoded = encode_message(message, n, p);
        let decoded = decode_message(&encoded, message.len(), p).unwrap();
        
        assert_eq!(message.to_vec(), decoded);
    }
    
    #[test]
    fn test_encrypt_decrypt() {
        let keypair = KeyPair::generate(SecurityLevel::Medium).unwrap();
        let message = b"Test message for BlackLock encryption";
        
        let ciphertext = keypair.public_key().encrypt(message).unwrap();
        let decrypted = keypair.secret_key().decrypt(&ciphertext).unwrap();
        
        assert_eq!(message.to_vec(), decrypted);
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
