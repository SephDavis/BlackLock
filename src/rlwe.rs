/// Public key for encryption
#[derive(Clone)]
pub struct PublicKey {
    /// Public polynomial a (in NTT domain for efficiency)
    a_ntt: Vec<u64>,
    /// Public polynomial b = a * s + e (in NTT domain)
    b_ntt: Vec<u64>,
    /// NTT tables
    ntt: NttTables,
    /// Parameters
@@ -36,8 +36,8 @@ pub struct PublicKey {
/// Secret key for decryption (zeroized on drop for security)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    /// Secret polynomial s (in NTT domain for efficiency)
    s_ntt: Vec<u64>,
    /// Parameters (not sensitive, but included for convenience)
    #[zeroize(skip)]
    params: Parameters,
@@ -49,10 +49,10 @@ pub struct SecretKey {
/// Encrypted ciphertext
#[derive(Clone)]
pub struct Ciphertext {
    /// First component: u = a * r + e1 (coefficient domain)
    u: Vec<u64>,
    /// Second component: v = b * r + e2 + encode(m) (coefficient domain)
    v: Vec<u64>,
    /// Original message length
    msg_len: usize,
    /// Parameters used
@@ -70,30 +70,46 @@ impl KeyPair {
    pub fn generate_with_params(params: Parameters) -> Result<Self> {
        let ntt = NttTables::new(&params);
        let mut rng = StdRng::from_entropy();
        let q = params.q;
        let n = params.n;

        // Generate random public polynomial a
        let mut a: Vec<u64> = (0..n)
            .map(|_| rng.next_u64() % q)
            .collect();

        // Generate secret polynomial s with small coefficients
        let mut s: Vec<u64> = sample_secret(&mut rng, n, params.eta, q);

        // Generate small error polynomial e
        let e: Vec<u64> = sample_secret(&mut rng, n, params.eta, q);




        // Transform to NTT domain
        ntt.forward(&mut a);
        ntt.forward(&mut s);

        // Compute a * s in NTT domain
        let as_ntt = ntt.pointwise_mul(&a, &s);
        
        // Transform back to compute a*s + e
        let mut as_poly = as_ntt;
        ntt.inverse(&mut as_poly);
        
        // Add error: b = a*s + e
        let mut b: Vec<u64> = as_poly.iter()
            .zip(e.iter())
            .map(|(&as_val, &e_val)| {
                let sum = as_val + e_val;
                if sum >= q { sum - q } else { sum }
            })
            .collect();
        
        // Store b in NTT domain for faster encryption
        ntt.forward(&mut b);

        Ok(Self {
            public_key: PublicKey { a_ntt: a, b_ntt: b, ntt: ntt.clone(), params },
            secret_key: SecretKey { s_ntt: s, params, ntt },
        })
    }

@@ -114,8 +130,10 @@ impl KeyPair {
        // Serialize public key
        bytes.extend(self.public_key.to_bytes());

        // Serialize secret key (need to inverse NTT first for storage)
        let mut s = self.secret_key.s_ntt.clone();
        self.secret_key.ntt.inverse(&mut s);
        for &coeff in &s {
            bytes.extend(&coeff.to_le_bytes());
        }

@@ -133,50 +151,59 @@ impl PublicKey {
            });
        }

        let q = self.params.q;
        let n = self.params.n;
        
        // Use SHAKE256 to derive randomness
        let mut hasher = Shake256::default();
        hasher.update(message);
        hasher.update(&rand::random::<[u8; 32]>()); // Random nonce for CPA security
        let mut reader = hasher.finalize_xof();

        // Generate ephemeral secret r and errors e1, e2
        let mut r = sample_secret_from_xof(&mut reader, n, self.params.eta, q);
        let e1 = sample_secret_from_xof(&mut reader, n, self.params.eta, q);
        let e2 = sample_secret_from_xof(&mut reader, n, self.params.eta, q);
        
        // Transform r to NTT domain
        self.ntt.forward(&mut r);
        
        // Compute u = a * r + e1
        let ar_ntt = self.ntt.pointwise_mul(&self.a_ntt, &r);
        let mut ar = ar_ntt;
        self.ntt.inverse(&mut ar);
        
        let u: Vec<u64> = ar.iter()
            .zip(e1.iter())
            .map(|(&ar_val, &e_val)| {
                let sum = ar_val + e_val;
                if sum >= q { sum - q } else { sum }
            })
            .collect();









        // Compute v = b * r + e2 + encode(message)
        let br_ntt = self.ntt.pointwise_mul(&self.b_ntt, &r);
        let mut br = br_ntt;
        self.ntt.inverse(&mut br);
        
        // Encode message: each bit becomes 0 or q/2
        let encoded = encode_message(message, n, q);
        
        let v: Vec<u64> = br.iter()
            .zip(e2.iter())
            .zip(encoded.iter())
            .map(|((&br_val, &e_val), &m_val)| {
                let mut sum = br_val + e_val + m_val;
                while sum >= q {
                    sum -= q;
                }
                sum
            })
            .collect();

        Ok(Ciphertext {
            u,
            v,
            msg_len: message.len(),
            params: self.params,
        })
@@ -194,10 +221,16 @@ impl PublicKey {
            _ => 255,
        });

        // Store in coefficient form for interoperability
        let mut a = self.a_ntt.clone();
        let mut b = self.b_ntt.clone();
        self.ntt.inverse(&mut a);
        self.ntt.inverse(&mut b);
        
        for &coeff in &a {
            bytes.extend(&coeff.to_le_bytes());
        }
        for &coeff in &b {
            bytes.extend(&coeff.to_le_bytes());
        }

@@ -208,29 +241,29 @@ impl PublicKey {
impl SecretKey {
    /// Decrypt a ciphertext using this secret key
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Vec<u8>> {
        let q = self.params.q;




        // Transform u to NTT domain
        let mut u_ntt = ciphertext.u.clone();
        self.ntt.forward(&mut u_ntt);


        // Compute u * s in NTT domain
        let us_ntt = self.ntt.pointwise_mul(&u_ntt, &self.s_ntt);

        // Transform back
        let mut us = us_ntt;
        self.ntt.inverse(&mut us);

        // Compute v - u*s
        let noisy_message: Vec<u64> = ciphertext.v.iter()
            .zip(us.iter())
            .map(|(&v, &us_val)| {
                if v >= us_val { v - us_val } else { v + q - us_val }
            })
            .collect();

        // Decode message using threshold decoding
        decode_message(&noisy_message, ciphertext.msg_len, q)
    }
}

@@ -250,13 +283,13 @@ impl Ciphertext {
            _ => 255,
        });

        // u coefficients
        for &coeff in &self.u {
            bytes.extend(&coeff.to_le_bytes());
        }

        // v coefficients
        for &coeff in &self.v {
            bytes.extend(&coeff.to_le_bytes());
        }

@@ -279,15 +312,15 @@ impl Ciphertext {
        }

        let mut offset = 5;
        let mut u = Vec::with_capacity(params.n);
        let mut v = Vec::with_capacity(params.n);

        for _ in 0..params.n {
            let coeff = u64::from_le_bytes([
                bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
                bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
            ]);
            u.push(coeff);
            offset += 8;
        }

@@ -296,27 +329,27 @@ impl Ciphertext {
                bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
                bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
            ]);
            v.push(coeff);
            offset += 8;
        }

        Ok(Self { u, v, msg_len, params })
    }
}

/// Sample a secret polynomial with small coefficients from centered binomial distribution
fn sample_secret(rng: &mut impl RngCore, n: usize, eta: u32, q: u64) -> Vec<u64> {
    (0..n)
        .map(|_| {
            let mut a = 0i32;
            let mut b = 0i32;
            for _ in 0..eta {
                a += (rng.next_u32() & 1) as i32;
                b += (rng.next_u32() & 1) as i32;
            }
            let val = a - b;
            if val < 0 {
                (q as i64 + val as i64) as u64
            } else {
                val as u64
            }
@@ -329,16 +362,16 @@ fn sample_secret_from_xof(reader: &mut impl XofReader, n: usize, eta: u32, q: u6
    let mut buf = [0u8; 4];
    (0..n)
        .map(|_| {
            let mut a = 0i32;
            let mut b = 0i32;
            for _ in 0..eta {
                reader.read(&mut buf);
                a += (buf[0] & 1) as i32;
                b += (buf[1] & 1) as i32;
            }
            let val = a - b;
            if val < 0 {
                (q as i64 + val as i64) as u64
            } else {
                val as u64
            }
@@ -347,48 +380,47 @@ fn sample_secret_from_xof(reader: &mut impl XofReader, n: usize, eta: u32, q: u6
}

/// Encode a message into polynomial coefficients
/// Each message bit is encoded as either 0 or q/2
fn encode_message(message: &[u8], n: usize, q: u64) -> Vec<u64> {
    let mut encoded = vec![0u64; n];
    let half_q = q / 2;


    for (i, &byte) in message.iter().enumerate() {
        for bit_idx in 0..8 {
            let coeff_idx = i * 8 + bit_idx;



            if coeff_idx < n {
                let bit = (byte >> bit_idx) & 1;
                encoded[coeff_idx] = if bit == 1 { half_q } else { 0 };

            }

        }
    }

    encoded
}

/// Decode a message from polynomial coefficients using threshold decoding
/// Values closer to 0 decode as 0, values closer to q/2 decode as 1
fn decode_message(coeffs: &[u64], msg_len: usize, q: u64) -> Result<Vec<u8>> {
    let mut message = vec![0u8; msg_len];
    let quarter_q = q / 4;
    let three_quarter_q = (3 * q) / 4;

    for (i, byte) in message.iter_mut().enumerate() {
        for bit_idx in 0..8 {
            let coeff_idx = i * 8 + bit_idx;




            if coeff_idx < coeffs.len() {
                let val = coeffs[coeff_idx];
                // Threshold decode:
                // Values in [q/4, 3q/4) are closer to q/2 -> decode as 1
                // Values in [0, q/4) or [3q/4, q) are closer to 0 -> decode as 0
                let bit = if val >= quarter_q && val < three_quarter_q {
                    1u8
                } else {
                    0u8
                };
                *byte |= bit << bit_idx;
            }

        }

    }

    Ok(message)
@@ -401,11 +433,11 @@ mod tests {
    #[test]
    fn test_encode_decode() {
        let message = b"Hello!";
        let q = 12289u64;
        let n = 512;

        let encoded = encode_message(message, n, q);
        let decoded = decode_message(&encoded, message.len(), q).unwrap();

        assert_eq!(message.to_vec(), decoded);
    }
@@ -433,4 +465,15 @@ mod tests {
        let decrypted = keypair.secret_key().decrypt(&restored).unwrap();
        assert_eq!(message.to_vec(), decrypted);
    }
    
    #[test]
    fn test_multiple_messages() {
        let keypair = KeyPair::generate(SecurityLevel::Low).unwrap();
        
        for msg in [b"Short".as_slice(), b"A longer test message", b"!@#$%^&*()"] {
            let ct = keypair.public_key().encrypt(msg).unwrap();
            let dec = keypair.secret_key().decrypt(&ct).unwrap();
            assert_eq!(msg.to_vec(), dec);
        }
    }
}
