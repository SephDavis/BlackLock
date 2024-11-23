# BlackLock: A Paradigm in Post-Quantum Encryption via Ring Learning with Rounding (RLWR)

**Developed by Toby Davis**

---

## Abstract

This repository introduces **BlackLock**, a theoretical construct in post-quantum cryptographic design that explores the latent potentialities of **Ring Learning with Rounding (RLWR)**. Conceived during the summer of 2023 as a personal intellectual exercise, **BlackLock** investigates the intricate interplay of lattice-based cryptographic primitives within the framework of advanced polynomial algebraic structures. This documentation is exploratory in nature; references, while illuminating, may lack strict adherence to formal academic standards.

BlackLock diverges from traditional post-quantum encryption paradigms by eschewing Gaussian noise, instead embedding a deterministic rounding mechanism intrinsic to RLWR—a nuanced extension of **Ring Learning with Errors (RLWE)**. This innovation positions BlackLock as a compelling candidate for scenarios demanding cryptographic robustness under quantum adversarial models.

---

## Theoretical Underpinnings

The foundational architecture of **BlackLock** is predicated on the RLWR problem, which amalgamates computational efficiency with cryptographic intractability. RLWR operates within polynomial rings endowed with modular arithmetic and convolutional operations accelerated via the **Number Theoretic Transform (NTT)** [2]. By adopting binary coefficient distributions, the scheme minimizes noise variance, thereby optimizing both storage and computational throughput.

### Application Context

BlackLock is envisioned as an avant-garde cryptographic mechanism for **Virtual Private Networks (VPNs)**, specifically engineered for covert communications in high-risk geopolitical environments. The algorithm's resistance to quantum computing attacks renders it indispensable for secure channels necessitating heightened operational resilience.

---

## Key Generation Protocol

BlackLock’s key generation process orchestrates a delicate synthesis of sparse binary polynomials within modular ring structures. The steps are delineated as follows:

1. **Sparse Polynomial Synthesis**:
   - Generate a binary polynomial \( f(x) \) with coefficients in \{0, 1\}, ensuring invertibility modulo \( q \) and \( p \) [3].

2. **Auxiliary Polynomial Construction**:
   - Construct another binary polynomial \( g(x) \), sparse and similarly constrained to \{0, 1\}.

3. **Public Key Derivation**:
   - Compute \( h(x) = \text{round}\left(\frac{p}{q} f_{\text{inv}}(x) g(x)\right) \mod p \), where \( f_{\text{inv}}(x) \) denotes the modular inverse of \( f(x) \). The modular arithmetic, coupled with the rounding function, obfuscates intermediate states to amplify cryptographic security.

4. **Supplementary Secret Component**:
   - Synthesize a tertiary sparse binary polynomial \( k(x) \) as an additional layer of obfuscation.

The resulting public key \( h(x) \) encapsulates the core cryptographic representation, while the private key comprises \( f(x) \) and \( k(x) \).

---

## Encryption and Decryption Mechanisms

### Encryption:
- Encode the plaintext as a binary polynomial within the polynomial ring domain.
- Select a cryptographic blinding factor.
- Leverage the **NTT** for high-efficiency polynomial multiplication to produce the ciphertext [4].

### Decryption:
- Execute modular polynomial operations using the private key components.
- Reconstruct the original plaintext by inverting the encoding transformations [5].

---

## Comparative Analysis: RLWR vs. RLWE

The superiority of RLWR stems from its deterministic noise introduction via rounding, which eschews the Gaussian or discrete uniform distributions typical in RLWE:

- **Noise Simplification**:
  - RLWR’s rounding mechanism circumvents the computational intensity associated with Gaussian noise sampling, reducing cryptographic overhead without compromising security [7].
- **Efficiency Gains**:
  - Storage and computation are streamlined through binary coefficient constraints and modular arithmetic, aligning with trends in lightweight cryptographic design.

This distinction renders RLWR an ideal substrate for practical applications, including fast homomorphic encryption schemes like FHEW [6].

---

## Limitations and Prospective Directions

While **BlackLock** represents a thought experiment in post-quantum cryptography, its practical applicability remains nascent. Areas for future exploration include:

- Rigorous cryptanalytic evaluation to ascertain resistance against adaptive attacks.
- Optimization of polynomial inversion methods to enhance computational tractability.

---

## References

1. Alwen, J., Krenn, S., Pietrzak, K., & Wichs, D. "Learning with Rounding, Revisited."
2. Grezl, J., et al. "NTT multiplication for NTT-unfriendly rings." RSA Conference (2020).
3. Fan, J., and Vercauteren, F. "Somewhat Practical Fully Homomorphic Encryption." (2012).
4. Lepoint, T., and Naehrig, M. "Comparison of FV and YASHE." (2014).
5. Peikert, C. "A decade of lattice cryptography." (2016).
6. Ducas, L., and Micciancio, D. "FHEW: Bootstrapping Homomorphic Encryption." (2015).
7. Regev, O. "On lattices, learning with errors, and cryptography." (2009).

---

**Disclaimer**: This project is purely exploratory and serves as a speculative framework for advancing post-quantum cryptographic research.
