# Month 2 – Lattice-Based Cryptography: Mathematical Foundations of CRYSTALS-Kyber (ML-KEM)

---

## Overview

Month 1 established *why* post-quantum cryptography matters - the harvest-now-decrypt-later threat model, the vulnerability of RSA and ECC to Shor's algorithm, and the NIST standardisation response. Month 2 goes deeper into *how* the solution actually works.

This month's focus is CRYSTALS-Kyber, standardised by NIST as FIPS 203 under the name ML-KEM (Module-Lattice-based Key Encapsulation Mechanism). Understanding Kyber properly requires working through the mathematical structures that make it both functional and secure — the algebra, the hardness assumptions, the encryption scheme, and the engineering optimisations that make it deployable at scale.

The source material for this month is the lecture series by Professor Alfred Menezes (University of Waterloo, August 2024), combined with the NIST FIPS 203 specification and the original CRYSTALS-Kyber IEEE paper (2018, European Symposium on Security and Privacy).

---

## 1. Why a New Cryptographic Structure?

RSA and ECC derive their security from number-theoretic problems - integer factorisation and the elliptic curve discrete logarithm problem respectively. Both are efficiently solvable by Shor's algorithm on a sufficiently powerful quantum computer.

Post-quantum cryptography needs to be built on a different class of mathematical problem - one that remains hard even for quantum computers. Kyber is built on **lattice problems**, specifically variants of the **Learning With Errors (LWE)** problem. These problems have been studied extensively since the early 2000s and no known quantum algorithm provides a significant advantage in solving them.

---

## 2. Mathematical Foundations

### 2.1 Modular Arithmetic

The foundation of Kyber's arithmetic is modular integer arithmetic over $\mathbb{Z}_q$ - the set of integers $\{0, 1, 2, \ldots, q-1\}$ where $q$ is a prime modulus. All addition, subtraction and multiplication operations are performed modulo $q$.

An important concept is **symmetric mod**: rather than representing integers in the range $[0, q-1]$, we centre them around zero, giving the range $[-(q-1)/2,\; (q-1)/2]$. This symmetric representation is crucial for measuring the *size* of elements - a concept that underpins the security of lattice-based schemes.

For ML-KEM-768, **$q = 3329$**.

**Example in $\mathbb{Z}_{17}$:**

$$9 + 15 \equiv 7 \pmod{17}, \qquad 9 - 15 \equiv 11 \pmod{17}, \qquad 9 \times 15 \equiv 16 \pmod{17}$$

### 2.2 Polynomial Rings

Kyber operates in the **polynomial ring**:

$$R_q = \mathbb{Z}_q[x] \;/\; (x^n + 1)$$

where $q$ is the prime modulus and $n$ is a positive integer. This ring consists of all polynomials with integer coefficients in $\mathbb{Z}_q$, of degree at most $n-1$. When polynomials are multiplied, the result is reduced modulo $(x^n + 1)$, keeping the degree bounded.

**Why this ring?** The reduction polynomial $x^n + 1$ is irreducible over $\mathbb{Z}_q$ when $n$ is a power of 2. This enables the **Number-Theoretic Transform (NTT)** for fast polynomial multiplication - critical for practical performance.

For ML-KEM-768, **$n = 256$**, giving polynomials of degree at most 255 with coefficients in $\mathbb{Z}_{3329}$.

A polynomial can be represented equivalently as a vector of $n$ coefficients:

$$f(x) = f_0 + f_1 x + f_2 x^2 + \cdots + f_{n-1} x^{n-1} \;\longleftrightarrow\; (f_0,\; f_1,\; \ldots,\; f_{n-1})$$

**To multiply two polynomials** $f(x), g(x) \in R_q$:
1. Compute $h(x) = f(x) \times g(x)$ in $\mathbb{Z}_q[x]$ - degree at most $2n-2$
2. Reduce $h(x)$ modulo $x^n + 1$ to get a remainder polynomial of degree at most $n-1$
3. The result $f(x) \times g(x) = \delta(x)$ in $R_q$, and the size of $R_q$ is $q^n$

### 2.3 Module Structure

Kyber extends from individual polynomials to **vectors of polynomials**. The module $R_q^k$ is the set of column vectors of length $k$ whose components are polynomials in $R_q$:

$$\mathbf{a} = \begin{bmatrix} a_1 \\ a_2 \\ \vdots \\ a_k \end{bmatrix}, \quad a_i \in R_q$$

For ML-KEM-768, **$k = 3$**, so module elements are vectors of 3 polynomials.

Operations on module elements:
- Addition/subtraction of two vectors in $R_q^k$ produces another vector in $R_q^k$ (component-wise)
- Multiplication (inner product) of two vectors in $R_q^k$ produces a polynomial in $R_q$
- All vectors in $R_q^k$ are written as column vectors

### 2.4 Size of Polynomials - The Infinity Norm

A core concept in lattice cryptography is the *size* of a polynomial. Kyber uses the **infinity norm** $\|\cdot\|_\infty$:

- For an integer $x \in \mathbb{Z}_q$: $\|x\|_\infty = |x \bmod_s q|$ (symmetric mod)
- For a polynomial $f \in R_q$: $\|f\|_\infty = \max_i \|f_i\|_\infty$
- For a module element $\mathbf{a} \in R_q^k$: $\|\mathbf{a}\|_\infty = \max_i \|a_i\|_\infty$

A polynomial is called **"small"** if $\|f\|_\infty$ is small relative to $q/2$. The set of small polynomials bounded by $\eta$ is:

$$S_\eta = \{ f \in R_q \mid \|f\|_\infty \leq \eta \}$$

This distinction between large and small polynomials is the foundation of the security argument - error terms are small, but public parameters are large and computationally indistinguishable from random.

---

## 3. Lattice Problems Underlying Kyber's Security

### 3.1 Module Learning With Errors (MLWE)

The **MLWE** problem is parameterised by prime $q$, integers $n, k, l$ with $k \geq l$, and small bounds $\eta_1, \eta_2 \ll q/2$.

**Given:** A matrix $\mathbf{A} \in R_q^{k \times l}$ and a vector:

$$\mathbf{t} = \mathbf{A} \cdot \mathbf{s} + \mathbf{e}$$

where $\mathbf{s} \in S_{\eta_1}^l$ (small secret) and $\mathbf{e} \in S_{\eta_2}^k$ (small error)

**Required:** Find $\mathbf{s}$

If $\mathbf{e} = 0$, then $\mathbf{t} = \mathbf{A} \cdot \mathbf{s}$ is a standard linear system solvable by conventional algebra. The addition of the small error term $\mathbf{e}$ makes the problem computationally hard - this is the core "Learning With Errors" intuition.

### 3.2 Decisional MLWE (D-MLWE)

**Given:** $(\mathbf{A}, \mathbf{z})$

**Required:** Determine whether $\mathbf{z} = \mathbf{A} \cdot \mathbf{s} + \mathbf{e}$ for some small $\mathbf{s}, \mathbf{e}$ (an MLWE instance), or whether $\mathbf{z}$ is a uniformly random element of $R_q^k$.

If D-MLWE is intractable, then Kyber's public key $(\mathbf{A}, \mathbf{t})$ where $\mathbf{t} = \mathbf{A} \cdot \mathbf{s} + \mathbf{e}$ is computationally indistinguishable from random data. An adversary learns nothing useful from observing the public key.

### 3.3 Module Short Integer Solution (MSIS)

The security of Dilithium (covered in Month 3) rests on the **MSIS** problem: given $\mathbf{A} \in R_q^{k \times l}$, find a short vector $\mathbf{z}$ such that:

$$\mathbf{A} \cdot \mathbf{z} = 0 \quad \text{in } R_q$$

---

## 4. CRYSTALS-Kyber: The Encryption Scheme

### 4.1 From PKE to KEM

Kyber is a **Key Encapsulation Mechanism (KEM)** constructed in two stages:

1. **Kyber-PKE**: A public-key encryption scheme, secure against passive chosen-plaintext attacks
2. **Kyber-KEM**: Derived from Kyber-PKE by applying the **Fujisaki-Okamoto (FO) transform**, upgrading security to active chosen-ciphertext attacks

### 4.2 Domain Parameters (ML-KEM-768)

| Parameter | Value | Meaning |
|-----------|-------|---------|
| $q$ | 3329 | Prime modulus |
| $n$ | 256 | Polynomial degree |
| $k$ | 3 | Module rank |
| $\eta_1$ | 2 | Secret/error distribution bound |
| $\eta_2$ | 2 | Error distribution bound |
| $d_u$ | 10 | Ciphertext compression (u component) |
| $d_v$ | 4 | Ciphertext compression (v component) |

### 4.3 Key Generation

Alice generates her key pair:

1. Select random seed $\rho \in \{0,1\}^{256}$ and expand to generate public matrix $\mathbf{A} \in R_q^{k \times k}$ using SHAKE-128
2. Sample small secret $\mathbf{s} \in S_{\eta_1}^k$ and error $\mathbf{e} \in S_{\eta_2}^k$ using the Central Binomial Distribution
3. Compute:

$$\mathbf{t} = \mathbf{A} \cdot \mathbf{s} + \mathbf{e}$$

4. **Public (encryption) key:** $(\rho, \mathbf{t})$ — $\rho$ replaces the full matrix $\mathbf{A}$ since anyone knowing $\rho$ can regenerate $\mathbf{A}$ via SHAKE-128
5. **Private (decryption) key:** $\mathbf{s}$

Computing $\mathbf{s}$ from $(\mathbf{A}, \mathbf{t})$ is an instance of MLWE - computationally infeasible by assumption.

**Key sizes:** ML-KEM-768 public key = **1,184 bytes** vs ECC (P-384) = 48 bytes vs RSA (3072-bit) = 384 bytes. The larger Kyber key is the direct cost of quantum resistance.

### 4.4 Encryption

To encrypt message $\mathbf{m} \in \{0,1\}^n$ for Alice, Bob does:

1. Obtain $(\rho, \mathbf{t})$ and regenerate $\mathbf{A} = \text{Expand}(\rho)$
2. Sample small $\mathbf{r} \in S_{\eta_1}^k$, $\mathbf{e}_1 \in S_{\eta_2}^k$, $e_2 \in S_{\eta_2}$
3. Compute:

$$\mathbf{u} = \mathbf{A}^T \cdot \mathbf{r} + \mathbf{e}_1$$

$$v = \mathbf{t}^T \cdot \mathbf{r} + e_2 + \left\lceil \frac{q}{2} \right\rceil \mathbf{m}$$

4. Compress: $c_1 = \text{Compress}_q(\mathbf{u},\, d_u)$ and $c_2 = \text{Compress}_q(v,\, d_v)$
5. Output ciphertext $\mathbf{c} = (c_1, c_2)$

### 4.5 Decryption

To decrypt $\mathbf{c} = (c_1, c_2)$, Alice uses private key $\mathbf{s}$:

1. Decompress: $\mathbf{u}' = \text{Decompress}_q(c_1, d_u)$ and $v' = \text{Decompress}_q(c_2, d_v)$
2. Compute:

$$\mathbf{m} = \text{Round}_q\!\left(v' - \mathbf{s}^T \cdot \mathbf{u}'\right)$$

**Why this works:** The quantity $v' - \mathbf{s}^T \cdot \mathbf{u}'$ reduces algebraically to approximately $\lceil q/2 \rceil \cdot \mathbf{m}$ plus a small error polynomial $E(x) = e^T r + e_2 - s^T e_1$. As long as $\|E\|_\infty < q/4$, the rounding function correctly recovers $\mathbf{m}$.

### 4.6 Decryption Failure - Negligible but Non-Zero

For ML-KEM-768, $|E_i|$ can theoretically exceed $q/4$, meaning decryption is not guaranteed with probability 1. However, this failure probability is less than $2^{-164}$ - negligible in practice. The Kyber parameters were carefully chosen to minimise this without compromising security.

---

## 5. Optimisations

### 5.1 Smaller Public Keys via Seed Compression

Rather than transmitting the full matrix $\mathbf{A} \in R_q^{k \times k}$, only the 256-bit seed $\rho$ is transmitted. Anyone can regenerate $\mathbf{A}$ deterministically using SHAKE-128. This reduces the public key from 4,608 bytes to **1,184 bytes**.

### 5.2 Ciphertext Compression

Ciphertext components are compressed: $\mathbf{u}$ from 12-bit to $d_u = 10$ bits per coefficient, and $v$ from 12-bit to $d_v = 4$ bits. This reduces ciphertext size from 1,536 bytes to **1,088 bytes**.

$$\text{Compress}_q(x, d) = \left\lceil \frac{2^d}{q} \cdot x \right\rfloor \bmod 2^d \qquad \text{Decompress}_q(y, d) = \left\lceil \frac{q}{2^d} \cdot y \right\rfloor \bmod q$$

### 5.3 Central Binomial Distribution (CBD)

Rather than sampling uniformly from $S_\eta$ (which would require rejection sampling and introduce timing side-channels), Kyber uses the **Central Binomial Distribution**. For each coefficient, $\eta$ pairs of bits $(a_i, b_i)$ are sampled and the coefficient is:

$$c = \sum_{i=1}^{\eta} (a_i - b_i), \qquad c \in [-\eta, \eta]$$

This produces a near-Gaussian distribution as required by lattice security arguments.

### 5.4 Fast Polynomial Multiplication via NTT

Naïve multiplication in $R_q = \mathbb{Z}_{3329}[x]/(x^{256}+1)$ takes $O(n^2)$ operations. The **Number-Theoretic Transform (NTT)** reduces this to $O(n \log n)$, enabled by the fact that 256th roots of unity exist in $\mathbb{Z}_{3329}$. Full NTT details are covered in Month 4.

---

## 6. From PKE to KEM: The Fujisaki-Okamoto Transform

The **FO transform** using hash functions $G, H, J$ upgrades Kyber-PKE to full CCA security:

**Encapsulation (Bob):**
1. Select random $\mathbf{m} \in \{0,1\}^{256}$
2. Compute $(K, R) = G(\mathbf{m},\, H(\text{ek}))$
3. Encrypt $\mathbf{m}$ using Kyber-PKE with randomness $R$; output secret key $K$ and ciphertext $\mathbf{c}$

**Decapsulation (Alice):**
1. Decrypt $\mathbf{c}$ to recover $\mathbf{m}'$, compute $(K', R') = G(\mathbf{m}',\, H(\text{ek}))$
2. Re-encrypt $\mathbf{m}'$ using $R'$ to get $\mathbf{c}'$
3. If $\mathbf{c} = \mathbf{c}'$, return $K'$; otherwise return $\bar{K} = J(\mathbf{z}, \mathbf{c})$

The re-encryption check detects any ciphertext tampering. **Security result:** Kyber-KEM is IND-CCA2 secure assuming D-MLWE is intractable and $G, H, J$ behave as random functions.

---

## 7. Parameter Sets and Key/Ciphertext Sizes

| Scheme | Security Level | Public Key | Ciphertext | Failure Rate |
|--------|---------------|------------|------------|--------------|
| ML-KEM-512 | Category 1 (AES-128) | 800 bytes | 768 bytes | $< 2^{-139}$ |
| ML-KEM-768 | Category 3 (AES-192) | 1,184 bytes | 1,088 bytes | $< 2^{-164}$ |
| ML-KEM-1024 | Category 5 (AES-256) | 1,568 bytes | 1,568 bytes | $< 2^{-174}$ |

For comparison, TLS 1.3 with X25519 uses 32-byte public keys. The larger Kyber keys represent the direct cost of quantum resistance — and the challenge that next-generation wireless and IoT deployments must solve.

---

## 8. Connection to This Research

Understanding Kyber's internals at this depth is directly relevant to the PQC-SOC Readiness Scanner in two ways:

**Detection side:** The scanner identifies systems still using RSA and ECC. Knowing the exact Kyber parameters and key sizes allows it to generate accurate migration recommendations — not generic advice, but specific guidance: migrate to ML-KEM-768, expect public keys of 1,184 bytes and ciphertexts of 1,088 bytes.

**Infrastructure side:** The size and computational overhead differences between classical and post-quantum schemes have direct implications for network infrastructure — TLS handshake sizes, certificate chain lengths, and processing overhead on constrained devices. This is precisely the problem Surrey's channel-aware PQC project addresses for 6G wireless networks: how to deploy these larger, more compute-intensive schemes where every byte and every millisecond matters.

Month 3 will cover CRYSTALS-Dilithium (ML-DSA, FIPS 204) — the post-quantum digital signature scheme.

---

## References

1. Bos, J. et al. "CRYSTALS-Kyber: a CCA-secure module-lattice-based KEM." *IEEE European Symposium on Security and Privacy*, 2018, pp. 353–367.
2. Menezes, A. "Kyber and Dilithium." Lecture series, cryptography101.ca, August 2024.
3. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard. csrc.nist.gov/pubs/fips/203/final
4. NIST FIPS 204: Module-Lattice-Based Digital Signature Standard. csrc.nist.gov/pubs/fips/204/final
5. NIST FIPS 205: Stateless Hash-Based Digital Signature Standard. csrc.nist.gov/pubs/fips/205/final

---

*Q-Day isn't the beginning of the threat. It's the end of the grace period.*
