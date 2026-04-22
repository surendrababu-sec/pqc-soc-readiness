# Month 3 - Lattice-Based Digital Signatures: Mathematical Foundations of CRYSTALS-Dilithium (ML-DSA)

---

## Overview

Month 2 covered CRYSTALS-Kyber - a Key Encapsulation Mechanism built on lattice problems. Kyber solves the problem of secure key exchange. But secure communication requires more than just confidentiality. It also requires authentication: the ability to prove that a message genuinely came from who it claims to come from, and that it hasn't been tampered with in transit.

That's what digital signatures do. And in a post-quantum world, we need digital signatures that remain secure even against adversaries armed with quantum computers.

This month's focus is CRYSTALS-Dilithium, standardised by NIST as FIPS 204 under the name ML-DSA (Module-Lattice-based Digital Signature Algorithm). Like Kyber, Dilithium is built on lattice problems - specifically the hardness of MLWE and MSIS, and its design is most clearly understood as a lattice-based adaptation of the classical Schnorr signature scheme.

The source material for this month is the lecture series by Professor Alfred Menezes (University of Waterloo, August 2024), combined with the NIST FIPS 204 specification and the original CRYSTALS-Dilithium paper (IACR Transactions on Cryptographic Hardware and Embedded Systems, Vol. 2018, No. 1, pp. 238–268).

---

## 1. Notation

Before going into the scheme, it helps to have the notation clear upfront. These definitions carry through all versions of Dilithium.

- $\mathbb{Z}_q$, $\text{mod}\, q$, $\text{mods}\, q$, $\||\cdot\||_\infty$ - modular arithmetic and infinity norm (same as Month 2)
- $R_q = \mathbb{Z}_q[x]/(x^n + 1)$ - the polynomial ring
- $S_\eta$ - set of polynomials in $R_q$ with coefficients in $[-\eta, \eta]$ (using $\text{mods}\, q$)
- $\tilde{S}_{\gamma_1}$ - set of polynomials in $R_q$ with coefficients in $(-\gamma_1, \gamma_1]$
- $(k, \ell)$ with $k > \ell$ - matrix dimensions
- $B_\tau$ - polynomials in $S_1$ with exactly $\tau$ coefficients equal to $\pm 1$ (the challenge space)
- $\beta = \tau\eta$ - bound on the infinity norm of $cs_i$ when $c \in B_\tau$
- $\gamma_2$ and $\alpha = 2\gamma_2$ - parameters for the Decompose function
- $\lambda$ - half the bit-length of the signature component $\tilde{c}$
- $d$ - number of bits dropped from $t$ during compression
- $\omega$ - maximum number of 1's in the hint vector $h$

**ML-DSA-87 Domain Parameters** (used throughout for concreteness):

| Parameter | Value |
|-----------|-------|
| $q$ | $2^{23} - 2^{13} + 1 = 8{,}380{,}417 \approx 2^{23}$ (23-bit prime) |
| $n$ | 256 |
| $(k, \ell)$ | $(8, 7)$ |
| $\eta$ | 2 |
| $d$ | 13 |
| $\gamma_1$ | $2^{19}$ |
| $\tau$ | 60, $\beta = \tau\eta = 120$ |
| $\gamma_2$ | $(q-1)/32 = 262{,}144 \approx 2^{18}$ |
| $\alpha = 2\gamma_2$ | $\approx 2^{19}$ |
| $\lambda$ | 256 |
| $\omega$ | 75 |

---

## 2. Why Dilithium? The Problem with Classical Signatures

Classical digital signature schemes like RSA-based signatures and ECDSA derive their security from the integer factorisation and elliptic curve discrete logarithm problems respectively. Both are efficiently solvable by Shor's algorithm on a quantum computer.

A quantum-safe signature scheme needs to be built on a problem that remains hard even with quantum computation. Dilithium achieves this by building on the **Schnorr signature scheme** as a conceptual template, but replacing its group-theoretic hardness assumption with lattice hardness assumptions - specifically MLWE and MSIS.

---

## 3. The Schnorr Signature Scheme

Understanding Schnorr is essential because Dilithium is a direct lattice adaptation of it. The core idea - commit, challenge, respond - carries straight through.

**Domain parameters:** A cyclic group of order $n$, generator $g$, and a hash function $H$.

**Key generation:** Alice selects $a \in_R [1, n-1]$ and computes $g^a$. Her verification (public) key is $g^a$; her signing (private) key is $a$. Computing $a$ from $g^a$ is the discrete logarithm problem.

**Signature generation:** To sign M ∈ {0,1}*, Alice:
1. Selects $y \in_R [1, n-1]$ and computes $w = g^y$ — the **commitment**
2. Computes $c = H(M \| w)$ — the **challenge**
3. Computes $z = y + ca \mod n$ — the **response**
4. Outputs $\sigma = (c, z)$

**Signature verification:** To verify $\sigma = (c, z)$ on $M$, Bob:
1. Obtains an authentic copy of Alice's public key $g^a$
2. Computes $w' = g^z(g^a)^{-c}$
3. Accepts iff $c = H(M \| w')$

**Why verification works:** Since $z = y + ca \mod n$, we have $g^z = g^{y+ca}$, so $g^y = g^z(g^a)^{-c}$, meaning $w = w'$.

The terminology — **commitment** ($w$), **challenge** ($c$), **response** ($z$) — carries directly into Dilithium.

---

## 4. Dilithium: First Attempt

The first attempt at a lattice-based signature scheme takes the Schnorr structure and replaces the group-theoretic operations with module lattice operations.

**Key generation:** Alice:
1. Selects $A \in_R R_q^{k \times \ell}$, $s_1 \in_R S_\eta^\ell$, and $s_2 \in_R S_\eta^k$
2. Computes $t = As_1 + s_2$
3. Her verification (public) key is $(A, t)$; her signing (private) key is $(s_1, s_2)$

Note: Computing $s_1$ from $(A, t)$ is an instance of MLWE — hard by assumption.

**Signature generation:** To sign $M \in \{0,1\}^*$, Alice:
1. Selects $y \in_R \tilde{S}_{\gamma_1}^\ell$
2. Computes $w = Ay$ (commitment)
3. Computes $c = H(M \| w)$ (challenge), where $c \in B_\tau$
4. Computes $z = y + cs_1$ (response)
5. Outputs $\sigma = (c, z)$

Note that $w \in R_q^k$, $c \in B_\tau$, $z \in R_q^\ell$. A "mods $q$" operator is not needed when computing $z = y + cs_1$, provided $\gamma_1 + \beta < q/2$ — because the coefficients of the polynomials in $y$ have symmetric mod representation lying in $(-\gamma_1, \gamma_1]$, and the coefficients of $cs_1$ lie in $[-\beta, \beta]$, so the result stays within the unambiguous range.

**Signature verification:** To verify $\sigma = (c, z)$ on $M$, Bob:
1. Obtains an authentic copy of Alice's public key $(A, t)$
2. Computes the commitment $w'$, and verifies that $c = H(M \| w')$

**How verification works:** Since $z = y + cs_1$, we have $Az = Ay + c(As_1) = w + c(t - s_2)$, so $Az - ct = w - cs_2$. The verifier who knows $A, t, z, c$ but not $s_2$ can only compute $w - cs_2$.

This is the central problem that the toy version solves.

---

## 5. Dilithium: Toy Version (V3a)

The toy version introduces the key insight: rather than using the full commitment $w$, the signer uses only the **high-order bits** of $w$. This allows verification without requiring knowledge of $s_2$.

**Key generation:** Same as the first attempt — verification key is $(A, t)$, signing key is $(s_1, s_2)$.

**Signature generation:** To sign $M \in \{0,1\}^*$, Alice:
1. Found $\leftarrow$ false (repeatedly selects random $y$'s)
2. While Found = false do:
   - a) Select $y \in_R \tilde{S}_{\gamma_1}^\ell$
   - b) Compute $w = Ay$ and $w_1 = \text{HighBits}(w)$
   - c) Compute $c = H(M \| w_1)$
   - d) Compute $z = y + cs_1$
   - e) If LowBits$(w - cs_2)$ are "sufficiently small" then Found $\leftarrow$ true
3. Output $\sigma = (c, z)$

**Signature verification:** To verify $\sigma = (c, z)$ on $M$, Bob:
1. Obtains an authentic copy of Alice's verification key $(A, t)$
2. Computes $w_1' = \text{HighBits}(Az - ct)$
3. Accepts iff $c = H(M \| w_1')$

The main idea: the signer uses only the HighBits of $w$ to compute the challenge $c$, where $w_1 = \text{HighBits}(w)$. The verifier can compute $w_1'$ from $Az - ct = w - cs_2$, and if the LowBits of $w - cs_2$ are sufficiently small, then $\text{HighBits}(w - cs_2) = \text{HighBits}(w) = w_1$.

---

## 6. Problems and Solutions

The toy version works in principle but has five engineering problems that need resolving before it becomes deployable. Each one has a concrete solution.

### Problem #1: Large Public and Private Keys

**Problem:** The public key $(A, t) \in R_q^{k \times \ell} \times R_q^k$. For ML-DSA-87 with $q = 2^{23} - 2^{13} + 1$, $n = 256$, $(k, \ell) = (8, 7)$, the matrix $A$ alone is $56 \times 256 \times 23$ bits = **41,216 bytes**. The vector $t$ is $8 \times 256 \times 23$ bits = **5,888 bytes**.

**Solution 1 (for A):** Generate $A$ from a 256-bit public seed $\rho$; the public key becomes $(\rho, t)$. Anyone can regenerate $A$ via ExpandA($\rho$) using SHAKE-128. This is the same seed compression trick used in Kyber.

**Solution 2 (for t):** Use only the "high-order bits" of the coefficients of polynomials in $t$. This is done using Power2Round (introduced in V3c), retaining $t_1$ (high bits) in the public key and $t_0$ (low bits) in the signing key.

**Problem:** The private key $(s_1, s_2) \in S_\eta^\ell \times S_\eta^k$. For ML-DSA-87 with $\eta = 2$, each coefficient requires 3 bits, giving $(8+7) \times 256 \times 3$ bits = **1,440 bytes**.

**Solution:** Generate $s_1$ and $s_2$ from a 512-bit secret seed $\rho'$ via ExpandS($\rho'$).

### Problem #2: Repeated Hashing of M

**Problem:** The message $M$ is hashed once during each iteration of the signing loop at step (c): compute $c = H(M \| w_1)$. This is slow if $M$ is large.

**Solution:** Pre-hash the message. Compute $\mu = H(tr \| M, 512)$ once before the loop and use $\mu$ instead of $M$ in all subsequent hash calls, so step (c) becomes: compute $\tilde{c} = H(\mu \| w_1, 2\lambda)$.

### Problem #3: Random Bits Required for Signing

**Problem:** A large number of random bits are needed for each iteration — specifically for step (a): select $y \in_R \tilde{S}_{\gamma_1}^\ell$.

**Solution:** Generate $y$ deterministically from a secret seed $\rho''$ and a counter $\kappa$, where $\rho'' = H(K \| \text{rnd} \| \mu, 512)$. The counter $\kappa$ increments by $\ell$ each iteration. This makes the signature generation algorithm **deterministic** (when rnd $= 0^{256}$) or **hedged** (when rnd is random). No external randomness is required during the signing loop.

### Problem #4: A Signature (c, z) Leaks Information About s₁

**Problem:** Since $z = y + cs_1$ and $y \in \tilde{S}_{\gamma_1}^\ell$, the coefficients of $y$ lie in $(-\gamma_1, \gamma_1]$. The coefficients of $cs_1$ lie in $[-\beta, \beta]$ where $\beta = \tau\eta$. So the coefficients of $z$ lie in $(-\gamma_1 - \beta, \gamma_1 + \beta]$.

If a coefficient of $z$ is $\gamma_1 + \beta$, then the corresponding coefficient of $cs_1$ must be $\beta$, which leaks information about $s_1$. More generally, if a coefficient of $z$ is close to the boundary $\pm\gamma_1$, it narrows down the possible values of the corresponding coefficient of $cs_1$.

**Solution (rejection sampling):** The signer repeatedly selects $y \in_R \tilde{S}_{\gamma_1}^\ell$ and computes $z = y + cs_1$ until all coefficients of $z$ satisfy $-\gamma_1 + \beta < \text{coeff}(z) \leq \gamma_1 - \beta$. Dilithium imposes a slightly stricter constraint: $\|z\|_\infty < \gamma_1 - \beta$.

This ensures that the coefficients of $z$ don't leak any information about the coefficients of $cs_1$, and hence about $s_1$. The signer also checks that LowBits$(w - cs_2)$ are sufficiently small. This combined rejection criterion is an example of **rejection sampling**.

**Why a coefficient of y is not allowed to be exactly $-\gamma_1$:** The number of possible values for each coefficient of $y$ is $2\gamma_1$. With $\gamma_1 = 2^{19}$, a coefficient can be selected uniformly at random by randomly selecting a binary string of length 20. Allowing $-\gamma_1$ would give $2\gamma_1 + 1$ possibilities, which is not a power of 2 and makes uniform generation more challenging.

### Problem #5: Computing HighBits(Az − ct)

**Problem:** In signature verification, the verifier needs to compute HighBits$(Az - ct)$. However, the verifier only knows the high-order bits of $t$ (after t compression in V3c). They cannot compute $Az - ct$ directly.

**Solution:** Use "hint bits" $h$ in the signature so that HighBits$(Az - ct)$ can be computed using only the high-order bits of $t$. The hint bits encode the carry digits when the low-order bits of $t$ are added back, allowing the verifier to recover the correct HighBits without knowing $t_0$. The full details are worked out in V3c.

---

## 7. V3b: Dilithium Without t Compression

V3b incorporates the five solutions from the problems section into a working scheme, stopping short of t compression. This gives a slightly simplified version of the full Dilithium scheme.

### 7.1 HighBits and LowBits (Simplified)

The Decompose function splits an integer into its high and low order parts with respect to a modulus $\alpha$.

**Decompose$(r, \alpha)$ [simplified]:**
- Input: $r \in [0, q-1]$, $\alpha$ even with $q - 1 = m\alpha$
- Output: $(r_1, r_0)$ such that $r = r_1\alpha + r_0$, with $-\alpha/2 < r_0 \leq \alpha/2$ and $0 \leq r_1 \leq m$
1. Set $r_0 = r \text{ mods } \alpha$ and $r_1 = (r - r_0)/\alpha$
2. Return $(r_1, r_0)$

Notation: $r_1 = \text{HighBits}(r, \alpha)$, $r_0 = \text{LowBits}(r, \alpha)$.

Note: $r_1\alpha$ is the nearest multiple of $\alpha$ to $r$, with ties broken by choosing the smaller multiple.

Decompose extends naturally to polynomials in $R_q$ and vectors of polynomials in $R_q^k$ by applying it to each coefficient.

### 7.2 Hashing

Dilithium uses **SHAKE256** (and also SHAKE128), both specified in FIPS 202 (SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions).

SHAKE256 is an eXtendable-Output Function (XOF). For $M \in \{0,1\}^*$ and $d \geq 1$, SHAKE256$(M, d)$ is the $d$-bit hash of $M$. Being a XOF means that SHAKE256$(M, d')$ is exactly equal to the first $d'$ bits of SHAKE256$(M, d)$ whenever $d' \leq d$.

For $M \in \{0,1\}^*$ and $d \geq 1$, Dilithium defines $H(M, d) = \text{SHAKE256}(M, d)$.

Specific uses:
- ExpandA($\rho$) uses SHAKE128 to expand the 256-bit seed into the matrix $A$
- ExpandS($\rho'$) uses SHAKE256 to expand the 512-bit seed into $(s_1, s_2)$
- ExpandMask($\rho'', \kappa$) uses SHAKE256 to generate the masking vector $y$

### 7.3 Key Generation

Alice does:
1. Select $\xi \in_R \{0,1\}^{256}$
2. Compute $(\rho, \rho', K) = H(\xi, 1024)$, where $\rho \in \{0,1\}^{256}$, $\rho' \in \{0,1\}^{512}$, $K \in \{0,1\}^{256}$
3. Compute $A = \text{ExpandA}(\rho)$ ($A \in R_q^{k \times \ell}$)
4. Compute $(s_1, s_2) = \text{ExpandS}(\rho')$ ($(s_1, s_2) \in S_\eta^\ell \times S_\eta^k$)
5. Compute $t = As_1 + s_2$ ($t \in R_q^k$)
6. Compute $tr = H(\rho \| t, 512)$

Alice's verification key is $PK = (\rho, t)$; her signature key is $SK = (\rho, K, tr, s_1, s_2)$.

### 7.4 Signature Generation

To sign $M \in \{0,1\}^*$, Alice does:
1. Compute $A = \text{ExpandA}(\rho)$
2. Compute $\mu = H(tr \| M, 512)$
3. Compute $\rho'' = H(K \| \text{rnd} \| \mu, 512)$, where either rnd $= 0^{256}$ (deterministic) or rnd $\in_R \{0,1\}^{256}$ (hedged)
4. $\kappa \leftarrow 0$
5. Found $\leftarrow$ false
6. While Found = false do:
   - (a) Compute $y = \text{ExpandMask}(\rho'', \kappa)$ ($y \in \tilde{S}_{\gamma_1}^\ell$)
   - (b) Compute $w = Ay$ and $w_1 = \text{HighBits}(w, 2\gamma_2)$
   - (c) Compute $\tilde{c} = H(\mu \| w_1, 2\lambda)$ and $c = \text{SampleInBall}(\tilde{c})$ ($c \in B_\tau$)
   - (d) Compute $z = y + cs_1$
   - (e) Compute $r_0 = \text{LowBits}(w - cs_2, 2\gamma_2)$
   - (f) If $\|z\|_\infty < \gamma_1 - \beta$ and $\|r_0\|_\infty < \gamma_2 - \beta$ then Found $\leftarrow$ true
   - (g) $\kappa \leftarrow \kappa + \ell$
7. Return $\sigma = (\tilde{c}, z)$

### 7.5 Signature Verification

To verify Alice's signature $\sigma = (\tilde{c}, z)$ on $M$, Bob does:
1. Obtain an authentic copy of Alice's public key $PK = (\rho, t)$
2. Check that $\|z\|_\infty < \gamma_1 - \beta$; if not then reject
3. Compute $A = \text{ExpandA}(\rho)$
4. Compute $tr = H(\rho \| t, 512)$ and $\mu = H(tr \| M, 512)$
5. Compute $c = \text{SampleInBall}(\tilde{c})$
6. Compute $w_1' = \text{HighBits}(Az - ct, 2\gamma_2)$
7. Check that $\tilde{c} = H(\mu \| w_1', 2\lambda)$; if not then reject
8. Accept the signature

### 7.6 Correctness

Signature verification works because:

$$Az - ct = A(y + cs_1) - c(As_1 + s_2) = Ay - cs_2 = w - cs_2$$

Since $\|\text{LowBits}(w - cs_2, 2\gamma_2)\|_\infty < \gamma_2 - \beta$ and $\|cs_2\|_\infty \leq \beta$, we have:

$$w_1' = \text{HighBits}(Az - ct, 2\gamma_2) = \text{HighBits}(w - cs_2, 2\gamma_2) = \text{HighBits}(w, 2\gamma_2) = w_1$$

Therefore $\tilde{c} = H(\mu \| w_1', 2\lambda)$ matches, and the signature is accepted.

### 7.7 Security

**Key generation:** If D-MLWE is intractable, then an adversary is unable to learn anything about the secret key component $s_1$ from the public key $(A, t)$.

**Signature forgery:** The adversary's task is: given $(A, t)$, find $(M, \tilde{c}, z)$ such that $\|z\|_\infty < \gamma_1 - \beta$ and $\tilde{c} = H(\mu \| w_1)$, where $\mu = H(M)$, $w_1 = \text{HighBits}(Az - ct, 2\gamma_2)$, and $c = \text{SampleInBall}(\tilde{c})$.

Finding a suitable $z$ requires solving the inhomogeneous MSIS (I-MSIS) problem — an instance of the (inhomogeneous) Module Short Integer Solutions problem. Since the adversary's forgery task reduces to I-MSIS, and MSIS has no known efficient algorithm (classical or quantum), the scheme is secure.

**Security claim:** Dilithium (without t compression) is existentially unforgeable against chosen-message attack assuming that D-MLWE and MSIS are intractable, and $H$ is modelled as a random function.

---

## 8. V3c: t Compression and Hint Bits

V3c adds t compression to reduce public key size, and introduces hint bits to make verification work correctly despite the verifier not having access to $t_0$.

### 8.1 Power2Round

**Power2Round$(r, d)$:**
- Input: $r \in [0, q-1]$, $d \in [1, \log_2 q]$
- Output: $(r_1, r_0)$ such that $r = r_1 \cdot 2^d + r_0$, with $-2^{d-1} < r_0 \leq 2^{d-1}$ and $0 \leq r_1 \leq \lceil(q-1)/2^d\rceil$
1. Set $r_0 = r \text{ mods } 2^d$ and $r_1 = (r - r_0)/2^d$
2. Return $(r_1, r_0)$

Notation: $r_1 = \text{HighBits}(r, \alpha)$, $r_0 = \text{LowBits}(r, \alpha)$ where $\alpha = 2^d$.

Power2Round extends to polynomials and vectors by applying it to each coefficient.

**Example:** Consider $R_q = \mathbb{Z}_{23}[x]/(x^4+1)$ and $d = 3$. Let $t = 2 + 11x + 5x^2 + 19x^3 \in R_q$. Then Power2Round$(t, d) = (t_1, t_0)$ where $t_1 = x + x^2 + 2x^3$ and $t_0 = 2 + 3x - 3x^2 + 3x^3$. Note that $t = t_1 \cdot 2^d + t_0$.

### 8.2 t Compression

The Dilithium verification key includes a vector of polynomials $t \in R_q^k$. t compression drops the $d$ low-order bits of each coefficient of each polynomial in $t$, using Power2Round to write $t = t_1 \cdot 2^d + t_0$.

- $t_1$ (high-order bits) is included in the verification key instead of $t$
- $t_0$ (low-order bits) is retained in the signing key

For ML-DSA-87 with $k = 8$ and $d = 13$: the full $t$ is $8 \times 256 \times 23$ bits = **5,888 bytes**, while $t_1$ is $8 \times 256 \times 10$ bits = **2,560 bytes** — a significant reduction.

### 8.3 Complications Due to t Compression

After t compression, the verifier only knows $t_1$, not $t_0$. The verifier needs to compute HighBits$(w - cs_2, 2\gamma_2)$, which requires $Az - ct$.

Instead of computing $Az - ct$, the verifier computes:

$$Az - ct_1 \cdot 2^d = Az - c(t - t_0) = Az - ct + ct_0 = w - cs_2 + ct_0$$

The coefficients of the polynomials in $-ct_0$ are expected to be relatively small. More precisely, we can expect that $\|-ct_0\|_\infty \leq \gamma_2$ with high probability. When $d = 13$, $\tau = 60$, and $\gamma_2 = 262{,}144$, the probability is 1.

If $\|-ct_0\|_\infty \leq \gamma_2$, then adding $(-ct_0)$ to $(w - cs_2 + ct_0)$ will affect the HighBits of $w - cs_2 + ct_0$ by $-1$, 0, or $+1$.

To enable the verifier to compute HighBits$(w - cs_2, 2\gamma_2)$ from $w - cs_2 + ct_0$ without knowledge of $t_0$, the signer includes "hint bits" in the signature.

### 8.4 Hint Bits: MakeHint and UseHint

The hint bits are essentially the "carry digits" when $(-ct_0)$ is added to $(w - cs_2 + ct_0)$.

**Modified Decompose$(r, \alpha)$:**
- Input: $r \in [0, q-1]$, $\alpha$ even with $q - 1 = m\alpha$
- Output: $(r_1, r_0)$ such that $r \equiv r_1\alpha + r_0 \pmod{q}$, with $-\alpha/2 \leq r_0 \leq \alpha/2$ and $0 \leq r_1 < m$
1. Compute $r_0 = r \text{ mods } \alpha$
2. If $r - r_0 = q - 1$: set $r_1 = 0$, $r_0 = r_0 - 1$; else set $r_1 = (r - r_0)/\alpha$
3. Return $(r_1, r_0)$

This modification handles the boundary case where the simplified Decompose would produce $r_1 = m$, keeping $r_1$ strictly less than $m$.

**MakeHint$(z, r, \alpha)$:**
- Input: $r \in [0, q-1]$, $-\alpha/2 \leq z \leq \alpha/2$
- Output: a hint bit $h \in \{0, 1\}$
1. Set $h = 1$ if HighBits$(r + z, \alpha) \neq$ HighBits$(r, \alpha)$; else $h = 0$
2. Return $h$

**UseHint$(h, r, \alpha)$:**
- Input: $h \in \{0,1\}$, $r \in [0, q-1]$
- Output: HighBits$(r + z, \alpha)$ for any $z$ with MakeHint$(z, r, \alpha) = h$
1. Compute $(r_1, r_0) = \text{Decompose}(r, \alpha)$
2. If $h = 1$ and $r_0 > 0$: return $r_1 + 1 \mod m$
3. If $h = 1$ and $r_0 \leq 0$: return $r_1 - 1 \mod m$
4. Return $r_1$

**Claim:** Suppose $r \in [0, q-1]$ and $-\alpha/2 \leq z \leq \alpha/2$. Then UseHint(MakeHint$(z, r, \alpha)$, $r$, $\alpha$) = HighBits$(r + z, \alpha)$.

MakeHint and UseHint extend naturally to polynomials in $R_q$ and vectors of polynomials in $R_q^\ell$.

---

## 9. V3d: Dilithium Full Scheme

V3d incorporates all five problem solutions plus t compression and hint bits into the complete ML-DSA scheme.

### 9.1 Key Generation

Alice does:
1. Select $\xi \in_R \{0,1\}^{256}$
2. Compute $(\rho, \rho', K) = H(\xi, 1024)$, where $\rho \in \{0,1\}^{256}$, $\rho' \in \{0,1\}^{512}$, $K \in \{0,1\}^{256}$
3. Compute $A = \text{ExpandA}(\rho)$ ($A \in R_q^{k \times \ell}$)
4. Compute $(s_1, s_2) = \text{ExpandS}(\rho')$ ($(s_1, s_2) \in S_\eta^\ell \times S_\eta^k$)
5. Compute $t = As_1 + s_2$ ($t \in R_q^k$)
6. Compute $(t_1, t_0) = \text{Power2Round}(t, d)$
7. Compute $tr = H(\rho \| t_1, 512)$

Alice's verification key is $PK = (\rho, t_1)$; her signature key is $SK = (\rho, K, tr, s_1, s_2, t_0)$.

### 9.2 Signature Generation

To sign $M \in \{0,1\}^*$, Alice does:
1. Compute $A = \text{ExpandA}(\rho)$
2. Compute $\mu = H(tr \| M, 512)$
3. Compute $\rho'' = H(K \| \text{rnd} \| \mu, 512)$
4. $\kappa \leftarrow 0$
5. Found $\leftarrow$ false
6. While Found = false do:
   - (a) Compute $y = \text{ExpandMask}(\rho'', \kappa)$ ($y \in \tilde{S}_{\gamma_1}^\ell$)
   - (b) Compute $w = Ay$ and $w_1 = \text{HighBits}(w, 2\gamma_2)$
   - (c) Compute $\tilde{c} = H(\mu \| w_1, 2\lambda)$ and $c = \text{SampleInBall}(\tilde{c})$ ($c \in B_\tau$)
   - (d) Compute $z = y + cs_1$
   - (e) Compute $r_0 = \text{LowBits}(w - cs_2, 2\gamma_2)$
   - (f) If $\|z\|_\infty < \gamma_1 - \beta$ and $\|r_0\|_\infty < \gamma_2 - \beta$ then:
     - i) If $\|-ct_0\|_\infty < \gamma_2$ then:
       - Compute $h = \text{MakeHint}(-ct_0, w - cs_2 + ct_0, 2\gamma_2)$
       - If the number of 1's in $h$ is $\leq \omega$ then Found $\leftarrow$ true
   - (g) $\kappa \leftarrow \kappa + \ell$
7. Return $\sigma = (\tilde{c}, z, h)$

### 9.3 Signature Verification

To verify Alice's signature $\sigma = (\tilde{c}, z, h)$ on $M$, Bob does:
1. Obtain an authentic copy of Alice's public key $PK = (\rho, t_1)$
2. Check that $\|z\|_\infty < \gamma_1 - \beta$ and that the number of 1's in $h$ is $\leq \omega$; if not then reject
3. Compute $A = \text{ExpandA}(\rho)$
4. Compute $tr = H(\rho \| t_1, 512)$ and $\mu = H(tr \| M, 512)$
5. Compute $c = \text{SampleInBall}(\tilde{c})$
6. Compute $w_1' = \text{UseHint}(h, Az - ct_1 \cdot 2^d, 2\gamma_2)$
7. Check that $\tilde{c} = H(\mu \| w_1', 2\lambda)$; if not then reject
8. Accept the signature

### 9.4 Correctness

We have:
$$Az - ct_1 \cdot 2^d = A(y + cs_1) - c(t - t_0) = Ay + cAs_1 - c(As_1 + s_2) + ct_0 = w - cs_2 + ct_0$$

Since $\|-ct_0\|_\infty < \gamma_2$, we have:
$$w_1' = \text{UseHint}(h, Az - ct_1 \cdot 2^d, 2\gamma_2) = \text{HighBits}(Az - ct_1 \cdot 2^d - ct_0, 2\gamma_2)$$
$$= \text{HighBits}(Az - ct, 2\gamma_2) = \text{HighBits}(w - cs_2, 2\gamma_2)$$

And since $\|\text{LowBits}(w - cs_2, 2\gamma_2)\|_\infty < \gamma_2 - \beta$ and $\|cs_2\|_\infty \leq \beta$:
$$\text{HighBits}(w - cs_2, 2\gamma_2) = \text{HighBits}(w, 2\gamma_2) = w_1$$

Therefore $w_1' = w_1$, and the signature verifies correctly.

### 9.5 Security

Compression of the public key component $t$ doesn't affect the security claim for Dilithium.

**Security claim:** Dilithium is existentially unforgeable against chosen-message attack assuming that D-MLWE and MSIS are intractable, and $H$ is modelled as a random function.

---

## 10. Parameter Sets and Key/Signature Sizes

### 10.1 ML-DSA Parameter Sets

| Scheme | Security Category | $q$ | $n$ | $(k,\ell)$ | $\eta$ | $d$ | $\gamma_1$ | $\tau$ | $\beta$ | $\gamma_2$ | $\lambda$ | $\omega$ |
|--------|------------------|-----|-----|-----------|--------|-----|-----------|--------|---------|-----------|---------|--------|
| ML-DSA-44 | 2 | $2^{23}-2^{13}+1$ | 256 | (4,4) | 2 | 13 | $2^{17}$ | 39 | 78 | $(q-1)/88$ | 128 | 80 |
| ML-DSA-65 | 3 | $2^{23}-2^{13}+1$ | 256 | (6,5) | 4 | 13 | $2^{19}$ | 49 | 196 | $(q-1)/32$ | 192 | 55 |
| ML-DSA-87 | 5 | $2^{23}-2^{13}+1$ | 256 | (8,7) | 2 | 13 | $2^{19}$ | 60 | 120 | $(q-1)/32$ | 256 | 75 |

Security categories 2, 3, 5: fastest known attacks require at least as much resource as exhaustive key search on a 256-bit hash function, a 192-bit block cipher, and a 256-bit block cipher respectively.

### 10.2 Key Sizes and Signature Sizes

| Scheme | Security Category | Signing Key (bytes) | Verification Key (bytes) | Signature (bytes) |
|--------|------------------|--------------------|--------------------------|--------------------|
| ML-DSA-44 | 2 | 2,560 | 1,312 | 2,420 |
| ML-DSA-65 | 3 | 4,032 | 1,952 | 3,309 |
| ML-DSA-87 | 5 | 4,896 | 2,592 | 4,627 |

Key sizes and signature sizes are significantly larger than for RSA and ECDSA. When migrating from RSA and ECC to Kyber and Dilithium, these increased sizes will be challenging to deal with in some scenarios — particularly in constrained network protocols and IoT environments.

For context, an ECDSA signature (P-256) is 64 bytes. An ML-DSA-87 signature is 4,627 bytes — over 70 times larger. This size difference is the direct cost of quantum resistance, and it has practical implications for TLS handshake overhead, certificate chain sizes, and bandwidth-constrained deployments.

### 10.3 ML-DSA-87 Key Composition (for reference)

**Verification key** $PK = (\rho, t_1)$: $\rho$ is 256 bits; $t_1$ is $8 \times 256 \times 10$ bits. Total: **2,592 bytes**.

**Signing key** $SK = (\rho, K, tr, s_1, s_2, t_0)$: $\rho$ is 256 bits; $K$ is 256 bits; $tr$ is 512 bits; $t_0$ is $8 \times 256 \times 13$ bits; $s_1$ and $s_2$ require 3 bits per coefficient (since $\eta = 2$, there are 5 possible values: $-2, -1, 0, 1, 2$). Total: **4,896 bytes**.

**Signature** $\sigma = (\tilde{c}, z, h)$: $\tilde{c}$ is 512 bits; $z$ is $7 \times 256 \times 20$ bits; $h$ is $75 + 8$ bytes. Total: **4,627 bytes**.

---

## 11. Expected Number of Iterations (Signing)

Each iteration of the main loop in signature generation has four requirements to be met simultaneously. Analysing each gives an approximation of how many iterations signing takes on average.

Let $p_1 = \text{Prob}(\|z\|_\infty < \gamma_1 - \beta)$. Recall $z = y + cs_1$ where $y \in \tilde{S}_{\gamma_1}^\ell$. For a coefficient of $cs_1$ equal to $u \in [-\beta, \beta]$, the corresponding coefficient of $z$ is in $(-\gamma_1 + \beta, \gamma_1 - \beta)$ provided the coefficient of $y$ is in $(-\gamma_1 + \beta - u, \gamma_1 - \beta - u)$. This interval has length $2(\gamma_1 - \beta) - 1$, independent of $u$. Hence:

$$p_1 = \left(\frac{2(\gamma_1 - \beta) - 1}{2\gamma_1}\right)^{256\ell} \approx e^{-256\ell\beta/\gamma_1}$$

Let $p_2 = \text{Prob}(\|r_0\|_\infty < \gamma_2 - \beta)$. Assuming LowBits$(w - cs_2, 2\gamma_2)$ are uniformly distributed:

$$p_2 \approx e^{-256k\beta/\gamma_2}$$

Let $p_3 = \text{Prob}(\|-ct_0\|_\infty < \gamma_2$ and the number of 1's in $h$ is $\leq \omega)$. Heuristically, $p_3 > 0.98$.

The probability all four requirements are met is $p_1 p_2 p_3$. The expected number of iterations in signing is:

$$1/(p_1 p_2 p_3) \approx 1/(p_1 p_2) \approx e^{256\beta(\ell/\gamma_1 + k/\gamma_2)}$$

For the three ML-DSA parameter sets:
- **ML-DSA-44:** expected iterations ≈ 4.25
- **ML-DSA-65:** expected iterations ≈ 5.1
- **ML-DSA-87:** expected iterations ≈ 3.85

---

## 12. Omitted Details

The full specification in FIPS 204 includes several implementation details beyond the scope of these notes:

- ExpandA($\rho$) uses SHAKE128 for matrix expansion
- ExpandS($\rho'$) uses SHAKE256 for secret key expansion
- ExpandMask($\rho'', \kappa$) uses SHAKE256 for mask generation
- Full description of SampleInBall : $\{0,1\}^{2\lambda} \to B_\tau$
- Formatting for bit strings and byte strings
- An optional upper bound on the number of iterations in signature generation
- **Number-Theoretic Transform (NTT)** for fast polynomial multiplication in $R_q = \mathbb{Z}_{2^{23}-2^{13}+1}[x]/(x^{256}+1)$ — will be added upon completion of Month 3 notes

---

## 13. Connection to This Research

Understanding Dilithium at this depth matters for the PQC-SOC Readiness Scanner in two direct ways.

**Detection side:** The scanner identifies systems using RSA or ECDSA for digital signatures — the quantum-vulnerable schemes that Dilithium replaces. Knowing the exact structure of ML-DSA allows the scanner to generate accurate migration recommendations: not just "switch to a post-quantum signature scheme" but specific guidance on which parameter set applies to a given security requirement, and what the key and signature size implications will be.

**Infrastructure side:** An ML-DSA-87 signature is 4,627 bytes. An ECDSA signature is 64 bytes. This 70x size difference has real consequences for TLS handshake overhead, certificate chains, firmware signing pipelines, and any protocol where signature size is constrained. This is the same deployment challenge discussed at the end of Month 2 — how to integrate these larger, more compute-intensive schemes into environments where every byte and every millisecond matters, from 6G wireless networks to constrained IoT infrastructure.

Together, Kyber (Month 2) and Dilithium (Month 3) form the core of the NIST PQC standardisation response: Kyber for key encapsulation, Dilithium for digital signatures. Month 4 will move from mathematical foundations into the scanner development phase — building the detection logic that operationalises this research.

---

## References

1. Ducas, L. et al. "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme." *IACR Transactions on Cryptographic Hardware and Embedded Systems*, Vol. 2018, No. 1, pp. 238–268.
2. Menezes, A. "Kyber and Dilithium." Lecture series, cryptography101.ca, August 2024.
3. NIST FIPS 204: Module-Lattice-Based Digital Signature Standard. csrc.nist.gov/pubs/fips/204/final
4. pq-crystals.org/dilithium — CRYSTALS-Dilithium Algorithm Specifications and Supporting Documentation (Version 3.1)

---

*Q-Day isn't the beginning of the threat. It's the end of the grace period.*
