# Research Notes - PQC SOC Readiness Project

---

## Month 1 - Post-Quantum Cryptography & The Harvest Now, Decrypt Later Threat

### 1. The Foundation We're All Trusting Right Now
Today's digital communication relies heavily on RSA - an asymmetric 
encryption algorithm that generates keys using the product of two 
astronomically large prime numbers. Factoring those numbers back apart 
is computationally infeasible for classical computers. We're talking 
millions of years. That's the entire premise of modern encryption security.

### 2. But a New Class of Computer is Coming
Quantum computers don't process information the way classical computers do. 
Instead of binary bits (0 or 1), they use qubits - which exploit quantum 
superposition to exist as 0 and 1 simultaneously. This allows quantum 
computers to explore vast solution spaces in parallel, solving certain 
mathematical problems exponentially faster than anything we have today.

### 3. The threat most organisations aren't acting on fast enough
Using Shor's Algorithm (or emerging approaches like adiabatic quantum 
computation), a sufficiently powerful quantum computer could break RSA 
encryption in hours. What takes classical computers millions of years 
becomes trivial. And threat actors already know this.

### 4. Harvest Now, Decrypt Later - The Silent Attack Already in Motion
The attack doesn't wait for quantum computers to exist. It happens 
right now - silently.

The lifecycle:

- **Step 1 - EXFILTRATION:** Threat actors intercept and steal encrypted 
  data in transit today. No alarms. No detection. Silent collection.

- **Step 2 - COLD STORAGE:** Stolen encrypted data sits preserved in 
  storage - unusable for now. Nation-state actors have the patience 
  and infrastructure for this.

- **Step 3 - Q-DAY ARRIVES:** A quantum computer powerful enough to run 
  Shor's Algorithm becomes available.

- **Step 4 - DECRYPTION:** Years of harvested data - financial records, 
  government communications, healthcare data, defence intelligence - 
  decrypted and read in plaintext.

- **Step 5 - EXPLOITATION:** Data sold, identities forged, state secrets 
  exposed. Irreversible damage.

The most alarming part? The attack is likely already happening. 
Data being stolen today may not be exploited for 10 years - but it will be.

### 5. NIST Has Responded - But Most Organisations Haven't
In 2024, NIST finalised the first official Post-Quantum Cryptography standards:

- **FIPS 203** (CRYSTALS-Kyber) - quantum-safe encryption & key exchange
- **FIPS 204** (CRYSTALS-Dilithium) - quantum-safe digital signatures
- **FIPS 205** (SPHINCS+) - digital signatures, hash-based backup

NIST isn't just advising migration. It's directing all critical 
infrastructure to begin transitioning now.

### 6. What Should Organisations Actually Do?
Waiting for Q-Day is not a strategy. Once data is harvested, 
it cannot be unharvested.

Practical quantum readiness roadmap:

1. Inventory cryptographic assets - identify every system using RSA, ECC, DH
2. Prioritise long-life and sensitive data
3. Re-encrypt or segment using post-quantum or hybrid algorithms
4. Adopt crypto-agility - build systems that can swap algorithms 
   without full rebuilds
5. Shorten data retention
6. Engage vendors and regulators - your supply chain's cryptographic 
   posture is your risk too

---

*Q-Day isn't the beginning of the threat. 
It's the end of the grace period.*
