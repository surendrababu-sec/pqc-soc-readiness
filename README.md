# PQC-SOC Readiness Scanner

> **Q-Day isn't the beginning of the threat. It's the end of the grace period.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Status: In Development](https://img.shields.io/badge/status-in%20development-orange.svg)](https://github.com/surendrababu-sec/pqc-soc-readiness)
[![NIST PQC](https://img.shields.io/badge/NIST-FIPS%20203%2F204%2F205-darkgreen.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Threat Model: HNDL](https://img.shields.io/badge/threat%20model-HNDL-red.svg)](https://github.com/surendrababu-sec/pqc-soc-readiness)

An independent research project and open-source Python tool auditing organisations' public-facing TLS endpoints for quantum-vulnerable cryptography under the **Harvest-Now, Decrypt-Later (HNDL)** threat model.

---

## Table of Contents

- [The Problem](#the-problem)
- [What This Project Is](#what-this-project-is)
- [Threat Model: HNDL](#threat-model-hndl)
- [Planned Architecture](#planned-architecture)
- [Current State](#current-state)
- [Research Foundation](#research-foundation)
- [Repository Structure](#repository-structure)
- [Usage](#usage)
- [Roadmap](#roadmap)
- [Manuscript](#manuscript)
- [How to Cite](#how-to-cite)
- [License](#license)
- [Author](#author)

---

## The Problem

Most organisations assume their encryption is secure. It isn't - not against what's coming.

The cryptography protecting healthcare records, financial transactions, government communications, and critical infrastructure today relies on mathematical problems - integer factorisation (RSA) and the discrete logarithm (ECC), that a sufficiently powerful quantum computer will solve using Shor's algorithm.

Nation-state adversaries are already harvesting encrypted traffic today, archiving it for the day quantum capability arrives. For data with long-term sensitivity, the compromise is **already happening**, silently - even though the decryption hasn't yet.

NIST finalised the post-quantum replacements in 2024 (FIPS 203, 204, 205). Migration must begin now. But organisations cannot migrate what they cannot see. Most have no inventory of where their quantum-vulnerable cryptography lives.

**This project is the diagnostic instrument for that migration.**

---

## What This Project Is

A research project and open-source tool with two inseparable components:

1. **Independent research** into the mathematical foundations of post-quantum cryptography - establishing the technical depth required to reason about cryptographic security in deployed systems.
2. **The PQC-SOC Readiness Scanner** - a Python tool, in active development, designed to identify quantum-vulnerable cryptography in real systems and recommend NIST-aligned migration paths.

The research drives the tool. The tool keeps the research grounded.

---

## Threat Model: HNDL

**Harvest-Now, Decrypt-Later** is the operative threat model.

| Property | Implication |
|----------|-------------|
| Attack happens **today** | Encrypted traffic intercepted and archived now |
| Decryption happens **later** | Adversary waits for sufficient quantum capability |
| Affects **long-lived data** | Patient records, financial transactions, IP, classified material |
| Mitigation requires **migration**, not just monitoring | Defenders cannot retroactively unencrypt what's already harvested |

HNDL inverts the usual security calculus: the longer the data's sensitivity lifetime, the more urgent the migration - even if Q-Day itself is years away.

---

## Planned Architecture

The scanner is designed in four layers:

```
┌──────────────────────────────────────────────────────────┐
│  INGESTION                                               │
│  TLS endpoints · PCAP captures · Configs · Cert stores   │
└────────────────────────┬─────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────┐
│  CRYPTOGRAPHIC ANALYSIS                                  │
│  Identifies algorithm family, parameters, usage context  │
└────────────────────────┬─────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────┐
│  RISK ENGINE                                             │
│  HNDL exposure scoring · NIST mapping · Migration advice │
└────────────────────────┬─────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────┐
│  REPORTING                                               │
│  JSON · CLI · SIEM-ready formats                         │
└──────────────────────────────────────────────────────────┘
```

**Detection targets:** RSA, ECC, DH, DSA, and identification of any already-deployed PQC (ML-KEM, ML-DSA, SLH-DSA).

**Recommendation targets:** FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), with hybrid mode guidance per NIST SP 800-208 during the transition period.

---

## Current State

Honesty matters more than ambition. Here is exactly where this project stands today:

| Component | State |
|-----------|-------|
| HNDL threat model & rationale | ✅ Established |
| Mathematical foundations (CRYSTALS-Kyber) | ✅ Documented in research notes |
| Mathematical foundations (CRYSTALS-Dilithium) | ✅ Documented in research notes |
| NIST FIPS 203/204/205 study | ✅ Documented |
| Scanner architecture & design | ✅ Defined |
| TLS certificate detection (RSA, ECC, DSA, DH) | ✅ Built and working |
| Multiple target scanning from file | ✅ Built and working |
| HNDL exposure scoring engine | ✅ Built - weighted 0–100 scoring with configurable rubric |
| NIST migration recommendation engine | ✅ Built - FIPS 203/204/205 mapped recommendations |
| Configurable sensitivity/lifetime/exposure flags | ✅ Built and working |
| JSON output for SIEM integration | ✅ Built - SIEM-ready JSON with full metadata |
| PCAP-based network capture analysis | 🟡 In progress |
| Manuscript for arXiv | 🟡 In preparation |

✅ = complete · 🟡 = in progress · ⏳ = planned

---

## Research Foundation

The scanner is built on a structured study of the mathematical foundations of post-quantum cryptography. Topics covered to date:

**Lattice-based cryptography**
- Polynomial rings of the form Rq = Zq[x]/(x^n + 1)
- Module Learning With Errors (MLWE) and the decisional variant (D-MLWE)
- Why no known quantum algorithm efficiently solves these problems

**CRYSTALS-Kyber (ML-KEM, FIPS 203)**
- Full key generation, encapsulation, and decapsulation construction
- IND-CPA → IND-CCA2 via the Fujisaki-Okamoto transform
- Parameter sets (ML-KEM-512/768/1024) and their overhead implications

**CRYSTALS-Dilithium (ML-DSA, FIPS 204)**
- Schnorr signature scheme foundations and lattice adaptation
- Rejection sampling, HighBits/LowBits decomposition, hint bits
- Full ML-DSA scheme construction: key generation, signing, verification, and correctness argument
- Parameter sets (ML-DSA-44/65/87) and key/signature size implications

**Classical cryptographic failure**
- Mathematical basis for RSA and ECC vulnerability under Shor's algorithm
- Quantum complexity of factoring and the discrete logarithm

**NIST PQC standardisation**
- FIPS 203 (ML-KEM, key encapsulation)
- FIPS 204 (ML-DSA, digital signatures)
- FIPS 205 (SLH-DSA, hash-based signatures)
- FIPS 203/204/205 parameter sets and hybrid deployment considerations during transition

Full structured notes:
- [`MONTH-1-NOTES.md`](MONTH-1-NOTES.md) - HNDL threat landscape, RSA/ECC quantum failure, NIST standardisation
- [`MONTH-2-NOTES.md`](MONTH-2-NOTES.md) - CRYSTALS-Kyber mathematical structure, ML-KEM construction
- [`MONTH-3-NOTES.md`](MONTH-3-NOTES.md) - CRYSTALS-Dilithium mathematical structure, ML-DSA construction (NTT section pending)
- [`RESEARCH-NOTES.md`](RESEARCH-NOTES.md) - Index across all research

---

## Repository Structure

```
pqc-soc-readiness/
├── scanner/                          # Python tool - in active development
│   ├── modules/
│   │   ├── certificate_analyser.py   # TLS certificate detection engine
│   │   └── risk_engine.py            # HNDL scoring and NIST recommendations
│   ├── knowledge/
│   │   ├── hndl_rubric.yaml          # Scoring weights and rubric
│   │   └── nist_mappings.yaml        # NIST PQC migration mappings
│   ├── output/                       # Scan results (auto-created, gitignored)
│   ├── targets.txt                   # Example target domains - edit with your own
│   └── main.py                       # Entry point and CLI interface
├── MONTH-1-NOTES.md                  # Phase 1: threat landscape & foundations
├── MONTH-2-NOTES.md                  # Phase 2: CRYSTALS-Kyber mathematics
├── MONTH-3-NOTES.md                  # Phase 3: CRYSTALS-Dilithium mathematics
├── RESEARCH-NOTES.md                 # Index of monthly notes
├── requirements.txt                  # Python dependencies
├── LICENSE                           # MIT
└── README.md                         # This file
```

---

## Usage

### Installation

```bash
git clone https://github.com/surendrababu-sec/pqc-soc-readiness.git
cd pqc-soc-readiness
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
pip install -r requirements.txt
```

### Keeping up to date

```bash
git pull
pip install -r requirements.txt
```

### Scan a single target

```bash
python scanner/main.py google.com
```

### Scan on a non-standard port

```bash
python scanner/main.py example.com --port 8443
```

### Scan multiple targets from a file

```bash
python scanner/main.py --targets scanner/targets.txt
```

> `targets.txt` contains example domains. Edit it with your own targets - one domain per line.

### Save results as a JSON report

```bash
python scanner/main.py google.com --output report.json
```

> Report saves automatically to `scanner/output/report.json`

### Show all available options

```bash
python scanner/main.py --help
```

---

## Roadmap

This project is structured as a 10-month independent research programme. Current phase: **Month 5 - Reporting & Network Analysis (Phase 3)**.

**Phase 1 - Foundation (Months 1-3)** ✅ *Complete*
- Mathematical foundations of PQC schemes
- HNDL threat model formalisation
- Scanner architecture and design

**Phase 2 - Detection & Risk Engine (Months 4-6)** ✅ *Complete*
- TLS endpoint probing & certificate analysis ✅
- Multiple target scanning from file ✅
- HNDL exposure scoring engine ✅
- NIST migration recommendation engine ✅
- Initial CLI interface ✅
- Configurable sensitivity/lifetime/exposure flags ✅
- JSON output for SIEM integration ✅

**Phase 3 - Reporting & Network Analysis (Months 6-8)** 🟡 *In progress*
- PCAP-based network capture analysis
- SIEM-ready CEF output format
- JSON report enhancements (failed scan details, priority ordering, timing)
- Documentation pass

**Phase 4 - Manuscript & Release (Months 8-10)** ⏳ *Planned*
- arXiv preprint preparation
- v0.1 release of the scanner
- Final documentation and community release

---

## Manuscript

> **PQC-SOC Readiness: Auditing Organisations' Public-Facing TLS Endpoints for Quantum-Vulnerable Cryptography Under the HNDL Threat Model**
>
> Surendra Babu Chilakaluru
>
> *Manuscript in preparation. Target: arXiv cs.CR, 2026.*

---

## How to Cite

Until the manuscript is published, you may cite this repository:

```bibtex
@misc{surendrababu_pqc_soc_2026,
  author       = {Chilakaluru, Surendra Babu},
  title        = {PQC-SOC Readiness Scanner: Auditing Organisations' Public-Facing TLS Endpoints for Quantum-Vulnerable                       Cryptography Under the HNDL Threat Model},
  year         = {2026},
  howpublished = {\url{https://github.com/surendrababu-sec/pqc-soc-readiness}},
  note         = {Open-source research project, in development}
}
```

---

## License

This project is released under the [MIT License](LICENSE).

---

## Author

**Surendra Babu Chilakaluru**

MSc Information Security & Digital Forensics - Distinction, University of East London. Independent researcher in post-quantum cryptography and security operations. Based in London, UK.

Connect: [LinkedIn](https://www.linkedin.com/in/surendra-babu-chilakaluru-4233a01b8/) · [GitHub](https://github.com/surendrababu-sec)

---

*This is independent research, conducted outside any academic programme, funded by the author's own time, and documented publicly with a full timestamped commit history.*
