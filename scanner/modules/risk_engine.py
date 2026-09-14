# Risk Engine
# This is where the scanner stops just detecting and starts thinking.
# It takes what the certificate analyser found and answers three questions:
# How bad is it? What should replace it? And why does it matter right now?

import yaml
from pathlib import Path
from typing import Optional
from pydantic import BaseModel

# Build the path to the knowledge folder relative to where this file lives
knowledge_folder = Path(__file__).parent.parent/ "knowledge"

# Load the scoring rubric - weights and max values for the quantum exposure score
with open(knowledge_folder / "quantum_exposure_rubric.yaml") as open_file:
    scoring_guide = yaml.safe_load(open_file)

scoring_weights = scoring_guide["weights"]
max_values = scoring_guide["max_values"]

# Load the NIST migration mappings
with open(knowledge_folder / "nist_mappings.yaml") as open_file:
    nist_mappings = yaml.safe_load(open_file)


# RiskFinding is a Pydantic model, where every field has an enforced type. If the wrong type gets passed in, Pydantic catches it immediately.
# For quantum-vulnerable findings, score is a number in 0-100, severity is one of CRITICAL/HIGH/MEDIUM/LOW, and threat_category names the threat pathway.
# For post-quantum-safe findings, score is None, severity is "INFO", and threat_category is "pq_safe" - the scoring model does not apply because there is no threat to score.
class RiskFinding(BaseModel):
    algorithm: str
    score: Optional[float]
    severity: str
    nist_standard: str
    migration_advice: str
    rationale: str
    key_size_source: str = "certificate" # where the key size came from
    threat_category: str # "confidentiality_harvest" (key exchange risk), "signature_forgery" (certificate forgery risk), or "pq_safe" (already post-quantum, no threat)


# Figures out how urgently the detected algorithm needs to be replaced.
# Returns a number from 0 to 3 - 0 means already safe, 3 means act now.
def get_algorithm_risk_score(algorithm, key_size):

    # Already post-quantum safe, no action needed.
    if any(safe_algorithm in algorithm for safe_algorithm in ["ML-KEM", "ML-DSA", "SLH-DSA"]):
        return 0
    
    # RSA - urgency depends on key size, smaller keys are more at risk
    if "RSA" in algorithm:
        if key_size and key_size < 2048:
            return 3    # Very small key, act immediately
        if key_size and key_size == 2048:
            return 2    # standard RSA, medium urgency
        return 1        #large key, still vulnerable but low urgency
    
    # ECC - same idea,smaller curves are more at risk
    if "ECC" in algorithm:
        if key_size and key_size < 256:
            return 3    # small curve, act immediately
        if key_size and key_size == 256:
            return 2    # standard ECC, medium urgency
        return 1        # larger curve, still vulnerable but low urgency
    
    # EdDSA - structurally an elliptic curve scheme, scored the same way as ECC
    if "EdDSA" in algorithm:
        if key_size and key_size < 256:
            return 3    
        if key_size and key_size == 256:
            return 2    # Ed25519 sits here
        return 1        # Ed448 sits here

    # DSA and DH are both quantum vulnerable, medium urgency
    if "DSA" in algorithm or "DH" in algorithm:
        return 2
    
    # Unknown algorithm - assume medium risk rather than dismissing it
    return 2


# Calculates the full quantum exposure score on a scale of 0 to 100.
# Combines the algorithm risk with three context factors, each rated 1 to 3:
#   data_sensitivity  - how sensitive is the data being protected? (1 = public data, 2 = internal, 3 = highly sensitive)
#   data_lifetime     - how long must this data stay secret? (1 = months, 2 = years, 3 = decades)
#   exposure_surface  - how accessible is this endpoint? (1 = internal only, 2 = partner-facing, 3 = public internet)
# If not specified, all three default to 2 - a fair middle-ground assumption.
def calculate_exposure_score(algorithm, key_size, data_sensitivity=2, data_lifetime=2, exposure_surface=2):
    
    # First get the basic risk score for this algorithm (0 to 3)
    algorithm_risk_score = get_algorithm_risk_score(algorithm, key_size)

    # Apply the weights from the rubric file to each factor
    raw_score = (
        scoring_weights["algorithm_risk"] * algorithm_risk_score
        + scoring_weights["data_sensitivity"] * data_sensitivity
        + scoring_weights["data_lifetime"] * data_lifetime
        + scoring_weights["exposure_surface"] * exposure_surface    
    )

    # Work out the highest possible raw score so we can normalise to 0-100
    max_possible_score = (
        scoring_weights["algorithm_risk"] * max_values["algorithm_risk"]
        + scoring_weights["data_sensitivity"] * max_values["data_sensitivity"]
        + scoring_weights["data_lifetime"] * max_values["data_lifetime"]
        + scoring_weights["exposure_surface"] * max_values["exposure_surface"]    
    )

    # Convert to a 0-100 scale and round to 2 decimal places
    final_score = round((raw_score / max_possible_score) * 100, 2)

    return final_score

# Turns the 0-100 score into a label a SOC analyst can act on immediately.
# Critical = act now, High = plan this quarter, Medium = in the roadmap. Low = keep monitoring.
def get_severity_label(score):

    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"

# Looks up the right NIST recommendation for the detected algorithm.
def get_nist_recommendation(algorithm, usage="signature"):

    # Hybrid PQC check runs before pure PQC because "ECC+ML-KEM" contains "ML-KEM" as a substring - if the pure PQ check ran first, hybrid findings would receive the generic "already post-quantum" text instead of the hybrid-specific ECC_hybrid YAML guidance.
    if "ECC+ML-KEM" in algorithm:
        mapping_key = "ECC_hybrid"
        entry = nist_mappings.get(mapping_key)
        if not entry:
            return "No recommendation available", "No mapping found for this algorithm"
        return entry["standard"], entry["migration"]

    # Pure post-quantum check runs before classical checks because algorithm names like "ML-DSA (ML-DSA-65)" contain the substring "DSA", which would otherwise match the classical DSA branch below and route the finding to the wrong YAML entry.
    if any(safe in algorithm for safe in ["ML-KEM", "ML-DSA", "SLH-DSA"]):
        return "FIPS 203/204/205 - already post-quantum", "This endpoint is already using NIST post-quantum cryptography. No migration action required."

    # Classical algorithm routing
    if "RSA" in algorithm:
        mapping_key = f"RSA_{usage}"
    elif "ECC" in algorithm:
        mapping_key = f"ECC_{usage}"
    elif "EdDSA" in algorithm:
        # Checked before DSA, since "DSA" is a substring of "EdDSA"
        mapping_key = "EdDSA_signature"
    elif "DSA" in algorithm:
        mapping_key = "DSA_signature"
    elif "DH" in algorithm:
        mapping_key = "DH_key_exchange"
    else:
        return "No recommendation available", "Algorithm not recognised - manual review required"
    
    entry = nist_mappings.get(mapping_key)
    if not entry:
        return "No recommendation available", "No mapping found for this algorithm"
    
    return entry["standard"], entry["migration"]


# Ties everything together and returns one complete finding.
# Post-quantum algorithms short-circuit at the top - they carry no HNDL or forgery threat, so the scoring model does not apply and no score, severity band, or threat category is assigned.
def evaluate_risk(algorithm, key_size, data_sensitivity=2, data_lifetime=2, exposure_surface=2, usage="signature", key_size_source="certificate"):

    # PQ-safe short-circuit
    # Any algorithm string containing ML-KEM, ML-DSA, or SLH-DSA is post-quantum safe. This catches pure PQ (ML-KEM, ML-DSA, SLH-DSA) and hybrid constructions such as ECC+ML-KEM, where the ML-KEM component protects the session even if the classical component is quantum-broken.
    if any(pq_algorithm in algorithm for pq_algorithm in ["ML-KEM", "ML-DSA", "SLH-DSA"]):

        # Route to the NIST recommendation - the existing function already distinguishes pure PQ from hybrid via the ECC_hybrid mapping
        nist_standard, migration_advice = get_nist_recommendation(algorithm, usage)

        rationale = (
            f"{algorithm} uses post-quantum cryptography and is not vulnerable to Shor's algorithm. "
            "No quantum key exchange or authentication forgery exposure detected for this endpoint. "
            "The quantum exposure scoring model does not apply to post-quantum findings, as there is no threat to score."
        )

        return RiskFinding(
            algorithm=algorithm,
            score=None,             # scoring model does not apply
            severity="INFO",        # informational, not actionable
            nist_standard=nist_standard,
            migration_advice=migration_advice,
            rationale=rationale,
            key_size_source=key_size_source,
            threat_category="pq_safe"
        )

    # Quantum-vulnerable path - scoring model applies

    # Step 1: Calculate the full quantum exposure score
    score = calculate_exposure_score(algorithm, key_size, data_sensitivity, data_lifetime, exposure_surface)

    # Step 2: Turn the score into a severity label
    severity = get_severity_label(score)

    # Step 3: Find the right NIST recommendation
    nist_standard, migration_advice = get_nist_recommendation(algorithm, usage)

    # Step 4: Build the rationale explaining why this score was given
    if "Unknown" in algorithm:
        rationale = (
            "Algorithm could not be identified, manual review required. "
            "Score is based on a precautionary medium-risk assumption. "
            f"Quantum exposure score: {score}/100 ({severity})."
        )
    else:
        if usage == "key_exchange":
            # Confidentiality risk - session keys captured today are retroactively decryptable once a quantum computer exists
            rationale = (
                f"{algorithm} is vulnerable to Shor's algorithm under the HNDL threat model. "
                "Session keys derived from this key exchange are at risk of retroactive decryption - "
                "traffic captured today can be decrypted once a sufficiently powerful quantum computer exists. "
                f"Quantum exposure score: {score}/100 ({severity})."
            )
        else:
            # Authentication risk - a quantum computer can derive the private signing key from the public key, enabling impersonation of the server for as long as the certificate remains valid
            rationale = (
                f"{algorithm} is vulnerable to Shor's algorithm. "
                "A quantum computer capable of breaking this signature scheme could derive the private signing key from the public key, "
                "and with the private key impersonate this endpoint for as long as the certificate remains valid - this is a forward-looking authentication risk. "
                f"Quantum exposure score: {score}/100 ({severity})."
            )

        # Append a source note for PCAP findings where key size was estimated
        if key_size_source == "modal_baseline":
            rationale += (
                " Key size not available from this capture - score assumes modal "
                "deployment baseline (RSA-2048 / ECC P-256 per Cloudflare Radar 2024)."
            )
        elif key_size_source == "live_fetch":
            rationale += (
                " Key size sourced from a live certificate fetch at time of analysis - "
                "may differ from the key size active during the original capture."
            )
        elif key_size_source == "supported_group":
            rationale += (
                " Key size derived from the classical ECC group offered in the Client Hello."
            )
        elif key_size_source == "negotiated_group":
            rationale += (
                " Key size read directly from the group the server selected in the KeyShare extension."
            )
        

    # Step 5: Package everything into a structured RiskFinding and return it.
    return RiskFinding(
        algorithm=algorithm,
        score=score,
        severity=severity,
        nist_standard=nist_standard,
        migration_advice=migration_advice,
        rationale=rationale,
        key_size_source=key_size_source,
        threat_category="confidentiality_harvest" if usage == "key_exchange" else "signature_forgery"
    )
