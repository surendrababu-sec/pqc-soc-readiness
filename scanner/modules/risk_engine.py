# Risk Engine
# This is where the scanner stops just detecting and starts thinking.
# It takes what the certificate analyser found and answers three questions:
# How bad is it? What should replace it? And why does it matter right now?

import yaml
from pathlib import Path
from pydantic import BaseModel

# Build the path to the knowledge folder relative to where this file lives
knowledge_folder = Path(__file__).parent.parent/ "knowledge"

# Load the scoring rubric - weights and max values for the HNDL score
with open(knowledge_folder / "hndl_rubric.yaml") as open_file:
    scoring_guide = yaml.safe_load(open_file)

scoring_weights = scoring_guide["weights"]
max_values = scoring_guide["max_values"]

# Load the NIST migration mappings
with open(knowledge_folder / "nist_mappings.yaml") as open_file:
    nist_mappings = yaml.safe_load(open_file)


# RiskFinding is a Pydantic model
# where every field has an enforced type. If the wrong type gets passed in, Pydantic catches it immediately.
class RiskFinding(BaseModel):
    algorithm: str
    score: float
    severity: str
    nist_standard: str
    migration_advice: str
    rationale: str


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
            return 3    # small curver, act immediately
        if key_size and key_size == 256:
            return 2    # standard ECC, medium urgency
        return 1        # larger curve, still vulnerable but low urgency
    
    # DSA and DH are both quantum vulnerable, medium urgency
    if "DSA" in algorithm or "DH" in algorithm:
        return 2
    
    # Unknown algorithm - assume medium risk rather than dismissing it
    return 2


# Calculates the full HNDL exposure score on a scale of 0 to 100.
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

    # Covert to a 0-100 scale and round to 2 decimal places
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
    
    if "RSA" in algorithm:
        mapping_key = f"RSA_{usage}"
    elif "ECC" in algorithm:
        mapping_key = f"ECC_{usage}"
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
def evaluate_risk(algorithm, key_size, data_sensitivity=2, data_lifetime=2, exposure_surface=2, usage="signature"):

    # Step 1: Calculate the full HNDL exposure score
    score = calculate_exposure_score(algorithm, key_size, data_sensitivity, data_lifetime, exposure_surface)

    # Step 2: Turn the score into a severity label
    severity = get_severity_label(score)

    # Step 3: Find the right NIST recommendation
    nist_standard, migration_advice = get_nist_recommendation(algorithm, usage)

    # Step 4: Build the rationale explaining why this score was given
    if "Unknown" in algorithm:
        rationale = (
            f"Algorithm could not be identified, manual review required. "
            f"Score is based on a precautionary medium-risk assumption. "
            f"HNDL exposure score: {score}/100 ({severity})."
        )
    else:
        rationale = (
            f"{algorithm} is vulnerable to Shor's algorithm under the HNDL threat model. "
            f"Data harvested today can be decrypted when quantum computers arrive. "
            f"HNDL exposure score: {score}/100 ({severity})."
     )

    # Step 5: Pakage everything into a structured RiskFinding and return it.
    return RiskFinding(
        algorithm=algorithm,
        score=score,
        severity=severity,
        nist_standard=nist_standard,
        migration_advice=migration_advice,
        rationale=rationale
    )
