"""Throwaway check for the three post-quantum rationale branches. Run from scanner/."""

from pathlib import Path

from cryptography.x509 import load_pem_x509_certificate

from modules.pcap_analyser import ALL_SUPPORTED_GROUPS
from modules.risk_engine import evaluate_risk, post_quantum_rationale
from modules.certificate_analyser import analyse_certificate
from modules.risk_engine import certificate_risk


def show(name, ok, detail):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    return ok


passed = 0
failed = 0


def check(name, ok, detail):
    global passed, failed
    show(name, ok, detail)
    if ok:
        passed += 1
    else:
        failed += 1


# 1. Hybrid, the group already confirmed in the CSV.
hybrid = ALL_SUPPORTED_GROUPS.get(0x11EC)
if hybrid is None:
    check("X25519MLKEM768 loaded", False, "0x11EC is not in supported_groups.csv")
else:
    finding = evaluate_risk(
        hybrid["group_type"],
        hybrid["key_size_bits"],
        usage="key_exchange",
        key_size_source="negotiated_group",
    )
    text = finding.rationale
    check("hybrid label", finding.threat_category == "pq_safe" and finding.score is None,
          f"{finding.threat_category}, score={finding.score}")
    check("hybrid rationale",
          "hybrid key exchange" in text
          and "classical half is still vulnerable" in text
          and "does not say anything about the certificate" in text
          and "not vulnerable to Shor's algorithm" not in text,
          text)

# 2. Pure ML-KEM, whichever CSV row has that group_type.
pure = next((entry for entry in ALL_SUPPORTED_GROUPS.values() if entry["group_type"] == "ML-KEM"), None)
if pure is None:
    print("[SKIP] pure ML-KEM: no group_type ML-KEM in the CSV")
else:
    finding = evaluate_risk(
        pure["group_type"],
        pure["key_size_bits"],
        usage="key_exchange",
        key_size_source="negotiated_group",
    )
    text = finding.rationale
    check("pure ML-KEM label", finding.threat_category == "pq_safe" and finding.score is None,
          f"{pure['name']}: {finding.threat_category}, score={finding.score}")
    check("pure ML-KEM rationale",
          "key exchange is not vulnerable to Shor's algorithm" in text
          and "does not say anything about the certificate" in text
          and "hybrid" not in text
          and "leaf public key" not in text,
          text)

# 3. Certificate, both sides post-quantum. Text only, then the real cert if it is on disk.
text = post_quantum_rationale("ML-DSA (ML-DSA-65)")
check("certificate rationale text",
      "leaf public key and the issuer signature are both post-quantum" in text
      and "does not say anything about the key exchange" in text
      and "hybrid" not in text,
      text)

row4 = Path("testdata/row4/row4_pq_leaf_pq_ca.crt")
if not row4.exists():
    print(f"[SKIP] row 4 certificate: {row4} not found")
else:
    certificate = load_pem_x509_certificate(row4.read_bytes())
    findings = analyse_certificate(certificate)
    risk = certificate_risk(findings)
    check("row 4 label", risk.threat_category == "pq_safe" and risk.score is None,
          f"{risk.threat_category}, score={risk.score}")
    check("row 4 rationale",
          "leaf public key and the issuer signature are both post-quantum" in risk.rationale,
          risk.rationale)

print(f"\n{passed} passed, {failed} failed")