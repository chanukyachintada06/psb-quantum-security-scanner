"""
Quantum Validation Engine — PQC Algorithm Classifier
Team CypherRed261 — PSB Hackathon 2026

Classifies TLS configurations against NIST PQC standards:
  - FIPS 203 (ML-KEM / CRYSTALS-Kyber)
  - FIPS 204 (ML-DSA / CRYSTALS-Dilithium)
  - FIPS 205 (SLH-DSA / SPHINCS+)
"""

from models import PQCAssessment


# Algorithms broken by Shor's algorithm on a cryptographically relevant quantum computer
QUANTUM_VULNERABLE_KEY_TYPES = {
    "RSA", "ECDSA", "ECDHE", "DH", "DSA", "EC"
}

# Algorithms safe against known quantum attacks
QUANTUM_SAFE_KEY_TYPES = {
    "Kyber", "Dilithium", "SPHINCS", "FALCON",
    "ML-KEM", "ML-DSA", "SLH-DSA", "CRYSTALS-Kyber", "CRYSTALS-Dilithium"
}

# Weak cipher patterns
WEAK_CIPHERS = ["DES", "3DES", "RC4", "NULL", "EXPORT", "ANON"]
WEAK_CBC = ["CBC"]
STRONG_CIPHERS = ["GCM", "CHACHA20", "CCM"]


def classify_tls_scan(
    tls_version: str,
    cipher_suite: str,
    key_type: str,
    key_size_bits: int
) -> PQCAssessment:
    """
    Classify a TLS configuration and return a PQC risk assessment.

    Args:
        tls_version:   TLS protocol version string e.g. "TLS 1.3"
        cipher_suite:  Cipher suite name e.g. "TLS_AES_256_GCM_SHA384"
        key_type:      Public key algorithm e.g. "RSA", "ECDSA"
        key_size_bits: Key size in bits e.g. 2048

    Returns:
        PQCAssessment with risk level, score, vulnerabilities and recommendations
    """
    vulnerabilities = []
    risk_score = 0

    # ── TLS VERSION SCORING ──────────────────────────────────
    tls_upper = tls_version.upper()

    if "SSL" in tls_upper or "2.0" in tls_version or "3.0" in tls_version:
        risk_score += 45
        vulnerabilities.append(
            "SSL 2.0/3.0 detected — protocol is completely broken and must be disabled immediately"
        )
    elif "1.0" in tls_version:
        risk_score += 35
        vulnerabilities.append(
            "TLS 1.0 detected — critically vulnerable to POODLE and BEAST attacks"
        )
    elif "1.1" in tls_version:
        risk_score += 20
        vulnerabilities.append(
            "TLS 1.1 detected — deprecated by RFC 8996, lacks modern security features"
        )
    elif "1.2" in tls_version:
        risk_score += 8
        vulnerabilities.append(
            "TLS 1.2 — acceptable but lacks quantum-safe key exchange by default"
        )
    # TLS 1.3 = 0 base risk (best available)

    # ── KEY TYPE SCORING ─────────────────────────────────────
    key_upper = key_type.upper()

    if "RSA" in key_upper:
        risk_score += 28
        vulnerabilities.append(
            "RSA public key infrastructure vulnerable to Shor's algorithm — "
            "a sufficiently large quantum computer breaks RSA factoring in polynomial time"
        )
    elif any(ec in key_upper for ec in ["ECDSA", "ECDHE", "EC", "P-256", "P-384"]):
        risk_score += 18
        vulnerabilities.append(
            "Elliptic Curve cryptography (ECDSA/ECDHE) vulnerable to quantum attacks — "
            "Shor's algorithm solves the discrete logarithm problem on elliptic curves"
        )
    elif any(pqc in key_type for pqc in QUANTUM_SAFE_KEY_TYPES):
        # PQC algorithm detected — this is good!
        risk_score = max(0, risk_score - 10)

    # ── KEY SIZE SCORING (RSA specific) ─────────────────────
    if "RSA" in key_upper and key_size_bits > 0:
        if key_size_bits < 1024:
            risk_score += 35
            vulnerabilities.append(
                f"Critically weak RSA key: {key_size_bits}-bit — "
                f"breakable by classical computers today"
            )
        elif key_size_bits < 2048:
            risk_score += 20
            vulnerabilities.append(
                f"Weak RSA key size: {key_size_bits}-bit — "
                f"below NIST minimum of 2048-bit"
            )
        elif key_size_bits == 2048:
            risk_score += 5
            vulnerabilities.append(
                "RSA-2048 meets classical minimums but remains quantum-vulnerable"
            )
        # RSA 4096+ = no additional penalty

    # ── CIPHER SUITE SCORING ────────────────────────────────
    cipher_upper = cipher_suite.upper()

    if any(w in cipher_upper for w in ["DES", "3DES", "RC4", "NULL", "EXPORT"]):
        risk_score += 30
        vulnerabilities.append(
            f"Critically weak cipher detected in suite '{cipher_suite}' — "
            f"DES/3DES/RC4/NULL are broken by classical cryptanalysis"
        )
    elif "CBC" in cipher_upper and "RSA" in cipher_upper:
        risk_score += 12
        vulnerabilities.append(
            "CBC mode with RSA key exchange — vulnerable to BEAST and padding oracle attacks"
        )
    elif "CBC" in cipher_upper:
        risk_score += 5
        vulnerabilities.append(
            "CBC mode cipher — consider upgrading to AEAD cipher (GCM/ChaCha20)"
        )
    elif any(s in cipher_upper for s in ["GCM", "CHACHA20", "CCM"]):
        pass  # AEAD ciphers — no penalty

    # ── FINAL SCORING ────────────────────────────────────────
    risk_score = min(risk_score, 100)
    risk_score = max(risk_score, 0)

    # Determine risk level
    if risk_score >= 70:
        risk_level = "CRITICAL"
    elif risk_score >= 40:
        risk_level = "HIGH"
    elif risk_score >= 15:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # PQC readiness is inverse of risk
    pqc_readiness = max(0, 100 - risk_score)

    # Build recommendations
    recommendations = build_recommendations(
        tls_version, key_type, key_size_bits, cipher_suite, risk_level
    )

    return PQCAssessment(
        risk_level=risk_level,
        risk_score=risk_score,
        pqc_readiness=pqc_readiness,
        quantum_vulnerable=(risk_score > 15),
        vulnerabilities=vulnerabilities,
        recommendations=recommendations
    )


def build_recommendations(
    tls_version: str,
    key_type: str,
    key_size_bits: int,
    cipher_suite: str,
    risk_level: str
) -> list:
    """
    Build a prioritised list of PQC migration recommendations
    based on the scanned TLS configuration.
    """
    recs = []
    cipher_upper = cipher_suite.upper()
    key_upper = key_type.upper()

    # Critical TLS version issues
    if any(v in tls_version for v in ["SSL", "1.0", "1.1"]):
        recs.append({
            "priority": "high",
            "text": (
                "<strong>Critical:</strong> Immediately disable SSL/TLS 1.0/1.1. "
                "Enforce TLS 1.3 minimum per RBI Cybersecurity Framework Section 4.2."
            )
        })

    # RSA key exchange
    if "RSA" in key_upper:
        recs.append({
            "priority": "high",
            "text": (
                "<strong>Deploy Kyber-768</strong> (CRYSTALS-Kyber, NIST FIPS 203) "
                "as post-quantum KEM. RSA is broken by Shor's algorithm on "
                "cryptographically relevant quantum computers."
            )
        })

    # EC signature replacement
    if any(ec in key_upper for ec in ["RSA", "ECDSA", "EC"]):
        recs.append({
            "priority": "high",
            "text": (
                "<strong>Replace digital signatures</strong> with ML-DSA "
                "(CRYSTALS-Dilithium, FIPS 204) or SLH-DSA (SPHINCS+, FIPS 205) "
                "for long-term quantum resistance."
            )
        })

    # Weak RSA key size
    if "RSA" in key_upper and key_size_bits > 0 and key_size_bits < 2048:
        recs.append({
            "priority": "high",
            "text": (
                f"<strong>Immediately rotate</strong> {key_size_bits}-bit RSA key. "
                f"Use minimum RSA-4096 as interim measure before full PQC migration."
            )
        })

    # Weak cipher
    if any(w in cipher_upper for w in ["DES", "3DES", "RC4"]):
        recs.append({
            "priority": "high",
            "text": (
                "<strong>Disable weak cipher suites</strong> immediately. "
                "Configure cipher priority: TLS_AES_256_GCM_SHA384, "
                "TLS_CHACHA20_POLY1305_SHA256 for TLS 1.3."
            )
        })

    # Certificate inventory
    if risk_level in ["HIGH", "CRITICAL"]:
        recs.append({
            "priority": "medium",
            "text": (
                "<strong>Inventory all certificates</strong> with RSA/ECDSA keys. "
                "Begin phased re-issuance with hybrid PQC+classical certificates "
                "per CERT-IN Annexure-A guidelines."
            )
        })

    # TLS 1.2 upgrade suggestion
    if "1.2" in tls_version:
        recs.append({
            "priority": "medium",
            "text": (
                "<strong>Upgrade to TLS 1.3</strong> to enable forward secrecy "
                "by default and reduce attack surface. "
                "Disable TLS 1.2 after migration validation."
            )
        })

    # Hybrid PQC deployment
    if risk_level in ["MEDIUM", "HIGH"]:
        recs.append({
            "priority": "medium",
            "text": (
                "<strong>Test hybrid PQC deployment:</strong> X25519+Kyber768 "
                "key exchange per IETF draft-ietf-tls-hybrid-design. "
                "Validates interoperability before full PQC cutover."
            )
        })

    # General crypto-agility
    recs.append({
        "priority": "low",
        "text": (
            "<strong>Adopt a crypto-agility framework</strong> to enable rapid "
            "algorithm rotation without full re-deployment cycles. "
            "Track NIST PQC final standards (FIPS 203, 204, 205)."
        )
    })

    # Well configured
    if not recs or risk_level == "LOW":
        recs = [{
            "priority": "low",
            "text": (
                "<strong>Well configured:</strong> Hybrid Kyber+X25519 key exchange "
                "is the next upgrade target. Monitor NIST PQC finalization "
                "and CERT-IN advisories to stay current."
            )
        }] + recs

    return recs
