from typing import Dict, Any, List

def calculate_confidence_score(resolved_ips: int, successful_scans: int, has_aaaa: bool) -> int:
    if resolved_ips == 0:
        return 0
    score = int((successful_scans / resolved_ips) * 100)
    if not has_aaaa:
        score = max(0, score - 10)
    return score

def assess_hndl_risk(key_type: str, key_size_bits: int, key_exchange: str, cert_days_remaining: int) -> bool:
    """
    Harvest Now, Decrypt Later (HNDL) risk is true if classical crypto is used
    AND (forward secrecy is missing OR the certificate lives for over a year OR key size is weak).
    """
    is_classical = key_type in ["RSA", "ECDSA", "DSA"]
    # If using static RSA key exchange, there is no forward secrecy
    no_pfs = "RSA (Static)" in key_exchange or "RSA" == key_exchange
    long_term = cert_days_remaining > 365
    
    weak_key = (key_type == "RSA" and key_size_bits <= 2048) or (key_type == "ECDSA" and key_size_bits <= 256)
    
    if is_classical and (no_pfs or long_term or weak_key):
        return True
    return False

def determine_crypto_mode(key_type: str, key_exchange: str) -> str:
    """Classify the overall cryptographic mode based on both KEM and signatures."""
    pqc_indicators = ["Kyber", "Dilithium", "Falcon", "SPHINCS+", "X25519Kyber768", "ML-KEM", "ML-DSA"]
    classical_sig_indicators = ["RSA", "ECDSA", "DSA"]
    classical_kem_indicators = ["RSA", "DHE", "ECDHE", "X25519"]
    
    kem_is_pqc = any(p in key_exchange for p in pqc_indicators)
    # Be careful: X25519Kyber768 has both X25519 and Kyber, so it is hybrid in itself.
    kem_is_classical = any(c in key_exchange for c in classical_kem_indicators)
    
    sig_is_pqc = any(p in key_type for p in pqc_indicators)
    sig_is_classical = key_type in classical_sig_indicators
    
    has_any_pqc = kem_is_pqc or sig_is_pqc
    has_any_classical = kem_is_classical or sig_is_classical
    if not has_any_pqc and not has_any_classical:
        # Fallback if unknown
        has_any_classical = True
    
    if has_any_pqc and has_any_classical:
        return "HYBRID"
    elif has_any_pqc and not has_any_classical:
        return "PQC_READY"
    return "CLASSICAL"

def estimate_quantum_horizon(key_type: str, key_size_bits: int) -> str:
    """Estimate the year this cryptography becomes vulnerable to CRQCs."""
    if key_type == "RSA":
        if key_size_bits <= 1024:
            return "2028"
        elif key_size_bits <= 2048:
            return "2030"
        elif key_size_bits <= 3072:
            return "2035"
        return "2035"
    elif key_type == "ECDSA":
        if key_size_bits <= 256:
            return "2035"
        return "2040"
    elif key_type == "EdDSA":
        return "2040"
    
    # Post-quantum assumptions
    return "2045+"

from typing import Tuple

def calculate_agility_score(tls_version: str, key_exchange: str, chain_status: str, key_type: str, key_size: int, cipher_suite: str) -> Tuple[int, List[str]]:
    """Calculate an agility score (0-100) based on modernization."""
    score = 30 # Base score for an average setup without particular extremes
    factors = []
    
    if tls_version == "TLS 1.3":
        score += 25
        factors.append("TLS 1.3 enabled (+25)")
    elif tls_version in ["TLS 1.0", "TLS 1.1"]:
        score -= 20
        factors.append(f"Deprecated TLS '{tls_version}' (-20)")
        
    if "ECDHE" in key_exchange or "DHE" in key_exchange or "X25519" in key_exchange:
        score += 20
        factors.append("Forward secrecy enabled (+20)")
    elif "RSA (Static)" in key_exchange or key_exchange == "RSA":
        score -= 20
        factors.append("Weak / static key exchange (-20)")
        
    if "GCM" in cipher_suite or "CHACHA20" in cipher_suite:
        score += 20
        factors.append("Modern cipher suites (+20)")
        
    pqc_indicators = ["Kyber", "Dilithium", "Falcon", "SPHINCS+", "X25519Kyber768", "ML-KEM", "ML-DSA"]
    if any(p in key_exchange or p in key_type for p in pqc_indicators):
        score += 20
        factors.append("Modular / Hybrid crypto present (+20)")
        
    if (key_type == "RSA" and key_size <= 2048) or (key_type == "ECDSA" and key_size <= 256):
        score -= 15
        factors.append("Legacy certs / weak key sizes (-15)")
        
    return max(0, min(100, score)), factors

def calculate_pqc_score(crypto_mode: str, agility_score: int) -> int:
    """Calculate the overall quantum readiness score."""
    if crypto_mode == "PQC_READY":
        return min(100, 80 + (agility_score // 5))
    elif crypto_mode == "HYBRID":
        return min(100, 60 + (agility_score // 3))
    
    # Classical mode is scored entirely by its agility (migration readiness)
    return max(0, agility_score - 20)

def generate_risk_profile(tls_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate per-IP TLS results into a unified risk profile."""
    
    if not tls_results:
         return {
            "pqc_score": 0,
            "crypto_mode": "UNKNOWN",
            "quantum_risk_horizon": "N/A",
            "crypto_agility_score": 0,
            "risk_level": "CRITICAL",
            "hndl_risk": True
         }
         
    # Take the worst-case scenario across all IPs for security profiling
    worst_tls_version = "Unknown"
    worst_key_type = "Unknown"
    worst_key_size = 99999
    worst_key_exchange = "Unknown"
    worst_chain = "VALID"
    worst_cert_days = 999
    worst_cipher_suite = "Unknown"
    
    for res in tls_results:
        tls = res.get("tls", {})
        cert = res.get("certificate", {})
        
        tv = tls.get("version", "Unknown")
        if tv != "Unknown":
            if worst_tls_version == "Unknown" or tv < worst_tls_version:
                 worst_tls_version = tv
                 
        v = tls.get("key_size_bits", 99999)
        if v < worst_key_size:
            worst_key_size = v
            worst_key_type = tls.get("public_key_type", "Unknown")
            
        ke = tls.get("key_exchange", "")
        if "Static" in ke or worst_key_exchange == "Unknown":
             worst_key_exchange = ke
             
        if cert.get("chain_status") == "WEAK" and worst_chain != "UNTRUSTED":
             worst_chain = "WEAK"
        elif cert.get("chain_status") == "UNTRUSTED":
             worst_chain = "UNTRUSTED"
             
        cdays = cert.get("days_remaining", 999)
        if cdays < worst_cert_days:
            worst_cert_days = cdays
            
        csuite = tls.get("cipher_suite", "Unknown")
        if csuite != "Unknown" and worst_cipher_suite == "Unknown":
             worst_cipher_suite = csuite
        elif ("GCM" not in csuite and "CHACHA20" not in csuite):
             worst_cipher_suite = csuite

    crypto_mode = determine_crypto_mode(worst_key_type, worst_key_exchange)
    hndl_risk = assess_hndl_risk(worst_key_type, worst_key_size, worst_key_exchange, worst_cert_days)
    risk_horizon = estimate_quantum_horizon(worst_key_type, worst_key_size)
    agility, agility_factors = calculate_agility_score(worst_tls_version, worst_key_exchange, worst_chain, worst_key_type, worst_key_size, worst_cipher_suite)
    pqc_score = calculate_pqc_score(crypto_mode, agility)
    
    risk_level = "LOW"
    if pqc_score < 40 or hndl_risk:
        risk_level = "CRITICAL"
    elif pqc_score < 60:
        risk_level = "HIGH"
    elif pqc_score < 80:
        risk_level = "MEDIUM"

    return {
        "pqc_score": pqc_score,
        "crypto_mode": crypto_mode,
        "quantum_risk_horizon": risk_horizon,
        "crypto_agility_score": agility,
        "agility_factors": agility_factors,
        "risk_level": risk_level,
        "hndl_risk": hndl_risk
    }
