from typing import Dict, Any, List

def calculate_confidence_score(resolved_ips: int, successful_scans: int, has_aaaa: bool) -> int:
    if resolved_ips == 0:
        return 0
    score = int((successful_scans / resolved_ips) * 100)
    if not has_aaaa:
        score = max(0, score - 10)
    return score

def assess_hndl_risk(key_type: str, key_exchange: str, cert_days_remaining: int) -> bool:
    """
    Harvest Now, Decrypt Later (HNDL) risk is true if classical crypto is used
    AND (forward secrecy is missing OR the certificate lives for over a year).
    """
    is_classical = key_type in ["RSA", "ECDSA", "DSA"]
    # If using static RSA key exchange, there is no forward secrecy
    no_pfs = "RSA (Static)" in key_exchange
    long_term = cert_days_remaining > 365
    
    if is_classical and (no_pfs or long_term):
        return True
    return False

def determine_crypto_mode(key_type: str, key_exchange: str) -> str:
    """Classify the overall cryptographic mode."""
    # Basic heuristic check for post-quantum algorithms
    pqc_indicators = ["Kyber", "Dilithium", "Falcon", "SPHINCS+", "X25519Kyber768"]
    
    has_pqc = any(p in key_exchange or p in key_type for p in pqc_indicators)
    is_classical = key_type in ["RSA", "ECDSA", "DSA"]
    
    if has_pqc and is_classical:
        return "HYBRID"
    elif has_pqc:
        return "PQC_READY"
    return "CLASSICAL"

def estimate_quantum_horizon(key_type: str, key_size_bits: int) -> int:
    """Estimate the year this cryptography becomes vulnerable to CRQCs."""
    if key_type == "RSA":
        if key_size_bits <= 2048:
            return 2030
        elif key_size_bits <= 3072:
            return 2033
        return 2035
    elif key_type == "ECDSA":
        if key_size_bits <= 256:
            return 2031
        return 2034
    elif key_type == "EdDSA":
        return 2034
    
    # Post-quantum assumptions
    return 2050

def calculate_agility_score(tls_version: str, key_exchange: str, chain_status: str) -> int:
    """Calculate an agility score (0-100) based on modernization."""
    score = 0
    
    if tls_version == "TLS 1.3":
        score += 40
    elif tls_version == "TLS 1.2":
        score += 20
        
    if "ECDHE" in key_exchange or "DHE" in key_exchange or "X25519" in key_exchange:
        score += 30
        
    if chain_status == "VALID":
        score += 30
        
    # Penalty for static RSA
    if "RSA (Static)" in key_exchange:
        score = int(score * 0.5)
        
    return min(100, score)

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
            "quantum_risk_horizon": 2026,
            "crypto_agility_score": 0,
            "risk_level": "CRITICAL",
            "hndl_risk": True
         }
         
    # Take the worst-case scenario across all IPs for security profiling
    worst_tls_version = "Unknown"
    worst_key_type = "RSA"
    worst_key_size = 4096
    worst_key_exchange = "X25519"
    worst_chain = "VALID"
    worst_cert_days = 999
    
    for res in tls_results:
        tls = res.get("tls", {})
        cert = res.get("certificate", {})
        
        # Simple string comparison for TLS version works here (TLS 1.0 < TLS 1.3)
        tv = tls.get("version", "Unknown")
        if tv != "Unknown":
            if worst_tls_version == "Unknown" or tv < worst_tls_version:
                 worst_tls_version = tv
                 
        v = tls.get("key_size_bits", 4096)
        if v < worst_key_size:
            worst_key_size = v
            worst_key_type = tls.get("public_key_type", "RSA")
            
        ke = tls.get("key_exchange", "")
        if "Static" in ke:
             worst_key_exchange = ke
             
        if cert.get("chain_status") == "WEAK" and worst_chain != "UNTRUSTED":
             worst_chain = "WEAK"
        elif cert.get("chain_status") == "UNTRUSTED":
             worst_chain = "UNTRUSTED"
             
        cdays = cert.get("days_remaining", 999)
        if cdays < worst_cert_days:
            worst_cert_days = cdays

    crypto_mode = determine_crypto_mode(worst_key_type, worst_key_exchange)
    hndl_risk = assess_hndl_risk(worst_key_type, worst_key_exchange, worst_cert_days)
    risk_horizon = estimate_quantum_horizon(worst_key_type, worst_key_size)
    agility = calculate_agility_score(worst_tls_version, worst_key_exchange, worst_chain)
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
        "risk_level": risk_level,
        "hndl_risk": hndl_risk
    }
