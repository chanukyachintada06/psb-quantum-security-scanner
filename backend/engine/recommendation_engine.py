from typing import List, Dict, Any

def analyze_findings(tls_results: List[Dict[str, Any]], risk_profile: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Generate misconfigurations and recommendations based on the aggregated TLS data.
    Returns a list of finding objects ready for database insertion.
    """
    findings = []
    
    if not tls_results:
        findings.append({
            "type": "MISCONFIG",
            "severity": "CRITICAL",
            "title": "Unreachable Target",
            "description": "No successful TLS connections could be established to any resolved IP address."
        })
        return findings
        
    worst_tls_version = "TLS 1.3"
    worst_key_type = "PQC"
    has_static_rsa = False
    has_weak_chain = False
    
    for res in tls_results:
        tls = res.get("tls", {})
        cert = res.get("certificate", {})
        
        tv = tls.get("version", "TLS 1.3")
        if tv in ["TLS 1.0", "TLS 1.1"]:
            worst_tls_version = tv
        elif tv == "TLS 1.2" and worst_tls_version == "TLS 1.3":
            worst_tls_version = tv
            
        ke = tls.get("key_exchange", "")
        if "Static" in ke:
             has_static_rsa = True
             
        if tls.get("public_key_type") in ["RSA", "ECDSA", "DSA"]:
             worst_key_type = "CLASSICAL"
             
        if cert.get("chain_status") in ["WEAK", "UNTRUSTED"]:
             has_weak_chain = True
             
    # Misconfigurations
    if worst_tls_version in ["TLS 1.0", "TLS 1.1"]:
        findings.append({
            "type": "MISCONFIG",
            "severity": "HIGH",
            "title": "Deprecated TLS Version",
            "description": f"The target supports {worst_tls_version}, which is deprecated and vulnerable to legacy cryptographic attacks."
        })
        findings.append({
            "type": "RECOMMENDATION",
            "severity": "HIGH",
            "title": "Upgrade to TLS 1.3",
            "description": "Disable support for TLS 1.0/1.1 and prioritize TLS 1.3 with strong cipher suites."
        })
        
    if has_static_rsa:
        findings.append({
            "type": "MISCONFIG",
            "severity": "CRITICAL",
            "title": "Missing Forward Secrecy",
            "description": "Static RSA key exchange detected. This severely increases Harvest Now, Decrypt Later (HNDL) risk against future quantum computers."
        })
        findings.append({
            "type": "RECOMMENDATION",
            "severity": "CRITICAL",
            "title": "Enable ECDHE or DHE",
            "description": "Reconfigure the server to only allow ephemeral Diffie-Hellman key exchanges to guarantee perfect forward secrecy."
        })
        
    if has_weak_chain:
        findings.append({
            "type": "MISCONFIG",
            "severity": "HIGH",
            "title": "Weak or Untrusted Certificate Chain",
            "description": "The certificate chain contains untrusted roots or relies on weak legacy signing algorithms (e.g., SHA-1)."
        })
        findings.append({
            "type": "RECOMMENDATION",
            "severity": "HIGH",
            "title": "Renew Certificate Chain",
            "description": "Replace the existing certificate with one issued by a trusted CA using SHA-256 or better."
        })
        
    if risk_profile.get("crypto_mode") == "CLASSICAL":
        findings.append({
            "type": "RECOMMENDATION",
            "severity": "MEDIUM",
            "title": "Prepare PQC Migration Strategy",
            "description": f"The cryptography relies purely on classical algorithms. Based on key sizes, risk horizon is ~{risk_profile.get('quantum_risk_horizon')}. Begin planning a transition to NIST-standardized PQC algorithms (e.g., FIPS 203 ML-KEM)."
        })

    return findings
