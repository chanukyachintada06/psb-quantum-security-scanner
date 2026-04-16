import sys
import os

sys.path.insert(0, os.path.abspath('.'))

import sys
import os

sys.path.insert(0, os.path.abspath('.'))

from backend.engine.risk_engine import generate_risk_profile

def print_result(title, res):
    print(f"\n--- {title} ---")
    print("Crypto Mode:", res["crypto_mode"])
    print("Agility Score:", res["crypto_agility_score"])
    print("Agility Factors:")
    for f in res.get("agility_factors", []):
        print(f"  - {f}")
    print("HNDL:", res["hndl_risk"])
    print("Horizon:", res["quantum_risk_horizon"])

# 1. Legacy RSA/TLS1.2 Site (CLASSICAL, Low Agility)
tls_legacy = [{
    "tls": {
        "version": "TLS 1.2",
        "key_size_bits": 2048,
        "public_key_type": "RSA",
        "key_exchange": "RSA (Static)",
        "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA"
    },
    "certificate": {"chain_status": "VALID", "days_remaining": 400}
}]
print_result("1. Legacy RSA/TLS1.2 Site", generate_risk_profile(tls_legacy))

# 2. Modern TLS1.3 / ECDHE Site (CLASSICAL, Medium/High Agility)
tls_modern = [{
    "tls": {
        "version": "TLS 1.3",
        "key_size_bits": 2048,
        "public_key_type": "RSA",
        "key_exchange": "ECDHE",
        "cipher_suite": "TLS_AES_256_GCM_SHA384"
    },
    "certificate": {"chain_status": "VALID", "days_remaining": 30}
}]
print_result("2. Modern TLS1.3 / ECDHE Site", generate_risk_profile(tls_modern))

# 3. Hybrid PQC Site (HYBRID, High Agility)
tls_hybrid = [{
    "tls": {
        "version": "TLS 1.3",
        "key_size_bits": 4096,
        "public_key_type": "RSA",
        "key_exchange": "X25519Kyber768",
        "cipher_suite": "TLS_CHACHA20_POLY1305_SHA256"
    },
    "certificate": {"chain_status": "VALID", "days_remaining": 100}
}]
print_result("3. Hybrid PQC Site", generate_risk_profile(tls_hybrid))

# 4. Fully PQC Mock (PQC_READY, Very High Agility)
tls_pqc = [{
    "tls": {
        "version": "TLS 1.3",
        "key_size_bits": 0, # not relevant for ML-DSA
        "public_key_type": "ML-DSA",
        "key_exchange": "ML-KEM",
        "cipher_suite": "TLS_AES_256_GCM_SHA384"
    },
    "certificate": {"chain_status": "VALID", "days_remaining": 30}
}]
print_result("4. Fully PQC Mock", generate_risk_profile(tls_pqc))

