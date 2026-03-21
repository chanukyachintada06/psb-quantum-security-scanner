"""
Pydantic response models for Quantum-Proof Systems Scanner API
Team CypherRed261 — PSB Hackathon 2026
"""

from pydantic import BaseModel
from typing import List, Optional


class TLSInfo(BaseModel):
    """TLS connection details extracted from the scanned server."""
    version: str            # e.g. "TLS 1.3"
    cipher_suite: str       # e.g. "TLS_AES_256_GCM_SHA384"
    key_exchange: str       # e.g. "ECDHE (X25519)"
    public_key_type: str    # e.g. "RSA", "ECDSA"
    key_size: str           # e.g. "2048-bit"
    signature_hash: str     # e.g. "SHA-256 with RSA"


class CertificateInfo(BaseModel):
    """X.509 certificate details parsed from the server's certificate chain."""
    subject: str
    issuer: str
    valid_from: str
    valid_until: str
    days_remaining: int
    is_expired: bool
    is_expiring_soon: bool  # True if expiring within 30 days


class Recommendation(BaseModel):
    """A single PQC migration recommendation."""
    priority: str   # "high", "medium", "low"
    text: str       # HTML-safe recommendation text


class PQCAssessment(BaseModel):
    """Post-Quantum Cryptography risk assessment result."""
    risk_level: str             # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    risk_score: int             # 0–100
    pqc_readiness: int          # 0–100 percentage
    quantum_vulnerable: bool
    vulnerabilities: List[str]
    recommendations: List[dict]


class CBOMEntry(BaseModel):
    """Cryptographic Bill of Materials entry for a single asset."""
    asset: str
    key_length: str
    cipher_suite: str
    tls_version: str
    certificate_authority: str
    quantum_safe: bool


class ScanResult(BaseModel):
    """Complete scan result returned by the /api/scan endpoint."""
    domain: str
    scan_timestamp: str
    tls: TLSInfo
    certificate: CertificateInfo
    pqc: PQCAssessment
    cbom: CBOMEntry
    scan_duration_ms: int


class ScanRequest(BaseModel):
    """Request body for POST /api/scan."""
    domain: str


class ErrorResponse(BaseModel):
    """Standard error response."""
    detail: str
    domain: Optional[str] = None
