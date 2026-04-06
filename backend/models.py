"""
Pydantic response models for Quantum-Proof Systems Scanner API
Team CypherRed261 — PSB Hackathon 2026
"""

from pydantic import BaseModel
from typing import List, Optional


from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class RiskProfile(BaseModel):
    pqc_score: int
    crypto_mode: str
    quantum_risk_horizon: Optional[int]
    crypto_agility_score: int
    risk_level: str
    hndl_risk: bool
    confidence_score: int

class IPDetail(BaseModel):
    ip_address: str
    is_successful: bool
    error_message: Optional[str] = None
    tls: Optional[Dict[str, Any]] = None
    certificate: Optional[Dict[str, Any]] = None
    scan_duration_ms: int

class Finding(BaseModel):
    type: str # MISCONFIG or RECOMMENDATION
    severity: str
    title: str
    description: str

class ScanResult(BaseModel):
    """Normalized payload containing the Engine's full output."""
    domain: str
    scan_version: str
    risk_profile: RiskProfile
    ip_details: List[IPDetail]
    findings: List[Finding]
    metadata: Dict[str, Any]
    scan_duration_ms: int

class ScanRequest(BaseModel):
    """Request body for POST /api/scan."""
    domain: str

class ErrorResponse(BaseModel):
    """Standard error response."""
    detail: str
    domain: Optional[str] = None
