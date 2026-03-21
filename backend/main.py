"""
Quantum-Proof Systems Scanner — FastAPI Backend (with MySQL)
Team CypherRed261 — PSB Hackathon 2026
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio
import time

from models import ScanRequest
from pydantic import BaseModel
from scanner import scan_domain
import database as db

# ── APP SETUP ──────────────────────────────────────────────────
app = FastAPI(
    title="Quantum-Proof Systems Scanner API",
    description=(
        "Real TLS cryptographic vulnerability assessment and PQC compliance "
        "scanner for banking infrastructure. Built for PNB PSB Hackathon 2026."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ── STARTUP ────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    print("\n" + "=" * 60)
    print("  Quantum-Proof Systems Scanner — API v1.0.0")
    print("  Team CypherRed261 | PSB Hackathon 2026 | LPU")
    print("  NIST FIPS 203 | FIPS 204 | FIPS 205 | CERT-IN | RBI CSF")
    print("=" * 60)
    print("  Docs: http://localhost:8000/docs")
    print("  API:  http://localhost:8000/api/scan")
    print("=" * 60)

    # Initialize database tables
    print("\n  Connecting to MySQL database...")
    if db.test_connection():
        print("  ✅ MySQL connected successfully!")
        db.init_db()
        db.save_audit_log(
            event_type='SYSTEM_STARTUP',
            description='Quantum-Proof Systems Scanner API started'
        )
    else:
        print("  ⚠️  MySQL not available — running without database")
    print()


# ── ROOT ───────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "status": "online",
        "project": "Quantum-Proof Systems Scanner",
        "team": "CypherRed261",
        "event": "PSB Hackathon 2026",
        "institution": "Lovely Professional University",
        "version": "1.0.0",
        "database": "MySQL (quantum_scanner_db)",
        "compliance": ["NIST FIPS 203", "NIST FIPS 204",
                       "NIST FIPS 205", "CERT-IN", "RBI CSF"],
    }


# ── HEALTH ─────────────────────────────────────────────────────
@app.get("/health")
async def health():
    db_status = db.test_connection()
    return {
        "status": "healthy",
        "database": "connected" if db_status else "disconnected",
        "timestamp": time.time()
    }


# ── SCAN (POST) ────────────────────────────────────────────────
@app.post("/api/scan", summary="Scan a domain for TLS/PQC vulnerabilities")
async def scan_post(request: ScanRequest, req: Request):
    if not request.domain or len(request.domain.strip()) < 3:
        raise HTTPException(status_code=400, detail="Domain is required")

    domain = request.domain.strip()
    client_ip = req.client.host if req.client else "unknown"

    # Log scan initiation
    _safe_db(db.save_audit_log, 'SCAN_INITIATED', domain, client_ip,
             f'Scan initiated for {domain}')

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_run_scan_sync, domain),
            timeout=25.0
        )

        # ── SAVE TO DATABASE ──────────────────────────────────
        scan_id = _safe_db(db.save_scan_result, result)

        if scan_id:
            # Save CBOM record
            _safe_db(db.save_cbom_record, scan_id, result.get('cbom', {}))

            # Save classification label (FR-17, FR-18)
            risk_level = result.get('pqc', {}).get('risk_level', 'HIGH')
            _safe_db(db.save_classification_label, scan_id, domain, risk_level)

            # Audit log — scan completed
            _safe_db(db.save_audit_log, 'SCAN_COMPLETED', domain, client_ip,
                     f'Scan completed — Risk: {risk_level} | '
                     f'Score: {result.get("pqc", {}).get("risk_score")}')

            # Add scan_id to response
            result['scan_id'] = scan_id

        return JSONResponse(content=result)

    except asyncio.TimeoutError:
        _safe_db(db.save_audit_log, 'SCAN_FAILED', domain, client_ip,
                 f'Scan timed out for {domain}')
        raise HTTPException(
            status_code=504,
            detail=f"Scan timed out for '{domain}' — server may be unreachable"
        )
    except ValueError as e:
        _safe_db(db.save_audit_log, 'SCAN_FAILED', domain, client_ip, str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        _safe_db(db.save_audit_log, 'SCAN_FAILED', domain, client_ip, str(e))
        raise HTTPException(status_code=422, detail=str(e))


# ── SCAN (GET) ─────────────────────────────────────────────────
@app.get("/api/scan/{domain:path}", summary="Scan a domain (GET method)")
async def scan_get(domain: str, req: Request):
    if not domain or len(domain.strip()) < 3:
        raise HTTPException(status_code=400, detail="Valid domain required")
    fake_req = ScanRequest(domain=domain)
    return await scan_post(fake_req, req)


# ── DB ENDPOINTS ───────────────────────────────────────────────
@app.get("/api/history", summary="Get recent scan history from database")
async def get_history(limit: int = 20):
    """Returns the last N scans stored in MySQL."""
    try:
        scans = db.get_recent_scans(limit)
        # Convert datetime objects to strings for JSON
        for scan in scans:
            for key, val in scan.items():
                if hasattr(val, 'isoformat'):
                    scan[key] = val.isoformat()
        return {"scans": scans, "count": len(scans)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/cbom", summary="Get CBOM records from database")
async def get_cbom(limit: int = 50):
    """Returns Cryptographic Bill of Materials records."""
    try:
        records = db.get_cbom_records(limit)
        for r in records:
            for key, val in r.items():
                if hasattr(val, 'isoformat'):
                    r[key] = val.isoformat()
        return {"cbom_records": records, "count": len(records)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit", summary="Get audit logs from database")
async def get_audit(limit: int = 50):
    """Returns system audit log entries (SRS Section 5.4)."""
    try:
        logs = db.get_audit_logs(limit)
        for log in logs:
            for key, val in log.items():
                if hasattr(val, 'isoformat'):
                    log[key] = val.isoformat()
        return {"audit_logs": logs, "count": len(logs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/stats", summary="Get dashboard statistics from database")
async def get_stats():
    """Returns aggregated scan statistics."""
    try:
        stats = db.get_dashboard_stats()
        for key, val in stats.items():
            if val is not None and hasattr(val, '__float__'):
                stats[key] = round(float(val), 1)
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/domain/{domain}", summary="Get all scans for a domain")
async def get_domain_history(domain: str):
    """Returns all historical scans for a specific domain."""
    try:
        scans = db.get_scans_by_domain(domain)
        for scan in scans:
            for key, val in scan.items():
                if hasattr(val, 'isoformat'):
                    scan[key] = val.isoformat()
        return {"domain": domain, "scans": scans, "count": len(scans)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── HELPERS ────────────────────────────────────────────────────
def _run_scan_sync(domain: str) -> dict:
    """Run async scan in sync thread."""
    import asyncio as _asyncio
    loop = _asyncio.new_event_loop()
    try:
        return loop.run_until_complete(scan_domain(domain))
    finally:
        loop.close()


def _safe_db(func, *args):
    """
    Call a DB function safely — if DB is unavailable, 
    log the error and continue without crashing.
    """
    try:
        return func(*args)
    except Exception as e:
        print(f"  ⚠️  DB warning: {e}")
        return None


# ── ERROR HANDLER ──────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {str(exc)}"}
    )


# ── ENTRY POINT ────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)


# ── LOGIN AUDIT ENDPOINT ───────────────────────────────────────
class LoginAuditRequest(BaseModel):
    username: str
    event: str = "USER_LOGIN"

@app.post("/api/audit-login", summary="Log user login event")
async def audit_login(request: LoginAuditRequest, req: Request):
    """Called by frontend when a user logs in successfully."""
    client_ip = req.client.host if req.client else "unknown"
    _safe_db(
        db.save_audit_log,
        request.event,
        None,
        client_ip,
        f'User logged in: {request.username}'
    )
    return {"status": "logged"}
