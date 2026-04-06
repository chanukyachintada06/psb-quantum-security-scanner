"""
Quantum-Proof Systems Scanner — FastAPI Backend (Supabase)
Team CypherRed261 — PSB Hackathon 2026
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio
import time
import os
import jwt  # PyJWT

from models import ScanRequest
from pydantic import BaseModel
from engine.scan_service import execute_scan
import database as db

# ── JWT HELPER ─────────────────────────────────────────────────
SYSTEM_USER_ID = os.getenv("SYSTEM_USER_ID", "00000000-0000-0000-0000-000000000000")

def extract_user_id(request: Request) -> str:
    """
    Extract the Supabase user UUID from the Authorization: Bearer <JWT> header.
    If the header is missing or invalid, fall back to SYSTEM_USER_ID (demo mode).
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return SYSTEM_USER_ID
    token = auth_header[len("Bearer "):].strip()
    try:
        # Decode WITHOUT verification — we trust Supabase issued it.
        # For production: verify with Supabase JWT secret.
        payload = jwt.decode(token, options={"verify_signature": False})
        uid = payload.get("sub")
        return uid if uid else SYSTEM_USER_ID
    except Exception:
        return SYSTEM_USER_ID

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
    allow_methods=["*"],
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

    print("\n  Connecting to Supabase...")
    if db.test_connection():
        print("  ✅ Supabase connected successfully!")
        db.save_audit_log(
            action='SYSTEM_STARTUP',
            metadata={'description': 'Quantum-Proof Systems Scanner API started'}
        )
    else:
        print("  ⚠️  Supabase not available — check SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env")
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
        "database": "supabase-connected" if db_status else "supabase-disconnected",
        "timestamp": time.time()
    }


# ── SCAN (POST) ────────────────────────────────────────────────
@app.post("/api/scan", summary="Scan a domain for TLS/PQC vulnerabilities")
async def scan_post(request: ScanRequest, req: Request):
    if not request.domain or len(request.domain.strip()) < 3:
        raise HTTPException(status_code=400, detail="Domain is required")

    domain    = request.domain.strip()
    client_ip = req.client.host if req.client else "unknown"
    user_id   = extract_user_id(req)   # ← Supabase JWT → user UUID

    _safe_db(db.save_audit_log,
             action='SCAN_INITIATED',
             user_id=user_id,
             domain=domain,
             ip_address=client_ip,
             metadata={'description': f'Scan initiated for {domain}'})

    try:
        # The new engine handles timeout natively in its asyncio gather loop if needed, 
        # but we can wrap it here to restrict overall connection hangs.
        result = await asyncio.wait_for(
            execute_scan(domain),
            timeout=120.0 # Multiple IPs can take longer, increase timeout
        )

        # ── SAVE TO SUPABASE ──────────────────────────────────
        # Extract email from JWT for auditing
        auth_header = req.headers.get("Authorization", "")
        token = auth_header[len("Bearer "):].strip() if auth_header.startswith("Bearer ") else None
        email = "unknown"
        if token:
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                email = payload.get("email", "unknown")
            except: pass

        scan_id = _safe_db(db.save_scan_result, user_id=user_id, scan_data=result, created_by=email)

        if scan_id:
            cbom = result.get('cbom', {})
            if cbom:
                _safe_db(db.save_cbom_record, scan_id, cbom)

            risk_level = result.get('pqc', {}).get('risk_level', 'HIGH')
            _safe_db(db.save_audit_log,
                     action='SCAN_COMPLETED',
                     user_id=user_id,
                     domain=domain,
                     ip_address=client_ip,
                     metadata={
                         'risk_level': risk_level,
                         'risk_score': result.get('pqc', {}).get('risk_score'),
                         'scan_id':    scan_id,
                     })
            result['scan_id'] = scan_id

        return JSONResponse(content=result)

    except asyncio.TimeoutError:
        _safe_db(db.save_audit_log, action='SCAN_FAILED', user_id=user_id,
                 domain=domain, ip_address=client_ip,
                 metadata={'error': f'Scan timed out for {domain}'})
        raise HTTPException(
            status_code=504,
            detail=f"Scan timed out for '{domain}' — server may be unreachable"
        )
    except ValueError as e:
        _safe_db(db.save_audit_log, action='SCAN_FAILED', user_id=user_id,
                 domain=domain, ip_address=client_ip, metadata={'error': str(e)})
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        _safe_db(db.save_audit_log, action='SCAN_FAILED', user_id=user_id,
                 domain=domain, ip_address=client_ip, metadata={'error': str(e)})
        raise HTTPException(status_code=422, detail=str(e))


# ── SCAN (GET) ─────────────────────────────────────────────────
@app.get("/api/scan/{domain:path}", summary="Scan a domain (GET method)")
async def scan_get(domain: str, req: Request):
    if not domain or len(domain.strip()) < 3:
        raise HTTPException(status_code=400, detail="Valid domain required")
    fake_req = ScanRequest(domain=domain)
    return await scan_post(fake_req, req)


# ── DB ENDPOINTS ───────────────────────────────────────────────
@app.get("/api/assets", summary="Get asset inventory (user-scoped)")
async def get_assets(req: Request):
    """Returns all assets for the authenticated user and their count."""
    user_id = extract_user_id(req)
    try:
        assets = db.get_assets(user_id)
        return {"assets": assets, "count": len(assets)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/history", summary="Get recent scan history (user-scoped)")
async def get_history(req: Request, limit: int = 20):
    """Returns the last N scans for the authenticated user."""
    user_id = extract_user_id(req)
    try:
        scans = db.get_recent_scans(user_id, limit)
        return {"scans": scans, "count": len(scans)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/cbom", summary="Get CBOM records (user-scoped)")
async def get_cbom(req: Request, limit: int = 50):
    """Returns Cryptographic Bill of Materials records for authenticated user."""
    user_id = extract_user_id(req)
    try:
        records = db.get_cbom_records(user_id, limit)
        return {"cbom_records": records, "count": len(records)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit", summary="Get audit logs (user-scoped)")
async def get_audit(req: Request, limit: int = 50):
    """Returns audit log entries for the authenticated user."""
    user_id = extract_user_id(req)
    try:
        logs = db.get_audit_logs(user_id, limit)
        return {"audit_logs": logs, "count": len(logs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/stats", summary="Get dashboard statistics (user-scoped)")
async def get_stats(req: Request):
    """Returns aggregated scan statistics for the authenticated user."""
    user_id = extract_user_id(req)
    try:
        return db.get_dashboard_stats(user_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/domain/{domain}", summary="Get all scans for a domain (user-scoped)")
async def get_domain_history(domain: str, req: Request):
    """Returns historical scans for a specific domain, filtered by user."""
    user_id = extract_user_id(req)
    try:
        scans = db.get_scans_by_domain(user_id, domain)
        return {"domain": domain, "scans": scans, "count": len(scans)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── ASSETS ─────────────────────────────────────────────────────

@app.post("/api/assets", summary="Add new asset")
async def add_asset_item(request: Request):
    """Adds a new asset to the user's inventory. Attaches current user email as creator."""
    user_id = extract_user_id(request)
    data = await request.json()
    
    # Extract email from JWT for auditing
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[len("Bearer "):].strip() if auth_header.startswith("Bearer ") else None
    email = "unknown"
    if token:
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            email = payload.get("email", "unknown")
        except: pass
    
    data["created_by"] = email
    res = db.add_asset(user_id, data)
    if not res:
        raise HTTPException(status_code=500, detail="Failed to add asset to database")
    return res

@app.delete("/api/assets/{asset_id}", summary="Delete an asset")
async def delete_asset_endpoint(asset_id: str, req: Request):
    """Deletes an asset from the user's inventory."""
    user_id = extract_user_id(req)
    success = db.delete_asset(user_id, asset_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete asset")
    return {"message": "Asset deleted successfully"}

@app.put("/api/assets/{asset_id}", summary="Update an asset")
async def update_asset_endpoint(asset_id: str, request: Request):
    """Updates an existing asset's details."""
    user_id = extract_user_id(request)
    data = await request.json()
    
    # Extract email from JWT for auditing
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[len("Bearer "):].strip() if auth_header.startswith("Bearer ") else None
    email = "unknown"
    if token:
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            email = payload.get("email", "unknown")
        except: pass
    
    data["updated_by"] = email
    success = db.update_asset(user_id, asset_id, data)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update asset")
    return {"message": "Asset updated successfully"}

@app.get("/api/nameservers", summary="Get nameserver records")
async def get_ns_records(req: Request, domain: str = None):
    """Returns DNS/Nameserver records for the user, optionally filtered by domain."""
    user_id = extract_user_id(req)
    try:
        records = db.get_nameservers(user_id, domain)
        return {"nameservers": records, "count": len(records)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Removed _run_scan_sync as execution is now natively async in engine

def _safe_db(func, *args, **kwargs):
    """
    Call a DB function safely — if DB is unavailable, 
    log the error and continue without crashing.
    """
    try:
        return func(*args, **kwargs)
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
    event: str = "USER_LOGIN"

@app.post("/api/audit-login", summary="Log user login event")
async def audit_login(request: LoginAuditRequest, req: Request):
    """Called by frontend after Supabase Auth login — logs the event with real user_id."""
    client_ip = req.client.host if req.client else "unknown"
    user_id   = extract_user_id(req)
    _safe_db(
        db.save_audit_log,
        action=request.event,
        user_id=user_id,
        ip_address=client_ip,
        metadata={'description': f'User login event: {request.event}'}
    )
    return {"status": "logged", "user_id": user_id}
