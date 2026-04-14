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

import json

# ── JWT AUTHENTICATION (HS256 / Supabase) ─────────────────────
# Supabase issues HS256-signed JWTs. We ONLY support HS256 here.
# The supabase_jwk.json (ES256) is intentionally NOT used for
# token verification — it causes 401 on every authenticated call.
JWT_ALGORITHM = "HS256"  # Supabase always issues HS256 tokens
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")
JWT_VERIFICATION_KEY = SUPABASE_JWT_SECRET  # HMAC secret, not a JWK

def _validate_jwt_config():
    """
    Startup guard — fails loudly if SUPABASE_JWT_SECRET is missing or
    looks like a placeholder. Called once during lifespan startup.
    """
    secret = SUPABASE_JWT_SECRET.strip()
    if not secret or secret in ("your-jwt-secret-here", "changeme"):
        raise RuntimeError(
            "FATAL: SUPABASE_JWT_SECRET is missing or set to a placeholder value. "
            "Set the correct secret from Supabase → Project Settings → API → JWT Secret."
        )
    if len(secret) < 32:
        print(
            "  ⚠️  WARNING: SUPABASE_JWT_SECRET looks very short. "
            "Ensure it is the full JWT secret from Supabase project settings."
        )
    print(f"  [OK] JWT config: algorithm=HS256, secret length={len(secret)} chars")

def extract_user_id(request: Request) -> str:
    """
    Extract and VERIFY the Supabase user UUID from the Authorization header.
    Requirements:
      1. Authorization: Bearer <JWT>
      2. Valid signature (HS256) using SUPABASE_JWT_SECRET
      3. Token must not be expired (exp)
      4. Token must contain a valid 'sub' (subject) claim
    Raises HTTP 401 Unauthorized for any failure.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401, 
            detail="Unauthorized: Missing or invalid Authorization header"
        )
    
    token = auth_header[len("Bearer "):].strip()
    
    if not SUPABASE_JWT_SECRET:
        # Fallback to a warning in logs if secret is missing, 
        # but in production this should be a configuration error.
        print("  ⚠️  CRITICAL: SUPABASE_JWT_SECRET is not set. Token verification will fail.")
        raise HTTPException(
            status_code=500, 
            detail="Internal Server Error: Auth configuration missing"
        )

    try:
        # Decode and VERIFY signature (HS256), expiry (exp), and subject (sub).
        # algorithms list is LOCKED to ["HS256"] — no ES256/RS256 allowed.
        payload = jwt.decode(
            token,
            SUPABASE_JWT_SECRET,   # Always use the raw HMAC secret
            algorithms=["HS256"],  # Supabase issues HS256 — do not change
            options={"verify_exp": True}
        )
        
        uid = payload.get("sub")
        if not uid:
            raise HTTPException(
                status_code=401, 
                detail="Unauthorized: Token missing 'sub' claim"
            )
        return str(uid)

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Unauthorized: Token has expired")
    except jwt.InvalidAlgorithmError:
        # This is the most likely cause of "The specified alg value is not allowed"
        try:
            unverified_header = jwt.get_unverified_header(token)
            alg = unverified_header.get("alg")
            msg = f"Unauthorized: Algorithm '{alg}' not allowed. Expected '{JWT_ALGORITHM}'."
            print(f"  ❌ JWT Auth Mismatch: {msg}")
            raise HTTPException(status_code=401, detail=msg)
        except HTTPException:
            raise
        except:
            raise HTTPException(status_code=401, detail="Unauthorized: Invalid algorithm header")
    except jwt.InvalidTokenError as e:
        # Log common issues for debugging
        print(f"  ❌ JWT invalid: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Unauthorized: Invalid token ({str(e)})")
    except Exception as e:
        if isinstance(e, HTTPException): raise e
        print(f"  ❌ JWT exception: {str(e)}")
        raise HTTPException(status_code=401, detail="Unauthorized: Authentication failed")

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

# ── CORS ───────────────────────────────────────────────────────
# Explicit origins so browsers send cookies/Authorization with credentials.
# Wildcard "*" cannot be combined with allow_credentials=True (CORS spec).
_CORS_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8080",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:3000",
    # Production frontend URL — add here when deploying:
    # "https://your-app.vercel.app",
]
# Allow all file:// and local origins during development by also checking
# the wildcard fallback when credentials are NOT needed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
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

    # ── VALIDATE JWT CONFIG (fail loudly on misconfiguration) ──
    try:
        _validate_jwt_config()
    except RuntimeError as cfg_err:
        print(f"  ❌ STARTUP ABORTED: {cfg_err}")
        raise  # Re-raise to stop the server from starting

    print("\n  Connecting to Supabase...")
    if db.test_connection():
        print("  [OK] Supabase connected successfully!")
        db.save_audit_log(
            action='SYSTEM_STARTUP',
            metadata={'description': 'Quantum-Proof Systems Scanner API started'}
        )
    else:
        print("  [WARN] Supabase not available — check SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env")
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
        "version": "1.0.1",
        "database": "Supabase (PostgreSQL)",
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
                payload = jwt.decode(token, algorithms=[JWT_ALGORITHM], options={"verify_signature": False})
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

@app.get("/api/compare-assets", summary="Compare assets by specific scan IDs")
async def compare_assets(req: Request, ids: str = ""):
    """Compare specific scans. Pass comma-separated UUIDs in 'ids' query."""
    user_id = extract_user_id(req)
    if not ids:
        raise HTTPException(status_code=400, detail="Missing 'ids' parameter")
    scan_ids = [s.strip() for s in ids.split(",") if s.strip()]
    
    comparisons = db.get_scans_by_ids(user_id, scan_ids)
    return {"comparisons": comparisons}

@app.get("/api/compare-assets-by-domain", summary="Compare latest scans for given domains")
async def compare_assets_domains(req: Request, domains: str = ""):
    """Compare assets by their domain. Fetches the latest scan for each. Pass comma-separated domains."""
    user_id = extract_user_id(req)
    if not domains:
        raise HTTPException(status_code=400, detail="Missing 'domains' parameter")
    domain_list = [d.strip() for d in domains.split(",") if d.strip()]
    
    comparisons = db.get_latest_scans_by_domains(user_id, domain_list)
    return {"comparisons": comparisons}

@app.get("/api/asset-trends/{domain}", summary="Get trend analysis for an asset")
async def get_asset_trends(domain: str, req: Request):
    """Returns historical scans sorted old-to-new, with average metrics."""
    user_id = extract_user_id(req)
    scans = db.get_scans_by_domain(user_id, domain)
    if not scans:
        return {"trends": [], "average_pqc_score": 0, "average_agility_score": 0, "latest_risk_level": "UNKNOWN"}
    
    scans.sort(key=lambda x: x["created_at"])  # Ascending for charts
    
    trends = []
    total_pqc = 0
    total_agility = 0
    for s in scans:
        p_val = s.get("pqc_score") or 0
        a_val = s.get("crypto_agility_score") or 0
        total_pqc += p_val
        total_agility += a_val
        trends.append({
            "scan_date": s.get("created_at"),
            "pqc_score": p_val,
            "agility_score": a_val,
            "risk_level": s.get("risk_level", "UNKNOWN")
        })
    
    count = len(scans)
    return {
        "trends": trends,
        "average_pqc_score": round(total_pqc / count),
        "average_agility_score": round(total_agility / count),
        "latest_risk_level": scans[-1].get("risk_level", "UNKNOWN")
    }


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
            payload = jwt.decode(token, algorithms=[JWT_ALGORITHM], options={"verify_signature": False})
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
            payload = jwt.decode(token, algorithms=[JWT_ALGORITHM], options={"verify_signature": False})
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


# ── REPORT GENERATION ─────────────────────────────────────────
import re as _re
from fastapi.responses import StreamingResponse
from engine.report_generator import generate_pdf_report, generate_excel_report

def _safe_filename(domain: str) -> str:
    """Sanitize domain for use in a filename."""
    safe = _re.sub(r"[^\w\-.]", "_", domain or "unknown")
    return safe[:60]  # cap length

@app.get(
    "/api/report/pdf/{scan_id}",
    summary="Download PDF report for a scan",
    response_description="application/pdf file download",
    tags=["Reports"],
)
async def get_pdf_report(scan_id: str, req: Request):
    """
    Generate and download an executive-style PDF report.
    
    - RBAC enforced: analysts see only their own scans.
    - Returns 404 if scan_id not found or not accessible.
    - No stack traces are leaked to the client.
    """
    user_id = extract_user_id(req)

    try:
        data = _safe_db(db.get_scan_for_report, scan_id=scan_id, user_id=user_id)
        if not data:
            raise HTTPException(status_code=404, detail="Scan not found or access denied.")

        pdf_bytes = generate_pdf_report(data)

        date_str  = data.get("generated_at", "")[:10]
        safe_name = _safe_filename(data.get("domain", "unknown"))
        filename  = f"QPS_Report_{safe_name}_{date_str}.pdf"

        _safe_db(db.save_audit_log,
                 action="REPORT_PDF_DOWNLOADED",
                 user_id=user_id,
                 domain=data.get("domain"),
                 metadata={"scan_id": scan_id, "filename": filename})

        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    except HTTPException:
        raise
    except Exception as e:
        print(f"  [WARN] PDF report generation error: {e}")
        raise HTTPException(status_code=500, detail="Report generation failed.")


@app.get(
    "/api/report/excel/{scan_id}",
    summary="Download Excel report for a scan",
    response_description="application/xlsx file download",
    tags=["Reports"],
)
async def get_excel_report(scan_id: str, req: Request):
    """
    Generate and download a multi-sheet Excel (.xlsx) report.

    Sheets: Summary · IP Node Details · Findings · Recommendations

    - RBAC enforced: analysts see only their own scans.
    - Returns 404 if scan_id not found or not accessible.
    - No stack traces are leaked to the client.
    """
    user_id = extract_user_id(req)

    try:
        data = _safe_db(db.get_scan_for_report, scan_id=scan_id, user_id=user_id)
        if not data:
            raise HTTPException(status_code=404, detail="Scan not found or access denied.")

        xlsx_bytes = generate_excel_report(data)

        date_str  = data.get("generated_at", "")[:10]
        safe_name = _safe_filename(data.get("domain", "unknown"))
        filename  = f"QPS_Report_{safe_name}_{date_str}.xlsx"

        _safe_db(db.save_audit_log,
                 action="REPORT_EXCEL_DOWNLOADED",
                 user_id=user_id,
                 domain=data.get("domain"),
                 metadata={"scan_id": scan_id, "filename": filename})

        return StreamingResponse(
            iter([xlsx_bytes]),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    except HTTPException:
        raise
    except Exception as e:
        print(f"  [WARN] Excel report generation error: {e}")
        raise HTTPException(status_code=500, detail="Report generation failed.")



@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail}
        )
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
