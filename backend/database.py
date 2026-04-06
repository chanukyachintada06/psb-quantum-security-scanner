"""
Database Layer — Quantum-Proof Systems Scanner
Team CypherRed261 — PSB Hackathon 2026

Supabase (PostgreSQL) backend.
Uses service_role key — NEVER expose this key to the frontend.
"""

import os
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

# ── SUPABASE CLIENT (service_role — bypasses RLS) ─────────────
SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

# System fallback user_id for demo / unauthenticated scans
SYSTEM_USER_ID: str = os.getenv("SYSTEM_USER_ID", "00000000-0000-0000-0000-000000000000")

_supabase: Client | None = None


def get_client() -> Client:
    """Return (and lazily initialise) the Supabase service-role client."""
    global _supabase
    if _supabase is None:
        if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
            raise RuntimeError(
                "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in .env"
            )
        _supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _supabase


# ── CONNECTION TEST ─────────────────────────────────────────────
def test_connection() -> bool:
    """Ping Supabase — returns True if reachable."""
    try:
        client = get_client()
        client.table("scan_results").select("id").limit(1).execute()
        return True
    except Exception as e:
        print(f"  ❌ Supabase connection failed: {e}")
        return False


# ── SAVE SCAN RESULT ───────────────────────────────────────────
def save_scan_result(user_id: str, scan_data: dict, created_by: str = None) -> str | None:
    """
    Insert a scan result into the normalized tables.
    """
    profile = scan_data.get("risk_profile", {})
    
    # 1. Insert Summary
    summary_row = {
        "user_id":              user_id,
        "domain":               scan_data.get("domain"),
        "scan_version":         scan_data.get("scan_version"),
        "pqc_score":            profile.get("pqc_score"),
        "crypto_mode":          profile.get("crypto_mode"),
        "quantum_risk_horizon": profile.get("quantum_risk_horizon"),
        "crypto_agility_score": profile.get("crypto_agility_score"),
        "risk_level":           profile.get("risk_level", "HIGH"),
        "hndl_risk":            profile.get("hndl_risk", False),
        "confidence_score":     profile.get("confidence_score", 0),
        "scan_duration_ms":     scan_data.get("scan_duration_ms", 0),
    }

    try:
        res = get_client().table("scan_results").insert(summary_row).execute()
        if not res.data:
            return None
        scan_id = res.data[0]["id"]
        
        # 2. Insert Per-IP Details
        details = scan_data.get("ip_details", [])
        detail_rows = []
        for d in details:
             tls = d.get("tls") or {}
             cert = d.get("certificate") or {}
             detail_rows.append({
                  "scan_id": scan_id,
                  "ip_address": d.get("ip_address"),
                  "tls_version": tls.get("version"),
                  "cipher_suite": tls.get("cipher_suite"),
                  "key_exchange": tls.get("key_exchange"),
                  "key_type": tls.get("public_key_type"),
                  "key_size": tls.get("key_size"),
                  "certificate_chain_status": cert.get("chain_status", "VALID"),
                  "is_successful": d.get("is_successful", True),
                  "error_message": d.get("error_message")
             })
        if detail_rows:
             get_client().table("scan_details").insert(detail_rows).execute()
             
        # 3. Insert Findings
        findings = scan_data.get("findings", [])
        finding_rows = []
        for f in findings:
             finding_rows.append({
                 "scan_id": scan_id,
                 "type": f.get("type"),
                 "severity": f.get("severity"),
                 "title": f.get("title"),
                 "description": f.get("description")
             })
        if finding_rows:
             get_client().table("scan_findings").insert(finding_rows).execute()
             
        # 4. Insert Metadata (Optional JSONB)
        get_client().table("scan_metadata").insert({
             "scan_id": scan_id,
             "raw_dns_records": scan_data.get("metadata", {}).get("raw_dns_records", {})
        }).execute()
        
        return scan_id

    except Exception as e:
        print(f"  ⚠️  save_scan_result error: {e}")
    return None


# ── SAVE CBOM RECORD ───────────────────────────────────────────
def save_cbom_record(scan_id: str, cbom_data: dict) -> None:
    """Insert a CBOM row linked to a scan."""
    row = {
        "scan_id":        scan_id,
        "algorithm":      cbom_data.get("algorithm"),
        "key_length":     cbom_data.get("key_length"),
        "cipher_suite":   cbom_data.get("cipher_suite"),
        "pqc_status":     cbom_data.get("pqc_status", "VULNERABLE"),
        "recommendation": cbom_data.get("recommendation"),
        "nist_standard":  cbom_data.get("nist_standard"),
    }
    try:
        get_client().table("cbom_records").insert(row).execute()
    except Exception as e:
        print(f"  ⚠️  save_cbom_record error: {e}")


# ── SAVE AUDIT LOG ─────────────────────────────────────────────
def save_audit_log(
    action: str,
    user_id: str | None = None,
    domain: str | None = None,
    ip_address: str | None = None,
    metadata: dict | None = None,
) -> None:
    """Insert an audit log entry."""
    row = {
        "user_id":    user_id,
        "action":     action,
        "domain":     domain,
        "ip_address": ip_address,
        "metadata":   metadata or {},
    }
    try:
        get_client().table("audit_logs").insert(row).execute()
    except Exception as e:
        print(f"  ⚠️  save_audit_log error: {e}")


# ── QUERY: RECENT SCANS ────────────────────────────────────────
def get_recent_scans(user_id: str, limit: int = 20) -> list:
    """Get the most recent scan results for a specific user."""
    try:
        res = (
            get_client()
            .table("scan_results")
            .select("id, domain, scan_version, pqc_score, risk_level, crypto_mode, crypto_agility_score, scan_duration_ms, created_at")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return res.data or []
    except Exception as e:
        print(f"  ⚠️  get_recent_scans error: {e}")
        return []


# ── QUERY: SCAN BY DOMAIN ──────────────────────────────────────
def get_scans_by_domain(user_id: str, domain: str) -> list:
    """Get all scans for a specific domain, filtered by user."""
    try:
        res = (
            get_client()
            .table("scan_results")
            .select("*")
            .eq("user_id", user_id)
            .eq("domain", domain)
            .order("created_at", desc=True)
            .execute()
        )
        return res.data or []
    except Exception as e:
        print(f"  ⚠️  get_scans_by_domain error: {e}")
        return []


# ── QUERY: CBOM RECORDS ────────────────────────────────────────
def get_cbom_records(user_id: str, limit: int = 50) -> list:
    """Get CBOM records for scans owned by this user (via JOIN)."""
    try:
        res = (
            get_client()
            .table("cbom_records")
            .select("*, scan_results!inner(user_id, domain, risk_level, created_at)")
            .eq("scan_results.user_id", user_id)
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return res.data or []
    except Exception as e:
        print(f"  ⚠️  get_cbom_records error: {e}")
        return []


# ── QUERY: AUDIT LOGS ──────────────────────────────────────────
def get_audit_logs(user_id: str, limit: int = 50) -> list:
    """Get audit log entries for this user."""
    try:
        res = (
            get_client()
            .table("audit_logs")
            .select("*")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return res.data or []
    except Exception as e:
        print(f"  ⚠️  get_audit_logs error: {e}")
        return []


# ── QUERY: DASHBOARD STATS ─────────────────────────────────────
def get_dashboard_stats(user_id: str) -> dict:
    """Compute aggregated stats for the dashboard per user from the assets inventory."""
    try:
        # Get all assets for this user
        res = (
            get_client()
            .table("assets")
            .select("asset_type, risk_level, ipv4, ipv6, scan_count")
            .eq("user_id", user_id)
            .execute()
        )
        rows = res.data or []
        
        # Initialize counters with all expected keys to ensure zero-data safety
        stats = {
            "total_assets": len(rows),
            "high_risk_assets_count": 0,
            "count_by_asset_type": {
                "Web App": 0, "API": 0, "Server": 0, "Gateway": 0, "Load Balancer": 0, "Other": 0
            },
            "count_by_risk_level": {
                "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
            },
            "ipv4_count": 0,
            "ipv6_count": 0,
            "total_scans": sum(r.get("scan_count") or 0 for r in rows)
        }
        
        for r in rows:
            # Asset Type grouping (case-insensitive keys for safety)
            atype = r.get("asset_type", "Other")
            if atype in stats["count_by_asset_type"]:
                stats["count_by_asset_type"][atype] += 1
            else:
                stats["count_by_asset_type"]["Other"] += 1
            
            # Risk grouping
            arisk = (r.get("risk_level") or "LOW").upper()
            if arisk in stats["count_by_risk_level"]:
                stats["count_by_risk_level"][arisk] += 1
            
            # High Risk Asset Definition: CRITICAL + HIGH
            if arisk in ["CRITICAL", "HIGH"]:
                stats["high_risk_assets_count"] += 1
            
            # IP versions
            if r.get("ipv4"): stats["ipv4_count"] += 1
            if r.get("ipv6"): stats["ipv6_count"] += 1
            
        return stats
    except Exception as e:
        print(f"  ⚠️  get_dashboard_stats error: {e}")
        return {
            "total_assets": 0,
            "high_risk_assets_count": 0,
            "count_by_asset_type": {"Web App": 0, "API": 0, "Server": 0, "Gateway": 0, "Load Balancer": 0, "Other": 0},
            "count_by_risk_level": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "ipv4_count": 0,
            "ipv6_count": 0,
            "total_scans": 0
        }


# ── LEGACY SHIM (backward-compat with init_db calls in main.py) ─
def init_db():
    """No-op — Supabase schema is managed via SQL Editor, not code."""
    print("  ℹ️  Supabase schema managed via SQL Editor (no init needed).")


# ── ASSETS ─────────────────────────────────────────────────────
def get_assets(user_id: str) -> list:
    """Get the full asset inventory for a specific user."""
    try:
        res = (
            get_client()
            .table("assets")
            .select("*")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .execute()
        )
        return res.data or []
    except Exception as e:
        print(f"  ⚠️  get_assets error: {e}")
        return []

def add_asset(user_id: str, data: dict) -> dict | None:
    """Add a new asset to the inventory."""
    row = {
        "user_id":          user_id,
        "name":             data.get("name"),
        "url":              data.get("url"),
        "ipv4":             data.get("ipv4"),
        "ipv6":             data.get("ipv6"),
        "asset_type":       data.get("asset_type"),
        "owner_department": data.get("owner_department"),
        "created_by":       data.get("created_by"),
        "risk_level":       data.get("risk_level", "LOW"),
        "cert_status":      data.get("cert_status", "Valid"),
    }
    try:
        res = get_client().table("assets").insert(row).execute()
        return res.data[0] if res.data else None
    except Exception as e:
        print(f"  ⚠️  add_asset error: {e}")
        return None

def delete_asset(user_id: str, asset_id: str) -> bool:
    """Delete an asset by ID."""
    try:
        get_client().table("assets").delete().eq("user_id", user_id).eq("id", asset_id).execute()
        return True
    except Exception as e:
        print(f"  ⚠️  delete_asset error: {e}")
        return False

def update_asset(user_id: str, asset_id: str, data: dict) -> bool:
    """Update an asset's information."""
    row = {
        "name":             data.get("name"),
        "url":              data.get("url"),
        "asset_type":       data.get("asset_type"),
        "owner_department": data.get("owner_department"),
        "updated_at":       "now()",
        "updated_by":       data.get("updated_by"),
    }
    # Remove nulls to avoid overwriting fields we didn't send
    row = {k: v for k, v in row.items() if v is not None}
    
    try:
        get_client().table("assets").update(row).eq("user_id", user_id).eq("id", asset_id).execute()
        return True
    except Exception as e:
        print(f"  ⚠️  update_asset error: {e}")
        return False

def get_nameservers(user_id: str, hostname: str = None) -> list:
    """Get nameserver records for a user, optionally filtered by hostname."""
    try:
        query = get_client().table("nameserver_records").select("*").eq("user_id", user_id)
        if hostname:
            query = query.eq("hostname", hostname)
        res = query.order("created_at", desc=True).execute()
        return res.data or []
    except Exception as e:
        print(f"  ⚠️  get_nameservers error: {e}")
        return []
