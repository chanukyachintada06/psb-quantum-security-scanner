"""
Database Layer — Quantum-Proof Systems Scanner
Team CypherRed261 — PSB Hackathon 2026

Supabase (PostgreSQL) backend.
Uses service_role key — NEVER expose this key to the frontend.

RBAC MODEL
──────────
  admin   → full read/write access across all users
  jury    → full read access across all users (hackathon judges)
  mentor  → full read access across all users
  test    → full access (internal QA accounts)
  auditor → read-only, scoped to own data (can be elevated later)
  analyst → default; restricted to own data only
"""

import os
import datetime
from supabase import create_client, Client
from dotenv import load_dotenv

# Ensure we always load .env from the backend directory regardless of cwd
env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path=env_path, override=True)

# ── SUPABASE CLIENT (service_role — bypasses RLS) ─────────────
# Try multiple naming conventions for maximum resilience on deployment
# Variables are loaded dynamically in get_client() to prevent Uvicorn reload caching issues.

# System fallback user_id for demo / unauthenticated scans
SYSTEM_USER_ID: str = os.getenv("SYSTEM_USER_ID", "00000000-0000-0000-0000-000000000000")

# ── RBAC CONFIGURATION ─────────────────────────────────────────
# Roles that bypass user_id filters and see ALL data in the system.
# These are evaluated purely in backend logic (RLS is bypassed by service_role key).
SUPERUSER_ROLES: set[str] = {"admin", "jury", "mentor", "test"}

# Per-request in-memory role cache: { user_id → role_string }
# Cleared on process restart — safe for stateless deployments.
_role_cache: dict[str, str] = {}

_supabase: Client | None = None


def get_client() -> Client:
    """Return (and lazily initialise) the Supabase service-role client."""
    global _supabase
    if _supabase is None:
        url = os.getenv("SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL", "")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY", "")
        
        if not url or not key:
            raise RuntimeError(
                "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in .env"
            )
        _supabase = create_client(url, key)
    return _supabase


# ── CONNECTION TEST ─────────────────────────────────────────────
def test_connection() -> bool:
    """Ping Supabase — returns True if reachable."""
    try:
        client = get_client()
        client.table("scan_results").select("id").limit(1).execute()
        return True
    except Exception as e:
        print(f"  [ERROR] Supabase connection failed: {e}")
        return False


# ============================================================
# RBAC HELPERS
# ============================================================

def get_user_role(user_id: str) -> str:
    """
    Fetch the role for a given user from the profiles table.

    Strategy:
      1. Check the in-process _role_cache first (avoids repeated DB hits per request).
      2. Query profiles table via service_role key (bypasses RLS).
      3. On any error or missing row, default to 'analyst' (least privilege).
    """
    if not user_id or user_id == SYSTEM_USER_ID:
        return "analyst"  # Demo / unauthenticated sessions are always analyst

    # Cache hit
    if user_id in _role_cache:
        return _role_cache[user_id]

    try:
        res = (
            get_client()
            .table("profiles")
            .select("role")
            .eq("id", user_id)
            .limit(1)
            .execute()
        )
        role = "analyst"  # safe default
        if res.data and len(res.data) > 0:
            role = res.data[0].get("role", "analyst") or "analyst"

        _role_cache[user_id] = role  # Cache for this process lifetime
        print(f"  🔐 RBAC: user={user_id[:8]}... role={role}")
        return role
    except Exception as e:
        print(f"  ⚠️  get_user_role error (defaulting to analyst): {e}")
        return "analyst"


def is_superuser(user_id: str) -> bool:
    """
    Returns True if the user's role is in SUPERUSER_ROLES.
    Superusers bypass all user_id-scoped filters and see the full dataset.
    """
    return get_user_role(user_id) in SUPERUSER_ROLES


def _log_superuser_access(user_id: str, action: str) -> None:
    """
    Write an audit log entry whenever a superuser accesses global data.
    Called internally — errors are silenced to never block the main query.
    """
    try:
        role = get_user_role(user_id)
        get_client().table("audit_logs").insert({
            "user_id":    user_id,
            "action":     f"SUPERUSER_{action}",
            "metadata":   {
                "role":      role,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "note":      "Global data access by privileged role"
            }
        }).execute()
    except Exception:
        pass  # Never let audit logging crash the main request


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
        print(f"  [WARN] save_scan_result error: {e}")
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
        print(f"  [WARN] save_cbom_record error: {e}")


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
        print(f"  [WARN] save_audit_log error: {e}")


# ── QUERY: RECENT SCANS ────────────────────────────────────────
def get_recent_scans(user_id: str, limit: int = 20) -> list:
    """
    Get the most recent scan results.
    Superusers (admin/jury/mentor/test) see ALL users' scans.
    Analysts see only their own.
    """
    superuser = is_superuser(user_id)
    if superuser:
        _log_superuser_access(user_id, "READ_ALL_SCANS")

    try:
        query = (
            get_client()
            .table("scan_results")
            .select("id, domain, scan_version, pqc_score, risk_level, crypto_mode, crypto_agility_score, scan_duration_ms, created_at, user_id")
        )
        if not superuser:
            query = query.eq("user_id", user_id)

        res = query.order("created_at", desc=True).limit(limit).execute()
        return res.data or []
    except Exception as e:
        print(f"  [WARN] get_recent_scans error: {e}")
        return []


# ── QUERY: SCAN BY DOMAIN ──────────────────────────────────────
def get_scans_by_domain(user_id: str, domain: str) -> list:
    """
    Get all scans for a specific domain.
    Superusers see results from ALL users for that domain.
    Analysts see only their own scans for that domain.
    """
    superuser = is_superuser(user_id)
    if superuser:
        _log_superuser_access(user_id, f"READ_ALL_SCANS_DOMAIN_{domain}")

    try:
        query = (
            get_client()
            .table("scan_results")
            .select("*")
            .eq("domain", domain)
        )
        if not superuser:
            query = query.eq("user_id", user_id)

        res = query.order("created_at", desc=True).execute()
        return res.data or []
    except Exception as e:
        print(f"  [WARN] get_scans_by_domain error: {e}")
        return []

# ── QUERY: COMPARE SCANS ───────────────────────────────────────
def get_scans_by_ids(user_id: str, scan_ids: list) -> list:
    """Fetch comparative scans given a list of IDs."""
    superuser = is_superuser(user_id)
    if superuser:
        _log_superuser_access(user_id, "COMPARE_SCANS_IDS")
    
    try:
        query = get_client().table("scan_results").select("id, domain, scan_version, pqc_score, risk_level, crypto_mode, crypto_agility_score, quantum_risk_horizon, hndl_risk, scan_duration_ms, created_at, user_id").in_("id", scan_ids)
        if not superuser:
            query = query.eq("user_id", user_id)
        res = query.execute()
        return res.data or []
    except Exception as e:
        print(f"  [WARN] get_scans_by_ids error: {e}")
        return []

def get_latest_scans_by_domains(user_id: str, domains: list) -> list:
    """Fetch the latest scan for each of the requested domains."""
    superuser = is_superuser(user_id)
    if superuser:
        _log_superuser_access(user_id, "COMPARE_SCANS_DOMAINS")
    
    scans = []
    try:
        query = get_client().table("scan_results").select("id, domain, scan_version, pqc_score, risk_level, crypto_mode, crypto_agility_score, quantum_risk_horizon, hndl_risk, scan_duration_ms, created_at, user_id").in_("domain", domains)
        if not superuser:
            query = query.eq("user_id", user_id)
        
        # We fetch ordered by created_at DESC, then deduplicate by domain locally
        res = query.order("created_at", desc=True).execute()
        
        if res.data:
            seen_domains = set()
            for row in res.data:
                if row["domain"] not in seen_domains:
                    scans.append(row)
                    seen_domains.add(row["domain"])
        return scans
    except Exception as e:
        print(f"  [WARN] get_latest_scans_by_domains error: {e}")
        return []


# ── QUERY: CBOM RECORDS ────────────────────────────────────────
def get_cbom_records(user_id: str, limit: int = 50) -> list:
    """
    Get Cryptographic Bill of Materials records.
    Superusers see ALL CBOM records across all users.
    Analysts see only CBOM records from their own scans.
    """
    superuser = is_superuser(user_id)
    if superuser:
        _log_superuser_access(user_id, "READ_ALL_CBOM")

    try:
        query = (
            get_client()
            .table("cbom_records")
            .select("*, scan_results!inner(user_id, domain, risk_level, created_at)")
        )
        # For analysts: filter to only their own scans via the JOIN
        if not superuser:
            query = query.eq("scan_results.user_id", user_id)

        res = query.order("created_at", desc=True).limit(limit).execute()
        return res.data or []
    except Exception as e:
        print(f"  [WARN] get_cbom_records error: {e}")
        return []


# ── QUERY: AUDIT LOGS ──────────────────────────────────────────
def get_audit_logs(user_id: str, limit: int = 50) -> list:
    """
    Get audit log entries.
    Superusers see the FULL system audit trail across all users.
    Analysts see only their own audit entries.
    """
    superuser = is_superuser(user_id)
    if superuser:
        _log_superuser_access(user_id, "READ_ALL_AUDIT_LOGS")

    try:
        query = (
            get_client()
            .table("audit_logs")
            .select("*")
        )
        if not superuser:
            query = query.eq("user_id", user_id)

        res = query.order("created_at", desc=True).limit(limit).execute()
        return res.data or []
    except Exception as e:
        print(f"  [WARN] get_audit_logs error: {e}")
        return []


# ── QUERY: DASHBOARD STATS ─────────────────────────────────────
def get_dashboard_stats(user_id: str) -> dict:
    """
    Compute aggregated dashboard stats from the assets inventory.
    Superusers see stats aggregated across ALL users (system-wide view).
    Analysts see stats for their own assets only.
    """
    superuser = is_superuser(user_id)
    if superuser:
        _log_superuser_access(user_id, "READ_ALL_DASHBOARD_STATS")

    try:
        # Superusers get the full inventory; analysts get own assets
        query = (
            get_client()
            .table("assets")
            .select("asset_type, risk_level, ipv4, ipv6, scan_count")
        )
        if not superuser:
            query = query.eq("user_id", user_id)

        res = query.execute()
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
        print(f"  [WARN] get_dashboard_stats error: {e}")
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
    """
    Get the asset inventory.
    Superusers see ALL assets across every user in the system.
    Analysts see only their own registered assets.
    """
    superuser = is_superuser(user_id)
    if superuser:
        _log_superuser_access(user_id, "READ_ALL_ASSETS")

    try:
        query = (
            get_client()
            .table("assets")
            .select("*")
        )
        if not superuser:
            query = query.eq("user_id", user_id)

        res = query.order("created_at", desc=True).execute()
        return res.data or []
    except Exception as e:
        print(f"  [WARN] get_assets error: {e}")
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
        print(f"  [WARN] add_asset error: {e}")
        return None

def delete_asset(user_id: str, asset_id: str) -> bool:
    """Delete an asset by ID."""
    try:
        get_client().table("assets").delete().eq("user_id", user_id).eq("id", asset_id).execute()
        return True
    except Exception as e:
        print(f"  [WARN] delete_asset error: {e}")
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
        print(f"  [WARN] update_asset error: {e}")
        return False


def get_nameservers(user_id: str, hostname: str = None) -> list:
    """
    Get nameserver records.
    Superusers see ALL nameserver records across every user.
    Analysts see only records scoped to their account.
    """
    superuser = is_superuser(user_id)
    if superuser:
        _log_superuser_access(user_id, "READ_ALL_NAMESERVERS")

    try:
        query = get_client().table("nameserver_records").select("*")
        if not superuser:
            query = query.eq("user_id", user_id)
        if hostname:
            query = query.eq("hostname", hostname)
        res = query.order("created_at", desc=True).execute()
        return res.data or []
    except Exception as e:
        print(f"  [WARN] get_nameservers error: {e}")
        return []


# ── QUERY: FULL SCAN FOR REPORT GENERATION ─────────────────────
def get_scan_for_report(scan_id: str, user_id: str) -> dict | None:
    """
    Fetch a complete scan record (results + node details + findings)
    for report generation.

    RBAC rules:
      - Superusers (admin/jury/mentor/test) can export any scan.
      - Analysts can only export scans they own.

    Returns a unified dict suitable for the report_generator module,
    or None if the scan is not found / access is denied.
    """
    if not scan_id:
        return None

    super_user = is_superuser(user_id)
    if super_user:
        _log_superuser_access(user_id, f"REPORT_EXPORT_{scan_id[:8]}")

    try:
        # 1. Fetch scan summary row
        query = (
            get_client()
            .table("scan_results")
            .select("*")
            .eq("id", scan_id)
        )
        # Analysts: enforce ownership
        if not super_user:
            query = query.eq("user_id", user_id)

        res = query.limit(1).execute()
        if not res.data:
            return None
        summary = res.data[0]

        # 2. Fetch per-IP details
        det_res = (
            get_client()
            .table("scan_details")
            .select("*")
            .eq("scan_id", scan_id)
            .execute()
        )
        details_raw = det_res.data or []

        # Normalize to the structure report_generator expects
        ip_details = []
        for d in details_raw:
            ip_details.append({
                "ip_address":    d.get("ip_address"),
                "is_successful": d.get("is_successful", True),
                "error_message": d.get("error_message"),
                "tls": {
                    "version":         d.get("tls_version"),
                    "cipher_suite":    d.get("cipher_suite"),
                    "key_exchange":    d.get("key_exchange"),
                    "public_key_type": d.get("key_type"),
                    "key_size":        d.get("key_size"),
                },
                "certificate": {
                    "chain_status": d.get("certificate_chain_status", "UNKNOWN"),
                },
            })

        # 3. Fetch findings
        findings_res = (
            get_client()
            .table("scan_findings")
            .select("*")
            .eq("scan_id", scan_id)
            .execute()
        )
        findings = findings_res.data or []

        # 4. Compose unified dict for the report generator
        return {
            "scan_id":          scan_id,
            "domain":           summary.get("domain"),
            "scan_version":     summary.get("scan_version"),
            "scan_duration_ms": summary.get("scan_duration_ms", 0),
            "generated_at":     datetime.datetime.utcnow().isoformat(),
            "generated_by":     summary.get("created_by", "Quantum Security Engine"),
            "risk_profile": {
                "risk_level":           summary.get("risk_level"),
                "pqc_score":            summary.get("pqc_score"),
                "crypto_agility_score": summary.get("crypto_agility_score"),
                "quantum_risk_horizon": summary.get("quantum_risk_horizon"),
                "hndl_risk":            summary.get("hndl_risk", False),
                "confidence_score":     summary.get("confidence_score", 0),
                "crypto_mode":          summary.get("crypto_mode"),
            },
            "ip_details": ip_details,
            "findings":   findings,
        }
        
        # Inject historical trend data for the PDF Generator
        try:
             history = get_scans_by_domain(user_id, summary.get("domain", ""))
             if history and len(history) > 1:
                 # Ensure chronologically sorted old-to-new
                 history.sort(key=lambda x: x.get("created_at", ""))
                 ret["historical_trends"] = [{
                     "scan_date": h.get("created_at"),
                     "pqc_score": h.get("pqc_score"),
                     "risk_level": h.get("risk_level")
                 } for h in history]
        except Exception as trend_e:
             print(f"  [WARN] Failed to inject trends into report: {trend_e}")
             
        return ret

    except Exception as e:
        print(f"  [WARN] get_scan_for_report error: {e}")
        return None

