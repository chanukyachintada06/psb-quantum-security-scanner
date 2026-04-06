import asyncio
import time
from typing import Dict, Any

from .dns_resolver import resolve_domain, sanitize_domain
from .tls_analyzer import analyze_ip_tls
from .risk_engine import generate_risk_profile, calculate_confidence_score
from .recommendation_engine import analyze_findings

SCAN_VERSION = "v1.2"
MAX_CONCURRENT_SCANS = 5

async def execute_scan(raw_domain: str) -> Dict[str, Any]:
    """
    Main orchestrator for the Quantum Security Intelligence Engine.
    Resolves DNS, scans all IPs concurrently, and generates a structured output.
    """
    start_time = time.time()
    
    # 1. DNS Resolution
    domain = sanitize_domain(raw_domain)
    dns_res = resolve_domain(domain)
    
    all_ips = dns_res["ipv4_addresses"] + dns_res["ipv6_addresses"]
    
    # Early exit if no IPs found
    if not all_ips:
        return _generate_failed_scan(domain, dns_res, SCAN_VERSION, "DNS resolution failed. No A or AAAA records found.")
        
    # 2. Async Multi-IP Scanning with Semaphore
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
    
    async def _bounded_scan(ip):
        async with semaphore:
            return await analyze_ip_tls(domain, ip)
            
    # Gather all results
    tasks = [_bounded_scan(ip) for ip in all_ips]
    ip_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Clean results (handle unexpected loop exceptions)
    valid_results = []
    failed_results = []
    successful_scan_count = 0
    
    for i, res in enumerate(ip_results):
        ip = all_ips[i]
        if isinstance(res, Exception):
             failed_results.append({
                 "ip_address": ip,
                 "is_successful": False,
                 "error_message": str(res)
             })
        elif not res.get("is_successful"):
             failed_results.append(res)
        else:
             valid_results.append(res)
             successful_scan_count += 1
             
    all_details = valid_results + failed_results
    
    # 3. Risk Generation
    risk_profile = generate_risk_profile(valid_results)
    
    # 4. Recommendation Generation
    findings = analyze_findings(valid_results, risk_profile)
    
    # 5. Confidence Scoring
    confidence = calculate_confidence_score(
        resolved_ips=len(all_ips),
        successful_scans=successful_scan_count,
        has_aaaa=len(dns_res["ipv6_addresses"]) > 0
    )
    risk_profile["confidence_score"] = confidence
    
    duration = int((time.time() - start_time) * 1000)
    
    # Return structured dict ready for database ingestion
    return {
        "domain": domain,
        "scan_version": SCAN_VERSION,
        "risk_profile": risk_profile,
        "ip_details": all_details,
        "findings": findings,
        "metadata": {
            "raw_dns_records": dns_res["raw_dns_records"]
        },
        "scan_duration_ms": duration
    }

def _generate_failed_scan(domain: str, dns_res: Dict, version: str, error_msg: str) -> Dict[str, Any]:
    return {
        "domain": domain,
        "scan_version": version,
        "risk_profile": {
            "pqc_score": 0,
            "crypto_mode": "UNKNOWN",
            "quantum_risk_horizon": None,
            "crypto_agility_score": 0,
            "risk_level": "LOW",
            "hndl_risk": False,
            "confidence_score": 0,
        },
        "ip_details": [],
        "findings": [{
            "type": "MISCONFIG",
            "severity": "CRITICAL",
            "title": "Resolution Failure",
            "description": error_msg
        }],
        "metadata": {
             "raw_dns_records": dns_res["raw_dns_records"]
        },
        "scan_duration_ms": 0
    }
