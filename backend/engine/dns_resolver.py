import dns.resolver
import re
from typing import Dict, List, Any

def sanitize_domain(raw_input: str) -> str:
    """
    Clean and validate domain/IP input from the user.
    """
    domain = raw_input.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0].split('?')[0].split('#')[0]
    domain = domain.split(':')[0]
    
    if len(domain) < 3 or len(domain) > 253:
        raise ValueError(f"Domain '{domain}' length is invalid")
        
    if not re.match(r'^[a-z0-9.\-]+$', domain):
        raise ValueError(f"Domain '{domain}' contains invalid characters")
        
    return domain

def resolve_domain(domain: str) -> Dict[str, Any]:
    """
    Resolve A, AAAA, NS, and MX records for a given domain using dnspython.
    """
    results = {
        "ipv4_addresses": [],
        "ipv6_addresses": [],
        "raw_dns_records": {
            "A": [],
            "AAAA": [],
            "NS": [],
            "MX": []
        }
    }
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    # Resolve A records (IPv4)
    try:
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = rdata.to_text()
            results["ipv4_addresses"].append(ip)
            results["raw_dns_records"]["A"].append(ip)
    except Exception:
        pass
        
    # Resolve AAAA records (IPv6)
    try:
        answers = resolver.resolve(domain, 'AAAA')
        for rdata in answers:
            ip = rdata.to_text()
            results["ipv6_addresses"].append(ip)
            results["raw_dns_records"]["AAAA"].append(ip)
    except Exception:
        pass
        
    # Extract base domain for NS and MX if subdomain provided (simple heuristic)
    parts = domain.split('.')
    base_domain = domain if len(parts) <= 2 else '.'.join(parts[-2:])
        
    # Resolve NS records
    try:
        answers = resolver.resolve(base_domain, 'NS')
        for rdata in answers:
            results["raw_dns_records"]["NS"].append(rdata.to_text())
    except Exception:
        pass
        
    # Resolve MX records
    try:
        answers = resolver.resolve(base_domain, 'MX')
        for rdata in answers:
            results["raw_dns_records"]["MX"].append(rdata.to_text())
    except Exception:
        pass
        
    return results
