"""
TLS Scanning Engine — Quantum-Proof Systems Scanner
Team CypherRed261 — PSB Hackathon 2026

Uses sslyze to perform real TLS handshake analysis and
cryptography to parse X.509 certificate details.
"""

import time
import re
from datetime import datetime, timezone
from typing import Optional

from sslyze import (
    ServerNetworkLocation,
    Scanner,
    ServerScanRequest,
    ScanCommand,
)
from sslyze.errors import (
    ConnectionToServerFailed,
    ServerHostnameCouldNotBeResolved,
)
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

from models import TLSInfo, CertificateInfo, CBOMEntry, PQCAssessment
from quantum_validator import classify_tls_scan

# Maximum time (seconds) to wait for a scan before giving up
SCAN_TIMEOUT_SECONDS = 15


def sanitize_domain(raw_input: str) -> str:
    """
    Clean and validate domain/IP input from the user.

    Strips protocol prefixes, paths, ports, and whitespace.
    Raises ValueError if input looks invalid after cleaning.
    """
    domain = raw_input.strip().lower()

    # Remove protocol prefix
    domain = re.sub(r'^https?://', '', domain)

    # Remove path, query string, fragment
    domain = domain.split('/')[0].split('?')[0].split('#')[0]

    # Remove port number
    domain = domain.split(':')[0]

    # Basic length and character validation
    if len(domain) < 3 or len(domain) > 253:
        raise ValueError(f"Domain '{domain}' length is invalid")

    # Allow: letters, digits, dots, hyphens (IPv4 too)
    if not re.match(r'^[a-z0-9.\-]+$', domain):
        raise ValueError(f"Domain '{domain}' contains invalid characters")

    return domain


async def scan_domain(raw_domain: str) -> dict:
    """
    Perform a full TLS scan on the given domain and return a structured result.

    Args:
        raw_domain: User-supplied domain or IP (may include http:// prefix etc.)

    Returns:
        Dictionary matching the ScanResult Pydantic model structure.

    Raises:
        ValueError: If the domain input is invalid.
        Exception:  If the scan fails (connection refused, timeout, etc.)
    """
    start_time = time.time()

    # Sanitize input
    domain = sanitize_domain(raw_domain)

    try:
        # ── SSLYZE SCAN ──────────────────────────────────────
        server_location = ServerNetworkLocation(domain, 443)

        scanner = Scanner()
        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
            }
        )
        scanner.queue_scans([scan_request])

        scan_result = None
        for result in scanner.get_results():
            scan_result = result
            break  # We only submitted one scan

        if scan_result is None:
            raise Exception(f"No scan result returned for {domain}")

        # Check for connectivity errors
        if scan_result.connectivity_error_trace:
            raise Exception(
                f"Cannot connect to {domain}:443 — "
                f"{scan_result.connectivity_error_trace}"
            )

        # ── PARSE TLS INFO ────────────────────────────────────
        tls_info = _extract_tls_info(scan_result, domain)

        # ── PARSE CERTIFICATE ────────────────────────────────
        cert_info = _extract_cert_info(scan_result)

        # ── PQC ASSESSMENT ────────────────────────────────────
        pqc: PQCAssessment = classify_tls_scan(
            tls_version=tls_info["version"],
            cipher_suite=tls_info["cipher_suite"],
            key_type=tls_info["public_key_type"],
            key_size_bits=tls_info.get("key_size_bits", 0)
        )

        # ── CBOM ENTRY ────────────────────────────────────────
        cbom = CBOMEntry(
            asset=domain,
            key_length=tls_info["key_size"],
            cipher_suite=tls_info["cipher_suite"],
            tls_version=tls_info["version"],
            certificate_authority=cert_info.get("issuer", "Unknown"),
            quantum_safe=not pqc.quantum_vulnerable
        )

        duration_ms = int((time.time() - start_time) * 1000)

        return {
            "domain": domain,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "tls": tls_info,
            "certificate": cert_info,
            "pqc": pqc.model_dump(),
            "cbom": cbom.model_dump(),
            "scan_duration_ms": duration_ms
        }

    except ServerHostnameCouldNotBeResolved:
        raise Exception(
            f"DNS resolution failed for '{domain}' — "
            f"check the domain name and try again"
        )
    except ConnectionToServerFailed as e:
        raise Exception(
            f"Connection refused to {domain}:443 — "
            f"server may be offline or blocking TLS probes"
        )
    except ValueError:
        raise
    except Exception as e:
        raise Exception(f"Scan failed for {domain}: {str(e)}")


def _extract_tls_info(scan_result, domain: str) -> dict:
    """
    Extract TLS version, cipher suite, and key information
    from the sslyze scan result.

    Priority order: TLS 1.3 > TLS 1.2 > TLS 1.1 > TLS 1.0 > SSL 3.0
    """
    # Map of version name → sslyze result attribute
    version_checks = [
        ("TLS 1.3", "tls_1_3_cipher_suites"),
        ("TLS 1.2", "tls_1_2_cipher_suites"),
        ("TLS 1.1", "tls_1_1_cipher_suites"),
        ("TLS 1.0", "tls_1_0_cipher_suites"),
        ("SSL 3.0", "ssl_3_0_cipher_suites"),
    ]

    tls_version = "Unknown"
    cipher_suite = "Unknown"

    for version_name, attr_name in version_checks:
        try:
            result_attr = getattr(scan_result.scan_result, attr_name, None)
            if result_attr is None or isinstance(result_attr, Exception):
                continue
            accepted = result_attr.result.accepted_cipher_suites
            if accepted:
                tls_version = version_name
                cipher_suite = accepted[0].cipher_suite.name
                break
        except Exception:
            continue

    # Extract key details from certificate
    key_type = "RSA"
    key_size = "2048-bit"
    key_size_bits = 2048
    key_exchange = "RSA (Static)"
    sig_hash = "SHA-256 with RSA"

    try:
        cert_result = scan_result.scan_result.certificate_info
        if cert_result and not isinstance(cert_result, Exception):
            deployments = cert_result.result.certificate_deployments
            if deployments:
                chain = deployments[0].received_certificate_chain
                if chain:
                    cert = chain[0]
                    pub_key = cert.public_key()
                    sig_algo = cert.signature_algorithm_oid.dotted_string

                    if isinstance(pub_key, rsa.RSAPublicKey):
                        key_type = "RSA"
                        key_size_bits = pub_key.key_size
                        key_size = f"{key_size_bits}-bit"
                        if tls_version == "TLS 1.3":
                            key_exchange = "ECDHE (X25519)"
                        elif tls_version == "TLS 1.2":
                            # Check cipher for ECDHE
                            if "ECDHE" in cipher_suite:
                                key_exchange = "ECDHE-RSA"
                            else:
                                key_exchange = "RSA (Static)"
                        else:
                            key_exchange = "RSA (Static)"
                        sig_hash = "SHA-256 with RSA"

                    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                        curve_name = pub_key.curve.name
                        key_type = "ECDSA"
                        key_size_bits = pub_key.key_size
                        key_size = f"{key_size_bits}-bit ({curve_name})"
                        key_exchange = "ECDHE (X25519)" if tls_version == "TLS 1.3" else "ECDHE"
                        sig_hash = "SHA-256 with ECDSA"

                    elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                        key_type = "EdDSA"
                        key_size = "256-bit (Ed25519)" if isinstance(pub_key, ed25519.Ed25519PublicKey) else "448-bit (Ed448)"
                        key_size_bits = 256
                        key_exchange = "X25519"
                        sig_hash = "EdDSA"

                    elif isinstance(pub_key, dsa.DSAPublicKey):
                        key_type = "DSA"
                        key_size_bits = pub_key.key_size
                        key_size = f"{key_size_bits}-bit"
                        key_exchange = "DHE"
                        sig_hash = "SHA-256 with DSA"

    except Exception:
        pass  # Use defaults if cert parsing fails

    return {
        "version": tls_version,
        "cipher_suite": cipher_suite,
        "key_exchange": key_exchange,
        "public_key_type": key_type,
        "key_size": key_size,
        "key_size_bits": key_size_bits,
        "signature_hash": sig_hash
    }


def _extract_cert_info(scan_result) -> dict:
    """
    Parse X.509 certificate details from the sslyze scan result.

    Returns a dict matching the CertificateInfo model.
    Falls back to safe defaults if parsing fails.
    """
    defaults = {
        "subject": "Unknown",
        "issuer": "Unknown CA",
        "valid_from": "Unknown",
        "valid_until": "Unknown",
        "days_remaining": 0,
        "is_expired": False,
        "is_expiring_soon": False
    }

    try:
        cert_result = scan_result.scan_result.certificate_info
        if not cert_result or isinstance(cert_result, Exception):
            return defaults

        deployments = cert_result.result.certificate_deployments
        if not deployments:
            return defaults

        chain = deployments[0].received_certificate_chain
        if not chain:
            return defaults

        cert = chain[0]

        # Extract readable subject CN
        subject_cn = "Unknown"
        try:
            for attr in cert.subject:
                if attr.oid.dotted_string == "2.5.4.3":  # commonName
                    subject_cn = attr.value
                    break
            if subject_cn == "Unknown":
                subject_cn = cert.subject.rfc4514_string()
        except Exception:
            subject_cn = "Unknown"

        # Extract readable issuer CN
        issuer_cn = "Unknown CA"
        try:
            for attr in cert.issuer:
                if attr.oid.dotted_string == "2.5.4.3":  # commonName
                    issuer_cn = attr.value
                    break
            # Fallback: try Organisation name
            if issuer_cn == "Unknown CA":
                for attr in cert.issuer:
                    if attr.oid.dotted_string == "2.5.4.10":  # organisationName
                        issuer_cn = attr.value
                        break
        except Exception:
            issuer_cn = "Unknown CA"

        # Parse dates — handle both aware and naive datetimes
        now = datetime.now(timezone.utc)

        try:
            valid_from = cert.not_valid_before_utc
        except AttributeError:
            from datetime import timezone as tz
            valid_from = cert.not_valid_before.replace(tzinfo=timezone.utc)

        try:
            valid_until = cert.not_valid_after_utc
        except AttributeError:
            valid_until = cert.not_valid_after.replace(tzinfo=timezone.utc)

        days_remaining = (valid_until - now).days

        return {
            "subject": subject_cn,
            "issuer": issuer_cn,
            "valid_from": valid_from.strftime("%Y-%m-%d"),
            "valid_until": valid_until.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
            "is_expired": days_remaining < 0,
            "is_expiring_soon": 0 <= days_remaining <= 30
        }

    except Exception:
        return defaults
