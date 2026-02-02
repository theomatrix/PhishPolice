import ssl
import socket
import datetime
from urllib.parse import urlparse
from typing import Dict, Any, Optional

def get_ssl_certificate_info(url: str) -> Dict[str, Any]:
    """
    Fetch and analyze SSL certificate for a given URL.
    Returns certificate details including validity, issuer, and security assessment.
    """
    result = {
        "has_ssl": False,
        "is_valid": False,
        "issuer": None,
        "subject": None,
        "expires_in_days": None,
        "issued_days_ago": None,
        "is_self_signed": False,
        "is_expired": False,
        "is_expiring_soon": False,
        "certificate_error": None,
        "security_score": 0  # 0-100
    }
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        if not hostname:
            result["certificate_error"] = "Invalid URL - no hostname"
            return result
        
        # Skip non-HTTPS URLs
        if parsed.scheme != "https":
            result["certificate_error"] = "Not using HTTPS"
            result["security_score"] = 20  # Very low score for HTTP
            return result
        
        # Create SSL context
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if not cert:
                        result["certificate_error"] = "No certificate returned"
                        return result
                    
                    result["has_ssl"] = True
                    
                    # Parse issuer
                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    result["issuer"] = issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Unknown'))
                    
                    # Parse subject
                    subject_dict = dict(x[0] for x in cert.get('subject', []))
                    result["subject"] = subject_dict.get('commonName', 'Unknown')
                    
                    # Check if self-signed
                    result["is_self_signed"] = result["issuer"] == result["subject"]
                    
                    # Parse dates
                    not_after = cert.get('notAfter')
                    not_before = cert.get('notBefore')
                    
                    if not_after:
                        expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        now = datetime.datetime.utcnow()
                        days_until_expiry = (expiry_date - now).days
                        result["expires_in_days"] = days_until_expiry
                        result["is_expired"] = days_until_expiry < 0
                        result["is_expiring_soon"] = 0 <= days_until_expiry <= 30
                    
                    if not_before:
                        issue_date = datetime.datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                        now = datetime.datetime.utcnow()
                        result["issued_days_ago"] = (now - issue_date).days
                    
                    # Certificate is valid if we got here without errors
                    result["is_valid"] = True
                    
                    # Calculate security score
                    result["security_score"] = calculate_ssl_security_score(result)
                    
        except ssl.SSLCertVerificationError as e:
            result["certificate_error"] = f"Certificate verification failed: {str(e)}"
            result["has_ssl"] = True
            result["is_valid"] = False
            result["security_score"] = 15  # Very low for invalid cert
            
        except ssl.SSLError as e:
            result["certificate_error"] = f"SSL error: {str(e)}"
            result["security_score"] = 10
            
    except socket.timeout:
        result["certificate_error"] = "Connection timeout"
        result["security_score"] = 30
        
    except socket.gaierror:
        result["certificate_error"] = "DNS resolution failed"
        result["security_score"] = 25
        
    except ConnectionRefusedError:
        result["certificate_error"] = "Connection refused"
        result["security_score"] = 20
        
    except Exception as e:
        result["certificate_error"] = f"Error: {str(e)}"
        result["security_score"] = 25
    
    return result


def calculate_ssl_security_score(cert_info: Dict[str, Any]) -> int:
    """Calculate a security score (0-100) based on SSL certificate properties."""
    score = 0
    
    if not cert_info.get("has_ssl"):
        return 20  # No SSL is a big red flag
    
    if not cert_info.get("is_valid"):
        return 15  # Invalid cert is worse than no SSL
    
    # Base score for valid SSL
    score = 60
    
    # Self-signed certificates are suspicious
    if cert_info.get("is_self_signed"):
        score -= 30
    
    # Expired certificates
    if cert_info.get("is_expired"):
        score -= 40
    elif cert_info.get("is_expiring_soon"):
        score -= 10
    
    # Newly issued certificates (less than 7 days) can be suspicious
    issued_days = cert_info.get("issued_days_ago", 365)
    if issued_days is not None and issued_days < 7:
        score -= 15
    elif issued_days is not None and issued_days < 30:
        score -= 5
    
    # Bonus for well-known issuers
    issuer = (cert_info.get("issuer") or "").lower()
    trusted_issuers = ["let's encrypt", "digicert", "comodo", "godaddy", "globalsign", 
                       "sectigo", "entrust", "geotrust", "thawte", "verisign", "google"]
    
    if any(ti in issuer for ti in trusted_issuers):
        score += 20
    
    # Long validity remaining is good
    expires_in = cert_info.get("expires_in_days", 0)
    if expires_in and expires_in > 180:
        score += 10
    elif expires_in and expires_in > 90:
        score += 5
    
    return max(0, min(100, score))


def format_ssl_summary(cert_info: Dict[str, Any]) -> str:
    """Format SSL certificate info as a human-readable summary."""
    if not cert_info.get("has_ssl"):
        if cert_info.get("certificate_error") == "Not using HTTPS":
            return "⚠️ Site uses HTTP (unencrypted) - not HTTPS"
        return f"❌ No SSL: {cert_info.get('certificate_error', 'Unknown error')}"
    
    if not cert_info.get("is_valid"):
        return f"❌ Invalid SSL certificate: {cert_info.get('certificate_error', 'Verification failed')}"
    
    parts = []
    
    if cert_info.get("is_expired"):
        parts.append("❌ EXPIRED certificate")
    elif cert_info.get("is_expiring_soon"):
        parts.append(f"⚠️ Expires in {cert_info.get('expires_in_days')} days")
    else:
        parts.append(f"✅ Valid SSL ({cert_info.get('expires_in_days', '?')} days remaining)")
    
    if cert_info.get("is_self_signed"):
        parts.append("⚠️ Self-signed certificate")
    else:
        parts.append(f"Issuer: {cert_info.get('issuer', 'Unknown')}")
    
    issued_days = cert_info.get("issued_days_ago")
    if issued_days is not None and issued_days < 7:
        parts.append(f"⚠️ Newly issued ({issued_days} days ago)")
    
    return " | ".join(parts)
