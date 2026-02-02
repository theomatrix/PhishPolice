"""
Certificate Transparency Monitor
Queries CT logs to check certificate issuance history for domains.
Can alert on suspicious cert patterns for trusted domains.
"""

import requests
from typing import Dict, Any, List
from datetime import datetime, timedelta
import sys

# crt.sh API for CT log queries
CRT_SH_API = "https://crt.sh/"


def check_certificate_transparency(hostname: str) -> Dict[str, Any]:
    """
    Check certificate transparency logs for a domain.
    Returns information about recently issued certificates.
    """
    result = {
        "checked": False,
        "recent_certs_count": 0,
        "certs_last_30_days": 0,
        "multiple_issuers": False,
        "issuers": [],
        "warning": None,
        "details": []
    }
    
    if not hostname:
        return result
    
    try:
        # Query crt.sh for certificate data
        response = requests.get(
            f"{CRT_SH_API}/?q={hostname}&output=json",
            timeout=10,
            headers={"User-Agent": "PhishPolice/2.0"}
        )
        
        if response.status_code != 200:
            result["details"].append("CT log check unavailable")
            return result
        
        certs = response.json()
        result["checked"] = True
        result["recent_certs_count"] = len(certs)
        
        if not certs:
            result["warning"] = "no_certs_found"
            result["details"].append("⚠️ No SSL certificates found in CT logs")
            return result
        
        # Parse certificate data
        issuers = set()
        recent_certs = 0
        thirty_days_ago = datetime.now() - timedelta(days=30)
        
        for cert in certs[:50]:  # Limit to last 50
            issuer = cert.get("issuer_name", "Unknown")
            issuers.add(issuer)
            
            # Check if cert was issued recently
            entry_date_str = cert.get("entry_timestamp", "")
            if entry_date_str:
                try:
                    entry_date = datetime.fromisoformat(entry_date_str.replace("T", " ").split(".")[0])
                    if entry_date > thirty_days_ago:
                        recent_certs += 1
                except:
                    pass
        
        result["issuers"] = list(issuers)[:5]
        result["certs_last_30_days"] = recent_certs
        result["multiple_issuers"] = len(issuers) > 3
        
        # Generate analysis
        if result["multiple_issuers"]:
            result["warning"] = "many_issuers"
            result["details"].append(f"⚠️ {len(issuers)} different cert issuers detected")
        
        if recent_certs > 5:
            result["warning"] = "frequent_reissuance"
            result["details"].append(f"⚠️ {recent_certs} certificates issued in last 30 days")
        
        if result["recent_certs_count"] < 3 and not is_new_domain(hostname):
            result["details"].append("✓ Normal certificate issuance pattern")
        else:
            result["details"].append(f"Found {result['recent_certs_count']} certificates in CT logs")
        
        return result
        
    except requests.Timeout:
        result["details"].append("CT log check timed out")
        return result
    except requests.RequestException as e:
        print(f"[PhishPolice] CT check error: {e}", file=sys.stderr)
        result["details"].append("CT log check failed")
        return result
    except Exception as e:
        print(f"[PhishPolice] CT parse error: {e}", file=sys.stderr)
        return result


def is_new_domain(hostname: str) -> bool:
    """
    Simple heuristic to guess if a domain might be newly registered.
    (In production, you'd check WHOIS or domain age services)
    """
    # Known TLDs often used for new/disposable domains
    suspicious_tlds = [".xyz", ".top", ".work", ".click", ".link", ".online", ".site"]
    return any(hostname.endswith(tld) for tld in suspicious_tlds)


def get_ct_risk_score(hostname: str) -> tuple:
    """
    Get CT-based risk score.
    Returns (risk_score from 0-0.15, list of evidence)
    """
    result = check_certificate_transparency(hostname)
    
    risk = 0.0
    evidence = result["details"]
    
    if result["warning"] == "no_certs_found":
        risk = 0.10  # Suspicious - no certs in CT logs
    elif result["warning"] == "many_issuers":
        risk = 0.08  # Multiple issuers could be suspicious
    elif result["warning"] == "frequent_reissuance":
        risk = 0.05  # Frequent reissuance might indicate issues
    
    return (risk, evidence)


def format_ct_summary(result: Dict[str, Any]) -> str:
    """Format CT check result as summary string."""
    if not result["checked"]:
        return "CT log check unavailable"
    
    if result["warning"] == "no_certs_found":
        return "⚠️ No certificates found in transparency logs"
    elif result["warning"] == "many_issuers":
        return f"⚠️ Multiple cert issuers ({len(result['issuers'])})"
    elif result["warning"] == "frequent_reissuance":
        return f"⚠️ Frequent cert reissuance ({result['certs_last_30_days']} in 30 days)"
    
    return f"✓ CT logs: {result['recent_certs_count']} certs found"
