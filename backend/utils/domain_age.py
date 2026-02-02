"""
Domain Age Checker
Checks domain registration age using WHOIS data.
Newly registered domains are often used for phishing.
"""

import sys
import re
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, List
import socket

# Use whois library if available, otherwise use socket-based fallback
try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


def check_domain_age(hostname: str) -> Dict[str, Any]:
    """
    Check the age of a domain using WHOIS data.
    
    Returns:
        Dict with age info, creation date, and risk assessment
    """
    result = {
        "checked": False,
        "domain": hostname,
        "creation_date": None,
        "age_days": None,
        "age_category": "unknown",  # new, young, established, mature
        "registrar": None,
        "warning": None,
        "details": []
    }
    
    if not hostname:
        return result
    
    # Clean hostname (remove www, subdomains for WHOIS)
    domain = extract_root_domain(hostname)
    result["domain"] = domain
    
    print(f"[PhishPolice] Checking domain age for: {domain}", file=sys.stderr)
    
    if HAS_WHOIS:
        return check_with_whois_lib(domain, result)
    else:
        return check_with_rdap_fallback(domain, result)


def extract_root_domain(hostname: str) -> str:
    """Extract the root domain from a hostname."""
    # Remove www prefix
    if hostname.startswith("www."):
        hostname = hostname[4:]
    
    # Simple extraction - get last two parts for common TLDs
    # For more complex TLDs like .co.uk, this is simplified
    parts = hostname.split(".")
    
    if len(parts) >= 2:
        # Check for common compound TLDs
        compound_tlds = ["co.uk", "com.au", "co.nz", "co.jp", "com.br", "co.in"]
        if len(parts) >= 3:
            potential_compound = f"{parts[-2]}.{parts[-1]}"
            if potential_compound in compound_tlds:
                return f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
        return f"{parts[-2]}.{parts[-1]}"
    
    return hostname


def check_with_whois_lib(domain: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Check domain age using python-whois library."""
    try:
        w = whois.whois(domain)
        
        result["checked"] = True
        
        # Handle creation date (can be list or single value)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            # Ensure it's a datetime object
            if isinstance(creation_date, str):
                creation_date = parse_date_string(creation_date)
            
            if creation_date:
                # Strip timezone info to avoid offset-naive/aware comparison
                if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                    creation_date = creation_date.replace(tzinfo=None)
                
                result["creation_date"] = creation_date.isoformat()
                age_days = (datetime.now() - creation_date).days
                result["age_days"] = age_days
                result["age_category"] = categorize_age(age_days)
                
                # Generate warnings
                if age_days < 30:
                    result["warning"] = "very_new"
                    result["details"].append(f"🚨 Domain registered only {age_days} days ago!")
                elif age_days < 90:
                    result["warning"] = "new"
                    result["details"].append(f"⚠️ Domain is only {age_days} days old")
                elif age_days < 365:
                    result["warning"] = "young"
                    result["details"].append(f"Domain is {age_days} days old (< 1 year)")
                else:
                    years = age_days // 365
                    result["details"].append(f"✓ Domain is {years}+ years old")
        else:
            result["details"].append("Creation date not available in WHOIS")
        
        # Get registrar if available
        if w.registrar:
            result["registrar"] = str(w.registrar)[:100]
        
        return result
        
    except Exception as e:
        print(f"[PhishPolice] WHOIS error for {domain}: {e}", file=sys.stderr)
        result["details"].append("WHOIS lookup failed")
        return result


def check_with_rdap_fallback(domain: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fallback using RDAP (Registration Data Access Protocol) via HTTP.
    RDAP is the modern replacement for WHOIS.
    """
    import requests
    
    try:
        # Use RDAP bootstrap to find the right server
        rdap_url = f"https://rdap.org/domain/{domain}"
        
        response = requests.get(rdap_url, timeout=10, headers={
            "Accept": "application/rdap+json",
            "User-Agent": "PhishPolice/2.1"
        })
        
        if response.status_code != 200:
            result["details"].append("Domain age check unavailable")
            return result
        
        data = response.json()
        result["checked"] = True
        
        # Find registration event
        events = data.get("events", [])
        for event in events:
            if event.get("eventAction") == "registration":
                date_str = event.get("eventDate", "")
                if date_str:
                    creation_date = parse_date_string(date_str)
                    if creation_date:
                        result["creation_date"] = creation_date.isoformat()
                        age_days = (datetime.now() - creation_date).days
                        result["age_days"] = age_days
                        result["age_category"] = categorize_age(age_days)
                        
                        if age_days < 30:
                            result["warning"] = "very_new"
                            result["details"].append(f"🚨 Domain registered only {age_days} days ago!")
                        elif age_days < 90:
                            result["warning"] = "new"
                            result["details"].append(f"⚠️ Domain is only {age_days} days old")
                        elif age_days < 365:
                            result["warning"] = "young"
                            result["details"].append(f"Domain is {age_days} days old (< 1 year)")
                        else:
                            years = age_days // 365
                            result["details"].append(f"✓ Domain is {years}+ years old")
                break
        
        # Get registrar
        entities = data.get("entities", [])
        for entity in entities:
            if "registrar" in entity.get("roles", []):
                result["registrar"] = entity.get("handle", "")[:100]
                break
        
        return result
        
    except Exception as e:
        print(f"[PhishPolice] RDAP error for {domain}: {e}", file=sys.stderr)
        result["details"].append("Domain age check unavailable")
        return result


def parse_date_string(date_str: str) -> datetime:
    """Parse various date string formats."""
    if isinstance(date_str, datetime):
        return date_str
    
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d/%m/%Y",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str[:19], fmt)
        except:
            continue
    
    return None


def categorize_age(age_days: int) -> str:
    """Categorize domain age into risk categories."""
    if age_days < 30:
        return "very_new"
    elif age_days < 90:
        return "new"
    elif age_days < 365:
        return "young"
    elif age_days < 730:
        return "established"
    else:
        return "mature"


def get_domain_age_risk_score(hostname: str) -> Tuple[float, List[str]]:
    """
    Calculate domain age risk contribution.
    Returns (risk_score 0-0.20, evidence list)
    
    Newly registered domains are highly suspicious for phishing.
    """
    result = check_domain_age(hostname)
    
    if not result["checked"] or result["age_days"] is None:
        return (0.0, result["details"])
    
    age_days = result["age_days"]
    evidence = result["details"]
    
    # Risk scoring based on age
    if age_days < 7:
        # Less than a week - extremely suspicious
        return (0.20, evidence)
    elif age_days < 30:
        # Less than a month - very suspicious
        return (0.15, evidence)
    elif age_days < 90:
        # Less than 3 months - suspicious
        return (0.10, evidence)
    elif age_days < 180:
        # Less than 6 months - slightly suspicious
        return (0.05, evidence)
    elif age_days < 365:
        # Less than a year - minor concern
        return (0.02, evidence)
    else:
        # Established domain - low/no risk
        return (0.0, evidence)


def format_domain_age_summary(result: Dict[str, Any]) -> str:
    """Format domain age result for display."""
    if not result["checked"]:
        return "Domain age: Check unavailable"
    
    if result["age_days"] is None:
        return "Domain age: Unknown"
    
    age_days = result["age_days"]
    
    if age_days < 30:
        return f"🚨 Domain Age: {age_days} days (VERY NEW)"
    elif age_days < 90:
        return f"⚠️ Domain Age: {age_days} days (New)"
    elif age_days < 365:
        return f"Domain Age: {age_days} days"
    else:
        years = age_days // 365
        return f"✓ Domain Age: {years}+ years"
