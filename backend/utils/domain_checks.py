import tldextract
from urllib.parse import urlparse
from typing import Dict, Any

def quick_domain_checks(url: str) -> Dict[str, Any]:
    """
    Perform quick domain analysis on a URL.
    Returns domain information including extracted parts and basic analysis.
    """
    result = {
        "domain": "",
        "subdomain": "",
        "suffix": "",
        "full_domain": "",
        "is_ip_address": False,
        "has_suspicious_subdomain": False,
        "has_many_subdomains": False,
        "has_suspicious_tld": False
    }
    
    try:
        # Extract domain parts using tldextract
        info = tldextract.extract(url)
        
        result["domain"] = info.domain
        result["subdomain"] = info.subdomain
        result["suffix"] = info.suffix
        result["full_domain"] = f"{info.domain}.{info.suffix}" if info.suffix else info.domain
        
        # Check if hostname is an IP address
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        
        # Simple IP check (IPv4)
        parts = hostname.split(".")
        if len(parts) == 4:
            try:
                if all(0 <= int(p) <= 255 for p in parts):
                    result["is_ip_address"] = True
            except ValueError:
                pass
        
        # Check for suspicious subdomains (common phishing pattern)
        suspicious_keywords = [
            "secure", "login", "signin", "account", "verify", "update",
            "confirm", "banking", "paypal", "amazon", "google", "microsoft",
            "apple", "netflix", "facebook", "instagram", "support", "help"
        ]
        
        subdomain_lower = info.subdomain.lower()
        if any(keyword in subdomain_lower for keyword in suspicious_keywords):
            result["has_suspicious_subdomain"] = True
        
        # Check for many subdomains (e.g., login.secure.account.bank.example.com)
        subdomain_count = len(info.subdomain.split(".")) if info.subdomain else 0
        if subdomain_count > 2:
            result["has_many_subdomains"] = True
        
        # Check for suspicious TLDs often used in phishing
        suspicious_tlds = [
            "tk", "ml", "ga", "cf", "gq",  # Free TLDs
            "xyz", "top", "work", "click", "link", "buzz",
            "online", "site", "website", "space", "fun"
        ]
        
        if info.suffix.lower() in suspicious_tlds:
            result["has_suspicious_tld"] = True
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def format_domain_summary(domain_info: Dict[str, Any]) -> str:
    """Format domain info as a human-readable summary."""
    parts = []
    
    if domain_info.get("is_ip_address"):
        parts.append("⚠️ Using IP address instead of domain name")
    
    if domain_info.get("has_suspicious_subdomain"):
        parts.append(f"⚠️ Suspicious subdomain detected: {domain_info.get('subdomain', '')}")
    
    if domain_info.get("has_many_subdomains"):
        parts.append("⚠️ Unusual number of subdomains")
    
    if domain_info.get("has_suspicious_tld"):
        parts.append(f"⚠️ Suspicious TLD: .{domain_info.get('suffix', '')}")
    
    if not parts:
        return f"Domain: {domain_info.get('full_domain', 'Unknown')}"
    
    return " | ".join(parts)
