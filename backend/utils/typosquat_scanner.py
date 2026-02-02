"""
Domain Typosquatting Scanner
Detects lookalike/phishing domains that impersonate popular brands.
Examples: googe.com, paypa1.com, arnazon.com
"""

from typing import Dict, Any, List, Tuple
import re

# Popular brand domains to check against
POPULAR_BRANDS = {
    # Tech
    "google": ["google.com", "gmail.com", "youtube.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "netflix": ["netflix.com"],
    "spotify": ["spotify.com"],
    "discord": ["discord.com", "discord.gg"],
    "github": ["github.com"],
    "dropbox": ["dropbox.com"],
    
    # Finance
    "paypal": ["paypal.com"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "wellsfargo": ["wellsfargo.com"],
    "citibank": ["citi.com", "citibank.com"],
    "venmo": ["venmo.com"],
    "stripe": ["stripe.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    
    # Shipping
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
    "dhl": ["dhl.com"],
    
    # Other
    "walmart": ["walmart.com"],
    "ebay": ["ebay.com"],
    "adobe": ["adobe.com"],
    "zoom": ["zoom.us"],
}

# Common typosquatting patterns
TYPO_PATTERNS = {
    "letter_swap": [
        ("a", "4"), ("a", "@"), ("a", "e"),
        ("e", "3"), ("e", "i"),
        ("i", "1"), ("i", "l"), ("i", "!"),
        ("l", "1"), ("l", "i"), ("l", "|"),
        ("o", "0"), ("o", "u"),
        ("s", "5"), ("s", "$"),
        ("g", "9"), ("g", "q"),
        ("b", "8"),
        ("t", "7"),
        ("z", "2"),
    ],
    "homoglyphs": [
        ("rn", "m"),  # paypal -> paypa1
        ("vv", "w"),
        ("cl", "d"),
        ("nn", "m"),
    ]
}


def calculate_levenshtein(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return calculate_levenshtein(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def normalize_domain(domain: str) -> str:
    """Normalize domain for comparison."""
    # Remove www prefix
    if domain.startswith("www."):
        domain = domain[4:]
    # Get just the domain name without TLD
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2].lower()  # e.g., "google" from "google.com"
    return domain.lower()


def detect_typosquatting(hostname: str) -> Dict[str, Any]:
    """
    Detect if the domain appears to be a typosquat of a known brand.
    Returns analysis with matches found.
    """
    result = {
        "is_typosquat": False,
        "suspected_brand": None,
        "similarity_score": 0,
        "technique": None,
        "details": []
    }
    
    if not hostname:
        return result
    
    # Normalize the input domain
    domain_name = normalize_domain(hostname)
    
    # Check each brand
    for brand, legit_domains in POPULAR_BRANDS.items():
        # Skip if exact match to legitimate domain
        if any(hostname.endswith(d) or hostname == d for d in legit_domains):
            result["details"].append(f"✓ Legitimate {brand} domain")
            return result
        
        # Check similarity to brand name
        distance = calculate_levenshtein(domain_name, brand)
        similarity = 1 - (distance / max(len(domain_name), len(brand)))
        
        # High similarity but not exact = potential typosquat
        if similarity >= 0.75 and domain_name != brand:
            result["is_typosquat"] = True
            result["suspected_brand"] = brand
            result["similarity_score"] = round(similarity * 100)
            result["technique"] = detect_technique(domain_name, brand)
            result["details"].append(
                f"⚠️ Domain '{domain_name}' is {result['similarity_score']}% similar to '{brand}'"
            )
            return result
        
        # Check for letter substitutions (e.g., g00gle, paypa1)
        if check_letter_substitution(domain_name, brand):
            result["is_typosquat"] = True
            result["suspected_brand"] = brand
            result["similarity_score"] = 95
            result["technique"] = "letter_substitution"
            result["details"].append(
                f"⚠️ Domain uses character substitution to mimic '{brand}'"
            )
            return result
        
        # Check for homoglyphs (rn -> m, etc.)
        if check_homoglyphs(domain_name, brand):
            result["is_typosquat"] = True
            result["suspected_brand"] = brand
            result["similarity_score"] = 90
            result["technique"] = "homoglyph"
            result["details"].append(
                f"⚠️ Domain uses lookalike characters to mimic '{brand}'"
            )
            return result
    
    return result


def check_letter_substitution(domain: str, brand: str) -> bool:
    """Check if domain uses common letter-to-number substitutions."""
    # Normalize domain by replacing common substitutions
    normalized = domain.lower()
    for original, substitution in TYPO_PATTERNS["letter_swap"]:
        normalized = normalized.replace(substitution, original)
    
    # After normalization, if it matches the brand, it's a typosquat
    distance = calculate_levenshtein(normalized, brand)
    return distance <= 1 and normalized != domain


def check_homoglyphs(domain: str, brand: str) -> bool:
    """Check for homoglyph attacks (rn looks like m, etc.)."""
    normalized = domain.lower()
    for fake, real in TYPO_PATTERNS["homoglyphs"]:
        normalized = normalized.replace(fake, real)
    
    distance = calculate_levenshtein(normalized, brand)
    return distance <= 1 and normalized != domain


def detect_technique(domain: str, brand: str) -> str:
    """Identify which typosquatting technique was used."""
    if len(domain) != len(brand):
        if len(domain) > len(brand):
            return "character_insertion"
        else:
            return "character_omission"
    
    # Count differences
    diffs = sum(1 for a, b in zip(domain, brand) if a != b)
    if diffs == 1:
        return "character_swap"
    elif diffs == 2:
        # Check if adjacent characters are swapped
        for i in range(len(domain) - 1):
            if domain[i] == brand[i+1] and domain[i+1] == brand[i]:
                return "adjacent_swap"
        return "character_substitution"
    
    return "multiple_changes"


def get_typosquat_risk_score(hostname: str) -> Tuple[float, List[str]]:
    """
    Get typosquatting risk score and evidence.
    Returns (risk_score from 0-1, list of evidence strings)
    """
    result = detect_typosquatting(hostname)
    
    if result["is_typosquat"]:
        # High risk - definite typosquat detected
        evidence = result["details"]
        evidence.append(f"Suspected impersonation of: {result['suspected_brand']}")
        evidence.append(f"Technique: {result['technique']}")
        return (0.35, evidence)  # Contributes up to 35% to risk score
    
    return (0.0, result["details"])


def format_typosquat_summary(result: Dict[str, Any]) -> str:
    """Format typosquatting result as a human-readable summary."""
    if result["is_typosquat"]:
        return f"⚠️ TYPOSQUAT ALERT: Domain mimics '{result['suspected_brand']}' ({result['similarity_score']}% match)"
    return "✓ No typosquatting detected"
