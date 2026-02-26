import os
import sys
import json
import requests
from typing import Dict, Any, List, Optional
from pathlib import Path

# Load .env from the backend directory
def load_env():
    """Load environment variables from .env file."""
    env_path = Path(__file__).parent.parent / '.env'
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()

# Load env on import
load_env()

NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "").strip()
# Using NVIDIA Mistral Small 3.1 24B - fast, multimodal model
NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
NVIDIA_MODEL = "mistralai/mistral-small-3.1-24b-instruct-2503"

# Configuration
ENABLE_AI_ANALYSIS = True
AI_TIMEOUT = 10  # Timeout in seconds

def analyze_with_llm(
    url: str,
    hostname: str,
    ssl_info: Dict[str, Any],
    domain_info: Dict[str, Any],
    forms: List[Dict],
    suspicious_patterns: List[str] = None,
    dom_analysis: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Use NVIDIA Mistral Small 3.1 24B to analyze webpage for phishing indicators.
    Returns structured analysis with verdict, confidence, and explanation.
    Falls back gracefully if API is unavailable.
    """
    
    if not ENABLE_AI_ANALYSIS:
        return {
            "summary": "AI analysis disabled",
            "risk_factors": [],
            "recommendation": "Review security details below"
        }
    
    api_key = NVIDIA_API_KEY or os.environ.get("NVIDIA_API_KEY", "").strip()
    
    if not api_key:
        return {
            "summary": "AI analysis unavailable - API key not configured",
            "risk_factors": [],
            "recommendation": "Configure NVIDIA_API_KEY in .env file"
        }
    
    prompt = build_analysis_prompt(url, hostname, ssl_info, domain_info, forms, suspicious_patterns, dom_analysis)
    
    try:
        response = requests.post(
            NVIDIA_API_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json"
            },
            json={
                "model": NVIDIA_MODEL,
                "messages": [{
                    "role": "user",
                    "content": prompt
                }],
                "max_tokens": 512,
                "temperature": 0.20,
                "top_p": 0.70,
                "frequency_penalty": 0.00,
                "presence_penalty": 0.00,
                "stream": False
            },
            timeout=(3, AI_TIMEOUT)
        )
        
        if response.status_code == 429:
            return {
                "summary": "AI rate limit reached - using security checks only",
                "risk_factors": [],
                "recommendation": "Wait a moment and scan again"
            }
        
        if response.status_code == 401:
            return {
                "summary": "AI authentication failed - check API key",
                "risk_factors": [],
                "recommendation": "Verify NVIDIA_API_KEY in .env file"
            }
        
        if response.status_code != 200:
            return {
                "summary": f"AI unavailable (HTTP {response.status_code}) - using security checks only",
                "risk_factors": [],
                "recommendation": "Review security details below"
            }
        
        data = response.json()
        choices = data.get("choices", [])
        
        if not choices:
            return {
                "summary": "AI returned no response - using security checks only",
                "risk_factors": [],
                "recommendation": "Review security details below"
            }
        
        message = choices[0].get("message", {})
        llm_response = message.get("content", "")
        
        if not llm_response:
            return {
                "summary": "AI response was empty - using security checks only",
                "risk_factors": [],
                "recommendation": "Review security details below"
            }
        
        return parse_llm_response(llm_response)
        
    except requests.Timeout:
        return {
            "summary": "AI analysis timed out - using security checks only",
            "risk_factors": [],
            "recommendation": "Review security details below"
        }
    except requests.ConnectionError:
        return {
            "summary": "AI service unreachable - using security checks only",
            "risk_factors": [],
            "recommendation": "Review security details below"
        }
    except requests.RequestException:
        return {
            "summary": "AI request failed - using security checks only",
            "risk_factors": [],
            "recommendation": "Review security details below"
        }
    except Exception:
        return {
            "summary": "AI analysis error - using security checks only",
            "risk_factors": [],
            "recommendation": "Review security details below"
        }


def build_analysis_prompt(
    url: str,
    hostname: str,
    ssl_info: Dict[str, Any],
    domain_info: Dict[str, Any],
    forms: List[Dict],
    suspicious_patterns: List[str] = None,
    dom_analysis: Dict[str, Any] = None
) -> str:
    """Build a structured prompt for phishing analysis."""
    
    password_forms = sum(1 for f in forms if f.get("hasPassword") or f.get("has_password"))
    email_forms = sum(1 for f in forms if f.get("hasEmail") or f.get("has_email"))
    external_action_forms = sum(1 for f in forms if f.get("submitsToDifferentDomain"))
    
    domain_flags = []
    if domain_info.get("is_ip_address"):
        domain_flags.append("Uses IP address instead of domain")
    if domain_info.get("has_suspicious_subdomain"):
        domain_flags.append(f"Suspicious subdomain: {domain_info.get('subdomain', '')}")
    if domain_info.get("has_suspicious_tld"):
        domain_flags.append(f"Suspicious TLD: .{domain_info.get('suffix', '')}")
    if domain_info.get("has_many_subdomains"):
        domain_flags.append("Unusually many subdomains")
    
    dom_flags = []
    if dom_analysis:
        if dom_analysis.get("hidden_iframes", 0) > 0:
            dom_flags.append(f"{dom_analysis.get('hidden_iframes')} hidden iframes detected")
        if dom_analysis.get("external_links_ratio", 0) > 0.7:
            dom_flags.append("High ratio of external links")

    prompt = f"""You are PhishPolice AI, a cybersecurity expert analyzing a webpage for phishing indicators.

WEBPAGE DATA:
- URL: {url}
- Hostname: {hostname}

SSL CERTIFICATE:
- Status: {"Valid ✓" if ssl_info.get("is_valid") else "Invalid/Missing ✗"} 
- Issuer: {ssl_info.get("issuer", "Unknown")}
- Expires in: {ssl_info.get("expires_in_days", "Unknown")} days
- Self-Signed: {"Yes ⚠️" if ssl_info.get("is_self_signed") else "No"}

DOMAIN ANALYSIS:
- Registered Domain: {domain_info.get("domain", hostname)}.{domain_info.get("suffix", "")}
- Subdomain: {domain_info.get("subdomain", "None")}
- Domain Flags: {", ".join(domain_flags) if domain_flags else "None"}

FORM ANALYSIS:
- Password input forms: {password_forms}
- Email input forms: {email_forms}
- Forms submitting to external domains: {external_action_forms}

PAGE BEHAVIOR:
- Suspicious patterns: {", ".join(suspicious_patterns[:5]) if suspicious_patterns else "None detected"}
- DOM flags: {", ".join(dom_flags) if dom_flags else "None"}

ANALYSIS TASK:
Analyze ALL factors above holistically. Consider:
1. URL typosquatting or brand impersonation attempts
2. SSL certificate legitimacy and issuer reputation
3. Domain age indicators and TLD reputation
4. Form behavior (collecting credentials, external submission)
5. Page structure anomalies

RESPOND IN THIS EXACT FORMAT:
SUMMARY: [One clear sentence about the security status - be specific, max 120 chars]
RISK_FACTORS: [Comma-separated specific risks found, or "None identified"]
RECOMMENDATION: [One actionable user recommendation - max 80 chars]"""

    return prompt


def parse_llm_response(response_text: str) -> Dict[str, Any]:
    """Parse the structured LLM response into a dictionary."""
    result = {
        "summary": "",
        "risk_factors": [],
        "recommendation": ""
    }
    
    lines = response_text.strip().split("\n")
    
    for line in lines:
        line = line.strip()
        if line.upper().startswith("SUMMARY:"):
            result["summary"] = line[8:].strip()
        elif line.upper().startswith("RISK_FACTORS:"):
            factors_str = line[13:].strip()
            if factors_str.lower() not in ("none identified", "none", "none detected"):
                result["risk_factors"] = [f.strip() for f in factors_str.split(",") if f.strip()]
        elif line.upper().startswith("RECOMMENDATION:"):
            result["recommendation"] = line[15:].strip()
    
    if not result["summary"]:
        result["summary"] = response_text[:150].replace("\n", " ").strip()
        if len(response_text) > 150:
            result["summary"] += "..."
    
    return result


def summarize_with_llm(url: str, domain_info: Dict, visual_info: Dict, forms: List) -> str:
    """Legacy function for backwards compatibility."""
    ssl_info = {"is_valid": True, "issuer": "Unknown"}
    analysis = analyze_with_llm(url, "", ssl_info, domain_info, forms)
    return analysis.get("summary", "Analysis unavailable")
