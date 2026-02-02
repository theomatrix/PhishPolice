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

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
# Using Gemini 2.5 Flash Lite - efficient and fast
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent"

def analyze_with_gemini(
    url: str,
    hostname: str,
    ssl_info: Dict[str, Any],
    domain_info: Dict[str, Any],
    forms: List[Dict],
    suspicious_patterns: List[str] = None,
    dom_analysis: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Use Gemini 1.5 Flash to analyze the webpage and provide a phishing assessment.
    Returns a structured analysis with verdict, confidence, and explanation.
    """
    
    # Re-check env in case it wasn't loaded at module import time
    api_key = GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY", "").strip()
    
    print(f"[PhishPolice] API Key loaded: {'Yes' if api_key else 'No'}", file=sys.stderr)
    
    if not api_key:
        print("[PhishPolice] ERROR: No API key found!", file=sys.stderr)
        return {
            "summary": "AI analysis unavailable - API key not configured",
            "risk_factors": [],
            "recommendation": "Configure GEMINI_API_KEY in .env file"
        }
    
    # Build context for the LLM
    prompt = build_analysis_prompt(url, hostname, ssl_info, domain_info, forms, suspicious_patterns, dom_analysis)
    
    print(f"[PhishPolice] Making Gemini API call for: {hostname}", file=sys.stderr)
    
    try:
        # Retry logic for rate limiting
        max_retries = 2
        retry_delay = 3  # seconds
        
        for attempt in range(max_retries):
            print(f"[PhishPolice] API attempt {attempt + 1}/{max_retries}", file=sys.stderr)
            
            response = requests.post(
                f"{GEMINI_API_URL}?key={api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{
                        "parts": [{"text": prompt}]
                    }],
                    "generationConfig": {
                        "temperature": 0.2,
                        "maxOutputTokens": 300,
                        "topP": 0.8
                    }
                },
                timeout=25
            )
            
            print(f"[PhishPolice] API response status: {response.status_code}", file=sys.stderr)
            
            # Handle rate limiting with retry
            if response.status_code == 429:
                print(f"[PhishPolice] Rate limited, waiting {retry_delay * (attempt + 1)}s...", file=sys.stderr)
                if attempt < max_retries - 1:
                    import time
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                else:
                    return {
                        "summary": "AI rate limit reached. Analysis based on security checks only.",
                        "risk_factors": ["Rate limited - try again in a minute"],
                        "recommendation": "Wait a moment and scan again for AI insights"
                    }
            
            # Success or other error - break retry loop
            break
        
        if response.status_code != 200:
            error_detail = response.text[:200] if response.text else "Unknown error"
            print(f"Gemini API error: {response.status_code} - {error_detail}", file=sys.stderr)
            return {
                "summary": f"AI analysis unavailable (code {response.status_code}). Using security checks only.",
                "risk_factors": [],
                "recommendation": "Review security details below"
            }
        
        data = response.json()
        
        # Extract the generated text
        candidates = data.get("candidates", [])
        if not candidates:
            return {
                "summary": "AI returned no response",
                "risk_factors": [],
                "recommendation": "Try scanning again"
            }
        
        content = candidates[0].get("content", {})
        parts = content.get("parts", [])
        if not parts:
            return {
                "summary": "AI response was empty",
                "risk_factors": [],
                "recommendation": "Try scanning again"
            }
        
        llm_response = parts[0].get("text", "")
        
        # Parse the structured response
        return parse_llm_response(llm_response)
        
    except requests.Timeout:
        return {
            "summary": "AI analysis timed out",
            "risk_factors": [],
            "recommendation": "Try scanning again"
        }
    except requests.RequestException as e:
        print(f"Gemini request error: {e}", file=sys.stderr)
        return {
            "summary": f"AI request failed",
            "risk_factors": [],
            "recommendation": "Check internet connection"
        }
    except Exception as e:
        print(f"Gemini analysis error: {e}", file=sys.stderr)
        return {
            "summary": f"AI analysis error",
            "risk_factors": [],
            "recommendation": "Try scanning again"
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
    
    # Count form types
    password_forms = sum(1 for f in forms if f.get("hasPassword") or f.get("has_password"))
    email_forms = sum(1 for f in forms if f.get("hasEmail") or f.get("has_email"))
    external_action_forms = sum(1 for f in forms if f.get("submitsToDifferentDomain"))
    
    # Domain analysis
    domain_flags = []
    if domain_info.get("is_ip_address"):
        domain_flags.append("Uses IP address instead of domain")
    if domain_info.get("has_suspicious_subdomain"):
        domain_flags.append(f"Suspicious subdomain: {domain_info.get('subdomain', '')}")
    if domain_info.get("has_suspicious_tld"):
        domain_flags.append(f"Suspicious TLD: .{domain_info.get('suffix', '')}")
    if domain_info.get("has_many_subdomains"):
        domain_flags.append("Unusually many subdomains")
    
    # DOM analysis
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
    
    # Fallback if parsing failed
    if not result["summary"]:
        result["summary"] = response_text[:150].replace("\n", " ").strip()
        if len(response_text) > 150:
            result["summary"] += "..."
    
    return result


def summarize_with_llm(url: str, domain_info: Dict, visual_info: Dict, forms: List) -> str:
    """Legacy function for backwards compatibility."""
    ssl_info = {"is_valid": True, "issuer": "Unknown"}
    analysis = analyze_with_gemini(url, "", ssl_info, domain_info, forms)
    return analysis.get("summary", "Analysis unavailable")
