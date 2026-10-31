import os
import sys
import json
import requests
from typing import Dict, Any, List, Optional
from pathlib import Path

# Load .env from the backend directory
def load_env():
    """Load environment variables from .env file without overriding existing env vars."""
    env_path = Path(__file__).parent.parent / '.env'
    if env_path.exists():
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    k = key.strip()
                    if k not in os.environ:
                        val = value.strip().strip('"').strip("'")
                        os.environ[k] = val

# Load env on import
load_env()

# Configuration
ENABLE_AI_ANALYSIS = True
AI_TIMEOUT = int(os.environ.get("AI_TIMEOUT", 10))  # Default 10s timeout for LLM analysis

# NVIDIA NIM Configuration
DEFAULT_NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
DEFAULT_NVIDIA_MODEL = "z-ai/glm-5.3-flash"

NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "").strip()
NVIDIA_API_URL = os.environ.get("NVIDIA_API_URL", DEFAULT_NVIDIA_URL).strip()
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", DEFAULT_NVIDIA_MODEL).strip()


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
    Analyze webpage for phishing indicators using NVIDIA NIM (Mistral Large).
    Returns structured analysis with summary, risk factors, and recommendation.
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
        print(f"ℹ️  [AI] No NVIDIA API key configured in .env (skipping AI analysis)", file=sys.stderr)
        return {
            "summary": "AI analysis unavailable",
            "risk_factors": [],
            "recommendation": "AI is not available, check the report below"
        }
    
    raw_url = NVIDIA_API_URL or DEFAULT_NVIDIA_URL
    api_url = raw_url if raw_url.endswith("/chat/completions") else f"{raw_url.rstrip('/')}/chat/completions"
    model_name = NVIDIA_MODEL or DEFAULT_NVIDIA_MODEL
    
    print(f"🤖 [AI] Analyzing {hostname} using NVIDIA NIM ({model_name})...", file=sys.stderr)
    
    prompt = build_analysis_prompt(url, hostname, ssl_info, domain_info, forms, suspicious_patterns, dom_analysis)
    
    try:
        response = requests.post(
            api_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            json={
                "model": model_name,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert analyzing webpage phishing risk. Respond directly in the required format without lengthy chain-of-thought."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "max_tokens": 1024,
                "temperature": 0.20,
                "stream": False
            },
            timeout=(3, AI_TIMEOUT)
        )
        
        if response.status_code == 429:
            print(f"⚠️  [AI Warning] NVIDIA NIM rate limit reached (HTTP 429)", file=sys.stderr)
            return {
                "summary": "AI rate limit reached - using security checks only",
                "risk_factors": [],
                "recommendation": "Wait a moment and scan again"
            }
        
        if response.status_code == 401:
            print(f"❌ [AI Error] NVIDIA NIM authentication failed (HTTP 401). Check API key.", file=sys.stderr)
            return {
                "summary": "AI authentication failed - check API key",
                "risk_factors": [],
                "recommendation": "Verify API key in .env file"
            }
            
        if response.status_code == 404:
            err_text = response.text[:200]
            print(f"❌ [AI Error] NVIDIA NIM returned 404: {err_text}", file=sys.stderr)
            return {
                "summary": "NVIDIA model or endpoint not found (HTTP 404)",
                "risk_factors": [],
                "recommendation": "Check model name and provider endpoint"
            }
        
        if response.status_code != 200:
            print(f"❌ [AI Error] NVIDIA NIM returned HTTP {response.status_code}: {response.text[:150]}", file=sys.stderr)
            return {
                "summary": f"AI unavailable (HTTP {response.status_code}) - using security checks only",
                "risk_factors": [],
                "recommendation": "Review security details below"
            }
        
        data = response.json()
        choices = data.get("choices", [])
        
        if not choices:
            print(f"⚠️  [AI Warning] NVIDIA NIM returned empty choices list", file=sys.stderr)
            return {
                "summary": "AI returned no response - using security checks only",
                "risk_factors": [],
                "recommendation": "Review security details below"
            }
        
        message = choices[0].get("message", {})
        llm_response = message.get("content") or ""
        
        # If content is empty because reasoning exhausted or used reasoning_content, fall back to reasoning_content
        if not llm_response and message.get("reasoning_content"):
            llm_response = message.get("reasoning_content", "")
        
        if not llm_response:
            print(f"⚠️  [AI Warning] NVIDIA NIM returned empty message content", file=sys.stderr)
            return {
                "summary": "AI response was empty - using security checks only",
                "risk_factors": [],
                "recommendation": "Review security details below"
            }
        
        parsed = parse_llm_response(llm_response)
        parsed["model"] = "GLM 5.3 Flash" if "glm" in model_name.lower() else model_name.split("/")[-1]
        print(f"✅ [AI] NVIDIA analysis complete: {parsed.get('summary', '')[:60]}...", file=sys.stderr)
        return parsed
        
    except requests.Timeout:
        print(f"⚠️  [AI Warning] NVIDIA NIM timed out after {AI_TIMEOUT}s", file=sys.stderr)
        return {
            "summary": "AI analysis timed out - using security checks only",
            "risk_factors": [],
            "recommendation": "Review security details below"
        }
    except requests.ConnectionError as e:
        print(f"⚠️  [AI Warning] Could not connect to NVIDIA NIM: {e}", file=sys.stderr)
        return {
            "summary": "AI service unreachable - using security checks only",
            "risk_factors": [],
            "recommendation": "Review security details below"
        }
    except requests.RequestException as e:
        print(f"⚠️  [AI Warning] NVIDIA NIM request error: {e}", file=sys.stderr)
        return {
            "summary": "AI request failed - using security checks only",
            "risk_factors": [],
            "recommendation": "Review security details below"
        }
    except Exception as e:
        print(f"⚠️  [AI Warning] Unexpected AI exception: {e}", file=sys.stderr)
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
    """Build the prompt for LLM phishing analysis with structured inputs."""
    
    password_forms = sum(1 for f in forms if f.get("hasPassword"))
    email_forms = sum(1 for f in forms if f.get("hasEmail"))
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
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                result["summary"] = line[:120]
                break
                
    if not result["summary"]:
        result["summary"] = "Security analysis completed"
        
    return result


def summarize_with_llm(
    url: str,
    ssl_info: Dict[str, Any],
    domain_info: Dict[str, Any],
    forms: List[Dict]
) -> str:
    """Convenience helper returning just the summary string."""
    from urllib.parse import urlparse
    hostname = urlparse(url).netloc
    res = analyze_with_llm(url, hostname, ssl_info, domain_info, forms)
    return res.get("summary", "Analysis unavailable")
