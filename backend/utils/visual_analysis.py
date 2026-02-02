"""
Visual Analysis Module
Analyzes webpage screenshots using Gemini Vision to detect:
- Brand impersonation (fake logos, copied designs)
- Login page mimicry
- Urgency/fear-based UI elements
- Suspicious overlays or popups
"""

import os
import sys
import requests
from typing import Dict, Any
from pathlib import Path

# Load env
def load_env():
    env_path = Path(__file__).parent.parent / '.env'
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()

load_env()

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
GEMINI_VISION_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent"


def analyze_visual(image_b64: str, hostname: str = "") -> Dict[str, Any]:
    """
    Analyze a webpage screenshot using Gemini Vision.
    
    Args:
        image_b64: Base64 encoded PNG image of the webpage
        hostname: The hostname being analyzed (for context)
    
    Returns:
        Analysis results including brand detection and risk indicators
    """
    result = {
        "analyzed": False,
        "detected_brand": None,
        "is_login_page": False,
        "has_urgency_elements": False,
        "brand_match_confidence": 0,
        "visual_risk_score": 0.0,
        "findings": [],
        "summary": ""
    }
    
    # Skip if no image provided
    if not image_b64 or len(image_b64) < 100:
        result["findings"].append("No screenshot provided")
        return result
    
    api_key = GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY", "").strip()
    
    if not api_key:
        result["findings"].append("Visual analysis unavailable - API key not configured")
        return result
    
    print(f"[PhishPolice] Visual analysis starting for: {hostname}", file=sys.stderr)
    
    # Build the vision prompt
    prompt = build_vision_prompt(hostname)
    
    try:
        response = requests.post(
            f"{GEMINI_VISION_URL}?key={api_key}",
            headers={"Content-Type": "application/json"},
            json={
                "contents": [{
                    "parts": [
                        {"text": prompt},
                        {
                            "inline_data": {
                                "mime_type": "image/png",
                                "data": image_b64
                            }
                        }
                    ]
                }],
                "generationConfig": {
                    "temperature": 0.1,
                    "maxOutputTokens": 400,
                    "topP": 0.8
                }
            },
            timeout=30
        )
        
        print(f"[PhishPolice] Visual API response: {response.status_code}", file=sys.stderr)
        
        if response.status_code == 429:
            result["findings"].append("Visual analysis rate limited")
            return result
        
        if response.status_code != 200:
            result["findings"].append(f"Visual analysis failed (HTTP {response.status_code})")
            return result
        
        data = response.json()
        candidates = data.get("candidates", [])
        
        if not candidates:
            result["findings"].append("No visual analysis response")
            return result
        
        content = candidates[0].get("content", {})
        parts = content.get("parts", [])
        
        if not parts:
            result["findings"].append("Empty visual analysis response")
            return result
        
        llm_response = parts[0].get("text", "")
        
        # Parse the structured response
        parsed = parse_vision_response(llm_response)
        result.update(parsed)
        result["analyzed"] = True
        
        print(f"[PhishPolice] Visual analysis complete: brand={result.get('detected_brand')}, risk={result.get('visual_risk_score')}", file=sys.stderr)
        
        return result
        
    except requests.Timeout:
        result["findings"].append("Visual analysis timed out")
        return result
    except requests.RequestException as e:
        print(f"[PhishPolice] Visual analysis error: {e}", file=sys.stderr)
        result["findings"].append("Visual analysis request failed")
        return result
    except Exception as e:
        print(f"[PhishPolice] Visual parse error: {e}", file=sys.stderr)
        result["findings"].append("Visual analysis error")
        return result


def build_vision_prompt(hostname: str) -> str:
    """Build the prompt for visual phishing analysis."""
    return f"""You are PhishPolice Visual Analyzer. Analyze this webpage screenshot for phishing indicators.

CONTEXT: This page is from hostname: {hostname}

ANALYZE THE SCREENSHOT FOR:
1. **Brand Detection**: Does this page use logos, colors, or design elements that mimic a well-known brand (Google, Microsoft, PayPal, Amazon, bank, etc.)?
2. **Login Page**: Is this a login/signin page requesting credentials?
3. **Urgency Elements**: Are there urgent messages like "Account suspended", "Verify immediately", countdown timers, or threatening language?
4. **Suspicious UI**: Are there fake popups, overlays, or elements that look like system dialogs?
5. **Quality Issues**: Does the page have poor grammar, low-quality images, or unprofessional design that suggests a fake site?

RESPOND IN THIS EXACT FORMAT (one line each):
BRAND: [Brand name detected or "None"]
CONFIDENCE: [0-100 percent confidence in brand match]
IS_LOGIN: [Yes/No]
HAS_URGENCY: [Yes/No]
RISK: [Low/Medium/High/Critical]
FINDINGS: [Comma-separated list of specific findings]
SUMMARY: [One sentence summary of visual analysis]"""


def parse_vision_response(response_text: str) -> Dict[str, Any]:
    """Parse the structured vision analysis response."""
    result = {
        "detected_brand": None,
        "brand_match_confidence": 0,
        "is_login_page": False,
        "has_urgency_elements": False,
        "visual_risk_score": 0.0,
        "findings": [],
        "summary": ""
    }
    
    lines = response_text.strip().split("\n")
    
    for line in lines:
        line = line.strip()
        upper = line.upper()
        
        if upper.startswith("BRAND:"):
            brand = line[6:].strip()
            if brand.lower() not in ("none", "n/a", "unknown", ""):
                result["detected_brand"] = brand
        
        elif upper.startswith("CONFIDENCE:"):
            try:
                conf_str = line[11:].strip().replace("%", "")
                result["brand_match_confidence"] = int(conf_str)
            except:
                pass
        
        elif upper.startswith("IS_LOGIN:"):
            val = line[9:].strip().lower()
            result["is_login_page"] = val in ("yes", "true", "1")
        
        elif upper.startswith("HAS_URGENCY:"):
            val = line[12:].strip().lower()
            result["has_urgency_elements"] = val in ("yes", "true", "1")
        
        elif upper.startswith("RISK:"):
            risk = line[5:].strip().lower()
            risk_scores = {"low": 0.1, "medium": 0.25, "high": 0.4, "critical": 0.6}
            result["visual_risk_score"] = risk_scores.get(risk, 0.1)
        
        elif upper.startswith("FINDINGS:"):
            findings_str = line[9:].strip()
            if findings_str.lower() not in ("none", "n/a", ""):
                result["findings"] = [f.strip() for f in findings_str.split(",") if f.strip()]
        
        elif upper.startswith("SUMMARY:"):
            result["summary"] = line[8:].strip()
    
    return result


def get_visual_risk_score(visual_result: Dict[str, Any]) -> tuple:
    """
    Calculate visual risk contribution.
    Returns (risk_score 0-0.25, evidence list)
    """
    if not visual_result.get("analyzed"):
        return (0.0, ["Visual analysis not performed"])
    
    risk = 0.0
    evidence = []
    
    # Brand impersonation is high risk
    if visual_result.get("detected_brand") and visual_result.get("brand_match_confidence", 0) > 70:
        risk += 0.15
        evidence.append(f"⚠️ Visual brand match: {visual_result['detected_brand']} ({visual_result['brand_match_confidence']}% confidence)")
    
    # Login page context
    if visual_result.get("is_login_page"):
        risk += 0.05
        evidence.append("🔐 Login page detected")
    
    # Urgency/fear tactics
    if visual_result.get("has_urgency_elements"):
        risk += 0.08
        evidence.append("⚠️ Urgency/fear elements detected")
    
    # Add specific findings
    for finding in visual_result.get("findings", [])[:3]:
        evidence.append(f"👁️ {finding}")
    
    return (min(risk, 0.25), evidence)


def format_visual_summary(visual_result: Dict[str, Any]) -> str:
    """Format visual analysis as human-readable summary."""
    if not visual_result.get("analyzed"):
        return "Visual analysis not available"
    
    if visual_result.get("detected_brand"):
        return f"👁️ Visual: Detected {visual_result['detected_brand']} branding ({visual_result.get('brand_match_confidence', 0)}% match)"
    
    if visual_result.get("summary"):
        return f"👁️ {visual_result['summary']}"
    
    return "👁️ Visual analysis: No brand impersonation detected"
