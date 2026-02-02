from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from urllib.parse import urlparse
import os
import sys
from pathlib import Path

# Load .env manually to ensure it works
env_path = Path(__file__).parent / '.env'
if env_path.exists():
    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip()

from utils.domain_checks import quick_domain_checks
from utils.visual_analysis import analyze_visual, get_visual_risk_score, format_visual_summary
from utils.ssl_check import get_ssl_certificate_info, format_ssl_summary
from utils.llm_proxy import analyze_with_gemini
from utils.typosquat_scanner import detect_typosquatting, get_typosquat_risk_score, format_typosquat_summary
from utils.ct_monitor import check_certificate_transparency, get_ct_risk_score, format_ct_summary
from utils.domain_age import check_domain_age, get_domain_age_risk_score, format_domain_age_summary

app = Flask(__name__)

# Security: Configure CORS
CORS(app, 
     origins=["chrome-extension://*", "moz-extension://*"],
     methods=["POST", "GET"],
     allow_headers=["Content-Type"])

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Constants
MAX_URL_LENGTH = 2048
MAX_IMAGE_SIZE = 5 * 1024 * 1024
MAX_FORMS = 100

def validate_url(url):
    if not url or not isinstance(url, str):
        return False, "Missing or invalid URL"
    if len(url) > MAX_URL_LENGTH:
        return False, "URL too long"
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "Invalid URL scheme"
        if not parsed.netloc:
            return False, "Invalid URL format"
        return True, None
    except Exception:
        return False, "Malformed URL"

def validate_request_data(data):
    errors = []
    url = data.get("url", "")
    valid, error = validate_url(url)
    if not valid:
        errors.append(error)
    
    image_b64 = data.get("image_b64", "")
    if image_b64 and len(image_b64) > MAX_IMAGE_SIZE:
        errors.append("Image too large")
    
    forms = data.get("forms", [])
    if not isinstance(forms, list):
        errors.append("Forms must be a list")
    elif len(forms) > MAX_FORMS:
        errors.append("Too many forms")
    
    return errors

@app.route("/api/analyze", methods=["POST"])
@limiter.limit("10 per minute")
def analyze():
    """Analyze a webpage for phishing indicators."""
    try:
        data = request.get_json()
    except Exception:
        return jsonify({"error": "Invalid JSON payload"}), 400
    
    if not data:
        return jsonify({"error": "Missing request body"}), 400
    
    validation_errors = validate_request_data(data)
    if validation_errors:
        return jsonify({"error": "Validation failed", "details": validation_errors}), 400
    
    # Extract data
    url = data.get("url", "")
    hostname = data.get("hostname", "")
    forms = data.get("forms", [])
    image_b64 = data.get("image_b64", "")
    suspicious_patterns = data.get("suspiciousPatterns", [])
    dom_signature = data.get("dom_signature", "")
    external_links = data.get("externalLinks", {})
    
    try:
        print(f"[PhishPolice] Analyzing: {hostname}", file=sys.stderr)
        
        # === NEW: Typosquatting Detection ===
        typosquat_result = detect_typosquatting(hostname)
        typosquat_risk, typosquat_evidence = get_typosquat_risk_score(hostname)
        print(f"[PhishPolice] Typosquat check: {typosquat_result['is_typosquat']}", file=sys.stderr)
        
        # SSL certificate verification
        ssl_info = get_ssl_certificate_info(url)
        ssl_summary = format_ssl_summary(ssl_info)
        
        # === NEW: Certificate Transparency Check ===
        ct_result = check_certificate_transparency(hostname)
        ct_risk, ct_evidence = get_ct_risk_score(hostname)
        print(f"[PhishPolice] CT check complete: {ct_result.get('recent_certs_count', 0)} certs", file=sys.stderr)
        
        # Domain analysis
        domain_info = quick_domain_checks(url)
        
        # === NEW: Domain Age Check via WHOIS ===
        domain_age_result = check_domain_age(hostname)
        domain_age_risk, domain_age_evidence = get_domain_age_risk_score(hostname)
        print(f"[PhishPolice] Domain age: {domain_age_result.get('age_days')} days, risk={domain_age_risk}", file=sys.stderr)
        
        # Visual analysis (screenshot to Gemini Vision)
        visual_info = analyze_visual(image_b64, hostname)
        visual_risk, visual_evidence = get_visual_risk_score(visual_info)
        print(f"[PhishPolice] Visual analysis: brand={visual_info.get('detected_brand')}, risk={visual_risk}", file=sys.stderr)
        
        # DOM analysis metrics
        dom_analysis = {
            "signature_length": len(dom_signature),
            "external_links": external_links.get("external", 0),
            "total_links": external_links.get("total", 1),
            "external_links_ratio": external_links.get("external", 0) / max(external_links.get("total", 1), 1),
            "hidden_iframes": len([p for p in suspicious_patterns if "hidden_iframe" in p.lower()]) if suspicious_patterns else 0
        }
        
        # LLM-powered analysis
        llm_analysis = analyze_with_gemini(
            url=url,
            hostname=hostname,
            ssl_info=ssl_info,
            domain_info=domain_info,
            forms=forms,
            suspicious_patterns=suspicious_patterns,
            dom_analysis=dom_analysis
        )
        
        # Calculate multi-factor risk score (includes all factors including domain age)
        risk_score = calculate_risk_score(
            ssl_info, domain_info, forms, suspicious_patterns, 
            dom_analysis, visual_info, typosquat_risk, ct_risk, visual_risk, domain_age_risk
        )
        verdict = determine_verdict(risk_score)
        
        # Build evidence list with all checks including domain age
        evidence = build_evidence_list(
            ssl_info, ssl_summary, domain_info, forms, 
            suspicious_patterns, dom_analysis,
            typosquat_result, ct_result, visual_info, domain_age_result
        )
        
        resp = {
            "verdict": verdict,
            "score": risk_score,
            "evidence": evidence,
            "ssl_info": {
                "has_ssl": ssl_info.get("has_ssl", False),
                "is_valid": ssl_info.get("is_valid", False),
                "issuer": ssl_info.get("issuer"),
                "expires_in_days": ssl_info.get("expires_in_days"),
                "security_score": ssl_info.get("security_score", 0)
            },
            "domain_info": {
                "domain": domain_info.get("full_domain", ""),
                "is_suspicious": domain_info.get("has_suspicious_subdomain") or domain_info.get("has_suspicious_tld"),
                "is_typosquat": typosquat_result.get("is_typosquat", False),
                "suspected_brand": typosquat_result.get("suspected_brand"),
                "age_days": domain_age_result.get("age_days"),
                "age_category": domain_age_result.get("age_category")
            },
            "ct_info": {
                "checked": ct_result.get("checked", False),
                "certs_found": ct_result.get("recent_certs_count", 0),
                "warning": ct_result.get("warning")
            },
            "visual_info": {
                "analyzed": visual_info.get("analyzed", False),
                "detected_brand": visual_info.get("detected_brand"),
                "is_login_page": visual_info.get("is_login_page", False),
                "has_urgency": visual_info.get("has_urgency_elements", False),
                "visual_risk": visual_info.get("visual_risk_score", 0)
            },
            "llm_analysis": {
                "summary": llm_analysis.get("summary", "Analysis unavailable"),
                "risk_factors": llm_analysis.get("risk_factors", []),
                "recommendation": llm_analysis.get("recommendation", "")
            }
        }
        return jsonify(resp)
        
    except Exception as e:
        app.logger.error(f"Analysis error: {str(e)}")
        print(f"[PhishPolice] ERROR: {str(e)}", file=sys.stderr)
        return jsonify({"error": "Analysis failed", "details": str(e)}), 500


def calculate_risk_score(ssl_info, domain_info, forms, suspicious_patterns, dom_analysis, visual_info, typosquat_risk=0, ct_risk=0, visual_risk=0, domain_age_risk=0):
    """Calculate risk score based on multiple factors (0-1 scale)."""
    score = 0.0
    
    # === TYPOSQUATTING Factor (max 0.25) ===
    score += typosquat_risk  # Already 0-0.35 from typosquat scanner
    
    # === DOMAIN AGE Factor (max 0.20) ===
    score += domain_age_risk  # From domain age checker (new domains are risky)
    
    # === VISUAL Factor (max 0.20) ===
    score += visual_risk  # From visual analysis
    
    # === SSL Factor (max 0.12) ===
    ssl_security = ssl_info.get("security_score", 50)
    if ssl_security < 30:
        score += 0.10
    elif ssl_security < 50:
        score += 0.05
    elif ssl_security < 70:
        score += 0.02
    
    if ssl_info.get("is_self_signed"):
        score += 0.05
    if not ssl_info.get("is_valid") and ssl_info.get("has_ssl"):
        score += 0.06
    if ssl_info.get("is_expired"):
        score += 0.05
    if not ssl_info.get("has_ssl"):
        score += 0.06
    
    # === CT Monitor Factor (max 0.08) ===
    score += ct_risk  # Already 0-0.15 from CT monitor
    
    # === Domain Factor (max 0.08) ===
    if domain_info.get("is_ip_address"):
        score += 0.05
    if domain_info.get("has_suspicious_tld"):
        score += 0.04
    if domain_info.get("has_many_subdomains"):
        score += 0.02
    
    # === Form Factor (max 0.15) ===
    password_forms = sum(1 for f in forms if f.get("hasPassword") or f.get("has_password"))
    if password_forms > 0:
        score += 0.06
    if password_forms > 1:
        score += 0.03
    
    external_forms = sum(1 for f in forms if f.get("submitsToDifferentDomain"))
    if external_forms > 0:
        score += 0.08
    
    # === DOM/Behavior Factor (max 0.10) ===
    if suspicious_patterns and isinstance(suspicious_patterns, list):
        urgency_count = len([p for p in suspicious_patterns if "urgency" in p.lower()])
        score += min(0.06, urgency_count * 0.02)
        
        if dom_analysis.get("hidden_iframes", 0) > 0:
            score += 0.04
    
    if dom_analysis.get("external_links_ratio", 0) > 0.8:
        score += 0.03
    
    return min(round(score, 2), 0.99)


def determine_verdict(score):
    if score >= 0.55:
        return "phish"
    elif score >= 0.25:
        return "suspicious"
    else:
        return "safe"


def build_evidence_list(ssl_info, ssl_summary, domain_info, forms, suspicious_patterns, dom_analysis, typosquat_result, ct_result, visual_info=None, domain_age_result=None):
    evidence = []
    
    # Typosquatting (most important if detected)
    if typosquat_result.get("is_typosquat"):
        evidence.append(f"🚨 TYPOSQUAT: Mimics '{typosquat_result['suspected_brand']}' ({typosquat_result['similarity_score']}% match)")
    
    # Domain age (new domains are suspicious)
    if domain_age_result and domain_age_result.get("age_days") is not None:
        age_days = domain_age_result["age_days"]
        if age_days < 30:
            evidence.append(f"🚨 NEW DOMAIN: Registered only {age_days} days ago!")
        elif age_days < 90:
            evidence.append(f"⚠️ Young domain: Only {age_days} days old")
        elif age_days >= 365:
            years = age_days // 365
            evidence.append(f"✓ Established domain: {years}+ years old")
    
    # Visual analysis (brand impersonation)
    if visual_info and visual_info.get("analyzed"):
        if visual_info.get("detected_brand"):
            evidence.append(f"👁️ Visual: Detected {visual_info['detected_brand']} branding ({visual_info.get('brand_match_confidence', 0)}% match)")
        if visual_info.get("has_urgency_elements"):
            evidence.append("⚠️ Visual urgency/fear elements detected")
        if visual_info.get("is_login_page"):
            evidence.append("🔐 Login page detected by visual analysis")
        for finding in visual_info.get("findings", [])[:2]:
            if finding and not finding.startswith("Visual"):
                evidence.append(f"👁️ {finding}")
    
    # SSL evidence
    evidence.append(ssl_summary)
    
    # CT evidence
    ct_summary = format_ct_summary(ct_result)
    if ct_result.get("warning"):
        evidence.append(ct_summary)
    
    # Domain evidence
    if domain_info.get("has_suspicious_subdomain"):
        evidence.append(f"⚠️ Suspicious subdomain: {domain_info.get('subdomain', '')}")
    if domain_info.get("has_suspicious_tld"):
        evidence.append(f"⚠️ High-risk TLD: .{domain_info.get('suffix', '')}")
    if domain_info.get("is_ip_address"):
        evidence.append("⚠️ Uses IP address instead of domain name")
    
    # Form evidence
    password_forms = sum(1 for f in forms if f.get("hasPassword") or f.get("has_password"))
    external_forms = sum(1 for f in forms if f.get("submitsToDifferentDomain"))
    
    if password_forms > 0:
        evidence.append(f"🔐 {password_forms} form(s) collecting passwords")
    if external_forms > 0:
        evidence.append(f"⚠️ {external_forms} form(s) submitting to external domains")
    
    # DOM evidence
    if dom_analysis.get("hidden_iframes", 0) > 0:
        evidence.append("⚠️ Hidden iframes detected")
    
    # If safe, add positive note
    if not typosquat_result.get("is_typosquat") and ssl_info.get("is_valid"):
        if not (visual_info and visual_info.get("detected_brand")):
            evidence.append("✓ No brand impersonation detected")
    
    return evidence


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy", 
        "version": "2.2.0",
        "name": "PhishPolice",
        "features": ["ssl_check", "domain_analysis", "domain_age", "llm_analysis", "typosquat_scanner", "ct_monitor", "visual_analysis"]
    })

if __name__ == "__main__":
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    HOST = "127.0.0.1"
    print(f"🛡️ PhishPolice Backend v2.2 starting on {HOST}:5000", file=sys.stderr)
    print(f"   Features: Typosquat, Domain Age, CT Monitor, Visual Analysis, Gemini AI", file=sys.stderr)
    app.run(host=HOST, port=5000, debug=DEBUG)
