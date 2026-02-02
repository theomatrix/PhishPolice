# PhishPolice - System Design

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Chrome         │    │  Flask Backend   │    │  External APIs  │
│  Extension      │◄──►│  (Analysis       │◄──►│  • Gemini AI    │
│  • Popup UI     │    │   Engine)        │    │  • crt.sh       │
│  • Content      │    │  • Multi-layer   │    │  • WHOIS        │
│    Script       │    │    Security      │    │                 │
│  • Background   │    │    Analysis      │    │                 │
│    Service      │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🔄 Analysis Flow

### 1. User Interaction
```javascript
User clicks "Scan" → Content script extracts page data → Screenshot captured
```

### 2. Data Collection
- **URL & Hostname**: Target website identification
- **DOM Signature**: Forms, hidden elements, external links
- **Screenshot**: Base64 encoded PNG for visual analysis
- **Suspicious Patterns**: Urgency language, hidden iframes

### 3. Parallel Security Analysis
```python
# Six concurrent analysis modules
├── Typosquatting Scanner    # Brand impersonation detection
├── Visual Analysis          # Gemini Vision API
├── Domain Age Checker       # WHOIS lookup
├── SSL Certificate Verify   # Real-time cert validation
├── Certificate Transparency # CT log monitoring
└── LLM Context Analysis     # Gemini text analysis
```

### 4. Risk Scoring & Response
```python
risk_score = weighted_sum([
    typosquat_risk * 0.25,
    domain_age_risk * 0.20,
    visual_risk * 0.20,
    ssl_risk * 0.12,
    ct_risk * 0.08,
    domain_risk * 0.08,
    form_risk * 0.10,
    dom_risk * 0.05
])

verdict = "safe" | "suspicious" | "phish"  # Based on thresholds
```

## 🧠 AI Integration

### Gemini 2.5 Flash Lite
**Text Analysis**:
```python
prompt = f"""
Analyze webpage for phishing indicators:
- URL: {url}
- SSL: {ssl_status}
- Forms: {form_count} password fields
- Domain: {domain_flags}

Respond: SUMMARY | RISK_FACTORS | RECOMMENDATION
"""
```

**Visual Analysis**:
```python
vision_prompt = f"""
Analyze screenshot for:
1. Brand impersonation (logos, colors)
2. Login page detection
3. Urgency/fear elements
4. Suspicious UI overlays

Format: BRAND | CONFIDENCE | IS_LOGIN | HAS_URGENCY | FINDINGS
"""
```

## 🔍 Core Detection Modules

### 1. Typosquatting Scanner
```python
# Levenshtein distance + pattern matching
brands = ["google", "paypal", "amazon", ...]
techniques = ["character_swap", "homoglyphs", "insertion"]

def detect_typosquat(domain):
    for brand in brands:
        similarity = levenshtein_similarity(domain, brand)
        if similarity > 0.75 and domain != brand:
            return {"is_typosquat": True, "brand": brand}
```

### 2. Visual Brand Detection
- Screenshot → Base64 → Gemini Vision API
- Brand logo recognition with confidence scoring
- UI element analysis (login forms, urgency banners)
- Design quality assessment

### 3. Domain Age Analysis
```python
# WHOIS lookup with risk categorization
age_risk_map = {
    "< 7 days": 0.20,    # Critical
    "< 30 days": 0.15,   # Very High  
    "< 90 days": 0.10,   # High
    "< 180 days": 0.05,  # Medium
    "> 1 year": 0.00     # Established
}
```

### 4. SSL Certificate Verification
- Real-time certificate chain validation
- Issuer reputation scoring (0-100)
- Expiration monitoring and self-signed detection
- Security protocol analysis

## 📊 Data Models

### Analysis Request
```json
{
  "url": "string",
  "hostname": "string", 
  "forms": [{"hasPassword": bool, "submitsToDifferentDomain": bool}],
  "dom_signature": "string",
  "suspiciousPatterns": ["string"],
  "externalLinks": {"external": int, "total": int},
  "image_b64": "string"
}
```

### Analysis Response
```json
{
  "verdict": "safe|suspicious|phish",
  "score": 0.42,
  "evidence": ["🚨 TYPOSQUAT: Mimics 'google'", "✓ Valid SSL"],
  "ssl_info": {"is_valid": bool, "security_score": int},
  "domain_info": {"is_typosquat": bool, "age_days": int},
  "visual_info": {"detected_brand": "string", "is_login_page": bool},
  "llm_analysis": {"summary": "string", "recommendation": "string"}
}
```

## 🔒 Security Design

### Rate Limiting
```python
@limiter.limit("10 per minute")
@limiter.limit("50 per hour") 
@limiter.limit("200 per day")
```

### Input Validation
- URL length: max 2048 chars
- Image size: max 5MB
- Form count: max 100
- JSON payload validation

### API Security
- CORS restricted to browser extensions
- Environment variable API key storage
- Request timeout handling (25s)
- Retry logic for rate limiting

## 🚀 Performance Optimizations

### Parallel Processing
- All 6 analysis modules run concurrently
- Non-blocking I/O for external API calls
- Timeout handling prevents hanging requests

### Caching Strategy
- No server-side data persistence (privacy)
- Client-side scan history (last 10 results)
- API response caching in browser extension

### Error Handling
```python
# Graceful degradation
if gemini_api_fails:
    return security_analysis_only()
if ssl_check_fails:
    continue_with_other_modules()
```

## 📱 User Interface Design

### Extension Popup
- **Glassmorphism design** with modern aesthetics
- **One-click scanning** with progress indicators
- **Color-coded results**: Green (Safe), Yellow (Suspicious), Red (Phish)
- **Evidence list** with emoji indicators for quick scanning
- **Scan history** with timestamp and quick access

### Result Display
```
🛡️ PhishPolice Analysis
━━━━━━━━━━━━━━━━━━━━━━━━
✅ SAFE (Score: 15%)

Evidence:
✓ Valid SSL certificate
✓ Established domain (3+ years)
✓ No brand impersonation detected
```

## 🔧 Technology Stack

**Frontend**: Chrome Extension Manifest V3, Vanilla JS, CSS3
**Backend**: Flask, Flask-CORS, Flask-Limiter
**AI/ML**: Google Gemini 2.5 Flash Lite (text + vision)
**External APIs**: crt.sh (Certificate Transparency), WHOIS/RDAP
**Security**: Rate limiting, input validation, CORS protection


<hr>
made with kiro as said on dashboard
