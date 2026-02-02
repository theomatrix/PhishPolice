# PhishPolice - Requirements

## 🎯 Project Overview
**PhishPolice** is an AI-powered browser extension that protects users from phishing attacks using real-time multi-layered security analysis.

## 🚀 Core Features

### 1. AI-Powered Threat Detection
- **Gemini 2.5 Flash Lite** integration for intelligent phishing assessment
- Real-time analysis of webpage content, forms, and behavior patterns
- Natural language explanations and security recommendations

### 2. Visual Brand Impersonation Detection
- Screenshot analysis using Gemini Vision API
- Detects fake logos and copied designs from trusted brands
- Identifies urgency/fear-based UI elements and suspicious overlays

### 3. Domain Typosquatting Scanner
- Detects lookalike domains (e.g., `g00gle.com`, `paypa1.com`)
- Covers 40+ popular brands (Google, PayPal, Amazon, banks, etc.)
- Advanced pattern matching for character substitution and homoglyphs

### 4. Multi-Factor Security Analysis
- **SSL Certificate Verification**: Real-time validation and security scoring
- **Domain Age Checking**: WHOIS lookup to detect newly registered domains
- **Certificate Transparency**: Monitors suspicious certificate patterns
- **DOM Analysis**: Detects hidden iframes, external form submissions

### 5. User Experience
- One-click scanning from browser toolbar
- Clear risk scoring: Safe (0-25%), Suspicious (25-55%), Phishing (55%+)
- Detailed evidence list with actionable recommendations
- Scan history with last 10 results

## 🏗️ Technical Requirements

### Frontend (Chrome Extension)
- Manifest V3 compliance for modern security
- Vanilla JavaScript (no dependencies)
- Screenshot capture and DOM analysis
- Local storage for scan history

### Backend (Flask API)
- Python 3.8+ with Flask framework
- Rate limiting (10 req/min, 50/hour, 200/day)
- CORS support for browser extensions
- Modular analysis utilities

### External Integrations
- **Gemini 2.5 Flash Lite API** for AI analysis
- **Certificate Transparency logs** (crt.sh) for cert monitoring
- **WHOIS/RDAP** for domain age verification

## 🎯 Success Criteria
1. **Accuracy**: >90% detection rate for known phishing patterns
2. **Performance**: Analysis completed within 30 seconds
3. **Usability**: Simple one-click operation with clear results
4. **Security**: No data persistence, API key protection
5. **Scalability**: Rate limiting and error handling for production use

## 🔒 Security & Privacy
- No user data collection or storage
- API keys secured in environment variables
- Manual scan only (no background monitoring)
- CORS restricted to browser extensions only

## 📊 Risk Scoring Algorithm
Multi-factor weighted scoring system:
- Typosquatting Detection: 25%
- Domain Age Analysis: 20% 
- Visual Brand Analysis: 20%
- SSL/Certificate Transparency: 12%
- Form Behavior Analysis: 10%
- Domain Reputation: 8%
- DOM/Behavior Patterns: 5%
<hr>
MADE WITH KIRO AS SAID ON THE DASHBOARD
