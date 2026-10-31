<p align="center">
  <img src="extension/icons/icon-128.png" alt="PhishPolice Logo" width="128" height="128">
</p>

<h1 align="center">🛡️ PhishPolice</h1>
<h3 align="center">Your Web Guardian — AI-Powered Phishing & Pre-Click Link Protection</h3>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.3.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/AI-GLM%205.3%20Flash%20(NVIDIA%20NIM)-orange.svg" alt="AI Model">
  <img src="https://img.shields.io/badge/platform-Chrome%20MV3-yellow.svg" alt="Platform">
  <img src="https://img.shields.io/badge/tests-163%20passed-brightgreen.svg" alt="Tests">
  <img src="https://img.shields.io/badge/docker-ready-blue.svg" alt="Docker">
</p>

[![Open Source Helpers](https://www.codetriage.com/theomatrix/phishpolice/badges/users.svg)](https://www.codetriage.com/theomatrix/phishpolice)

---

## 🌟 Overview

**PhishPolice** is a multi-layered security browser extension and analysis engine designed to neutralize phishing attacks *before* the damage occurs. Rather than relying on static, outdated URL blocklists, PhishPolice inspects active pages and links before click using real-time heuristics, local zero-network pattern analysis, computer vision, and optional LLM threat reasoning.

- 🔎 **Pre-Click Link Scanner**: Inspects links on hover and intercepts malicious clicks with a full-screen safety warning.
- 🛡️ **Trusted Sites Whitelist**: Allows daily-use domains to bypass scans with cloud sync across devices and shared-host guards.
- 🔤 **Typosquatting & Homoglyph Detector**: Spots lookalike letters (`paypa1.com`, Cyrillic IDNs, character swaps).
- 📅 **Domain Age Verification (WHOIS)**: Flags newly registered domains (<30 days) commonly used in flash phishing campaigns.
- 🔒 **SSL/TLS & Certificate Transparency (CT)**: Inspects SSL certificates, CAs, and crt.sh transparency logs.
- 👁️ **Visual Screenshot & DOM Analysis**: Uses computer vision to catch brand impersonation and fake login forms.
- 🤖 **GLM 5.3 Flash AI via NVIDIA NIM (Optional)**: Provides fast natural language threat summaries with strict 10s timeout protection without blocking core functionality.
- 🐳 **Docker & Production Ready**: Packaged with a multi-stage Dockerfile and full 163-test pytest suite backed by CI/CD.

---

## ⚡ What's New in v2.3

- 🚀 **Pre-Click Link Hover Protection**:
  - Instant local checks (<1 ms) for lookalikes, punycode, URL shorteners, and risky TLDs.
  - On-demand backend verification for uncached external links with a 30-minute dual-layer cache.
  - Interactive tooltip card, color-coded link dot badges, wavy red underlines on phishing links, and a click-interception stop dialog.
- 🛡️ **Trusted Sites Management (`chrome.storage.sync`)**:
  - Whitelist personal domains directly from the Scan tab or the dedicated Trusted tab.
  - Neutral grey "Trusted" card state that explains the site is trusted while still monitoring the address.
  - Automatic URL sanitization (`https://www.notion.so/page` → `notion.so`) and duplicate/format validation.
  - **Shared Host Guard**: Specific protection for shared platforms (`github.io`, `vercel.app`, `sites.google.com`, etc.) tagged with **Exact address only**.
  - **Undo Toast**: Revert accidental additions or removals instantly.
- 🎨 **Modern Popup Redesign**:
  - Clean light/dark theme with CSS custom properties.
  - Needle risk gauge (0–100%), evidence checkmarks, and integrated report modal connected to Google Safe Browsing.
- 🐳 **Docker & Gunicorn Support**:
  - Production multi-stage `Dockerfile` with non-root security and Gunicorn workers.
- 🧪 **Comprehensive Pytest Suite & GitHub Actions CI**:
  - 163 automated backend tests covering every check module with automated push/PR matrix testing.

---

## ✨ Core Features & Security Modules

### 1. 🔎 Pre-Click Link Scanner (`link_scanner.js`)

Catches phishing links before you navigate to them.

```
Hover / Focus Link ──► Cheap Local Checks (<1 ms, zero network)
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
        Flagged or Uncached         Clean & Cached
              │                           │
     On-demand Backend Scan        Instant Tooltip Card
              │                           │
     Update Cache & Badge          Color Dot on Link
```

- **Local Checks (Zero Network)**:
  - Punycode & Internationalized Domain Names (`xn--...`).
  - Raw IPv4 addresses used as web hosts.
  - URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
  - High-risk TLDs (`.tk`, `.ml`, `.ga`, `.xyz`, etc.).
  - Deep subdomains (`a.b.c.d.evil.com`).
  - Brand buried in subdomains (`paypal.com.evil-site.xyz`).
  - Homoglyph & leet substitutions (`paypa1.com`, `g00gle.com`).
  - Credential keywords in external paths.
- **Visual Feedback**:
  - Hover tooltip with verdict, destination hostname, top reasons, and action guidance.
  - Small status dot appended to scanned links.
  - Red wavy underline for confirmed phishing links.
  - **Stop Screen Dialog**: Intercepts direct clicks on phishing links with "Go back (safe)" as primary and "Open anyway" as secondary.
- **Two-Layer Cache**:
  - In-memory `Map` for instant lookups during browsing.
  - `chrome.storage.local` backing with a 30-minute TTL to prevent duplicate network calls.

---

### 2. 🛡️ Trusted Sites Whitelist

Enables users to trust everyday websites without disabling security monitoring.

- **Scan Tab Action**: Click **Trust this site** to convert the verdict to a neutral grey "Trusted" state.
- **Trusted Tab**:
  - Type or paste messy URLs; PhishPolice normalizes them automatically.
  - First-letter avatar badge and date added.
  - **Shared Host Protection**: Flags multi-tenant platforms like `github.io`, `sites.google.com`, `vercel.app`, `netlify.app`, `pages.dev`, `notion.site`, and `herokuapp.com` with an amber **Exact address only** badge to prevent trusting all tenant pages on that domain.
  - **Undo Toast**: 4-second action toast allows instant undo if a site is removed or added by mistake.
  - **Cloud Sync**: Synced across browsers using `chrome.storage.sync`.

---

### 3. 🔤 Domain Typosquatting Scanner

Detects lookalike domains crafted to deceive:

| Attack Type | Example | Detection |
|-------------|---------|-----------|
| **Character Swap** | `googe.com` → google | ✅ |
| **Number / Leet Substitution** | `paypa1.com` → paypal | ✅ |
| **Homoglyphs** | `arnazon.com` (rn→m) | ✅ |
| **Punycode / IDN** | `xn--pypal-4ve.com` | ✅ |
| **Subdomain Camouflage** | `paypal.com.secure-login.xyz` | ✅ |

*Tracks 40+ high-value target brands (Google, Microsoft, PayPal, Amazon, Chase, Wells Fargo, Apple, etc.).*

---

### 4. 📅 Domain Age Verification (WHOIS)

Newly registered domains are a primary indicator of phishing infrastructure:

| Domain Age | Risk Level | Score Impact |
|------------|------------|--------------|
| < 7 days | 🚨 Critical | +20% |
| < 30 days | 🚨 Very High | +15% |
| < 90 days | ⚠️ High | +10% |
| < 180 days | ⚠️ Medium | +5% |
| 1+ years | ✓ Established | 0% |

*Utilizes direct WHOIS querying with fallback to RDAP JSON endpoints.*

---

### 5. 🔒 SSL/TLS & Certificate Transparency

- **Real-Time Handshake Check**: Validates validity dates, expiration, issuer trust, and self-signed certificates.
- **Certificate Transparency Logs (crt.sh)**: Flags rapid re-issuances (>5 certs in 30 days) and unusual CA switches.

---

### 6. 👁️ Visual & DOM Fingerprint Analysis

- **Brand Detection**: Inspects DOM signatures and screenshots to identify logo/brand spoofing.
- **Credential Harvesting**: Flags forms submitting passwords or credit cards across origins.
- **Urgency Language**: Detects psychological manipulation keywords (*"account suspended"*, *"verify immediately"*).

---

### 7. 🤖 AI-Enhanced Reasoning (GLM 5.3 Flash via NVIDIA NIM)

- Powered by NVIDIA NIM using `z-ai/glm-5.3-flash` (or configurable via `NVIDIA_MODEL`).
- Multimodal model supporting both textual threat explanations and visual screenshot brand detection.
- **Strict 10s Backend Timeout Protection (`AI_TIMEOUT=10`)**: The backend enforces a 10-second deadline so scans never block the browser or popup, falling back gracefully to heuristic checks if the AI takes longer.
- **100% Optional**: If no API key is provided or the service times out, **all core security modules continue running normally**.

---

## 📊 Risk Scoring Weights

| Security Check | Weight | Mechanism | Offline / Zero-AI |
|---|:---:|---|:---:|
| **Typosquatting & Homoglyphs** | 25% | Levenshtein, substitution matrix, brand map | ✅ Yes |
| **Domain Registration Age** | 20% | WHOIS / RDAP lookup | ✅ Yes |
| **Visual Brand Impersonation** | 20% | Screenshot feature detection | ⚡ Optional AI |
| **SSL / CT Transparency** | 12% | Socket handshake + crt.sh CT queries | ✅ Yes |
| **Forms & Credential Actions** | 10% | DOM inspection for cross-origin submission | ✅ Yes |
| **Domain & TLD Reputation** | 8% | Risky TLDs, subdomain depth heuristics | ✅ Yes |
| **DOM & Urgency Language** | 5% | Hidden elements, iframes, keyword patterns | ✅ Yes |
| **AI Threat Explanation** | Context | Natural language synthesis | ⚡ Optional AI |

---

## 🏗️ Project Architecture

```
PhishPolice/
├── .github/
│   └── workflows/
│       └── ci.yml                 # GitHub Actions automated CI matrix
├── backend/
│   ├── app.py                     # Flask API service & route handlers
│   ├── requirements.txt           # Python dependencies (Flask, Gunicorn, pytest)
│   ├── pytest.ini                 # Backend pytest configuration
│   ├── tests/                     # 163 automated unit tests
│   │   ├── conftest.py
│   │   ├── test_app.py
│   │   ├── test_ssl_check.py
│   │   ├── test_domain_checks.py
│   │   ├── test_domain_age.py
│   │   ├── test_typosquat_scanner.py
│   │   ├── test_ct_monitor.py
│   │   ├── test_visual_analysis.py
│   │   └── test_llm_proxy.py
│   └── utils/                     # Modular security analyzers
│       ├── ct_monitor.py
│       ├── domain_age.py
│       ├── domain_checks.py
│       ├── llm_proxy.py
│       ├── ssl_check.py
│       ├── typosquat_scanner.py
│       └── visual_analysis.py
├── extension/                     # Chrome Extension (Manifest V3)
│   ├── manifest.json              # Extension metadata, permissions & scripts
│   ├── popup.html                 # Redesigned popup UI (Scan, Trusted, History)
│   ├── popup.js                   # UI controller & trusted-sites sync
│   ├── link_scanner.js            # Pre-click hover detection & click interceptor
│   ├── link_scanner.css           # Injected tooltip & stop overlay styles
│   ├── content.js                 # In-page feature extractor
│   ├── background.js              # Service worker
│   ├── icons/                     # 16px, 48px, 128px assets
│   ├── package.json               # Jest test runner configuration
│   └── tests/                     # Frontend unit tests
│       └── test_link_scanner.test.js
├── Dockerfile                     # Multi-stage production container build
├── .dockerignore                  # Docker ignore rules
├── PRIVACY.md                     # Chrome Web Store data disclosure policy
└── pytest.ini                     # Root pytest pointer
```

---

## 🛠️ Installation & Setup

### Option 1: Run with Docker (Recommended)

Build and launch the backend in an isolated container:

```bash
# Build the Docker image
docker build -t phishpolice-backend .

# Run with local port mapping (and optional .env file)
docker run -d -p 5000:5000 --name phishpolice phishpolice-backend
```

The service will be live at `http://127.0.0.1:5000`.

---

### Option 2: Local Python Environment

#### Prerequisites
- Python 3.10–3.13
- Google Chrome browser

```bash
# 1. Navigate to backend directory
cd backend

# 2. Create and activate a virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Optional: Configure AI API Key
# Create backend/.env and add:
# NVIDIA_API_KEY=your_key_here
# NVIDIA_MODEL=z-ai/glm-5.3-flash
# AI_TIMEOUT=10

# 5. Start the backend
python app.py
```

The backend starts on `http://127.0.0.1:5000`.

---

### Option 3: Load Extension in Chrome

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** via the toggle in the top-right corner.
3. Click **Load unpacked**.
4. Select the `extension/` directory from this repository.
5. The PhishPolice shield icon will appear in your Chrome toolbar!

> **Note**: Whenever you update extension scripts, go to `chrome://extensions/`, click the **Reload (↻)** button on PhishPolice, and refresh your open browser tabs (F5).

---

## 🧪 Running Tests

### Backend Unit Tests (Pytest)

Run all 163 backend tests across all modules:

```bash
# From repository root:
pytest -v
```

All tests run in ~1.2 seconds:
- Domain reputation & TLD checks
- Typosquatting & homoglyph matrices
- WHOIS & RDAP parsing
- Certificate verification & CT log monitoring
- Visual feature extraction & LLM fallback resilience
- Flask endpoints, validation, and rate limiting

---

## ⚙️ API Reference

### `POST /api/analyze`
Submits extracted page features for phishing evaluation.

**Payload:**
```json
{
  "url": "https://example-phish.xyz/login",
  "hostname": "example-phish.xyz",
  "title": "Account Sign-in",
  "forms": [
    {
      "action": "https://data-collector.com/post",
      "method": "POST",
      "hasPassword": true,
      "submitsToDifferentDomain": true
    }
  ],
  "dom_signature": "div#main|form.login|input#pass",
  "suspiciousPatterns": ["urgency: \"verify immediately\""],
  "externalLinks": { "external": 12, "total": 14 },
  "image_b64": ""
}
```

**Response:**
```json
{
  "verdict": "phish",
  "score": 0.88,
  "evidence": [
    "🚨 Typosquatting detected: Mimics \"PayPal\"",
    "🚨 Domain is 4 days old (Very new)",
    "⚠️ Form submits passwords to an external domain"
  ],
  "ssl_info": { "has_ssl": true, "is_valid": true, "issuer": "Let's Encrypt" },
  "domain_info": { "domain": "example-phish.xyz", "age_days": 4, "is_typosquat": true },
  "ct_info": { "checked": true, "certs_found": 1 },
  "visual_info": { "analyzed": false },
  "llm_analysis": {
    "summary": "Likely credential-harvesting phishing page mimicking PayPal.",
    "risk_factors": ["Typosquatting", "New domain", "Cross-domain login form"],
    "recommendation": "Do not enter credentials on this site."
  }
}
```

---

### `GET /api/health`
Status and capability probe.

```json
{
  "status": "healthy",
  "version": "2.2.0",
  "name": "PhishPolice",
  "features": [
    "ssl_check",
    "domain_analysis",
    "domain_age",
    "llm_analysis",
    "typosquat_scanner",
    "ct_monitor",
    "visual_analysis"
  ]
}
```

---

## 🔒 Privacy & Permissions

PhishPolice is committed to strict client-side data privacy:
- **No Browsing History Collected**: Browsing activity is never tracked or logged.
- **Local Pre-Checks**: Lookalikes, shorteners, and risky TLDs are evaluated inside the browser sandbox before any network request occurs.
- **No Remote Telemetry**: Analyzed data is processed strictly on your local backend (`127.0.0.1`).
- **No Password or Form Input Data**: Form values and keystrokes are never read. Only form presence and destination hostnames are inspected.

Read our full Web Store compliance policy in [PRIVACY.md](PRIVACY.md).

---

## 📈 Roadmap

- [x] Multi-factor security engine (SSL, WHOIS age, typosquatting, CT logs)
- [x] Optional AI analysis with graceful offline fallback
- [x] Visual brand impersonation detection
- [x] Link hover inspection and click interception (`link_scanner.js`)
- [x] Trusted domains management with cloud sync (`chrome.storage.sync`)
- [x] Shared-hosting protection (Exact address only)
- [x] Comprehensive pytest test suite (163 tests) & GitHub Actions CI
- [x] Production Docker container & Gunicorn WSGI
- [ ] Firefox Extension (Manifest V3) support
- [ ] Email client webmail integration (Gmail / Outlook web)
- [ ] Local bloom filter for top 1M benign domains

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

<p align="center">
  <b>Protected by PhishPolice 🛡️ — Think before you click.</b>
</p>
