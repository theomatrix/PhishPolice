# PhishPolice – Privacy Policy & Web Store Data Disclosure

_Last updated: November 2026_

---

## What PhishPolice does with your data

PhishPolice helps protect you from phishing websites. To do this it needs to
see the URLs of pages you visit and links you hover over. This section explains
exactly what is collected, what stays on your device, and what (if anything)
leaves it.

---

## Data that NEVER leaves your browser

| Data | Where it stays |
|---|---|
| Full browsing history | Your browser only — PhishPolice never reads it |
| Saved passwords / cookies | Never accessed |
| Form field values | Never read |
| Screenshot pixels | Captured locally and sent **only** to the locally-running backend on `127.0.0.1`; never to any cloud server |
| Scan history | Stored in `chrome.storage.local` on your device only |
| Cached link-scan results | Stored in `chrome.storage.local` on your device only |

---

## Local checks — zero network traffic

When you hover over a link, PhishPolice first runs a set of **purely local
checks** inside your browser. No data is sent anywhere:

- Punycode / internationalised domain names (`xn--…`)
- Raw IP addresses used as hostnames
- URL shorteners (bit.ly, tinyurl.com, etc.)
- High-risk TLDs (.tk, .ml, .xyz, …)
- Brand names buried in a subdomain of a different apex domain (e.g.
  `paypal.com.evil.xyz`)
- Homoglyph / leet-speak substitutions (`paypa1`, `g00gle`)
- Excessive subdomain depth
- Credential keywords in external URLs

These checks complete in under 1 ms and produce zero network requests.

---

## When data IS sent to the backend

The backend runs **locally on your own machine** at `http://127.0.0.1:5000`.
No data is sent to PhishPolice's servers or any third-party cloud service
unless you have separately configured an LLM API key in your `.env` file.

Data sent to the local backend on demand (hover/click or manual scan):

| Field | Why |
|---|---|
| Page URL (truncated to 2 048 chars) | Domain age, SSL, typosquat, CT checks |
| Hostname | All domain-level checks |
| Page title | LLM context |
| Form metadata (counts, field types, action domain — **no values**) | Login-page detection |
| DOM structure signature (tag names + IDs + classes, **no text content**) | Visual fingerprint |
| Page screenshot (PNG, base-64) | Visual brand-impersonation detection |
| Suspicious text patterns found by local regex | LLM context |

### When is a backend call made?

- **Hover on a link**: only if the local check flagged the link as suspicious or
  bad, **or** if the link is to an external domain not yet seen this session.
- **Manual scan** (popup "Scan again" button): always for the current page.
- **Same URL within 30 minutes**: never re-sent — the cached result is used.

---

## Optional: LLM API (Mistral AI)

If you add a `MISTRAL_API_KEY` to the backend `.env` file, a summary of the
page (URL, title, DOM patterns — **no personal data, no screenshots**) is sent
to the Mistral AI API for phishing analysis. This is **opt-in** and requires
you to set up your own API key. Mistral's own privacy policy applies to that
data.

Without an API key the LLM analysis step is skipped silently.

---

## Why broad host permissions are needed

PhishPolice requests `http://*/*` and `https://*/*` in
`host_permissions` so that:

1. The content script can observe link hover events on **any** page (not just
   ones you explicitly allow each time).
2. The popup's `fetch` call can reach the local backend at `127.0.0.1:5000`
   regardless of which page is active.

PhishPolice does **not** use these permissions to read page content, inject
ads, track navigation, or send data to remote servers.

---

## Data retention

| Store | TTL |
|---|---|
| In-memory link-scan cache | Until tab is closed |
| `chrome.storage.local` link cache | 30 minutes |
| `chrome.storage.local` scan history | Until you clear it via the extension |

---

## Contact

PhishPolice is an open-source project. Source code is available on GitHub.
For privacy questions, open an issue in the repository.

