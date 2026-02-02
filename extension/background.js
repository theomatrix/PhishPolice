// background.js - PhishPolice Service Worker

// Configuration
const CONFIG = {
  API_URL: "http://127.0.0.1:5000/api/analyze",
  REQUEST_TIMEOUT: 45000, // 45 seconds (increased for visual analysis)
  MAX_RETRIES: 2
};

// Listen for messages from popup (NOT automatic from content script)
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "ANALYZE_PAGE" && msg.features) {
    // Called by popup.js when user clicks Scan
    analyzePage(msg.features, msg.tabId)
      .then(result => {
        sendResponse({ ok: true, result });
      })
      .catch(error => {
        console.error("PhishPolice analysis failed:", error);
        sendResponse({ ok: false, error: error.message });
      });
    return true; // Keep channel open for async response
  }
});

/**
 * Analyze a page for phishing indicators
 * @param {Object} features - Page features from content script
 * @param {number} tabId - The tab ID being analyzed
 */
async function analyzePage(features, tabId) {
  try {
    // Get tab info for window ID
    const tab = await chrome.tabs.get(tabId);

    // Capture screenshot of the visible tab
    let imageData = "";
    try {
      const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
      imageData = dataUrl.split(",")[1] || "";
      console.log("PhishPolice: Screenshot captured");
    } catch (captureError) {
      console.warn("PhishPolice: Screenshot capture failed:", captureError.message);
      // Continue without screenshot - not critical
    }

    // Prepare payload with sanitized data
    const payload = {
      url: sanitizeString(features.url, 2048),
      hostname: sanitizeString(features.hostname, 255),
      title: sanitizeString(features.title, 500),
      forms: Array.isArray(features.forms) ? features.forms.slice(0, 100) : [],
      dom_signature: sanitizeString(features.dom_signature, 5000),
      suspiciousPatterns: Array.isArray(features.suspiciousPatterns) ? features.suspiciousPatterns : [],
      externalLinks: features.externalLinks || { external: 0, total: 0 },
      image_b64: imageData
    };

    console.log("PhishPolice: Sending analysis request for", features.hostname);

    // Send to backend with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

    const resp = await fetch(CONFIG.API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({}));
      throw new Error(errorData.error || `Server error: ${resp.status}`);
    }

    const result = await resp.json();

    // Validate response structure
    if (!result.verdict || typeof result.score !== "number") {
      throw new Error("Invalid response from server");
    }

    // Store result with timestamp
    const analysisData = {
      ...result,
      url: features.url,
      hostname: features.hostname,
      timestamp: Date.now()
    };

    await chrome.storage.local.set({ lastAnalysis: analysisData });

    console.log("PhishPolice: Analysis complete -", result.verdict, "score:", result.score);

    return result;

  } catch (error) {
    // Store error state
    await chrome.storage.local.set({
      lastAnalysis: {
        verdict: "error",
        score: 0,
        evidence: [`Analysis failed: ${error.message}`],
        url: features.url,
        timestamp: Date.now()
      }
    });
    throw error;
  }
}

/**
 * Sanitize a string to prevent injection attacks
 * @param {string} str - Input string
 * @param {number} maxLength - Maximum allowed length
 * @returns {string} Sanitized string
 */
function sanitizeString(str, maxLength) {
  if (typeof str !== "string") return "";
  return str.slice(0, maxLength);
}

// Log when service worker starts
console.log("PhishPolice background service worker initialized (manual scan mode)");
