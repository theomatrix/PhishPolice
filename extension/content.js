// content.js - PhishPolice Content Script

/**
 * Extract page features for phishing analysis
 * Only runs when called by popup.js (not automatically on page load)
 */

// Listen for messages from popup to analyze page
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "EXTRACT_FEATURES") {
    try {
      const features = extractPageFeatures();
      sendResponse({ ok: true, features });
    } catch (error) {
      console.error("PhishPolice feature extraction error:", error);
      sendResponse({ ok: false, error: error.message });
    }
  }
  return true; // Keep channel open for async
});

/**
 * Extract relevant features from the current page
 * @returns {Object} Page features object
 */
function extractPageFeatures() {
  const features = {
    url: location.href,
    hostname: location.hostname,
    title: document.title || "",
    protocol: location.protocol,
    forms: extractFormData(),
    dom_signature: generateDomSignature(),
    hasPasswordField: !!document.querySelector("input[type='password']"),
    externalLinks: countExternalLinks(),
    suspiciousPatterns: detectSuspiciousPatterns()
  };

  return features;
}

/**
 * Extract information about forms on the page
 * @returns {Array} Array of form data objects
 */
function extractFormData() {
  const forms = Array.from(document.forms);

  return forms.slice(0, 100).map(form => {
    const action = form.action || "";
    let actionHostname = "";

    try {
      if (action && action.startsWith("http")) {
        actionHostname = new URL(action).hostname;
      }
    } catch (e) {
      // Invalid URL
    }

    return {
      action: action ? action.slice(0, 500) : null,
      actionHostname: actionHostname,
      method: (form.method || "GET").toUpperCase(),
      inputCount: form.querySelectorAll("input, textarea, select").length,
      hasPassword: !!form.querySelector("input[type='password']"),
      hasEmail: !!form.querySelector("input[type='email']"),
      hasCreditCard: hasCreditCardFields(form),
      submitsToDifferentDomain: actionHostname && actionHostname !== location.hostname
    };
  });
}

/**
 * Check if form has credit card related fields
 * @param {HTMLFormElement} form - Form element
 * @returns {boolean}
 */
function hasCreditCardFields(form) {
  const ccPatterns = /card|credit|cvv|cvc|expir|ccnum/i;
  const inputs = form.querySelectorAll("input");

  for (const input of inputs) {
    const name = input.name || "";
    const id = input.id || "";
    const placeholder = input.placeholder || "";

    if (ccPatterns.test(name) || ccPatterns.test(id) || ccPatterns.test(placeholder)) {
      return true;
    }
  }

  return false;
}

/**
 * Generate a signature of the DOM structure
 * @returns {string} DOM signature string
 */
function generateDomSignature() {
  if (!document.body) return "";

  const elements = document.body.querySelectorAll("*");
  const signatureParts = [];
  const limit = Math.min(elements.length, 200);

  for (let i = 0; i < limit; i++) {
    signatureParts.push(nodeSignature(elements[i]));
  }

  return signatureParts.join("|").slice(0, 2000);
}

/**
 * Generate a signature for a single DOM node
 * @param {Element} node - DOM element
 * @returns {string} Node signature
 */
function nodeSignature(node) {
  let sig = node.nodeName;

  if (node.id) {
    sig += `#${node.id.slice(0, 50)}`;
  }

  if (node.className && typeof node.className === "string") {
    const classes = node.className.split(/\s+/).slice(0, 3).join(".");
    if (classes) sig += `.${classes.slice(0, 50)}`;
  }

  return sig;
}

/**
 * Count links pointing to external domains
 * @returns {Object} External link statistics
 */
function countExternalLinks() {
  const links = document.querySelectorAll("a[href]");
  let external = 0;
  let total = 0;

  links.forEach(link => {
    total++;
    try {
      const url = new URL(link.href);
      if (url.hostname !== location.hostname) {
        external++;
      }
    } catch (e) {
      // Invalid URL
    }
  });

  return { external, total };
}

/**
 * Detect common phishing patterns in the page
 * @returns {Array} List of detected suspicious patterns
 */
function detectSuspiciousPatterns() {
  const patterns = [];
  const bodyText = document.body?.innerText?.toLowerCase() || "";

  // Check for urgency language
  const urgencyPatterns = [
    "account suspended",
    "verify immediately",
    "urgent action required",
    "your account will be closed",
    "unusual activity",
    "confirm your identity",
    "security alert"
  ];

  urgencyPatterns.forEach(pattern => {
    if (bodyText.includes(pattern)) {
      patterns.push(`urgency: "${pattern}"`);
    }
  });

  // Check for hidden iframes
  const hiddenIframes = document.querySelectorAll('iframe[style*="display:none"], iframe[style*="visibility:hidden"], iframe[width="0"], iframe[height="0"]');
  if (hiddenIframes.length > 0) {
    patterns.push(`hidden_iframes: ${hiddenIframes.length}`);
  }

  // Check for data URI images (sometimes used to bypass filters)
  const dataUriImages = document.querySelectorAll('img[src^="data:"]');
  if (dataUriImages.length > 5) {
    patterns.push(`excessive_data_uri_images: ${dataUriImages.length}`);
  }

  return patterns.slice(0, 10); // Limit array size
}

// Log that content script is ready
console.log("PhishPolice content script ready (manual scan mode)");
