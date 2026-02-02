// popup.js - PhishPolice Popup UI Controller

const MAX_HISTORY_ITEMS = 10;
let IS_SCANNING = false; // Lock to prevent duplicate scans

document.addEventListener('DOMContentLoaded', () => {
  initializePopup();
  setupEventListeners();
  setupTabs();
});

/**
 * Initialize the popup with stored analysis data
 * Only shows previous analysis if it's for the current tab
 */
async function initializePopup() {
  try {
    // Get current tab URL
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentUrl = tab?.url || '';
    const currentHostname = currentUrl ? new URL(currentUrl).hostname : '';

    const data = await chrome.storage.local.get(['lastAnalysis', 'scanHistory']);
    const analysis = data.lastAnalysis;

    // Only show previous analysis if it matches current page
    if (analysis && analysis.hostname === currentHostname) {
      displayAnalysisResult(analysis);
    } else {
      // Show fresh "Ready to scan" state for new pages
      showNoAnalysis();
    }

    // Load scan history
    loadScanHistory(data.scanHistory || []);
  } catch (error) {
    console.error('Failed to load analysis:', error);
    showNoAnalysis();
  }
}

/**
 * Set up tab navigation
 */
function setupTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.dataset.tab;

      // Update active states
      tabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      tabContents.forEach(content => {
        content.classList.remove('active');
        if (content.id === `${tabId}Tab`) {
          content.classList.add('active');
        }
      });
    });
  });
}

/**
 * Set up event listeners for buttons
 */
function setupEventListeners() {
  document.getElementById('rescanBtn').addEventListener('click', async () => {
    await triggerRescan();
  });

  document.getElementById('reportBtn').addEventListener('click', async () => {
    try {
      const data = await chrome.storage.local.get(['lastAnalysis']);
      const analysis = data.lastAnalysis;

      if (analysis?.url) {
        const reportUrl = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(analysis.url)}`;
        chrome.tabs.create({ url: reportUrl });
      } else {
        showToast('No URL to report', 'error');
      }
    } catch (error) {
      console.error('Report failed:', error);
      showToast('Failed to open report page', 'error');
    }
  });

  // Clear history button
  document.getElementById('clearHistoryBtn')?.addEventListener('click', async () => {
    await chrome.storage.local.set({ scanHistory: [] });
    loadScanHistory([]);
    showToast('History cleared', 'success');
  });
}

/**
 * Load and display scan history
 */
function loadScanHistory(history) {
  const historyList = document.getElementById('historyList');
  const emptyHistory = document.getElementById('emptyHistory');

  if (!history || history.length === 0) {
    historyList.style.display = 'none';
    emptyHistory.style.display = 'flex';
    return;
  }

  historyList.style.display = 'block';
  emptyHistory.style.display = 'none';
  historyList.innerHTML = '';

  // Sort by timestamp descending
  const sortedHistory = [...history].sort((a, b) => b.timestamp - a.timestamp);

  sortedHistory.forEach((item, index) => {
    const historyItem = createHistoryItem(item, index);
    historyList.appendChild(historyItem);
  });
}

/**
 * Create a history item element
 */
function createHistoryItem(item, index) {
  const div = document.createElement('div');
  div.className = 'history-item';
  div.dataset.index = index;

  const verdictClass = item.verdict || 'unknown';
  const verdictIcon = {
    safe: '✓',
    suspicious: '⚠',
    phish: '✕',
    error: '!'
  }[verdictClass] || '?';

  const hostname = item.hostname || new URL(item.url || 'https://unknown').hostname;
  const time = formatTime(new Date(item.timestamp));
  const score = Math.round((item.score || 0) * 100);

  div.innerHTML = `
    <div class="history-verdict ${verdictClass}">
      <span>${verdictIcon}</span>
    </div>
    <div class="history-info">
      <div class="history-hostname">${escapeHtml(hostname)}</div>
      <div class="history-meta">
        <span class="history-score">${score}% risk</span>
        <span class="history-time">${time}</span>
      </div>
    </div>
    <div class="history-arrow">›</div>
  `;

  div.addEventListener('click', () => {
    displayAnalysisResult(item);
    // Switch to scan tab
    document.querySelector('[data-tab="scan"]').click();
  });

  return div;
}

/**
 * Save scan to history
 */
async function saveToHistory(analysis) {
  try {
    const data = await chrome.storage.local.get(['scanHistory']);
    let history = data.scanHistory || [];

    // Add new scan at the beginning
    const historyItem = {
      url: analysis.url,
      hostname: analysis.hostname,
      verdict: analysis.verdict,
      score: analysis.score,
      timestamp: analysis.timestamp || Date.now()
    };

    // Remove duplicate URLs (keep only latest)
    history = history.filter(h => h.url !== analysis.url);

    // Add to front
    history.unshift(historyItem);

    // Limit to max items
    if (history.length > MAX_HISTORY_ITEMS) {
      history = history.slice(0, MAX_HISTORY_ITEMS);
    }

    await chrome.storage.local.set({ scanHistory: history });
    loadScanHistory(history);
  } catch (error) {
    console.error('Failed to save history:', error);
  }
}

/**
 * Trigger a rescan of the current page
 */
async function triggerRescan() {
  // Prevent duplicate scans
  if (IS_SCANNING) {
    console.log('[PhishPolice] Scan already in progress, ignoring duplicate request');
    return;
  }

  IS_SCANNING = true;
  const rescanBtn = document.getElementById('rescanBtn');
  const originalContent = rescanBtn.innerHTML;

  try {
    rescanBtn.disabled = true;
    rescanBtn.innerHTML = '<span class="btn-spinner"></span> Scanning...';
    showScanningState();

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) {
      throw new Error('No active tab found');
    }

    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: extractPageFeaturesInline
    });

    if (!results || !results[0]?.result) {
      throw new Error('Failed to extract page features');
    }

    const features = results[0].result;

    let imageData = "";
    try {
      const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
      imageData = dataUrl.split(",")[1] || "";
    } catch (e) {
      console.warn("Screenshot capture failed:", e);
    }

    const payload = {
      url: features.url?.slice(0, 2048) || "",
      hostname: features.hostname?.slice(0, 255) || "",
      title: features.title?.slice(0, 500) || "",
      forms: Array.isArray(features.forms) ? features.forms.slice(0, 100) : [],
      dom_signature: features.dom_signature?.slice(0, 5000) || "",
      suspiciousPatterns: features.suspiciousPatterns || [],
      externalLinks: features.externalLinks || {},
      image_b64: imageData
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 45000); // 45s for visual analysis

    const resp = await fetch("http://127.0.0.1:5000/api/analyze", {
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
    console.log('[PhishPolice] API response received:', result);

    const analysisData = {
      ...result,
      url: features.url,
      hostname: features.hostname,
      timestamp: Date.now()
    };

    console.log('[PhishPolice] Saving and displaying analysis:', analysisData.verdict, analysisData.score);

    await chrome.storage.local.set({ lastAnalysis: analysisData });
    displayAnalysisResult(analysisData);
    await saveToHistory(analysisData);
    showToast('Scan complete!', 'success');

  } catch (error) {
    console.error('Rescan failed:', error);

    if (error.name === 'AbortError') {
      showToast('Scan timed out. Is the backend running?', 'error');
    } else {
      showToast(error.message || 'Scan failed', 'error');
    }

    const data = await chrome.storage.local.get(['lastAnalysis']);
    if (data.lastAnalysis) {
      displayAnalysisResult(data.lastAnalysis);
    } else {
      showNoAnalysis();
    }

  } finally {
    IS_SCANNING = false; // Release scan lock
    rescanBtn.disabled = false;
    rescanBtn.innerHTML = originalContent;
  }
}

/**
 * Inline function to extract page features
 */
function extractPageFeaturesInline() {
  const features = {
    url: location.href,
    hostname: location.hostname,
    title: document.title || "",
    forms: [],
    dom_signature: "",
    suspiciousPatterns: [],
    externalLinks: { external: 0, total: 0 }
  };

  // Extract form data
  const forms = Array.from(document.forms);
  features.forms = forms.slice(0, 100).map(form => {
    const action = form.action || "";
    let actionHostname = "";
    try {
      if (action && action.startsWith("http")) {
        actionHostname = new URL(action).hostname;
      }
    } catch (e) { }

    return {
      action: action.slice(0, 500),
      actionHostname: actionHostname,
      method: (form.method || "GET").toUpperCase(),
      inputCount: form.querySelectorAll("input, textarea, select").length,
      hasPassword: !!form.querySelector("input[type='password']"),
      hasEmail: !!form.querySelector("input[type='email']"),
      submitsToDifferentDomain: actionHostname && actionHostname !== location.hostname
    };
  });

  // Generate DOM signature
  if (document.body) {
    const elements = document.body.querySelectorAll("*");
    const parts = [];
    const limit = Math.min(elements.length, 200);
    for (let i = 0; i < limit; i++) {
      let sig = elements[i].nodeName;
      if (elements[i].id) sig += `#${elements[i].id.slice(0, 50)}`;
      if (elements[i].className && typeof elements[i].className === "string") {
        const cls = elements[i].className.split(/\s+/).slice(0, 3).join(".");
        if (cls) sig += `.${cls.slice(0, 50)}`;
      }
      parts.push(sig);
    }
    features.dom_signature = parts.join("|").slice(0, 2000);
  }

  // Detect suspicious patterns
  const bodyText = document.body?.innerText?.toLowerCase() || "";
  const urgencyPatterns = [
    "account suspended", "verify immediately", "urgent action",
    "your account will be closed", "unusual activity", "confirm your identity"
  ];
  urgencyPatterns.forEach(pattern => {
    if (bodyText.includes(pattern)) {
      features.suspiciousPatterns.push(`urgency: "${pattern}"`);
    }
  });

  // Hidden iframes
  const hiddenIframes = document.querySelectorAll('iframe[style*="display:none"], iframe[width="0"]');
  if (hiddenIframes.length > 0) {
    features.suspiciousPatterns.push(`hidden_iframes: ${hiddenIframes.length}`);
  }

  // External links
  const links = document.querySelectorAll('a[href]');
  links.forEach(link => {
    features.externalLinks.total++;
    try {
      const url = new URL(link.href);
      if (url.hostname !== location.hostname) {
        features.externalLinks.external++;
      }
    } catch (e) { }
  });

  return features;
}

/**
 * Show scanning state in UI
 */
function showScanningState() {
  document.getElementById('noAnalysis').style.display = 'none';
  document.getElementById('analysisResult').style.display = 'block';

  const verdictBadge = document.getElementById('verdictBadge');
  verdictBadge.className = 'verdict-badge loading';
  document.getElementById('verdictText').textContent = 'Analyzing...';
  document.getElementById('verdictIcon').textContent = '○';

  const progressCircle = document.getElementById('progressCircle');
  progressCircle.style.stroke = '#6366f1';
  progressCircle.style.strokeDashoffset = '377';
  progressCircle.classList.add('scanning');

  document.getElementById('scoreValue').textContent = '...';
  document.getElementById('evidenceList').innerHTML = '<li class="evidence-item scanning-msg">🔍 Analyzing with AI...</li>';

  const aiSummary = document.getElementById('aiSummary');
  if (aiSummary) {
    aiSummary.textContent = 'PhishPolice AI is analyzing this page...';
    aiSummary.classList.add('loading');
  }
  const aiRecommendation = document.getElementById('aiRecommendation');
  if (aiRecommendation) {
    aiRecommendation.style.display = 'none';
  }
}

/**
 * Display analysis result in the UI
 */
function displayAnalysisResult(analysis) {
  document.getElementById('noAnalysis').style.display = 'none';
  document.getElementById('analysisResult').style.display = 'block';

  const verdictBadge = document.getElementById('verdictBadge');
  const verdictText = document.getElementById('verdictText');
  const verdictIcon = document.getElementById('verdictIcon');

  const verdictConfig = {
    safe: { text: 'Safe', icon: '✓', class: 'safe' },
    suspicious: { text: 'Suspicious', icon: '⚠', class: 'suspicious' },
    phish: { text: 'Phishing Risk', icon: '✕', class: 'phish' },
    error: { text: 'Error', icon: '!', class: 'error' }
  };

  const config = verdictConfig[analysis.verdict] || verdictConfig.error;
  verdictBadge.className = `verdict-badge ${config.class}`;
  verdictText.textContent = config.text;
  verdictIcon.textContent = config.icon;

  const score = analysis.score || 0;
  const scorePercent = Math.round(score * 100);
  document.getElementById('scoreValue').textContent = `${scorePercent}%`;

  const progressCircle = document.getElementById('progressCircle');
  progressCircle.classList.remove('scanning');
  const circumference = 2 * Math.PI * 60;
  const offset = circumference - (score * circumference);

  const colors = {
    safe: '#00e5b0',
    suspicious: '#ffc107',
    phish: '#ff4d6a',
    error: '#666'
  };

  progressCircle.style.stroke = colors[analysis.verdict] || colors.error;

  setTimeout(() => {
    progressCircle.style.strokeDashoffset = offset;
  }, 100);

  const urlDisplay = document.getElementById('urlDisplay');
  urlDisplay.textContent = truncateUrl(analysis.url || analysis.hostname || '-');
  urlDisplay.title = analysis.url || '';

  // Update domain info display
  const domainInfo = analysis.domain_info || {};
  const domainInfoEl = document.getElementById('domainInfo');
  if (domainInfoEl) {
    let domainText = '';
    if (domainInfo.age_days !== null && domainInfo.age_days !== undefined) {
      const ageDays = domainInfo.age_days;
      if (ageDays < 30) {
        domainText = `🚨 Domain: ${ageDays} days old (NEW!)`;
        domainInfoEl.className = 'domain-info danger';
      } else if (ageDays < 90) {
        domainText = `⚠️ Domain: ${ageDays} days old`;
        domainInfoEl.className = 'domain-info warning';
      } else if (ageDays < 365) {
        domainText = `📅 Domain: ${ageDays} days old`;
        domainInfoEl.className = 'domain-info neutral';
      } else {
        const years = Math.floor(ageDays / 365);
        domainText = `✓ Domain: ${years}+ years old`;
        domainInfoEl.className = 'domain-info safe';
      }
    } else {
      domainText = '📅 Domain age: Unknown';
      domainInfoEl.className = 'domain-info neutral';
    }
    if (domainInfo.is_typosquat) {
      domainText = `🚨 Typosquat: Mimics ${domainInfo.suspected_brand}`;
      domainInfoEl.className = 'domain-info danger';
    }
    domainInfoEl.textContent = domainText;
    domainInfoEl.style.display = 'block';
  }

  const evidenceList = document.getElementById('evidenceList');
  evidenceList.innerHTML = '';

  if (analysis.evidence && Array.isArray(analysis.evidence)) {
    analysis.evidence.forEach(item => {
      const iconType = getEvidenceIconType(item, analysis.verdict);
      const li = document.createElement('li');
      li.className = 'evidence-item';
      li.innerHTML = `
        <span class="evidence-icon ${iconType}">${getEvidenceEmoji(iconType)}</span>
        <span>${escapeHtml(item)}</span>
      `;
      evidenceList.appendChild(li);
    });
  }

  updateAiAnalysis(analysis);

  if (analysis.timestamp) {
    const date = new Date(analysis.timestamp);
    document.getElementById('timestamp').textContent = `Analyzed ${formatTime(date)}`;
  }
}

/**
 * Update AI Analysis section with LLM results
 */
function updateAiAnalysis(analysis) {
  const aiSummary = document.getElementById('aiSummary');
  const aiRecommendation = document.getElementById('aiRecommendation');
  const aiRecommendationText = document.getElementById('aiRecommendationText');

  const llmAnalysis = analysis.llm_analysis || {};
  const summary = llmAnalysis.summary || 'AI analysis unavailable for this page.';
  const recommendation = llmAnalysis.recommendation || '';

  aiSummary.classList.remove('loading');
  aiSummary.textContent = summary;

  if (recommendation && recommendation.length > 0) {
    aiRecommendation.style.display = 'flex';
    aiRecommendationText.textContent = recommendation;
  } else {
    aiRecommendation.style.display = 'none';
  }
}

function showNoAnalysis() {
  document.getElementById('noAnalysis').style.display = 'block';
  document.getElementById('analysisResult').style.display = 'none';
}

function showError(message) {
  displayAnalysisResult({
    verdict: 'error',
    score: 0,
    evidence: [message],
    timestamp: Date.now()
  });
}

function showToast(message, type = 'info') {
  document.querySelectorAll('.toast').forEach(t => t.remove());
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.classList.add('show'), 10);
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function getEvidenceIconType(item, verdict) {
  const lower = item.toLowerCase();
  if (lower.includes('suspicious') || lower.includes('risk') || lower.includes('warning') || lower.includes('⚠️')) {
    return 'warning';
  }
  if (lower.includes('phish') || lower.includes('danger') || lower.includes('threat') || lower.includes('❌')) {
    return 'danger';
  }
  return 'info';
}

function getEvidenceEmoji(type) {
  const emojis = { info: 'ℹ️', warning: '⚠️', danger: '🚨' };
  return emojis[type] || emojis.info;
}

function truncateUrl(url) {
  if (url.length > 40) return url.slice(0, 37) + '...';
  return url;
}

function formatTime(date) {
  const now = new Date();
  const diff = now - date;
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
