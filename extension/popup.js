// popup.js – PhishPolice Popup UI Controller
// Drives the redesigned popup.html (Scan, Trusted Sites, History, Report)

'use strict';

/* ─── helpers & icons ─────────────────────────────────────────── */
const $ = id => document.getElementById(id);

const ICON = {
  ok:   '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="2,6 5,9 10,3"/></svg>',
  warn: '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="6" y1="3" x2="6" y2="7"/><circle cx="6" cy="9.5" r=".8" fill="currentColor" stroke="none"/></svg>',
  bad:  '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="2.5" y1="2.5" x2="9.5" y2="9.5"/><line x1="9.5" y1="2.5" x2="2.5" y2="9.5"/></svg>',
  x:    '<svg viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="m3 3 8 8M11 3l-8 8"/></svg>'
};

const SHARED_HOSTS = [
  "github.io", "sites.google.com", "blogspot.com", "wixsite.com",
  "netlify.app", "vercel.app", "pages.dev", "notion.site", "herokuapp.com",
  "glitch.me", "replit.dev", "codepen.io", "stackblitz.io", "web.app"
];
const isShared = d => SHARED_HOSTS.some(s => d === s || d.endsWith("." + s));

const MAX_HISTORY = 10;
let IS_SCANNING = false;

let trustedList = []; // [{ d: "github.com", on: "Oct 12" }]
let currentTabHostname = '';
let currentTabUrl = '';
let currentAnalysis = null;
let toastTimer = null;
let toastUndoAction = null;

/* ─── boot ────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initPopup();
  wireStaticButtons();
});

async function initPopup() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTabUrl  = tab?.url || '';
    try { currentTabHostname = currentTabUrl ? new URL(currentTabUrl).hostname.toLowerCase() : ''; } catch (_) {}

    // Load trusted sites first
    await loadTrustedSites();

    const data     = await chrome.storage.local.get(['lastAnalysis', 'scanHistory']);
    const analysis = data.lastAnalysis;
    currentAnalysis = analysis;

    if (isSiteTrusted(currentTabHostname)) {
      showTrustedState(currentTabHostname);
    } else if (analysis && analysis.hostname === currentTabHostname) {
      displayResult(analysis);
    } else {
      showReady(currentTabHostname, currentTabUrl);
    }

    renderHistory(data.scanHistory || []);
    renderTrustedRows();
  } catch (err) {
    console.error('[PhishPolice] init error', err);
    showReady('', '');
  }
}

/* ─── tab switching ───────────────────────────────────────────── */
function switchTab(tab) {
  // tab: 'scan' | 'trust' | 'hist'
  ['scan', 'trust', 'hist'].forEach(t => {
    const btn = $(`t-${t}`);
    if (btn) btn.setAttribute('aria-selected', t === tab ? 'true' : 'false');
  });
  $('scan').hidden    = tab !== 'scan';
  $('v-trust').hidden = tab !== 'trust';
  $('hist').hidden    = tab !== 'hist';
}

/* ─── static button wiring ────────────────────────────────────── */
function wireStaticButtons() {
  $('t-scan').addEventListener('click',  () => switchTab('scan'));
  $('t-hist').addEventListener('click',  () => switchTab('hist'));
  $('t-trust').addEventListener('click', () => switchTab('trust'));

  $('rescan').addEventListener('click', triggerRescan);

  $('report').addEventListener('click', openReportSheet);
  $('rep-cancel').addEventListener('click', closeReportSheet);
  $('rep-close').addEventListener('click',  closeReportSheet);

  // Trust toggle on Scan tab
  $('trust-toggle')?.addEventListener('click', () => {
    const targetDomain = cleanDomain(currentTabHostname);
    if (!targetDomain) return;
    if (isSiteTrusted(currentTabHostname)) {
      removeTrustedSite(targetDomain);
    } else {
      addTrustedSite(targetDomain);
    }
  });

  // Add site form on Trusted tab
  $('trust-form')?.addEventListener('submit', handleTrustFormSubmit);
  $('trust-inp')?.addEventListener('input', () => {
    $('trust-inp').removeAttribute('aria-invalid');
    $('trust-msg').textContent = '';
    $('trust-msg').className = '';
  });

  // Undo button on Toast
  $('undo')?.addEventListener('click', () => {
    if (toastUndoAction) {
      toastUndoAction();
      toastUndoAction = null;
    }
    $('toast')?.classList.remove('show');
  });

  // Chip toggle in Report sheet
  $('chips').addEventListener('click', e => {
    const btn = e.target.closest('button');
    if (!btn) return;
    const pressed = btn.getAttribute('aria-pressed') === 'true';
    btn.setAttribute('aria-pressed', pressed ? 'false' : 'true');
    const anySelected = [...$('chips').querySelectorAll('button')]
      .some(b => b.getAttribute('aria-pressed') === 'true');
    $('rep-send').disabled = !anySelected;
  });

  $('rep-send').addEventListener('click', sendReport);

  // Close sheet by clicking the backdrop
  $('sheet').addEventListener('click', e => {
    if (e.target === $('sheet')) closeReportSheet();
  });
}

/* ─── trusted sites logic ─────────────────────────────────────── */
async function loadTrustedSites() {
  try {
    let list = null;
    try {
      const syncData = await chrome.storage.sync.get('trustedSites');
      list = syncData.trustedSites;
    } catch (_) {}

    if (!list) {
      const localData = await chrome.storage.local.get('trustedSites');
      list = localData.trustedSites;
    }

    if (Array.isArray(list)) {
      trustedList = list.map(item => typeof item === 'string' ? { d: item, on: 'Earlier' } : item);
    } else {
      trustedList = [];
    }
  } catch (err) {
    console.warn('[PhishPolice] Could not load trusted sites', err);
    trustedList = [];
  }
}

async function saveTrustedSites() {
  try {
    await chrome.storage.sync.set({ trustedSites: trustedList });
  } catch (_) {}
  try {
    await chrome.storage.local.set({ trustedSites: trustedList });
  } catch (_) {}
}

function cleanDomain(input) {
  if (!input) return '';
  return input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .split(/[\/?#]/)[0]
    .replace(/^www\./, '');
}

function isSiteTrusted(hostname) {
  if (!hostname) return false;
  const host = hostname.toLowerCase();
  return trustedList.some(item => {
    const d = item.d.toLowerCase();
    if (isShared(d)) {
      return host === d; // exact address only for shared hosts
    }
    return host === d || host.endsWith('.' + d);
  });
}

function addTrustedSite(domain) {
  const d = cleanDomain(domain);
  if (!d) return;

  const newItem = { d, on: "Today" };
  trustedList.unshift(newItem);
  saveTrustedSites();
  updateTrustUI();

  showToast(`${d} added to trusted sites`, () => {
    trustedList = trustedList.filter(x => x.d !== d);
    saveTrustedSites();
    updateTrustUI();
  });
}

function removeTrustedSite(domain) {
  const d = cleanDomain(domain);
  const idx = trustedList.findIndex(x => x.d === d);
  if (idx === -1) return;
  const removed = trustedList[idx];

  trustedList.splice(idx, 1);
  saveTrustedSites();
  updateTrustUI();

  showToast(`${d} removed`, () => {
    trustedList.splice(idx, 0, removed);
    saveTrustedSites();
    updateTrustUI();
  });
}

function handleTrustFormSubmit(e) {
  e.preventDefault();
  const inp = $('trust-inp');
  const msg = $('trust-msg');
  if (!inp) return;

  const raw = inp.value;
  const d = cleanDomain(raw);

  const fail = errorMsg => {
    inp.setAttribute('aria-invalid', 'true');
    msg.textContent = errorMsg;
    msg.style.color = 'var(--bad)';
  };

  if (!d) return fail("Enter the site’s address.");
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d)) return fail("That doesn’t look like a web address.");
  if (trustedList.some(x => x.d === d)) return fail(`${d} is already trusted.`);

  inp.removeAttribute('aria-invalid');
  inp.value = '';
  msg.textContent = isShared(d)
    ? `Anyone can publish pages on ${d}, so only this exact address is trusted.`
    : '';
  msg.style.color = 'var(--muted)';

  addTrustedSite(d);
}

function renderTrustedRows() {
  const countEl = $('trust-count');
  if (countEl) countEl.textContent = trustedList.length ? String(trustedList.length) : '';

  const ul = $('trust-rows');
  if (!ul) return;

  if (trustedList.length === 0) {
    ul.innerHTML = `<li class="empty" style="padding:26px 8px;text-align:center;color:var(--muted);font-size:14px;line-height:1.5;list-style:none">No trusted sites yet. Add the ones you use every day so they skip the scan.</li>`;
    return;
  }

  ul.innerHTML = trustedList.map(x => `
    <li class="trust-row">
      <span class="trust-fav" aria-hidden="true">${escHtml(x.d[0] || '?')}</span>
      <div style="flex:1;min-width:0">
        <b>${escHtml(x.d)}${isShared(x.d) ? '<span class="exact-tag">Exact address only</span>' : ''}</b>
        <small>Added ${escHtml(x.on)}</small>
      </div>
      <button class="rm-btn" data-d="${escHtml(x.d)}" aria-label="Remove ${escHtml(x.d)}">${ICON.x}</button>
    </li>
  `).join('');

  ul.querySelectorAll('.rm-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const d = btn.getAttribute('data-d');
      if (d) removeTrustedSite(d);
    });
  });
}

function updateTrustUI() {
  renderTrustedRows();

  if (isSiteTrusted(currentTabHostname)) {
    showTrustedState(currentTabHostname);
  } else if (currentAnalysis && currentAnalysis.hostname === currentTabHostname) {
    displayResult(currentAnalysis);
  } else {
    showReady(currentTabHostname, currentTabUrl);
  }
}

/* ─── trusted neutral state in scan tab ───────────────────────── */
function showTrustedState(hostname) {
  stopScanning();
  applyVerdictTheme('muted');

  const card = $('verdict-card');
  if (card) {
    card.className = 'verdict trusted';
  }

  $('word').textContent = 'Trusted';
  $('sub').textContent  = 'You added this site, so PhishPolice skipped the scan.';
  $('host').textContent = hostname || '—';
  $('path').textContent = '';

  $('meter').hidden        = true;
  $('trust-checks').hidden = false;
  $('trust-why-host').textContent = `Other sites that link to ${hostname || 'this site'} aren’t trusted.`;

  $('aicard').hidden       = true;
  $('checks').hidden       = true;
  $('scan-actions').hidden = true;

  const toggle = $('trust-toggle');
  if (toggle) {
    toggle.textContent = 'Remove from trusted';
    toggle.className = 'btn';
  }
}

/* ─── ready / no-analysis state ──────────────────────────────── */
function showReady(hostname, url) {
  if (isSiteTrusted(hostname)) {
    showTrustedState(hostname);
    return;
  }

  stopScanning();
  applyVerdictTheme('muted');

  const card = $('verdict-card');
  if (card) card.className = 'verdict';

  $('word').textContent = 'Scan a page';
  $('sub').textContent  = 'Click "Scan again" to analyse this site.';
  $('host').textContent = hostname || '—';
  $('path').textContent = '';
  $('score').textContent = '';
  $('pin').style.left = '8%';

  $('meter').hidden        = false;
  $('trust-checks').hidden = true;
  $('aicard').hidden       = false;
  $('checks').hidden       = false;
  $('scan-actions').hidden = false;

  $('aicard').className = 'ai-card pending';
  $('aicard').innerHTML = buildAiCardPending('Ready to scan.');
  $('checks').innerHTML = '';

  const toggle = $('trust-toggle');
  if (toggle) {
    toggle.textContent = 'Trust this site';
    toggle.className = 'btn';
  }
}

/* ─── scanning state ──────────────────────────────────────────── */
function showScanning() {
  applyVerdictTheme('muted');
  const verdict = document.querySelector('.verdict');
  verdict?.classList.add('scanning');

  $('word').textContent  = 'Scanning…';
  $('sub').textContent   = 'Checking SSL, domain age, typosquatting…';
  $('score').textContent = '';
  $('pin').style.left    = '50%';

  $('meter').hidden        = false;
  $('trust-checks').hidden = true;
  $('aicard').hidden       = false;
  $('checks').hidden       = false;
  $('scan-actions').hidden = false;

  $('aicard').className = 'ai-card pending';
  $('aicard').innerHTML = buildAiCardPending('AI analysis in progress…');

  $('checks').innerHTML = '';
}

function stopScanning() {
  document.querySelector('.verdict')?.classList.remove('scanning');
}

/* ─── display result ──────────────────────────────────────────── */
function displayResult(analysis) {
  if (isSiteTrusted(analysis.hostname || currentTabHostname)) {
    showTrustedState(analysis.hostname || currentTabHostname);
    return;
  }

  stopScanning();

  const verdict = analysis.verdict || 'safe'; // 'safe' | 'suspicious' | 'phish'
  const colorKey = verdictToColor(verdict);

  applyVerdictTheme(colorKey);

  const card = $('verdict-card');
  if (card) card.className = 'verdict';

  // Verdict words
  const WORDS = { safe: 'Looks safe', suspicious: 'Be careful', phish: 'Likely phishing' };
  const SUBS  = {
    safe:       'No significant threats detected.',
    suspicious: 'Some signals look risky. Proceed with caution.',
    phish:      'High probability this page is a phishing site.'
  };
  $('word').textContent = WORDS[verdict] || 'Unknown';
  $('sub').textContent  = SUBS[verdict]  || '';

  // Host + path
  try {
    const u = new URL(analysis.url || `https://${analysis.hostname}`);
    $('host').textContent = u.hostname;
    $('path').textContent = u.pathname !== '/' ? u.pathname.slice(0, 40) : '';
  } catch (_) {
    $('host').textContent = analysis.hostname || '—';
    $('path').textContent = '';
  }

  // Score needle
  $('meter').hidden        = false;
  $('trust-checks').hidden = true;
  $('aicard').hidden       = false;
  $('checks').hidden       = false;
  $('scan-actions').hidden = false;

  const score = Math.min(Math.max(analysis.score || 0, 0), 0.99);
  const pct   = Math.round(score * 100);
  const pinPct = Math.round(pct * 0.84 + 8); // map 0-100 → 8-92%
  $('pin').style.left    = `${pinPct}%`;
  $('score').textContent = `Risk ${pct}/100`;

  // AI card
  renderAiCard(analysis, colorKey);

  // Checks / evidence
  renderChecks(analysis);

  // Trust button state
  const toggle = $('trust-toggle');
  if (toggle) {
    toggle.textContent = 'Trust this site';
    toggle.className = 'btn';
  }
}

/* ─── verdict → CSS color key ────────────────────────────────── */
function verdictToColor(verdict) {
  return { safe: 'safe', suspicious: 'warn', phish: 'bad' }[verdict] || 'muted';
}

/* ─── apply CSS variable theme ───────────────────────────────── */
function applyVerdictTheme(colorKey) {
  const r = document.documentElement;
  if (colorKey === 'safe') {
    r.style.setProperty('--verdict',    'var(--safe)');
    r.style.setProperty('--verdict-bg', 'var(--safe-bg)');
  } else if (colorKey === 'warn') {
    r.style.setProperty('--verdict',    'var(--warn)');
    r.style.setProperty('--verdict-bg', 'var(--warn-bg)');
  } else if (colorKey === 'bad') {
    r.style.setProperty('--verdict',    'var(--bad)');
    r.style.setProperty('--verdict-bg', 'var(--bad-bg)');
  } else {
    // muted (ready / scanning / trusted)
    r.style.setProperty('--verdict',    'var(--muted)');
    r.style.setProperty('--verdict-bg', 'var(--bg)');
  }
}

/* ─── AI card ─────────────────────────────────────────────────── */
function buildAiCardPending(msg) {
  return `
    <div class="ai-h">
      <span>GLM 5.3 Flash</span>
      <em>AI analysis</em>
    </div>
    <p class="ai-p">${escHtml(msg)}</p>`;
}

function renderAiCard(analysis, colorKey) {
  const llm = analysis.llm_analysis || {};
  const modelName = llm.model || 'GLM 5.3 Flash';
  const summary    = llm.summary        || 'AI analysis unavailable.';
  const recommendation = llm.recommendation || '';
  const factors   = Array.isArray(llm.risk_factors) ? llm.risk_factors : [];

  $('aicard').className = `ai-card ${colorKey}`;
  $('aicard').innerHTML = `
    <div class="ai-h">
      <span>${escHtml(modelName)}</span>
      <em>AI analysis</em>
    </div>
    <p class="ai-p">${escHtml(summary)}</p>
    ${recommendation ? `<p class="ai-f"><span>${escHtml(recommendation)}</span></p>` : ''}
    ${factors.length ? `<div class="ai-f"><span>Risk factors</span><strong>${escHtml(factors.slice(0,3).join(', '))}</strong></div>` : ''}`;
}

/* ─── checks / evidence list ──────────────────────────────────── */
function renderChecks(analysis) {
  const ul = $('checks');
  ul.innerHTML = '';

  const rows = buildCheckRows(analysis);
  rows.forEach(({ label, detail, type }) => {
    const li = document.createElement('li');
    li.className = 'done';
    li.innerHTML = `
      <div class="dot ${type}">${ICON[type]}</div>
      <div><h3>${escHtml(label)}</h3>${detail ? `<p>${escHtml(detail)}</p>` : ''}</div>`;
    ul.appendChild(li);
  });

  // Evidence strings from backend (additional rows)
  if (Array.isArray(analysis.evidence)) {
    analysis.evidence.forEach(ev => {
      const type = evidenceType(ev);
      const li = document.createElement('li');
      li.className = 'done';
      li.innerHTML = `
        <div class="dot ${type}">${ICON[type]}</div>
        <div><p>${escHtml(stripEmoji(ev))}</p></div>`;
      ul.appendChild(li);
    });
  }
}

function buildCheckRows(analysis) {
  const rows = [];
  const ssl  = analysis.ssl_info    || {};
  const dom  = analysis.domain_info || {};
  const ct   = analysis.ct_info     || {};
  const vis  = analysis.visual_info || {};

  // SSL
  if (ssl.has_ssl !== undefined) {
    if (!ssl.has_ssl) {
      rows.push({ label: 'No HTTPS', detail: 'Connection is not encrypted.', type: 'bad' });
    } else if (!ssl.is_valid) {
      rows.push({ label: 'Invalid SSL certificate', detail: ssl.issuer || '', type: 'bad' });
    } else {
      const days = ssl.expires_in_days;
      if (days !== undefined && days < 14) {
        rows.push({ label: `SSL expires in ${days} days`, detail: ssl.issuer || '', type: 'warn' });
      } else {
        rows.push({ label: 'Valid SSL certificate', detail: ssl.issuer ? `Issued by ${ssl.issuer}` : '', type: 'ok' });
      }
    }
  }

  // Domain age
  if (dom.age_days !== undefined && dom.age_days !== null) {
    const age = dom.age_days;
    if (age < 30) {
      rows.push({ label: `Domain is ${age} days old`, detail: 'Very new domain — high risk.', type: 'bad' });
    } else if (age < 180) {
      rows.push({ label: `Domain is ${age} days old`, detail: 'Relatively new.', type: 'warn' });
    } else {
      const yrs = (age / 365).toFixed(1);
      rows.push({ label: `Domain age: ${yrs} years`, detail: '', type: 'ok' });
    }
  }

  // Typosquat
  if (dom.is_typosquat) {
    rows.push({ label: `Typosquat detected`, detail: `Mimics "${dom.suspected_brand}"`, type: 'bad' });
  }

  // CT
  if (ct.warning) {
    rows.push({ label: 'Certificate transparency', detail: ct.warning, type: 'warn' });
  } else if (ct.checked && ct.certs_found > 0) {
    rows.push({ label: 'Certificate transparency OK', detail: `${ct.certs_found} cert(s) found`, type: 'ok' });
  }

  // Visual analysis
  if (vis.analyzed) {
    if (vis.is_login_page && vis.detected_brand) {
      rows.push({ label: `Fake login page`, detail: `Impersonates ${vis.detected_brand}`, type: 'bad' });
    } else if (vis.has_urgency) {
      rows.push({ label: 'Urgency language detected', detail: 'Page uses pressure tactics.', type: 'warn' });
    } else if (vis.detected_brand) {
      rows.push({ label: `Brand detected: ${vis.detected_brand}`, detail: '', type: 'warn' });
    }
  }

  return rows;
}

function evidenceType(ev) {
  const s = ev || '';
  if (/🚨|❌/.test(s) || /danger|phish|block|fake/i.test(s)) return 'bad';
  if (/⚠️?|⚠/.test(s) || /warn|suspicious|risk|caution/i.test(s)) return 'warn';
  return 'ok';
}

function stripEmoji(s) {
  return s.replace(/[\u{1F300}-\u{1FFFF}]|[\u2600-\u27BF]|✅|❌|⚠️?|🚨|✓|✗/gu, '').trim();
}

/* ─── history ─────────────────────────────────────────────────── */
function renderHistory(history) {
  const ul = $('hist');
  ul.innerHTML = '';

  if (!history || history.length === 0) {
    const li = document.createElement('li');
    li.style.cssText = 'justify-content:center;color:var(--muted);padding:40px 0;font-size:14px';
    li.textContent = 'No scans yet.';
    ul.appendChild(li);
    return;
  }

  const sorted = [...history].sort((a, b) => b.timestamp - a.timestamp);
  sorted.forEach(item => {
    const ck   = verdictToColor(item.verdict || 'safe');
    const pct  = Math.round((item.score || 0) * 100);
    const time = fmtTime(new Date(item.timestamp));
    const li   = document.createElement('li');
    li.innerHTML = `
      <div class="dot ${ck}">${ICON[ck] || ICON.ok}</div>
      <div style="min-width:0;flex:1">
        <div style="font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(item.hostname || '—')}</div>
        <small>${escHtml(time)}</small>
      </div>
      <span class="sc" style="color:var(--${ck})">${pct}</span>`;
    li.style.cursor = 'pointer';
    li.addEventListener('click', () => {
      displayResult(item);
      switchTab('scan');
    });
    ul.appendChild(li);
  });
}

async function saveToHistory(analysis) {
  try {
    const data = await chrome.storage.local.get(['scanHistory']);
    let history = data.scanHistory || [];
    history = history.filter(h => h.url !== analysis.url);
    history.unshift({
      url:       analysis.url,
      hostname:  analysis.hostname,
      verdict:   analysis.verdict,
      score:     analysis.score,
      timestamp: analysis.timestamp || Date.now()
    });
    if (history.length > MAX_HISTORY) history = history.slice(0, MAX_HISTORY);
    await chrome.storage.local.set({ scanHistory: history });
    renderHistory(history);
  } catch (err) {
    console.error('[PhishPolice] saveToHistory', err);
  }
}

/* ─── scan ────────────────────────────────────────────────────── */
async function triggerRescan() {
  if (IS_SCANNING) return;
  IS_SCANNING = true;
  $('rescan').disabled = true;
  $('rescan').textContent = 'Scanning…';

  showScanning();

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error('No active tab found.');

    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: extractPageFeaturesInline
    });
    if (!results?.[0]?.result) throw new Error('Failed to extract page features.');

    const features = results[0].result;

    let imageData = '';
    try {
      const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
      imageData = dataUrl.split(',')[1] || '';
    } catch (_) {}

    const payload = {
      url:                features.url?.slice(0, 2048)   || '',
      hostname:           features.hostname?.slice(0, 255) || '',
      title:              features.title?.slice(0, 500)   || '',
      forms:              Array.isArray(features.forms) ? features.forms.slice(0, 100) : [],
      dom_signature:      features.dom_signature?.slice(0, 5000) || '',
      suspiciousPatterns: features.suspiciousPatterns || [],
      externalLinks:      features.externalLinks || {},
      image_b64:          imageData
    };

    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 45_000);

    const resp = await fetch('http://127.0.0.1:5000/api/analyze', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
      signal:  controller.signal
    });
    clearTimeout(tid);

    if (!resp.ok) {
      const e = await resp.json().catch(() => ({}));
      throw new Error(e.error || `Server error ${resp.status}`);
    }

    const result = await resp.json();
    const analysisData = {
      ...result,
      url:       features.url,
      hostname:  features.hostname,
      timestamp: Date.now()
    };

    currentAnalysis = analysisData;
    await chrome.storage.local.set({ lastAnalysis: analysisData });
    displayResult(analysisData);
    await saveToHistory(analysisData);
    showToast('Scan complete!', null, 'success');

  } catch (err) {
    console.error('[PhishPolice] scan error', err);
    const msg = err.name === 'AbortError'
      ? 'Scan timed out. Is the backend running?'
      : (err.message || 'Scan failed');
    showToast(msg, null, 'error');
    stopScanning();

    const data = await chrome.storage.local.get(['lastAnalysis']);
    if (data.lastAnalysis) displayResult(data.lastAnalysis);
    else showReady(currentTabHostname, currentTabUrl);
  } finally {
    IS_SCANNING = false;
    $('rescan').disabled = false;
    $('rescan').textContent = 'Scan again';
  }
}

/* Inline page-feature extractor (runs in page context via scripting API) */
function extractPageFeaturesInline() {
  const features = {
    url:                location.href,
    hostname:           location.hostname,
    title:              document.title || '',
    forms:              [],
    dom_signature:      '',
    suspiciousPatterns: [],
    externalLinks:      { external: 0, total: 0 }
  };

  // Forms
  features.forms = Array.from(document.forms).slice(0, 100).map(form => {
    let actionHost = '';
    try { if (form.action?.startsWith('http')) actionHost = new URL(form.action).hostname; } catch (_) {}
    return {
      action:                   (form.action || '').slice(0, 500),
      actionHostname:           actionHost,
      method:                   (form.method || 'GET').toUpperCase(),
      inputCount:               form.querySelectorAll('input,textarea,select').length,
      hasPassword:              !!form.querySelector("input[type='password']"),
      hasEmail:                 !!form.querySelector("input[type='email']"),
      submitsToDifferentDomain: !!(actionHost && actionHost !== location.hostname)
    };
  });

  // DOM signature
  if (document.body) {
    const els  = document.body.querySelectorAll('*');
    const parts = [];
    const lim  = Math.min(els.length, 200);
    for (let i = 0; i < lim; i++) {
      let sig = els[i].nodeName;
      if (els[i].id) sig += `#${els[i].id.slice(0, 50)}`;
      if (els[i].className && typeof els[i].className === 'string') {
        const cls = els[i].className.split(/\s+/).slice(0, 3).join('.');
        if (cls) sig += `.${cls.slice(0, 50)}`;
      }
      parts.push(sig);
    }
    features.dom_signature = parts.join('|').slice(0, 2000);
  }

  // Suspicious patterns
  const bodyText = document.body?.innerText?.toLowerCase() || '';
  ['account suspended','verify immediately','urgent action',
   'your account will be closed','unusual activity','confirm your identity']
    .forEach(p => { if (bodyText.includes(p)) features.suspiciousPatterns.push(`urgency: "${p}"`); });

  const hiddenIframes = document.querySelectorAll('iframe[style*="display:none"],iframe[width="0"]');
  if (hiddenIframes.length) features.suspiciousPatterns.push(`hidden_iframes: ${hiddenIframes.length}`);

  // External links
  document.querySelectorAll('a[href]').forEach(a => {
    features.externalLinks.total++;
    try {
      if (new URL(a.href).hostname !== location.hostname) features.externalLinks.external++;
    } catch (_) {}
  });

  return features;
}

/* ─── report sheet ────────────────────────────────────────────── */
async function openReportSheet() {
  $('rep-form').hidden = false;
  $('rep-done').hidden = true;
  $('rep-send').disabled = true;
  $('rep-note').value = '';
  $('chips').querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', 'false'));

  $('sheet').hidden = false;
}

function closeReportSheet() {
  $('sheet').hidden = true;
}

async function sendReport() {
  const data = await chrome.storage.local.get(['lastAnalysis']);
  const analysis = data.lastAnalysis;

  const chips = [...$('chips').querySelectorAll('button[aria-pressed="true"]')]
    .map(b => b.textContent);
  const note = $('rep-note').value.trim();

  if (analysis?.url) {
    const reportUrl = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(analysis.url)}`;
    chrome.tabs.create({ url: reportUrl });
  }

  $('rep-form').hidden = true;
  $('rep-done').hidden = false;

  const sum = $('rep-sum');
  sum.innerHTML = '';
  if (analysis?.hostname) {
    sum.innerHTML += `<div><dt>Site</dt><dd>${escHtml(analysis.hostname)}</dd></div>`;
  }
  if (chips.length) {
    sum.innerHTML += `<div><dt>Reasons</dt><dd>${escHtml(chips.join(', '))}</dd></div>`;
  }
  if (note) {
    sum.innerHTML += `<div><dt>Note</dt><dd>${escHtml(note)}</dd></div>`;
  }
}

/* ─── toast with undo ─────────────────────────────────────────── */
function showToast(text, onUndo, type = 'info') {
  const t = $('toast');
  const msg = $('toast-t');
  const undoBtn = $('undo');
  if (!t || !msg) return;

  msg.textContent = text;
  t.className = `toast show${type === 'error' ? ' toast-error' : type === 'success' ? ' toast-success' : ''}`;

  if (onUndo) {
    undoBtn.hidden = false;
    toastUndoAction = onUndo;
  } else {
    undoBtn.hidden = true;
    toastUndoAction = null;
  }

  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    t.classList.remove('show');
    toastUndoAction = null;
  }, 4000);
}

/* ─── utilities ───────────────────────────────────────────────── */
function fmtTime(date) {
  const diff = Date.now() - date.getTime();
  if (diff < 60_000)    return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function escHtml(str) {
  const d = document.createElement('div');
  d.textContent = String(str ?? '');
  return d.innerHTML;
}
