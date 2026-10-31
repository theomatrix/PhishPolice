// link_scanner.js – PhishPolice pre-click link scanner  v3.0
// CSS is in link_scanner.css (declared in manifest) — bypasses host page CSP.
'use strict';

/* ═══════════════════════════════════════════════════════════════
   SECTION 1 – TRUSTED SITES
   Stored in chrome.storage.sync so it follows the user across devices.
   ═══════════════════════════════════════════════════════════════ */

/**
 * Shared hosting platforms where trusting the apex domain would be unsafe
 * (anyone can publish a page on them).  We match exact address only.
 */
const SHARED_HOSTS = new Set([
  'github.io','sites.google.com','blogspot.com','wixsite.com',
  'netlify.app','vercel.app','pages.dev','notion.site','herokuapp.com',
  'glitch.me','replit.dev','codepen.io','stackblitz.io','web.app'
]);

// In-memory copy; populated once on startup and kept in sync.
let trustedDomains = new Set();

/** Load trusted list from storage into the in-memory Set */
async function loadTrusted() {
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
      trustedDomains = new Set(list.map(x => (typeof x === 'string' ? x : x.d).toLowerCase()));
    }
  } catch (_) {}
}

/** Persist the in-memory Set back to storage */
async function saveTrusted() {
  try {
    const list = [...trustedDomains].map(d => ({ d, on: 'Today' }));
    await chrome.storage.sync.set({ trustedSites: list });
    await chrome.storage.local.set({ trustedSites: list });
  } catch (_) {}
}

/**
 * Check whether a URL's domain is trusted.
 * Rule: exact registered-domain match unless it's a shared host,
 * in which case the full hostname must match exactly.
 */
function isTrusted(url) {
  let hostname;
  try { hostname = new URL(url).hostname.toLowerCase(); } catch (_) { return false; }
  const apex = apexDomain(hostname);
  if (SHARED_HOSTS.has(apex) || SHARED_HOSTS.has(hostname)) {
    return trustedDomains.has(hostname); // exact match for shared hosts
  }
  return trustedDomains.has(apex) || trustedDomains.has(hostname);
}

// Listen for storage changes from popup (trusted list updated there)
chrome.storage.onChanged.addListener((changes, area) => {
  if (changes.trustedSites) {
    const list = changes.trustedSites.newValue || [];
    trustedDomains = new Set(list.map(x => (typeof x === 'string' ? x : x.d).toLowerCase()));
  }
});

// Kick off initial load
loadTrusted();


/* ═══════════════════════════════════════════════════════════════
   SECTION 2 – LOCAL CHECKS (zero-network, < 1 ms)
   ═══════════════════════════════════════════════════════════════ */

const BRANDS = [
  'google','facebook','apple','amazon','microsoft','paypal','netflix',
  'instagram','twitter','linkedin','dropbox','github','yahoo','outlook',
  'office365','onedrive','icloud','chase','wellsfargo','bankofamerica',
  'citibank','amex','americanexpress','ebay','walmart','target'
];

const SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','ow.ly','goo.gl','buff.ly','ift.tt',
  'dlvr.it','short.io','rb.gy','cutt.ly','is.gd','v.gd','tiny.cc',
  'lnkd.in','youtu.be','amzn.to','mcaf.ee','bl.ink','shorturl.at'
]);

const RISKY_TLDS = new Set([
  'tk','ml','ga','cf','gq','xyz','top','click','link','work',
  'support','online','site','website','tech','live','stream'
]);

function normalizeLookalike(s) {
  return s
    .replace(/0/g,'o').replace(/1/g,'l').replace(/3/g,'e')
    .replace(/4/g,'a').replace(/5/g,'s').replace(/6/g,'g').replace(/8/g,'b')
    .replace(/\u0430/g,'a').replace(/\u0435/g,'e').replace(/\u043e/g,'o')
    .replace(/\u0440/g,'p').replace(/\u0441/g,'c').replace(/\u0443/g,'y');
}

function apexDomain(hostname) {
  const parts = hostname.replace(/^www\./,'').split('.');
  return parts.slice(-2).join('.').toLowerCase();
}

function localCheck(url) {
  const reasons = [];
  let maxRisk = 0;
  const bump = (level, reason) => { reasons.push(reason); if (level > maxRisk) maxRisk = level; };

  let parsed;
  try { parsed = new URL(url); } catch (_) { return { risk:'safe', reasons:[] }; }
  const { hostname, protocol } = parsed;

  if (protocol === 'http:' && hostname !== 'localhost' && !/^\d+\.\d+\.\d+\.\d+$/.test(hostname))
    bump(1, 'No HTTPS encryption');
  if (hostname.includes('xn--'))
    bump(2, 'Internationalised (punycode) domain — common phishing trick');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname))
    bump(2, 'Raw IP address used instead of a domain name');

  const apex = apexDomain(hostname);
  if (SHORTENERS.has(apex) || SHORTENERS.has(hostname))
    bump(1, 'URL shortener — true destination is hidden');

  const tld = hostname.split('.').pop().toLowerCase();
  if (RISKY_TLDS.has(tld))
    bump(1, `High-risk TLD (.${tld})`);

  if (hostname.replace(/^www\./,'').split('.').length > 4)
    bump(1, 'Unusually deep subdomain structure');

  const normalHost = normalizeLookalike(hostname.toLowerCase());
  for (const brand of BRANDS) {
    if (normalHost.includes(brand) && !normalHost.endsWith(`.${brand}.com`) && apex !== `${brand}.com`) {
      bump(2, `Brand name "${brand}" appears in hostname but domain is "${apex}"`);
      break;
    }
  }

  const normalApex = normalizeLookalike(apex.split('.')[0]);
  for (const brand of BRANDS) {
    if (normalApex === brand && apex.split('.')[0] !== brand) {
      bump(2, `"${apex.split('.')[0]}" uses lookalike characters to mimic "${brand}"`);
      break;
    }
  }

  if (apexDomain(hostname) !== apexDomain(location.hostname)) {
    const full = url.toLowerCase();
    if (/login|signin|account|verify|secure|banking|update.?password|confirm/.test(full))
      bump(1, 'Credential-related keywords in an external URL');
  }

  if (hostname.length > 40)
    bump(1, 'Unusually long hostname');

  return { risk: ['safe','suspicious','bad'][maxRisk], reasons };
}


/* ═══════════════════════════════════════════════════════════════
   SECTION 3 – CACHE (memory + chrome.storage, 30 min TTL)
   ═══════════════════════════════════════════════════════════════ */

const CACHE_TTL = 30 * 60 * 1000;
const memCache  = new Map();

function hashUrl(url) {
  let h = 5381;
  for (let i = 0; i < Math.min(url.length, 256); i++)
    h = (((h << 5) + h) ^ url.charCodeAt(i)) >>> 0;
  return h.toString(36);
}

async function getCached(url) {
  if (memCache.has(url)) {
    const { result, ts } = memCache.get(url);
    if (Date.now() - ts < CACHE_TTL) return result;
    memCache.delete(url);
  }
  try {
    const key  = `lsc_${hashUrl(url)}`;
    const data = await chrome.storage.local.get(key);
    if (data[key]) {
      const { result, ts } = data[key];
      if (Date.now() - ts < CACHE_TTL) { memCache.set(url, { result, ts }); return result; }
    }
  } catch (_) {}
  return null;
}

async function setCached(url, result) {
  const ts = Date.now();
  memCache.set(url, { result, ts });
  try {
    await chrome.storage.local.set({ [`lsc_${hashUrl(url)}`]: { result, ts } });
  } catch (_) {}
}


/* ═══════════════════════════════════════════════════════════════
   SECTION 4 – BACKEND CALL (on-demand, deduped, 8 s timeout)
   ═══════════════════════════════════════════════════════════════ */

const BACKEND = 'http://127.0.0.1:5000';

async function callBackend(url) {
  const cached = await getCached(url);
  if (cached) return cached;

  let parsed;
  try { parsed = new URL(url); } catch (_) { return null; }

  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), 8000);
  try {
    const resp = await fetch(`${BACKEND}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: url.slice(0, 2048), hostname: parsed.hostname.slice(0, 255),
        title: '', forms: [], dom_signature: '',
        suspiciousPatterns: [], externalLinks: { external:0, total:0 }, image_b64: ''
      }),
      signal: controller.signal
    });
    clearTimeout(tid);
    if (!resp.ok) return null;
    const result = await resp.json();
    await setCached(url, result);
    return result;
  } catch (_) {
    clearTimeout(tid);
    return null;
  }
}

function shouldCallBackend(url, localResult) {
  let hostname;
  try { hostname = new URL(url).hostname; } catch (_) { return false; }
  if (apexDomain(hostname) === apexDomain(location.hostname)) return false;
  return localResult.risk !== 'safe' || !memCache.has(url);
}

function mergeResults(local, backend) {
  const order = { safe:0, suspicious:1, bad:2 };
  const backendRisk = { safe:'safe', suspicious:'suspicious', phish:'bad' }[backend.verdict] || 'safe';
  const risk = order[backendRisk] >= order[local.risk] ? backendRisk : local.risk;
  const reasons = [
    ...local.reasons,
    ...(Array.isArray(backend.evidence) ? backend.evidence.map(stripEmoji).filter(Boolean) : [])
  ];
  return { risk, reasons };
}


/* ═══════════════════════════════════════════════════════════════
   SECTION 5 – TOOLTIP  (single element, repositioned on hover)
   CSS comes from link_scanner.css (manifest-declared).
   ═══════════════════════════════════════════════════════════════ */

const IC = {
  safe: '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m2.5 6.3 2.5 2.4 4.5-5"/></svg>',
  warn: '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 2.5v4.2M6 9.3v.1"/></svg>',
  bad:  '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="m3 3 6 6M9 3 3 9"/></svg>'
};

const WORDS = { safe:'Looks safe', suspicious:'Be careful', bad:'Likely phishing' };
const ACTS  = { safe:'Safe to open', suspicious:"Don't enter passwords", bad:"Don't open this link" };

let tipEl         = null;
let hideTimer     = null;
let scanTimer     = null;
let currentAnchor = null;

function getTip() {
  if (tipEl) return tipEl;
  tipEl = document.createElement('div');
  tipEl.id = 'pp-tip';
  tipEl.setAttribute('role', 'status');
  tipEl.setAttribute('aria-live', 'polite');
  // Append to <html> so it's outside any overflow:hidden containers
  document.documentElement.appendChild(tipEl);
  return tipEl;
}

function placeTip(anchor) {
  const tip = getTip();
  const r   = anchor.getBoundingClientRect();
  const w   = 300;
  const h   = tip.offsetHeight || 170;
  const left = Math.max(8, Math.min(r.left, window.innerWidth - w - 8));
  const below = r.bottom + 8;
  const top   = (below + h > window.innerHeight) ? Math.max(8, r.top - h - 8) : below;
  tip.style.left = `${left}px`;
  tip.style.top  = `${top}px`;
}

function showSpinner(anchor, hostText) {
  const tip = getTip();
  tip.innerHTML = `
    <div class="pp-tip-h">
      <span class="pp-dot pp-spin"></span>
      <span class="pp-word">Checking link…</span>
    </div>
    ${hostText ? `<p class="pp-host">${escHtml(hostText)}</p>` : ''}`;
  tip.classList.add('pp-show');
  placeTip(anchor);
}

function showResult(anchor, { risk, reasons, hostname, score }) {
  const tip  = getTip();
  const ck   = risk === 'bad' ? 'bad' : risk === 'suspicious' ? 'warn' : 'safe';
  const scoreStr = (score !== undefined && score !== null) ? ` · ${Math.round(score * 100)}/100` : '';
  const topWhy   = (reasons || []).slice(0, 2);

  tip.innerHTML = `
    <div class="pp-tip-h">
      <span class="pp-dot pp-${ck}">${IC[ck]}</span>
      <span class="pp-word pp-${ck}">${escHtml(WORDS[risk] || 'Unknown')}</span>
    </div>
    ${hostname ? `<p class="pp-host">${escHtml(hostname)}</p>` : ''}
    ${topWhy.length ? `<ul class="pp-why">${topWhy.map(r => `<li>${escHtml(r)}</li>`).join('')}</ul>` : ''}
    <p class="pp-act pp-${ck}">
      ${escHtml(ACTS[risk] || '')}
      <span class="pp-by">PhishPolice${scoreStr}</span>
    </p>`;

  tip.classList.add('pp-show');
  placeTip(anchor);
  markLink(anchor, risk);
}

function hideTip(delay = 200) {
  clearTimeout(hideTimer);
  hideTimer = setTimeout(() => tipEl?.classList.remove('pp-show'), delay);
}

function markLink(el, risk) {
  if (!el) return;
  el.setAttribute('data-pp-v', 'done');
  el.removeAttribute('data-pp-safe');
  el.removeAttribute('data-pp-warn');
  el.removeAttribute('data-pp-bad');
  const attr = risk === 'safe' ? 'data-pp-safe' : risk === 'suspicious' ? 'data-pp-warn' : 'data-pp-bad';
  el.setAttribute(attr, '');
}


/* ═══════════════════════════════════════════════════════════════
   SECTION 6 – STOP OVERLAY (click intercept for 'bad' links)
   ═══════════════════════════════════════════════════════════════ */

let stopEl     = null;
let pendingUrl = null;

function getStop() {
  if (stopEl) return stopEl;
  stopEl = document.createElement('div');
  stopEl.id = 'pp-stop';
  stopEl.setAttribute('role', 'dialog');
  stopEl.setAttribute('aria-modal', 'true');
  stopEl.setAttribute('aria-labelledby', 'pp-stop-h');
  stopEl.innerHTML = `
    <div class="pp-stop-card">
      <div class="pp-dot pp-bad" style="width:30px;height:30px">${IC.bad}</div>
      <h2 class="pp-stop-h" id="pp-stop-h">This link looks like phishing</h2>
      <p class="pp-stop-p">The destination address was flagged as likely malicious:</p>
      <code class="pp-stop-url" id="pp-stop-url"></code>
      <ul class="pp-why" id="pp-stop-why" style="color:#5C6B66;font-size:13px"></ul>
      <button class="pp-btn"       id="pp-stop-back">Go back</button>
      <button class="pp-btn-ghost" id="pp-stop-go">Open anyway</button>
    </div>`;
  document.documentElement.appendChild(stopEl);
  document.getElementById('pp-stop-back').addEventListener('click', closeStop);
  document.getElementById('pp-stop-go').addEventListener('click', () => { closeStop(); if (pendingUrl) window.location.href = pendingUrl; });
  stopEl.addEventListener('click', e => { if (e.target === stopEl) closeStop(); });
  return stopEl;
}

function showStop({ url, hostname, reasons }) {
  pendingUrl = url;
  hideTip(0);
  const el = getStop();
  el.hidden = false;
  const urlEl = document.getElementById('pp-stop-url');
  const whyEl = document.getElementById('pp-stop-why');
  if (urlEl) urlEl.textContent = url || hostname || '';
  if (whyEl) whyEl.innerHTML  = (reasons || []).slice(0, 4).map(r => `<li>${escHtml(r)}</li>`).join('');
  requestAnimationFrame(() => document.getElementById('pp-stop-back')?.focus());
}

function closeStop() {
  if (stopEl) stopEl.hidden = true;
  pendingUrl = null;
}


/* ═══════════════════════════════════════════════════════════════
   SECTION 7 – SCAN ORCHESTRATION
   ═══════════════════════════════════════════════════════════════ */

const inFlight = new Set();

async function scanLink(anchor, url, fromClick) {
  // Skip if domain is trusted
  if (isTrusted(url)) {
    if (!fromClick) {
      let hostname = '';
      try { hostname = new URL(url).hostname; } catch (_) {}
      showResult(anchor, { risk:'safe', reasons:['You\'ve marked this site as trusted'], hostname, score:null });
    }
    return;
  }

  let hostname = '';
  try { hostname = new URL(url).hostname; } catch (_) {}

  // Instant memory cache hit
  const instant = memCache.get(url);
  if (instant && Date.now() - instant.ts < CACHE_TTL) {
    const merged = mergeResults(localCheck(url), instant.result);
    if (fromClick && merged.risk === 'bad') showStop({ url, hostname, reasons: merged.reasons });
    else showResult(anchor, { ...merged, hostname, score: instant.result?.score });
    return;
  }

  if (!fromClick) showSpinner(anchor, hostname);

  const local = localCheck(url);

  if (!shouldCallBackend(url, local)) {
    if (fromClick && local.risk === 'bad') showStop({ url, hostname, reasons: local.reasons });
    else showResult(anchor, { ...local, hostname, score: null });
    return;
  }

  if (!inFlight.has(url)) {
    inFlight.add(url);
    callBackend(url).then(result => {
      inFlight.delete(url);
      if (!result) return;
      const merged = mergeResults(local, result);
      if (fromClick && merged.risk === 'bad') {
        showStop({ url, hostname, reasons: merged.reasons });
      } else if (currentAnchor === anchor) {
        showResult(anchor, { ...merged, hostname, score: result.score });
      }
    }).catch(() => inFlight.delete(url));
  }

  // Show local result immediately while backend loads
  if (fromClick && local.risk === 'bad') showStop({ url, hostname, reasons: local.reasons });
  else showResult(anchor, { ...local, hostname, score: null });
}


/* ═══════════════════════════════════════════════════════════════
   SECTION 8 – EVENT WIRING
   ═══════════════════════════════════════════════════════════════ */

function resolveHref(el) {
  const a = el.closest('a[href]');
  if (!a) return null;
  const href = a.href;
  if (!href ||
      href.startsWith('javascript:') || href.startsWith('mailto:') ||
      href.startsWith('tel:') || href === window.location.href ||
      href.startsWith(window.location.href + '#'))
    return null;
  try {
    const u = new URL(href);
    if (u.pathname === location.pathname && u.search === location.search && u.hash)
      return null;
  } catch (_) {}
  return href;
}

// ── Hover ────────────────────────────────────────────────────────
document.addEventListener('mouseover', e => {
  const anchor = e.target.closest('a[href]');
  const url    = anchor ? resolveHref(e.target) : null;
  if (!url) return;
  clearTimeout(scanTimer);
  clearTimeout(hideTimer);
  currentAnchor = anchor;
  scanTimer = setTimeout(() => scanLink(anchor, url, false), 350);
}, { passive: true, capture: true });

document.addEventListener('mouseout', e => {
  if (!e.target.closest('a[href]')) return;
  clearTimeout(scanTimer);
  currentAnchor = null;
  hideTip(400);
}, { passive: true, capture: true });

// ── Keyboard (Tab / focus) ───────────────────────────────────────
document.addEventListener('focusin', e => {
  const anchor = e.target.closest('a[href]');
  const url    = anchor ? resolveHref(e.target) : null;
  if (!url) return;
  currentAnchor = anchor;
  clearTimeout(scanTimer);
  scanTimer = setTimeout(() => scanLink(anchor, url, false), 120);
}, { capture: true });

document.addEventListener('focusout', e => {
  if (!e.target.closest('a[href]')) return;
  clearTimeout(scanTimer);
  currentAnchor = null;
  hideTip(300);
}, { capture: true });

// ── Escape ───────────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { hideTip(0); closeStop(); }
}, { capture: true });

// ── Scroll (reposition) ──────────────────────────────────────────
document.addEventListener('scroll', () => {
  if (currentAnchor && tipEl?.classList.contains('pp-show')) placeTip(currentAnchor);
}, { passive: true });

// ── Click intercept ──────────────────────────────────────────────
document.addEventListener('click', e => {
  if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
  const anchor = e.target.closest('a[href]');
  const url    = resolveHref(e.target);
  if (!url || !anchor) return;
  if (isTrusted(url)) return; // trusted → navigate freely

  // Memory cache instant check
  const cached = memCache.get(url);
  if (cached && Date.now() - cached.ts < CACHE_TTL) {
    const r = mergeResults(localCheck(url), cached.result);
    if (r.risk === 'bad') {
      e.preventDefault(); e.stopImmediatePropagation();
      let hostname = '';
      try { hostname = new URL(url).hostname; } catch (_) {}
      showStop({ url, hostname, reasons: r.reasons });
    }
    return;
  }

  const local = localCheck(url);
  if (local.risk === 'bad') {
    e.preventDefault(); e.stopImmediatePropagation();
    let hostname = '';
    try { hostname = new URL(url).hostname; } catch (_) {}
    showStop({ url, hostname, reasons: local.reasons });
    callBackend(url).then(result => {
      if (!result || stopEl?.hidden !== false) return;
      const merged = mergeResults(local, result);
      const whyEl = document.getElementById('pp-stop-why');
      if (whyEl) whyEl.innerHTML = merged.reasons.slice(0, 4).map(r => `<li>${escHtml(r)}</li>`).join('');
    }).catch(() => {});
  }
}, true);


/* ═══════════════════════════════════════════════════════════════
   SECTION 9 – UTILITIES
   ═══════════════════════════════════════════════════════════════ */

function escHtml(str) {
  const d = document.createElement('div');
  d.textContent = String(str ?? '');
  return d.innerHTML;
}

function stripEmoji(s) {
  return String(s).replace(/[\u{1F300}-\u{1FFFF}]|[\u2600-\u27BF]|✅|❌|⚠️?|🚨|✓|✗/gu, '').trim();
}

console.log('[PhishPolice] Link scanner v3.0 active (CSS via manifest, trusted-sites aware).');

/* ── CommonJS export guard (Jest test harness only) ───────────── */
if (typeof module !== 'undefined' && module.exports !== undefined) {
  module.exports = {
    normalizeLookalike, apexDomain, hashUrl,
    localCheck, mergeResults, shouldCallBackend,
    getCached, setCached, callBackend, stripEmoji,
    isTrusted, SHARED_HOSTS,
  };
}
