/**
 * test_link_scanner.test.js
 *
 * Jest tests for extension/link_scanner.js
 *
 * Covers:
 *   - normalizeLookalike()     – leet/homoglyph normalisation
 *   - apexDomain()             – apex domain extraction
 *   - hashUrl()                – URL hashing
 *   - localCheck()             – all 10 local-check rules
 *   - mergeResults()           – combining local + backend results
 *   - shouldCallBackend()      – gateway logic
 *   - getCached() / setCached()– two-layer cache (memory + storage mock)
 *   - callBackend()            – fetch wrapper with cache + error handling
 *   - stripEmoji()             – emoji stripping utility
 *
 * @jest-environment node
 */

'use strict';

/* ── Browser-global stubs required before require() ─────────────── */

// chrome.storage mock
const storageMock = {};
global.chrome = {
  storage: {
    local: {
      get: jest.fn(async (key) => {
        const k = typeof key === 'string' ? key : Object.keys(key)[0];
        return { [k]: storageMock[k] };
      }),
      set: jest.fn(async (obj) => {
        Object.assign(storageMock, obj);
      }),
    },
    sync: {
      get: jest.fn(async (key) => {
        const k = typeof key === 'string' ? key : Object.keys(key)[0];
        return { [k]: storageMock[k] };
      }),
      set: jest.fn(async (obj) => {
        Object.assign(storageMock, obj);
      }),
    },
    onChanged: {
      addListener: jest.fn(),
    },
  },
};

// Minimal DOM stubs (link_scanner registers event listeners at module load)
global.document = {
  addEventListener:    jest.fn(),
  documentElement:     { appendChild: jest.fn(), style: { setProperty: jest.fn() } },
  createElement:       jest.fn(() => ({ textContent: '', innerHTML: '' })),
  querySelector:       jest.fn(() => null),
  querySelectorAll:    jest.fn(() => []),
};
global.window = { location: { href: 'https://example.com', hostname: 'example.com' } };
global.location = global.window.location;
global.requestAnimationFrame = jest.fn();
global.fetch = jest.fn();

/* ── Load the module ─────────────────────────────────────────────── */
const {
  normalizeLookalike,
  apexDomain,
  hashUrl,
  localCheck,
  mergeResults,
  shouldCallBackend,
  getCached,
  setCached,
  callBackend,
  stripEmoji,
  isTrusted,
  SHARED_HOSTS,
} = require('../link_scanner.js');

/* ══════════════════════════════════════════════════════════════════
   1 · normalizeLookalike
   ══════════════════════════════════════════════════════════════════ */
describe('normalizeLookalike()', () => {
  test('converts leet digits in paypa1 → paypal', () => {
    expect(normalizeLookalike('paypa1')).toBe('paypal');
  });

  test('converts multiple substitutions: g00g1e → google', () => {
    expect(normalizeLookalike('g00g1e')).toBe('google');
  });

  test('converts Cyrillic lookalikes to Latin', () => {
    // Cyrillic а (U+0430) → 'a'
    const cyrillic = 'p\u0430yp\u0430l';
    expect(normalizeLookalike(cyrillic)).toBe('paypal');
  });

  test('leaves clean ASCII strings unchanged', () => {
    expect(normalizeLookalike('github')).toBe('github');
  });

  test('converts 3→e, 4→a, 5→s, 6→g, 8→b', () => {
    expect(normalizeLookalike('3456')).toBe('easg'); // 3→e,4→a,5→s,6→g
    expect(normalizeLookalike('8')).toBe('b');
  });
});

/* ══════════════════════════════════════════════════════════════════
   2 · apexDomain
   ══════════════════════════════════════════════════════════════════ */
describe('apexDomain()', () => {
  test('returns simple domain as-is', () => {
    expect(apexDomain('google.com')).toBe('google.com');
  });

  test('strips www prefix', () => {
    expect(apexDomain('www.google.com')).toBe('google.com');
  });

  test('strips arbitrary subdomain', () => {
    expect(apexDomain('mail.sub.paypal.com')).toBe('paypal.com');
  });

  test('handles deep subdomain', () => {
    expect(apexDomain('a.b.c.d.evil.xyz')).toBe('evil.xyz');
  });

  test('lowercases the result', () => {
    expect(apexDomain('GOOGLE.COM')).toBe('google.com');
  });
});

/* ══════════════════════════════════════════════════════════════════
   3 · hashUrl
   ══════════════════════════════════════════════════════════════════ */
describe('hashUrl()', () => {
  test('returns a string', () => {
    expect(typeof hashUrl('https://example.com')).toBe('string');
  });

  test('is deterministic — same input gives same output', () => {
    const url = 'https://paypal.com/login';
    expect(hashUrl(url)).toBe(hashUrl(url));
  });

  test('different URLs produce different hashes (no trivial collision)', () => {
    expect(hashUrl('https://google.com')).not.toBe(hashUrl('https://github.com'));
  });

  test('output is non-empty', () => {
    expect(hashUrl('https://example.com').length).toBeGreaterThan(0);
  });
});

/* ══════════════════════════════════════════════════════════════════
   4 · localCheck — all 10 rules
   ══════════════════════════════════════════════════════════════════ */
describe('localCheck()', () => {
  // ── Happy path ──────────────────────────────────────────────────
  test('returns safe for a clean HTTPS URL', () => {
    const r = localCheck('https://github.com/features');
    expect(r.risk).toBe('safe');
    expect(r.reasons).toHaveLength(0);
  });

  test('returns safe for well-known safe domain', () => {
    expect(localCheck('https://amazon.com/dp/B09').risk).toBe('safe');
  });

  // ── Rule 1: No HTTPS ────────────────────────────────────────────
  test('flags HTTP (non-localhost) as suspicious', () => {
    const r = localCheck('http://somesite.com/login');
    expect(r.risk).toBe('suspicious');
    expect(r.reasons.some(s => /HTTPS/i.test(s))).toBe(true);
  });

  test('does NOT flag http://localhost (dev exemption)', () => {
    const r = localCheck('http://localhost:3000/');
    expect(r.reasons.some(s => /HTTPS/i.test(s))).toBe(false);
  });

  // ── Rule 2: Punycode ────────────────────────────────────────────
  test('flags punycode/IDN hostname as bad', () => {
    const r = localCheck('https://xn--pypal-4ve.com/');   // pаypal.com with Cyrillic а
    expect(r.risk).toBe('bad');
    expect(r.reasons.some(s => /punycode|internationalised/i.test(s))).toBe(true);
  });

  // ── Rule 3: IP address ──────────────────────────────────────────
  test('flags raw IPv4 host as bad', () => {
    const r = localCheck('http://192.168.1.1/phish.html');
    expect(r.risk).toBe('bad');
    expect(r.reasons.some(s => /ip address/i.test(s))).toBe(true);
  });

  // ── Rule 4: URL shortener ───────────────────────────────────────
  test('flags bit.ly as suspicious', () => {
    const r = localCheck('https://bit.ly/3xABCDE');
    expect(r.risk).toBe('suspicious');
    expect(r.reasons.some(s => /shortener/i.test(s))).toBe(true);
  });

  test('flags tinyurl.com as suspicious', () => {
    const r = localCheck('https://tinyurl.com/y4ub9c3');
    expect(r.risk).toBe('suspicious');
  });

  // ── Rule 5: Risky TLD ───────────────────────────────────────────
  test('flags .tk TLD as suspicious', () => {
    const r = localCheck('https://free-bank.tk/login');
    expect(r.risk).toBe('suspicious');
    expect(r.reasons.some(s => /\.tk/i.test(s))).toBe(true);
  });

  test('flags .xyz TLD as suspicious', () => {
    const r = localCheck('https://paypal-secure.xyz/verify');
    expect(r.risk).not.toBe('safe');
  });

  // ── Rule 6: Excessive subdomains ───────────────────────────────
  test('flags more than 4 subdomain parts as suspicious', () => {
    const r = localCheck('https://a.b.c.d.evil.com/');
    expect(r.risk).toBe('suspicious');
    expect(r.reasons.some(s => /subdomain/i.test(s))).toBe(true);
  });

  // ── Rule 7: Brand in subdomain of different apex ─────────────
  test('flags brand name in subdomain of wrong apex', () => {
    const r = localCheck('https://paypal.com.evil-site.xyz/login');
    expect(r.risk).toBe('bad');
    expect(r.reasons.some(s => /paypal/i.test(s))).toBe(true);
  });

  test('does NOT flag legitimate paypal.com itself', () => {
    const r = localCheck('https://www.paypal.com/signin');
    // Should not be flagged for brand-in-subdomain rule
    expect(r.reasons.some(s => /brand name.*paypal.*domain.*paypal/i.test(s))).toBe(false);
  });

  // ── Rule 8: Homoglyph apex ─────────────────────────────────────
  test('flags leet-speak paypa1.com as bad', () => {
    const r = localCheck('https://paypa1.com/login');
    expect(r.risk).toBe('bad');
    expect(r.reasons.some(s => /lookalike/i.test(s))).toBe(true);
  });

  test('flags g00gle.com as bad', () => {
    const r = localCheck('https://g00gle.com/');
    expect(r.risk).toBe('bad');
  });

  // ── Rule 9: Credential keywords ─────────────────────────────────
  test('flags credential keywords in external URL path', () => {
    // link_scanner uses location.hostname = 'example.com'
    const r = localCheck('https://different-domain.com/login?redirect=account');
    expect(r.risk).toBe('suspicious');
    expect(r.reasons.some(s => /credential/i.test(s))).toBe(true);
  });

  // ── Rule 10: Long hostname ──────────────────────────────────────
  test('flags hostname longer than 40 chars as suspicious', () => {
    const long = 'a'.repeat(45) + '.com';
    const r = localCheck(`https://${long}/`);
    expect(r.risk).toBe('suspicious');
    expect(r.reasons.some(s => /long hostname/i.test(s))).toBe(true);
  });

  // ── Edge cases ──────────────────────────────────────────────────
  test('returns safe for unparseable URL', () => {
    const r = localCheck('not-a-url-at-all');
    expect(r.risk).toBe('safe');
  });

  test('accumulates multiple flags and takes worst risk', () => {
    // Both punycode (bad) and risky TLD (suspicious) — result should be bad
    const r = localCheck('https://xn--pple-43d.tk/');
    expect(r.risk).toBe('bad');
    expect(r.reasons.length).toBeGreaterThanOrEqual(2);
  });
});

/* ══════════════════════════════════════════════════════════════════
   5 · mergeResults
   ══════════════════════════════════════════════════════════════════ */
describe('mergeResults()', () => {
  test('safe local + safe backend → safe', () => {
    const r = mergeResults(
      { risk: 'safe', reasons: [] },
      { verdict: 'safe', evidence: [] }
    );
    expect(r.risk).toBe('safe');
  });

  test('safe local + phish backend → bad', () => {
    const r = mergeResults(
      { risk: 'safe', reasons: [] },
      { verdict: 'phish', evidence: ['⚠️ Typosquat detected'] }
    );
    expect(r.risk).toBe('bad');
  });

  test('suspicious local + safe backend → suspicious (local wins)', () => {
    const r = mergeResults(
      { risk: 'suspicious', reasons: ['No HTTPS encryption'] },
      { verdict: 'safe', evidence: [] }
    );
    expect(r.risk).toBe('suspicious');
  });

  test('bad local + safe backend → bad (local wins)', () => {
    const r = mergeResults(
      { risk: 'bad', reasons: ['Punycode hostname'] },
      { verdict: 'safe', evidence: [] }
    );
    expect(r.risk).toBe('bad');
  });

  test('merges reasons from both local and backend evidence', () => {
    const r = mergeResults(
      { risk: 'suspicious', reasons: ['No HTTPS'] },
      { verdict: 'suspicious', evidence: ['✅ SSL valid', '⚠️ New domain'] }
    );
    expect(r.reasons).toContain('No HTTPS');
    expect(r.reasons.some(s => s.includes('SSL valid'))).toBe(true);
    expect(r.reasons.some(s => s.includes('New domain'))).toBe(true);
  });

  test('handles missing evidence array gracefully', () => {
    const r = mergeResults(
      { risk: 'safe', reasons: [] },
      { verdict: 'phish' }          // no evidence key
    );
    expect(r.risk).toBe('bad');
    expect(r.reasons).toEqual([]);
  });

  test('suspicious backend + safe local → suspicious', () => {
    const r = mergeResults(
      { risk: 'safe', reasons: [] },
      { verdict: 'suspicious', evidence: ['Risky TLD'] }
    );
    expect(r.risk).toBe('suspicious');
  });
});

/* ══════════════════════════════════════════════════════════════════
   6 · shouldCallBackend
   ══════════════════════════════════════════════════════════════════ */
describe('shouldCallBackend()', () => {
  // location.hostname = 'example.com' (set in global stub above)

  test('returns false for same-domain URL regardless of risk', () => {
    expect(shouldCallBackend('https://example.com/page', { risk: 'bad' })).toBe(false);
  });

  test('returns true for external suspicious URL', () => {
    expect(shouldCallBackend('https://paypa1.com/login', { risk: 'suspicious' })).toBe(true);
  });

  test('returns true for external bad URL', () => {
    expect(shouldCallBackend('https://evil.tk/', { risk: 'bad' })).toBe(true);
  });

  test('returns true for external safe URL not yet in memory cache', () => {
    // memCache is empty for a fresh URL
    expect(shouldCallBackend('https://new-fresh-uncached-domain.com/', { risk: 'safe' })).toBe(true);
  });
});

/* ══════════════════════════════════════════════════════════════════
   7 · getCached / setCached
   ══════════════════════════════════════════════════════════════════ */
describe('getCached() / setCached()', () => {
  beforeEach(() => {
    // Clear storage mock and reset chrome.storage mocks
    Object.keys(storageMock).forEach(k => delete storageMock[k]);
    chrome.storage.local.get.mockClear();
    chrome.storage.local.set.mockClear();
  });

  test('getCached returns null for unknown URL', async () => {
    chrome.storage.local.get.mockResolvedValueOnce({});
    const result = await getCached('https://not-cached.com/');
    expect(result).toBeNull();
  });

  test('setCached then getCached returns the stored result (memory hit)', async () => {
    const url    = 'https://test-cache.com/path';
    const result = { verdict: 'safe', score: 0.05 };
    await setCached(url, result);
    // Second call should hit memory cache, not storage
    const got = await getCached(url);
    expect(got).toEqual(result);
  });

  test('getCached returns null for an expired storage entry', async () => {
    const url = 'https://expired-entry.com/';
    const key = `lsc_${hashUrl(url)}`;
    // Simulate an old timestamp (35 minutes ago)
    const oldTs = Date.now() - 35 * 60 * 1000;
    chrome.storage.local.get.mockResolvedValueOnce({
      [key]: { result: { verdict: 'phish' }, ts: oldTs }
    });
    const got = await getCached(url);
    expect(got).toBeNull();
  });

  test('setCached writes to chrome.storage.local', async () => {
    await setCached('https://write-test.com/', { verdict: 'safe' });
    expect(chrome.storage.local.set).toHaveBeenCalledTimes(1);
  });
});

/* ══════════════════════════════════════════════════════════════════
   8 · callBackend
   ══════════════════════════════════════════════════════════════════ */
describe('callBackend()', () => {
  beforeEach(() => {
    Object.keys(storageMock).forEach(k => delete storageMock[k]);
    chrome.storage.local.get.mockReset();
    chrome.storage.local.set.mockReset();
    fetch.mockReset();

    // Default: storage returns nothing cached
    chrome.storage.local.get.mockResolvedValue({});
    chrome.storage.local.set.mockResolvedValue(undefined);
  });

  test('returns null when fetch throws (network error)', async () => {
    fetch.mockRejectedValueOnce(new Error('Network error'));
    const result = await callBackend('https://error-domain.com/');
    expect(result).toBeNull();
  });

  test('returns null when server responds with non-ok status', async () => {
    fetch.mockResolvedValueOnce({ ok: false, status: 500, json: jest.fn() });
    const result = await callBackend('https://server-error.com/');
    expect(result).toBeNull();
  });

  test('returns parsed JSON on successful response', async () => {
    const apiResponse = { verdict: 'phish', score: 0.92, evidence: ['Typosquat'] };
    fetch.mockResolvedValueOnce({
      ok:   true,
      json: jest.fn().mockResolvedValueOnce(apiResponse),
    });
    const result = await callBackend('https://phishing-site.com/');
    expect(result).toEqual(apiResponse);
  });

  test('sends POST to /api/analyze with correct Content-Type', async () => {
    fetch.mockResolvedValueOnce({
      ok:   true,
      json: jest.fn().mockResolvedValueOnce({ verdict: 'safe', score: 0.01 }),
    });
    await callBackend('https://check-headers.com/');
    expect(fetch).toHaveBeenCalledWith(
      'http://127.0.0.1:5000/api/analyze',
      expect.objectContaining({
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
      })
    );
  });

  test('payload contains url and hostname fields', async () => {
    fetch.mockResolvedValueOnce({
      ok:   true,
      json: jest.fn().mockResolvedValueOnce({ verdict: 'safe' }),
    });
    await callBackend('https://payload-check.com/some/path');
    const body = JSON.parse(fetch.mock.calls[0][1].body);
    expect(body.url).toContain('payload-check.com');
    expect(body.hostname).toBe('payload-check.com');
  });

  test('uses memory cache on second call — fetch called only once', async () => {
    const url = 'https://cached-twice.com/';
    fetch.mockResolvedValue({
      ok:   true,
      json: jest.fn().mockResolvedValue({ verdict: 'safe', score: 0.02 }),
    });
    await callBackend(url);
    await callBackend(url);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  test('returns null for an unparseable URL', async () => {
    const result = await callBackend('not-a-valid-url');
    expect(result).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });
});

/* ══════════════════════════════════════════════════════════════════
   9 · stripEmoji
   ══════════════════════════════════════════════════════════════════ */
describe('stripEmoji()', () => {
  test('removes ✅ from a string', () => {
    expect(stripEmoji('✅ SSL valid')).toBe('SSL valid');
  });

  test('removes ❌ from a string', () => {
    expect(stripEmoji('❌ Invalid cert')).toBe('Invalid cert');
  });

  test('removes ⚠️ from a string', () => {
    expect(stripEmoji('⚠️ Risky TLD')).toBe('Risky TLD');
  });

  test('removes 🚨 from a string', () => {
    expect(stripEmoji('🚨 Typosquat detected')).toBe('Typosquat detected');
  });

  test('leaves plain ASCII strings unchanged', () => {
    expect(stripEmoji('No emoji here')).toBe('No emoji here');
  });

  test('handles null/undefined gracefully', () => {
    expect(() => stripEmoji(null)).not.toThrow();
    expect(() => stripEmoji(undefined)).not.toThrow();
  });
});

/* ══════════════════════════════════════════════════════════════════
   10 · Trusted Sites & SHARED_HOSTS
   ══════════════════════════════════════════════════════════════════ */
describe('Trusted Sites & isTrusted()', () => {
  test('SHARED_HOSTS contains known multi-tenant providers', () => {
    expect(SHARED_HOSTS.has('github.io')).toBe(true);
    expect(SHARED_HOSTS.has('vercel.app')).toBe(true);
    expect(SHARED_HOSTS.has('sites.google.com')).toBe(true);
  });

  test('isTrusted returns false for untrusted sites', () => {
    expect(isTrusted('https://unknown-phish.com')).toBe(false);
  });

  test('isTrusted returns false for malformed URLs', () => {
    expect(isTrusted('not-a-valid-url')).toBe(false);
  });
});

