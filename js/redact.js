/* =============================================
   PII redaction – shared by the HAR Analyzer and the RUM Event Parser.
   Pure client-side, no storage, no network. Nothing here is ever sent to
   Datadog or anywhere else.

   Model
   - Uploaded data is kept untouched in memory. A *redacted view copy* is built
     for rendering whenever the "Redact PII in view" toggle is on (default).
   - Exports and "Copy summary" are ALWAYS built from the redacted copy,
     regardless of the toggle.
   - Redaction is deterministic: the same value always maps to the same short
     tag (e.g. [email:3fa91c]) so you can still tell two values apart / correlate
     them without seeing them.

   What is NOT redacted on purpose: Datadog session / view / application IDs,
   trace IDs, SDK versions, service / env / version tags. Those are what these
   tools exist to show, and they are not personal data on their own.

   Limits: pattern matching cannot recognise free-text names, street addresses
   or opaque customer IDs inside arbitrary strings. Keys named like usr.*,
   email, ip, phone, etc. are caught by name; everything else is caught by
   value pattern only.
   ============================================= */

(function (global) {
  'use strict';

  /* ── state ─────────────────────────────────────────────────────────── */
  let enabled = true;                    // in-memory only, resets on reload
  const listeners = [];

  /* ── hashing → short stable tag ────────────────────────────────────── */
  function hash(s) {                     // FNV-1a 32-bit
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); }
    return (h >>> 0).toString(16).padStart(8, '0').slice(0, 6);
  }
  const tag = (kind, v) => '[' + kind + ':' + hash(String(v)) + ']';
  const pseudo = (v) => tag('redacted', v);

  function maskToken(t) {
    const s = String(t);
    return s.length > 4 ? s.slice(0, 4) + '…[masked]' : '[masked]';
  }

  /* ── value patterns ────────────────────────────────────────────────── */
  const RE_EMAIL  = /[A-Za-z0-9._%+\-]+(?:@|%40)[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}/g;
  const RE_JWT    = /\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*/g;
  const RE_AUTH   = /\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+\/=\-]{8,}/gi;
  // not preceded by [\w./-] so "Chrome/154.0.0.0" or "v1.2.3.4" is left alone
  const RE_IPV4   = /(?<![\w./-])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w]|\.\d)/g;
  const RE_IPV6   = /(?<![\w:])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4})(?![\w:])/gi;
  const RE_SSN    = /(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])/g;
  const RE_PHONE  = /(?<![\w.])(?:\+?\d{1,3}[ .-])?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?![\w])/g;
  const RE_CARD   = /(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d])/g;

  function luhn(digits) {
    let sum = 0, alt = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let n = digits.charCodeAt(i) - 48;
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  }

  // Free-text scrub. Safe on any string; returns the input untouched if nothing matches.
  function text(s) {
    if (typeof s !== 'string' || !s) return s;
    return s
      .replace(RE_JWT,   (m) => tag('jwt', m))
      .replace(RE_AUTH,  (m, scheme) => scheme + ' [redacted]')
      .replace(RE_EMAIL, (m) => tag('email', m.toLowerCase().replace('%40', '@')))
      .replace(RE_SSN,   (m) => tag('ssn', m))
      .replace(RE_CARD,  (m) => {
        const d = m.replace(/[ -]/g, '');
        // 13–19 digits, Luhn-valid, a real card prefix, and either grouped or 15/16 long.
        // Keeps 19-digit trace IDs and 13-digit epoch-ms timestamps from being swallowed.
        if (d.length < 13 || d.length > 19 || !/^[3-6]/.test(d) || !luhn(d)) return m;
        if (d === m && d.length !== 15 && d.length !== 16) return m;
        return tag('card', d);
      })
      .replace(RE_IPV4,  (m) => tag('ip', m))
      .replace(RE_IPV6,  (m) => tag('ip', m.toLowerCase()))
      .replace(RE_PHONE, (m) => tag('phone', m));
  }

  /* ── URLs ──────────────────────────────────────────────────────────── */
  // Query-param values are dropped unless the param is known to be non-personal.
  const SAFE_PARAMS = new Set([
    'ddsource', 'ddtags', 'ddforward', 'dd-evp-origin', 'dd-evp-origin-version', 'dd-request-id',
    'batch_time', 'api-version', 'dd_session_id', 'session_id', 'dd_app_id', 'app_id', 'application_id',
    'type', 'format', 'from', 'to', 'interval', 'limit', 'offset', 'version', 'env', 'service',
  ]);

  function url(u) {
    if (typeof u !== 'string' || !u) return u;
    const s = u.trim();
    if (/^data:|^blob:/i.test(s)) return s.slice(0, s.indexOf(',') > 0 ? s.indexOf(',') : 12) + '…[omitted]';
    let parsed = null, relative = false;
    try { parsed = new URL(s); }
    catch (_) { try { parsed = new URL(s, 'http://relative.invalid'); relative = true; } catch (__) { /* leave null */ } }

    if (!parsed) {                                       // not a URL at all: cut query/fragment, scrub the rest
      return text(s.replace(/[?#].*$/, '')) + (/[?#]/.test(s) ? '?[redacted]' : '');
    }

    const pairs = [];
    parsed.searchParams.forEach((v, k) => {
      const lk = k.toLowerCase();
      if (lk === 'dd-api-key' || /api[_-]?key|client[_-]?token/.test(lk)) pairs.push(k + '=' + maskToken(v));
      else if (SAFE_PARAMS.has(lk)) pairs.push(k + '=' + text(v));
      else pairs.push(k + '=[redacted]');
    });

    let path;
    try { path = text(decodeURIComponent(parsed.pathname)); } catch (_) { path = text(parsed.pathname); }
    const origin = relative ? '' : parsed.protocol + '//' + parsed.host;  // userinfo and #fragment dropped
    return origin + path + (pairs.length ? '?' + pairs.join('&') : '');
  }

  /* ── headers ───────────────────────────────────────────────────────── */
  const HEADER_FULL = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|x-forwarded-for|x-real-ip|forwarded|true-client-ip|cf-connecting-ip|x-amz-security-token)$/i;
  const HEADER_URL  = /^(referer|referrer|origin|location|content-location)$/i;

  function header(name, value) {
    const n = String(name || '');
    const v = value == null ? '' : String(value);
    if (/^dd-api-key$/i.test(n)) return maskToken(v);
    if (HEADER_FULL.test(n)) return '[redacted]';
    if (HEADER_URL.test(n)) return url(v);
    return text(v);
  }

  /* ── structured data ───────────────────────────────────────────────── */
  const SENSITIVE_KEY = /(password|passwd|secret|token|api[_-]?key|app[_-]?key|authorization|cookie|credit[_-]?card|card[_-]?number|cvv|ssn)/i;
  const KEY_IS_TOKEN  = /(api[_-]?key|client[_-]?token)/i;     // partially shown (first 4 chars) instead of blanked
  // Key *paths* whose value is personal data by name
  const PII_PATH = new RegExp([
    '(^|\\.)usr(\\.|$)',                                         // RUM user object: all of it
    '(^|\\.)account\\.name$',
    '(^|\\.)url_query(\\.|$)',                                   // RUM view/action query params
    '(^|[._])(e[-_]?mail|phone(_?number)?|mobile|first_?name|last_?name|full_?name|display_?name|user_?name|user_?id|userid|dob|birth_?date|address|street|postal_?code|zip(_?code)?|ip|ip_?address|client_?ip|remote_?addr|latitude|longitude|lat|lon|lng)$',
    '(^|\\.)geo\\.(city|country_subdivision|country_subdivision_iso_code)$',
    '(^|\\.)client\\.ip$',
  ].join('|'), 'i');
  const URL_KEY     = /(^|[._])(url|referrer|href|uri)(_path|_details)?$/i;
  // "key:value" tags / group-by values whose KEY looks personal
  const PII_TAG_KEY = /(e[-_]?mail|username|user[_-]?name|user[_-]?id|usr[._]|(^|[._-])user$|client[_-]?ip|(^|[._-])ip([_-]?address)?$|phone|customer|member|first[_-]?name|last[_-]?name|full[_-]?name|ssn)/i;

  function str(s, path) {
    const last = path ? path.split('.').pop() : '';
    if (last && SENSITIVE_KEY.test(last)) return KEY_IS_TOKEN.test(last) ? maskToken(s) : '[redacted]';
    if (path && PII_PATH.test(path)) return pseudo(s);
    if (/^(https?|wss?|ftp):\/\//i.test(s) || (last && URL_KEY.test(last))) return url(s);
    const m = s.match(/^([A-Za-z0-9_.@\-]+):([\s\S]+)$/);       // "key:value"
    if (m) {
      if (PII_TAG_KEY.test(m[1])) return m[1] + ':' + pseudo(m[2]);
      if (/^(https?|wss?):\/\//i.test(m[2])) return m[1] + ':' + url(m[2]);
    }
    return text(s);
  }

  function deep(v, path, depth) {
    path = path || '';
    depth = depth || 0;
    if (depth > 60) return '[max depth]';
    if (Array.isArray(v)) {
      if (path && PII_PATH.test(path)) return v.map((x) => (x !== null && typeof x === 'object') ? '[redacted]' : pseudo(x));
      return v.map((x) => deep(x, path, depth + 1));
    }
    if (v !== null && typeof v === 'object') {
      const out = {};
      // Datadog scalar-query group column: { type:'group', name:'usr.email', values:[…] }
      const piiGroup = v.type === 'group' && typeof v.name === 'string' && (PII_TAG_KEY.test(v.name) || PII_PATH.test(v.name));
      for (const k of Object.keys(v)) {
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
        if (piiGroup && k === 'values' && Array.isArray(v[k])) {
          out[k] = v[k].map((x) => Array.isArray(x) ? x.map(pseudo) : (x == null ? x : pseudo(x)));
          continue;
        }
        out[k] = deep(v[k], path ? path + '.' + k : k, depth + 1);
      }
      return out;
    }
    if (typeof v === 'string') return str(v, path);
    if ((typeof v === 'number' || typeof v === 'boolean') && path) {
      const last = path.split('.').pop();
      if (SENSITIVE_KEY.test(last) || PII_PATH.test(path)) return pseudo(v);
    }
    return v;
  }

  // Response / request bodies: JSON → key-aware redaction, anything else → free-text scrub.
  function body(t) {
    if (typeof t !== 'string' || !t) return t;
    const s = t.trim();
    if (/^[\[{]/.test(s)) {
      try { return JSON.stringify(deep(JSON.parse(s)), null, 2); } catch (_) { /* fall through */ }
    }
    return text(t);
  }

  /* ── toggle UI ─────────────────────────────────────────────────────── */
  function injectStyle() {
    if (document.getElementById('pii-redact-style')) return;
    const st = document.createElement('style');
    st.id = 'pii-redact-style';
    st.textContent =
      '.pii-bar{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem 1rem;margin:0 auto 1rem;max-width:1100px;' +
      'padding:.6rem .9rem;border:1px solid rgba(128,128,128,.4);border-radius:8px;background:rgba(128,128,128,.12);font-size:.85rem}' +
      '.pii-bar label{display:flex;align-items:center;gap:.5rem;margin:0;cursor:pointer;font-weight:600}' +
      '.pii-bar input{width:1rem;height:1rem;cursor:pointer}' +
      '.pii-bar .pii-note{opacity:.8}' +
      '.pii-bar.is-off{border-color:#d9822b;background:rgba(217,130,43,.14)}';
    document.head.appendChild(st);
  }

  function mountToggle(host, opts) {
    if (!host) return;
    injectStyle();
    const bar = document.createElement('div');
    bar.className = 'pii-bar';
    bar.setAttribute('role', 'group');
    bar.setAttribute('aria-label', 'PII redaction');
    const label = document.createElement('label');
    const box = document.createElement('input');
    box.type = 'checkbox'; box.id = 'pii-redact'; box.checked = enabled;
    const span = document.createElement('span');
    span.textContent = 'Redact PII in this view';
    label.append(box, span);
    const note = document.createElement('span');
    note.className = 'pii-note';
    note.textContent = 'Emails, IPs, tokens, auth headers, user fields and URL query values are masked. ' +
                       'Copy summary and Export are always redacted.';
    bar.append(label, note);
    box.addEventListener('change', () => { setEnabled(box.checked); bar.classList.toggle('is-off', !box.checked); });
    if (opts && opts.prepend) host.insertBefore(bar, host.firstChild); else host.appendChild(bar);
  }

  function setEnabled(v) {
    enabled = !!v;
    listeners.forEach((fn) => { try { fn(enabled); } catch (_) { /* ignore */ } });
  }

  global.PIIRedact = {
    text, url, header, body, deep, str, maskToken, pseudo,
    isEnabled: () => enabled,
    setEnabled,
    onChange: (fn) => listeners.push(fn),
    mountToggle,
  };
})(typeof window !== 'undefined' ? window : globalThis);
