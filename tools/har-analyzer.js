/* =============================================
   Datadog HAR Analyzer – har-analyzer.js
   Pure client-side. No data leaves the browser.
   ============================================= */

'use strict';

// ── Constants ──────────────────────────────────────────────────────────────

const DD_INTAKE_PATTERNS = [
  /browser-intake-datadoghq\.com/,
  /rum\.browser-intake-datadoghq\.com/,
  /logs\.browser-intake-datadoghq\.com/,
  /trace\.browser-intake-datadoghq\.com/,
  /session-replay\.browser-intake-datadoghq\.com/,
  /p\.datadoghq\.com/,
  /datadoghq\.com\/api\//,
  /datadoghq\.eu\/api\//,
  /browser-intake-datadoghq\.eu/,
  /rum\.browser-intake-datadoghq\.eu/,
  /logs\.browser-intake-datadoghq\.eu/,
  /session-replay\.browser-intake-datadoghq\.eu/,
  /ddog-gov\.com\/api\//,
  /browser-intake-ddog-gov\.com/,
  /datadoghq-gov\.com/,
];

const SESSION_REPLAY_PATTERNS = [
  /session-replay\.browser-intake-datadoghq\.com/,
  /session-replay\.browser-intake-datadoghq\.eu/,
  /\/api\/v2\/replay/,
];

const DD_SDK_PATTERNS = [
  /datadoghq-browser-agent\.com.*datadog-rum/,
  /datadoghq-browser-agent\.com.*datadog-logs/,
  /datadoghq-browser-agent\.com.*datadog-rum-slim/,
];

// Per docs.datadoghq.com/real_user_monitoring/application_monitoring/browser/troubleshooting/#rum-cookies
// Only _dd_s is the current RUM session cookie.
// _dd_l, _dd_r, _dd are deprecated predecessors replaced by _dd_s in recent SDK versions.
// dd_site_test_* and dd_cookie_test_* are transient (expire instantly) — unlikely in a HAR.
const DD_COOKIE_NAMES = ['_dd_s', '_dd_s_v2', '_dd_r', '_dd_l', '_dd'];

const KNOWN_OFFICIAL_SDK_HOSTS = [
  'www.datadoghq-browser-agent.com',
  'static.datadoghq.com',
];

// ── Utilities ──────────────────────────────────────────────────────────────

function isIntakeUrl(url) { return DD_INTAKE_PATTERNS.some(p => p.test(url)); }
function isReplayUrl(url) { return SESSION_REPLAY_PATTERNS.some(p => p.test(url)); }
function isSdkUrl(url)    { return DD_SDK_PATTERNS.some(p => p.test(url)); }
function isError(status)  { return status === 0 || status >= 400; }

function formatBytes(bytes) {
  if (!bytes || bytes < 0) return '–';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(2) + ' MB';
}

function formatMs(ms) {
  if (ms == null || ms < 0) return '–';
  if (ms >= 1000) return (ms / 1000).toFixed(2) + 's';
  return Math.round(ms) + 'ms';
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function parseCookieHeader(str) {
  const r = {};
  str.split(';').forEach(p => {
    const eq = p.indexOf('=');
    if (eq > -1) r[p.slice(0, eq).trim()] = p.slice(eq + 1).trim();
  });
  return r;
}

function parseDdSValue(raw) {
  const r = {};
  raw.split('&').forEach(s => { const eq = s.indexOf('='); if (eq > -1) r[s.slice(0, eq)] = s.slice(eq + 1); });
  return r;
}

function parseDdSV2Value(raw) {
  try { return parseDdSValue(atob(raw)); } catch { return {}; }
}

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    btn.classList.add('copied');
    setTimeout(() => btn.classList.remove('copied'), 1800);
  }).catch(() => {
    const ta = Object.assign(document.createElement('textarea'), { value: text });
    Object.assign(ta.style, { position: 'fixed', opacity: '0' });
    document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
    btn.classList.add('copied'); setTimeout(() => btn.classList.remove('copied'), 1800);
  });
}

// Extract version string from SDK URL, e.g. /us1/v5/ → "v5"
function extractSdkVersion(url) {
  const m = url.match(/\/(v\d+(?:\.\d+)*)\//);
  return m ? m[1] : null;
}

// Extract SDK type from URL
function extractSdkType(url) {
  if (/datadog-rum-slim/.test(url)) return 'rum-slim';
  if (/datadog-rum/.test(url))      return 'rum';
  if (/datadog-logs/.test(url))     return 'logs';
  return 'unknown';
}

// Try to extract DD_RUM.init() config from inline script text
function extractInitConfig(scriptText) {
  if (!scriptText) return null;
  try {
    // Match DD_RUM.init({ ... }) allowing for window.DD_RUM
    const m = scriptText.match(/DD_RUM\s*&&\s*DD_RUM\.init\s*\(\s*(\{[\s\S]*?\})\s*\)/);
    if (!m) return null;
    // Sanitize JS object to JSON: strip comments, trailing commas, unquoted keys
    let obj = m[1]
      .replace(/\/\/.*$/gm, '')           // strip line comments
      .replace(/\/\*[\s\S]*?\*\//g, '')   // strip block comments
      .replace(/,\s*([}\]])/g, '$1')      // trailing commas
      .replace(/([{,]\s*)([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:/g, '$1"$2":'); // unquoted keys
    return JSON.parse(obj);
  } catch { return null; }
}

// ── Warnings builder ───────────────────────────────────────────────────────

function buildWarnings(analysis) {
  const warns = [];

  const { sdkLoads, initConfig, intakeErrors, intakeSuccess,
          replayRequests, sessionId, ddCookies, endpointHits } = analysis;

  // ── SDK Health ──
  const rumSdk  = sdkLoads.find(s => s.type === 'rum' || s.type === 'rum-slim');
  const logsSdk = sdkLoads.find(s => s.type === 'logs');

  if (sdkLoads.length === 0) {
    warns.push({ sev: 'error', cat: 'SDK', msg: 'No Datadog browser SDK load detected in this HAR.' });
  } else {
    sdkLoads.forEach(sdk => {
      if (isError(sdk.status)) {
        warns.push({ sev: 'error', cat: 'SDK', msg: `SDK script failed to load (${sdk.status || 'network error'}): ${sdk.url}` });
      }
      if (sdk.loadTimeMs > 2000) {
        warns.push({ sev: 'warn', cat: 'SDK', msg: `SDK took ${formatMs(sdk.loadTimeMs)} to load — slow load may delay first event capture.`, detail: sdk.url });
      }
      if (!KNOWN_OFFICIAL_SDK_HOSTS.some(h => sdk.url.includes(h))) {
        warns.push({ sev: 'info', cat: 'SDK', msg: `SDK loaded from non-standard host (self-hosted or proxied): ${sdk.url}` });
      }
    });

    // Mismatched RUM vs Logs versions
    if (rumSdk && logsSdk && rumSdk.version !== logsSdk.version) {
      warns.push({ sev: 'warn', cat: 'SDK', msg: `RUM SDK (${rumSdk.version}) and Logs SDK (${logsSdk.version}) are on different major versions — this can cause unexpected behaviour.` });
    }
  }

  // ── Init Config ──
  if (initConfig) {
    const cfg = initConfig;

    if (cfg.sessionSampleRate === 0) {
      warns.push({ sev: 'error', cat: 'Config', msg: 'sessionSampleRate is 0 — no sessions will be recorded.' });
    } else if (cfg.sessionSampleRate < 100 && cfg.sessionSampleRate > 0) {
      warns.push({ sev: 'info', cat: 'Config', msg: `sessionSampleRate is ${cfg.sessionSampleRate}% — some sessions are intentionally dropped client-side. Gaps in intake traffic are expected.` });
    }

    if (cfg.sessionReplaySampleRate === 0) {
      warns.push({ sev: 'warn', cat: 'Config', msg: 'sessionReplaySampleRate is 0 — Session Replay is disabled.' });
    }

    if (cfg.trackingConsent === 'not-granted') {
      warns.push({ sev: 'error', cat: 'Config', msg: "trackingConsent is 'not-granted' — RUM will not collect data until consent is given." });
    }

    if (cfg.defaultPrivacyLevel === 'mask') {
      warns.push({ sev: 'info', cat: 'Config', msg: "defaultPrivacyLevel is 'mask' — all text content will be masked in Session Replay." });
    } else if (cfg.defaultPrivacyLevel === 'mask-user-input') {
      warns.push({ sev: 'info', cat: 'Config', msg: "defaultPrivacyLevel is 'mask-user-input' — form inputs will be masked in Session Replay." });
    }

    if (!cfg.version) {
      warns.push({ sev: 'info', cat: 'Config', msg: "No 'version' set in DD_RUM.init() — version faceting in RUM Explorer will not be available." });
    }
    if (!cfg.env) {
      warns.push({ sev: 'info', cat: 'Config', msg: "No 'env' set in DD_RUM.init() — environment faceting will not be available." });
    }
    if (!cfg.service) {
      warns.push({ sev: 'info', cat: 'Config', msg: "No 'service' set in DD_RUM.init() — service faceting will not be available." });
    }
    if (cfg.trackUserInteractions === false) {
      warns.push({ sev: 'warn', cat: 'Config', msg: "trackUserInteractions is false — click/action events will not be captured." });
    }
    if (cfg.trackResources === false) {
      warns.push({ sev: 'warn', cat: 'Config', msg: "trackResources is false — resource timing data will not be captured." });
    }
    if (cfg.trackLongTasks === false) {
      warns.push({ sev: 'info', cat: 'Config', msg: "trackLongTasks is false — long task events will not be captured." });
    }

    // Replay present but sampleRate is 0
    if (replayRequests.length > 0 && cfg.sessionReplaySampleRate === 0) {
      warns.push({ sev: 'warn', cat: 'Config', msg: 'Session Replay requests are present in this HAR but sessionReplaySampleRate is 0 in init config — unexpected behaviour.' });
    }

    // No replay but sampleRate is 100
    if (replayRequests.length === 0 && cfg.sessionReplaySampleRate === 100 && (intakeSuccess.length + intakeErrors.length) > 5) {
      warns.push({ sev: 'warn', cat: 'Config', msg: 'sessionReplaySampleRate is 100% but no Session Replay requests found — check if the page is excluded via privacy masks or replay is blocked.' });
    }
  } else if (sdkLoads.length > 0) {
    warns.push({ sev: 'info', cat: 'Config', msg: 'Could not extract DD_RUM.init() config from inline scripts — config review skipped.' });
  }

  // ── Duplicate SDK init ──
  if (analysis.sdkInitCount > 1) {
    warns.push({ sev: 'error', cat: 'Config', msg: `DD_RUM.init() called ${analysis.sdkInitCount} times — duplicate initialisation causes double-counting of events. Common in SPAs on route change.` });
  }

  // ── Sampling gap ──
  if (initConfig && initConfig.sessionSampleRate < 100) {
    const totalIntake = intakeSuccess.length + intakeErrors.length;
    if (totalIntake === 0 && analysis.totalEntries > 20) {
      warns.push({ sev: 'warn', cat: 'Sampling', msg: `No intake traffic found. With sessionSampleRate at ${initConfig.sessionSampleRate}%, this session may have been sampled out.` });
    }
  }

  // ── Blocked / CSP ──
  const blockedSdk = sdkLoads.filter(s => s.status === 0);
  if (blockedSdk.length > 0) {
    warns.push({ sev: 'error', cat: 'CSP/Network', msg: `${blockedSdk.length} SDK script request(s) were blocked (status 0) — likely a Content Security Policy issue. Add 'connect-src https://*.datadoghq.com' to your CSP.` });
  }

  const blockedIntake = [...intakeErrors, ...intakeSuccess].filter(e => e.status === 0);
  if (blockedIntake.length > 0) {
    warns.push({ sev: 'error', cat: 'CSP/Network', msg: `${blockedIntake.length} intake request(s) were blocked (status 0) — check Content Security Policy allows intake endpoints.` });
  }

  // Check for CORS issues: intake requests with origin header but no CORS response
  const corsIssues = [...intakeErrors, ...intakeSuccess].filter(e => {
    const hasOrigin = e.reqHeaders.some(h => h.name.toLowerCase() === 'origin');
    const hasCors   = e.resHeaders.some(h => h.name.toLowerCase() === 'access-control-allow-origin');
    return hasOrigin && !hasCors && !isError(e.status);
  });
  if (corsIssues.length > 0) {
    warns.push({ sev: 'warn', cat: 'CSP/Network', msg: `${corsIssues.length} intake request(s) sent an Origin header but received no Access-Control-Allow-Origin in response — possible CORS misconfiguration.` });
  }

  // ── Large payloads ──
  // The Datadog docs define the threshold as 3KiB for global context/user info/feature flags.
  // compressIntakeRequest (SDK >= v5.3.0) raises this to 16KiB.
  // Requests beyond RUM technical limits are rejected by intake.
  const compress = initConfig && initConfig.compressIntakeRequest;
  const softLimit = compress ? 16384 : 3072; // 16KiB compressed, 3KiB uncompressed
  const hardLimit = 5242880;                 // 5MB absolute ceiling
  const allIntake = [...intakeSuccess, ...intakeErrors];
  const overSoft = allIntake.filter(e => e.reqBodySize > softLimit && e.reqBodySize <= hardLimit);
  const overHard = allIntake.filter(e => e.reqBodySize > hardLimit);
  if (overHard.length > 0) {
    warns.push({ sev: 'error', cat: 'Payload', msg: overHard.length + ' intake request(s) exceed 5MB and will likely be rejected by the Datadog intake.' });
  }
  if (overSoft.length > 0) {
    const limitLabel = compress ? '16KiB' : '3KiB';
    const compressHint = compress ? '' : ' Consider enabling compressIntakeRequest (SDK v5.3.0+) to extend the limit to 16KiB.';
    warns.push({ sev: 'warn', cat: 'Payload', msg: overSoft.length + ' intake request(s) exceed the recommended ' + limitLabel + ' threshold. Large global context, user info, or feature flag data can impact performance on slow connections.' + compressHint, detail: 'docs.datadoghq.com/real_user_monitoring/application_monitoring/browser/troubleshooting/#customer-data-exceeds-the-recommended-threshold-warning' });
  }

  // ── SDK load timing ──
  if (rumSdk && rumSdk.status === 200 && analysis.firstIntakeOffsetMs != null) {
    if (analysis.firstIntakeOffsetMs > 5000) {
      warns.push({ sev: 'warn', cat: 'Timing', msg: `First intake event fired ${formatMs(analysis.firstIntakeOffsetMs)} after page start — SDK may be loading too late (check script placement in <head> vs end of <body>).` });
    }
  }

  // ── Rate limiting ──
  const rateLimited = intakeErrors.filter(e => e.status === 429);
  if (rateLimited.length > 0) {
    warns.push({ sev: 'error', cat: 'Rate Limit', msg: `${rateLimited.length} intake request(s) rate-limited (429). Check x-ratelimit-remaining headers.` });
  }

  // ── Proxy detection ──
  const proxied = [...intakeSuccess, ...intakeErrors].filter(e =>
    e.reqHeaders.some(h => h.name.toLowerCase() === 'x-forwarded-for')
  );
  if (proxied.length > 0) {
    warns.push({ sev: 'info', cat: 'Proxy', msg: `${proxied.length} intake request(s) include x-forwarded-for — traffic appears to be routed through a proxy. This can affect geolocation accuracy in RUM.` });
  }

  // ── APM correlation ──
  const apmCors = analysis.apmCorrelations || [];
  if (apmCors.length > 0) {
    const allUnsampled = apmCors.every(c => c.sampled === false);
    if (allUnsampled) {
      warns.push({ sev: 'warn', cat: 'APM', msg: 'RUM is injecting trace headers but all requests have x-datadog-sampling-priority: 0. Traces will not be retained. Check APM trace retention filters or the traceSampleRate in your allowedTracingUrls config.' });
    }
    const missingOrigin = apmCors.filter(c => c.origin !== 'rum');
    if (missingOrigin.length > 0) {
      warns.push({ sev: 'warn', cat: 'APM', msg: `${missingOrigin.length} correlated request(s) are missing x-datadog-origin: rum — these traces may not be linked back to RUM in the Datadog UI.` });
    }
  }

  return warns;
}

// ── Event type breakdown from intake payloads ──────────────────────────────

function extractEventTypes(entries) {
  const counts = {};
  entries.forEach(entry => {
    if (!isIntakeUrl(entry.request?.url || '')) return;
    try {
      const u = new URL(entry.request.url);
      // RUM v2 endpoint encodes type in the path: /api/v2/rum, /api/v2/logs, /api/v2/replay
      const pathMatch = u.pathname.match(/\/api\/v2\/(\w+)/);
      if (pathMatch) {
        const t = pathMatch[1];
        counts[t] = (counts[t] || 0) + 1;
        return;
      }
      // Older approach: ddsource query param
      const src = u.searchParams.get('ddsource') || u.searchParams.get('ddtags');
      if (src) { counts[src] = (counts[src] || 0) + 1; return; }
    } catch {}
    // Fallback: hostname hint
    const url = entry.request?.url || '';
    if (/session-replay/.test(url))  { counts['replay'] = (counts['replay'] || 0) + 1; return; }
    if (/logs/.test(url))             { counts['logs']   = (counts['logs']   || 0) + 1; return; }
    if (/rum/.test(url))              { counts['rum']    = (counts['rum']    || 0) + 1; return; }
    counts['intake'] = (counts['intake'] || 0) + 1;
  });
  return counts;
}

// ── Core Analysis ──────────────────────────────────────────────────────────

function analyzeHAR(harData, filename) {
  const entries = harData?.log?.entries || [];
  const creator = harData?.log?.creator || {};
  const pages   = harData?.log?.pages   || [];

  const ddCookies      = [];
  const intakeErrors   = [];
  const intakeSuccess  = [];
  const replayRequests = [];
  const sdkLoads       = [];
  const seenCookieKeys = new Set();
  const endpointHits   = {};

  let sessionId = null, sessionIdSource = null;
  let appId     = null, appIdSource     = null;
  let initConfig      = null;
  let sdkInitCount    = 0;
  let pageStartTime   = null;
  let firstIntakeTime = null;

  // Try to get page start time
  if (pages.length > 0 && pages[0].startedDateTime) {
    pageStartTime = new Date(pages[0].startedDateTime).getTime();
  }

  // ── Pass 1: extract init config from inline scripts in pages ──
  // HAR doesn't capture inline scripts directly, but we can check response
  // bodies of HTML pages for the init call
  entries.forEach(entry => {
    const contentType = (entry.response?.headers || []).find(h => h.name.toLowerCase() === 'content-type')?.value || '';
    if (!contentType.includes('text/html') && !contentType.includes('javascript')) return;
    const text = entry.response?.content?.text || '';
    if (!text) return;
    if (!initConfig && text.includes('DD_RUM')) {
      const cfg = extractInitConfig(text);
      if (cfg) initConfig = cfg;
    }
    // Count init calls
    const initMatches = text.match(/DD_RUM\.init\s*\(/g);
    if (initMatches) sdkInitCount += initMatches.length;
  });

  // ── Pass 2: main entry analysis ──
  entries.forEach(entry => {
    const url    = entry.request?.url    || '';
    const method = entry.request?.method || 'GET';
    const status = entry.response?.status || 0;
    const startedMs = entry.startedDateTime ? new Date(entry.startedDateTime).getTime() : null;

    // ── SDK load detection ──
    if (isSdkUrl(url)) {
      const loadTimeMs = entry.time || 0;
      const version    = extractSdkVersion(url);
      const type       = extractSdkType(url);
      sdkLoads.push({ url, status, loadTimeMs, version, type, startedMs });
    }

    // ── Cookie extraction ──
    const allHeaders = [
      ...(entry.request?.headers  || []),
      ...(entry.response?.headers || []),
    ];

    allHeaders.forEach(h => {
      const hn = h.name.toLowerCase();
      if (hn !== 'cookie' && hn !== 'set-cookie') return;
      const parsed = parseCookieHeader(h.value);
      DD_COOKIE_NAMES.forEach(ck => {
        if (parsed[ck] === undefined) return;
        const key = `${ck}::${parsed[ck]}`;
        if (seenCookieKeys.has(key)) return;
        seenCookieKeys.add(key);
        let segments = {}, decoded = null;
        if (ck === '_dd_s')    { segments = parseDdSValue(parsed[ck]);   decoded = JSON.stringify(segments, null, 2); }
        if (ck === '_dd_s_v2') { segments = parseDdSV2Value(parsed[ck]); decoded = JSON.stringify(segments, null, 2); }
        if (!sessionId && segments.id)  { sessionId = segments.id;  sessionIdSource = `${ck} cookie`; }
        if (!sessionId && segments.rum) { sessionId = segments.rum; sessionIdSource = `${ck} cookie (rum segment)`; }
        ddCookies.push({ name: ck, value: parsed[ck], decoded, segments, header: h.name, url });
      });
    });

    // ── Only continue for intake URLs ──
    if (!isIntakeUrl(url)) return;

    // Track first intake time
    if (startedMs && !firstIntakeTime) firstIntakeTime = startedMs;

    try {
      const hostname = new URL(url).hostname;
      endpointHits[hostname] = (endpointHits[hostname] || 0) + 1;
    } catch {}

    // RUM IDs from URL params
    try {
      const u = new URL(url);
      if (!sessionId) { const v = u.searchParams.get('dd_session_id') || u.searchParams.get('session_id'); if (v) { sessionId = v; sessionIdSource = 'URL param'; } }
      if (!appId)     { const v = u.searchParams.get('dd_app_id') || u.searchParams.get('app_id') || u.searchParams.get('application_id'); if (v) { appId = v; appIdSource = 'URL param'; } }
    } catch {}

    // RUM IDs from headers
    allHeaders.forEach(h => {
      const hn = h.name.toLowerCase();
      if (!appId     && hn === 'x-datadog-application-id') { appId     = h.value; appIdSource     = 'request header'; }
      if (!sessionId && hn === 'x-datadog-session-id')     { sessionId = h.value; sessionIdSource = 'request header'; }
    });

    // RUM IDs from POST body
    try {
      const body = entry.request?.postData?.text;
      if (body) {
        if (body.trim().startsWith('{')) {
          try { const p = JSON.parse(body); if (!appId && p.application_id) { appId = p.application_id; appIdSource = 'request body'; } if (!sessionId && p.session_id) { sessionId = p.session_id; sessionIdSource = 'request body'; } } catch {}
        }
        const aidM = body.match(/"application[_-]id"\s*:\s*"([^"]+)"/); if (!appId && aidM) { appId = aidM[1]; appIdSource = 'request body'; }
        const sidM = body.match(/"session[_-]id"\s*:\s*"([^"]+)"/);     if (!sessionId && sidM) { sessionId = sidM[1]; sessionIdSource = 'request body'; }
      }
    } catch {}

    const WANT_REQ = new Set(['content-type','x-datadog-parent-id','x-datadog-trace-id','x-datadog-sampling-priority','x-datadog-application-id','x-datadog-session-id','dd-api-key','authorization','origin','referer','x-forwarded-for']);
    const WANT_RES = new Set(['content-type','x-ratelimit-limit','x-ratelimit-remaining','x-ratelimit-reset','x-ratelimit-period','x-datadog-trace-id','retry-after','server','access-control-allow-origin']);

    const reqHeaders   = (entry.request?.headers  || []).filter(h => WANT_REQ.has(h.name.toLowerCase()));
    const resHeaders   = (entry.response?.headers || []).filter(h => WANT_RES.has(h.name.toLowerCase()));
    const bodyText     = entry.response?.content?.text || '';
    const bodySize     = entry.response?.bodySize || entry.response?.content?.size || 0;
    const reqBodySize  = entry.request?.bodySize || entry.request?.postData?.text?.length || 0;
    const timings      = entry.timings || {};
    const totalTime    = entry.time || 0;

    const entryData = { url, method, status, reqHeaders, resHeaders, bodyText, bodySize, reqBodySize, totalTime, timings, startedMs };

    if (isReplayUrl(url)) replayRequests.push(entryData);
    if (isError(status))  intakeErrors.push(entryData);
    else                  intakeSuccess.push(entryData);
  });

  const firstIntakeOffsetMs = (pageStartTime && firstIntakeTime) ? firstIntakeTime - pageStartTime : null;
  const eventTypeCounts = extractEventTypes(entries);

  // ── APM correlation: scan all non-intake XHR/fetch for propagation headers ──
  // RUM injects these on requests to allowedTracingUrls to link frontend resources to APM traces.
  // Docs: docs.datadoghq.com/real_user_monitoring/correlate_with_other_telemetry/apm/
  const apmCorrelations = [];
  entries.forEach(entry => {
    const url    = entry.request?.url || '';
    if (isIntakeUrl(url) || isSdkUrl(url)) return; // skip intake/SDK — we only want app requests
    const reqHdrs = entry.request?.headers || [];
    const traceId    = reqHdrs.find(h => h.name.toLowerCase() === 'x-datadog-trace-id');
    const parentId   = reqHdrs.find(h => h.name.toLowerCase() === 'x-datadog-parent-id');
    const origin     = reqHdrs.find(h => h.name.toLowerCase() === 'x-datadog-origin');
    const sampling   = reqHdrs.find(h => h.name.toLowerCase() === 'x-datadog-sampling-priority');
    const traceparent= reqHdrs.find(h => h.name.toLowerCase() === 'traceparent');
    if (!traceId && !traceparent) return; // no correlation headers — not an instrumented request
    apmCorrelations.push({
      url,
      method:       entry.request?.method || 'GET',
      status:       entry.response?.status || 0,
      traceId:      traceId?.value     || null,
      parentId:     parentId?.value    || null,
      origin:       origin?.value      || null,  // should be 'rum'
      sampling:     sampling?.value    || null,  // '1' = sampled, '0' = not sampled
      traceparent:  traceparent?.value || null,
      sampled:      sampling ? sampling.value === '1' : null,
    });
  });

  const warnings = buildWarnings({
    sdkLoads, initConfig, intakeErrors, intakeSuccess, replayRequests,
    sessionId, ddCookies, endpointHits, sdkInitCount,
    totalEntries: entries.length, firstIntakeOffsetMs, apmCorrelations,
  });

  return {
    filename, creator,
    totalEntries: entries.length,
    ddCookies, intakeErrors, intakeSuccess, replayRequests,
    sessionId, sessionIdSource, appId, appIdSource,
    sdkLoads, initConfig, sdkInitCount,
    eventTypeCounts, endpointHits, warnings,
    firstIntakeOffsetMs, apmCorrelations,
  };
}

// ── Render helpers ─────────────────────────────────────────────────────────

function makeCopyBtn(text) {
  const btn = document.createElement('button');
  btn.className = 'copy-btn';
  btn.title = 'Copy';
  btn.setAttribute('aria-label', 'Copy to clipboard');
  btn.innerHTML = '<i class="bi bi-clipboard"></i>';
  btn.addEventListener('click', e => {
    e.stopPropagation();
    copyToClipboard(text, btn);
    btn.innerHTML = '<i class="bi bi-check-lg"></i>';
    setTimeout(() => { btn.innerHTML = '<i class="bi bi-clipboard"></i>'; }, 1800);
  });
  return btn;
}

function makeCollapsible(headerHtml, bodyEl, startOpen = false) {
  const wrap   = document.createElement('div');
  wrap.className = 'collapsible-item';
  const toggle = document.createElement('button');
  toggle.className = 'collapsible-toggle';
  toggle.setAttribute('aria-expanded', String(startOpen));
  toggle.innerHTML = headerHtml + `<i class="bi bi-chevron-down collapsible-chevron${startOpen ? ' open' : ''}"></i>`;
  bodyEl.classList.add('collapsible-body');
  if (startOpen) bodyEl.classList.add('open');
  toggle.addEventListener('click', () => {
    const open = bodyEl.classList.toggle('open');
    toggle.setAttribute('aria-expanded', String(open));
    toggle.querySelector('.collapsible-chevron').classList.toggle('open', open);
  });
  wrap.appendChild(toggle);
  wrap.appendChild(bodyEl);
  return wrap;
}

// ── Render: Full File Card ─────────────────────────────────────────────────

function renderFileCard(analysis) {
  const {
    filename, creator, totalEntries, ddCookies, intakeErrors, intakeSuccess,
    replayRequests, sessionId, sessionIdSource, appId, appIdSource,
    sdkLoads, initConfig, sdkInitCount, eventTypeCounts,
    endpointHits, warnings, firstIntakeOffsetMs, apmCorrelations,
  } = analysis;

  const errorWarns = warnings.filter(w => w.sev === 'error');
  const warnWarns  = warnings.filter(w => w.sev === 'warn');

  const card = document.createElement('div');
  card.className = 'file-card';

  // ── Header ──
  const header = document.createElement('div');
  header.className = 'file-card-header';
  header.innerHTML = `
    <span class="file-card-icon"><i class="bi bi-file-earmark-text"></i></span>
    <span class="file-card-name">${escHtml(filename)}</span>
    <div class="badges">
      ${errorWarns.length     ? `<span class="badge-pill badge-danger"><i class="bi bi-x-circle"></i> ${errorWarns.length} error${errorWarns.length > 1 ? 's' : ''}</span>` : ''}
      ${warnWarns.length      ? `<span class="badge-pill badge-warn"><i class="bi bi-exclamation-triangle"></i> ${warnWarns.length} warning${warnWarns.length > 1 ? 's' : ''}</span>` : ''}
      ${intakeErrors.length   ? `<span class="badge-pill badge-danger">${intakeErrors.length} intake error${intakeErrors.length > 1 ? 's' : ''}</span>` : ''}
      ${ddCookies.length      ? `<span class="badge-pill badge-info">${ddCookies.length} DD cookie${ddCookies.length > 1 ? 's' : ''}</span>` : ''}
      ${sessionId             ? `<span class="badge-pill badge-success">RUM session</span>` : ''}
      ${replayRequests.length ? `<span class="badge-pill badge-purple">${replayRequests.length} replay</span>` : ''}
    </div>
  `;
  card.appendChild(header);

  // ── Summary strip ──
  const strip = document.createElement('div');
  strip.className = 'summary-strip';
  const rumSdk = sdkLoads.find(s => s.type === 'rum' || s.type === 'rum-slim');
  strip.innerHTML = `
    <div class="stat-cell">
      <div class="stat-label">Total requests</div>
      <div class="stat-value">${totalEntries.toLocaleString()}</div>
    </div>
    <div class="stat-cell">
      <div class="stat-label">Intake ok</div>
      <div class="stat-value ${intakeSuccess.length > 0 ? 'v-success' : ''}">${intakeSuccess.length}</div>
    </div>
    <div class="stat-cell">
      <div class="stat-label">Intake errors</div>
      <div class="stat-value ${intakeErrors.length > 0 ? 'v-danger' : ''}">${intakeErrors.length}</div>
    </div>
    <div class="stat-cell">
      <div class="stat-label">Session replay</div>
      <div class="stat-value ${replayRequests.length > 0 ? 'v-purple' : ''}">${replayRequests.length}</div>
    </div>
    <div class="stat-cell">
      <div class="stat-label">SDK version</div>
      <div class="stat-value v-primary" style="font-size:1.1rem">${rumSdk ? escHtml(rumSdk.version || '?') : '–'}</div>
    </div>
    <div class="stat-cell">
      <div class="stat-label">Warnings</div>
      <div class="stat-value ${warnings.length > 0 ? 'v-warn' : ''}">${warnings.length}</div>
    </div>
  `;
  card.appendChild(strip);

  // ── Warnings ──
  if (warnings.length > 0) {
    const warnBlock = document.createElement('div');
    warnBlock.className = 'section-block';
    warnBlock.innerHTML = `<div class="block-heading"><i class="bi bi-shield-exclamation"></i> Diagnostics & warnings</div>`;
    const warnList = document.createElement('div');
    warnList.className = 'warn-list';
    warnings.forEach(w => {
      const item = document.createElement('div');
      item.className = `warn-item warn-${w.sev}`;
      item.innerHTML = `
        <span class="warn-icon">${w.sev === 'error' ? '<i class="bi bi-x-circle-fill"></i>' : w.sev === 'warn' ? '<i class="bi bi-exclamation-triangle-fill"></i>' : '<i class="bi bi-info-circle-fill"></i>'}</span>
        <span class="warn-cat">${escHtml(w.cat)}</span>
        <span class="warn-msg">${escHtml(w.msg)}${w.detail ? `<span class="warn-detail">${escHtml(w.detail)}</span>` : ''}</span>
      `;
      warnList.appendChild(item);
    });
    warnBlock.appendChild(warnList);
    card.appendChild(warnBlock);
  }

  // ── SDK Health ──
  const sdkBlock = document.createElement('div');
  sdkBlock.className = 'section-block';
  sdkBlock.innerHTML = `<div class="block-heading"><i class="bi bi-cpu"></i> SDK health</div><p class="section-caveat"><i class="bi bi-info-circle"></i> SDK script requests (<code>datadog-rum.js</code>, <code>datadog-rum-slim.js</code>, <code>datadog-logs.js</code>) are only present in a HAR if the browser loaded them during the capture window. If the SDK was already cached or the HAR was started after page load, these will not appear. <strong>Best effort only.</strong></p>`;
  if (sdkLoads.length === 0) {
    sdkBlock.innerHTML += `<p class="empty-note">No SDK script loads found in this capture.</p>`;
  } else {
    const sdkGrid = document.createElement('div');
    sdkGrid.className = 'sdk-grid';
    sdkLoads.forEach(sdk => {
      const ok = !isError(sdk.status);
      const officialHost = KNOWN_OFFICIAL_SDK_HOSTS.some(h => sdk.url.includes(h));
      sdkGrid.innerHTML += `
        <div class="sdk-card">
          <div class="sdk-card-top">
            <span class="sdk-type-badge ${ok ? 'ok' : 'err'}">${escHtml(sdk.type)}</span>
            <span class="sdk-version">${sdk.version ? escHtml(sdk.version) : 'unknown version'}</span>
            <span class="sdk-status ${ok ? 'ok' : 'err'}">${sdk.status === 0 ? 'BLOCKED' : sdk.status}</span>
          </div>
          <div class="sdk-url" title="${escHtml(sdk.url)}">${escHtml(sdk.url)}</div>
          <div class="sdk-meta">
            ${sdk.loadTimeMs ? `<span>Load time: ${formatMs(sdk.loadTimeMs)}</span>` : ''}
            ${!officialHost ? `<span class="sdk-custom-host">⚠ Non-official host</span>` : ''}
            ${sdkInitCount > 1 ? `<span class="sdk-custom-host">⚠ Init called ${sdkInitCount}×</span>` : ''}
          </div>
        </div>
      `;
    });
    sdkBlock.appendChild(sdkGrid);
  }
  card.appendChild(sdkBlock);

  // ── Init Config ──
  if (initConfig) {
    const cfgBlock = document.createElement('div');
    cfgBlock.className = 'section-block';
    cfgBlock.innerHTML = `<div class="block-heading"><i class="bi bi-gear"></i> Init configuration</div>`;
    const cfgGrid = document.createElement('div');
    cfgGrid.className = 'cfg-grid';
    const cfgFields = [
      ['clientToken',              initConfig.clientToken              || '–'],
      ['applicationId',            initConfig.applicationId            || '–'],
      ['site',                     initConfig.site                     || '–'],
      ['service',                  initConfig.service                  || '–'],
      ['env',                      initConfig.env                      || '–'],
      ['version',                  initConfig.version                  || '–'],
      ['sessionSampleRate',        initConfig.sessionSampleRate        != null ? initConfig.sessionSampleRate + '%' : '–'],
      ['sessionReplaySampleRate',  initConfig.sessionReplaySampleRate  != null ? initConfig.sessionReplaySampleRate + '%' : '–'],
      ['defaultPrivacyLevel',      initConfig.defaultPrivacyLevel      || '–'],
      ['trackingConsent',          initConfig.trackingConsent          || '–'],
      ['trackUserInteractions',    initConfig.trackUserInteractions    != null ? String(initConfig.trackUserInteractions) : '–'],
      ['trackResources',           initConfig.trackResources           != null ? String(initConfig.trackResources) : '–'],
      ['trackLongTasks',           initConfig.trackLongTasks           != null ? String(initConfig.trackLongTasks) : '–'],
      ['sessionPersistence',       initConfig.sessionPersistence       || '–'],
    ];
    cfgFields.forEach(([k, v]) => {
      const flagWarn = (k === 'sessionSampleRate' && parseInt(v) < 100) ||
                       (k === 'sessionReplaySampleRate' && parseInt(v) === 0) ||
                       (k === 'trackingConsent' && v === 'not-granted') ||
                       (k === 'trackUserInteractions' && v === 'false') ||
                       (k === 'trackResources' && v === 'false');
      cfgGrid.innerHTML += `
        <div class="cfg-row">
          <span class="cfg-key">${escHtml(k)}</span>
          <span class="cfg-val ${flagWarn ? 'cfg-flagged' : ''}">${escHtml(String(v))}</span>
        </div>
      `;
    });
    cfgBlock.appendChild(cfgGrid);
    card.appendChild(cfgBlock);
  }

  // ── RUM Identifiers ──
  const rumBlock = document.createElement('div');
  rumBlock.className = 'section-block';
  rumBlock.innerHTML = `<div class="block-heading"><i class="bi bi-eye"></i> RUM identifiers</div>`;
  const rumGrid = document.createElement('div');
  rumGrid.className = 'rum-grid';
  [
    { label: 'Session ID',      val: sessionId, src: sessionIdSource },
    { label: 'Application ID',  val: appId,     src: appIdSource },
  ].forEach(({ label, val, src }) => {
    const box    = document.createElement('div');
    box.className = 'rum-box';
    const keyEl  = document.createElement('div');
    keyEl.className = 'rum-key';
    keyEl.textContent = label + (src ? ` · via ${src}` : '');
    box.appendChild(keyEl);
    const valDiv = document.createElement('div');
    valDiv.className = val ? 'rum-val' : 'rum-val empty';
    if (val) { const span = document.createElement('span'); span.textContent = val; valDiv.appendChild(span); valDiv.appendChild(makeCopyBtn(val)); }
    else { valDiv.textContent = 'not found'; }
    box.appendChild(valDiv);
    rumGrid.appendChild(box);
  });
  // First intake offset
  if (firstIntakeOffsetMs != null) {
    const timeBox = document.createElement('div');
    timeBox.className = 'rum-box';
    timeBox.innerHTML = `<div class="rum-key">First event after page start</div><div class="rum-val">${escHtml(formatMs(firstIntakeOffsetMs))}</div>`;
    rumGrid.appendChild(timeBox);
  }
  rumBlock.appendChild(rumGrid);
  card.appendChild(rumBlock);

  // ── Event type breakdown ──
  if (Object.keys(eventTypeCounts).length > 0) {
    const evtBlock = document.createElement('div');
    evtBlock.className = 'section-block';
    evtBlock.innerHTML = `<div class="block-heading"><i class="bi bi-bar-chart"></i> Intake event types</div>`;
    const evtRow = document.createElement('div');
    evtRow.className = 'event-type-row';
    Object.entries(eventTypeCounts).sort((a, b) => b[1] - a[1]).forEach(([type, count]) => {
      evtRow.innerHTML += `<div class="event-type-chip"><span class="event-type-label">${escHtml(type)}</span><span class="event-type-count">${count}</span></div>`;
    });
    evtBlock.appendChild(evtRow);
    card.appendChild(evtBlock);
  }

  // ── RUM <> APM Correlation ──
  const apmBlock = document.createElement('div');
  apmBlock.className = 'section-block';
  apmBlock.innerHTML = `<div class="block-heading"><i class="bi bi-diagram-3"></i> RUM &harr; APM correlation</div>`;

  if (apmCorrelations.length === 0) {
    apmBlock.innerHTML += `<p class="empty-note">No APM propagation headers found on outgoing requests. Either <code>allowedTracingUrls</code> is not configured, no matching requests were captured, or the HAR was taken before the RUM SDK injected headers.</p>`;
  } else {
    const sampledCount   = apmCorrelations.filter(c => c.sampled === true).length;
    const unsampledCount = apmCorrelations.filter(c => c.sampled === false).length;
    const w3cCount       = apmCorrelations.filter(c => !!c.traceparent).length;
    const ddCount        = apmCorrelations.filter(c => !!c.traceId).length;

    const apmSummary = document.createElement('div');
    apmSummary.className = 'apm-summary';
    apmSummary.innerHTML = `
      <div class="apm-stat"><span class="apm-stat-val">${apmCorrelations.length}</span><span class="apm-stat-label">correlated requests</span></div>
      <div class="apm-stat"><span class="apm-stat-val v-success">${sampledCount}</span><span class="apm-stat-label">sampled (priority=1)</span></div>
      <div class="apm-stat"><span class="apm-stat-val">${unsampledCount}</span><span class="apm-stat-label">not sampled (priority=0)</span></div>
      <div class="apm-stat"><span class="apm-stat-val">${ddCount}</span><span class="apm-stat-label">Datadog headers</span></div>
      <div class="apm-stat"><span class="apm-stat-val">${w3cCount}</span><span class="apm-stat-label">W3C traceparent</span></div>
    `;
    apmBlock.appendChild(apmSummary);

    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    const table = document.createElement('table');
    table.className = 'data-table';
    table.innerHTML = `<thead><tr><th>URL</th><th>Method</th><th>Status</th><th>Trace ID</th><th>Origin</th><th>Sampled</th><th>W3C traceparent</th></tr></thead>`;
    const tbody = document.createElement('tbody');
    apmCorrelations.forEach(c => {
      const sampledLabel = c.sampled === true ? '<span style="color:#1e8449;font-weight:700">Yes</span>' : c.sampled === false ? '<span style="color:#c0392b">No</span>' : '–';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="mono url-cell" title="${escHtml(c.url)}">${escHtml(c.url)}</td>
        <td>${escHtml(c.method)}</td>
        <td>${escHtml(String(c.status || '–'))}</td>
        <td class="mono" title="${escHtml(c.traceId || '')}">${c.traceId ? escHtml(c.traceId) : '–'}</td>
        <td>${c.origin ? `<code>${escHtml(c.origin)}</code>` : '–'}</td>
        <td>${sampledLabel}</td>
        <td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(c.traceparent || '')}">${c.traceparent ? escHtml(c.traceparent) : '–'}</td>
      `;
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    apmBlock.appendChild(wrap);

    // Warning if no sampled requests despite having correlations
    if (sampledCount === 0 && apmCorrelations.length > 0) {
      apmBlock.innerHTML += `<p class="section-caveat" style="margin-top:10px"><i class="bi bi-exclamation-triangle"></i> All correlated requests have <strong>x-datadog-sampling-priority: 0</strong> — traces are being sent but not retained. Check your APM trace retention filters or <code>traceSampleRate</code> in <code>allowedTracingUrls</code>.</p>`;
    }
    if (ddCount > 0 && w3cCount === 0) {
      apmBlock.innerHTML += `<p class="section-caveat" style="margin-top:8px"><i class="bi bi-info-circle"></i> Only Datadog-format headers detected. If your backend uses W3C Trace Context, consider adding <code>traceparent</code> propagation via <code>allowedTracingUrls</code> header type config.</p>`;
    }
  }
  card.appendChild(apmBlock);

  // ── DD Cookies ──
  const cookiesBlock = document.createElement('div');
  cookiesBlock.className = 'section-block';
  cookiesBlock.innerHTML = `<div class="block-heading"><i class="bi bi-shield-lock"></i> Datadog cookies</div><p class="section-caveat"><i class="bi bi-info-circle"></i> Cookies are typically visible in <strong>DevTools &rsaquo; Application &rsaquo; Cookies</strong> rather than network request headers. HAR files may not include cookie headers depending on browser and capture settings. <strong>Best effort only.</strong></p>`;
  if (ddCookies.length === 0) {
    cookiesBlock.innerHTML += `<p class="empty-note">No Datadog cookies found in request/response headers. Check DevTools &rsaquo; Application &rsaquo; Cookies directly if needed.</p>`;
  } else {
    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    const table = document.createElement('table');
    table.className = 'data-table';
    table.innerHTML = `<thead><tr><th>Cookie</th><th>Raw value</th><th>Decoded segments</th><th>URL</th><th></th></tr></thead>`;
    const tbody = document.createElement('tbody');
    ddCookies.forEach(c => {
      const decodedStr = c.decoded ? Object.entries(JSON.parse(c.decoded)).map(([k, v]) => `${k}=${v}`).join(' · ') : '–';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="name-cell">${escHtml(c.name)}</td>
        <td class="mono" title="${escHtml(c.value)}">${escHtml(c.value)}</td>
        <td class="mono" title="${escHtml(decodedStr)}">${escHtml(decodedStr)}</td>
        <td class="mono url-cell" title="${escHtml(c.url)}">${escHtml(c.url)}</td>
        <td class="copy-cell"></td>
      `;
      tr.querySelector('.copy-cell').appendChild(makeCopyBtn(c.value));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    cookiesBlock.appendChild(wrap);
  }
  card.appendChild(cookiesBlock);

  // ── Intake Errors ──
  if (intakeErrors.length > 0) {
    const errBlock = document.createElement('div');
    errBlock.className = 'section-block';
    errBlock.innerHTML = `<div class="block-heading"><i class="bi bi-exclamation-triangle"></i> Intake errors</div>`;
    const list = document.createElement('div');
    list.className = 'error-list';
    intakeErrors.forEach(err => {
      const item   = document.createElement('div');
      item.className = 'error-item';
      const toggle = document.createElement('button');
      toggle.className = 'error-toggle';
      toggle.setAttribute('aria-expanded', 'false');
      const statusLabel = err.status === 0 ? 'BLOCKED' : err.status;
      toggle.innerHTML = `
        <span class="err-status">${escHtml(String(statusLabel))}</span>
        <span class="err-method">${escHtml(err.method)}</span>
        <span class="err-url" title="${escHtml(err.url)}">${escHtml(err.url)}</span>
        <i class="bi bi-chevron-down err-chevron"></i>
      `;
      const detail = document.createElement('div');
      detail.className = 'error-detail';
      const sections = [];
      if (err.reqHeaders.length)  sections.push(`<div class="detail-section"><div class="detail-label">Request headers</div>${err.reqHeaders.map(h => `<div class="header-row"><span class="hname">${escHtml(h.name)}</span><span class="hval">${escHtml(h.value)}</span></div>`).join('')}</div>`);
      if (err.resHeaders.length)  sections.push(`<div class="detail-section"><div class="detail-label">Response headers</div>${err.resHeaders.map(h => `<div class="header-row"><span class="hname">${escHtml(h.name)}</span><span class="hval">${escHtml(h.value)}</span></div>`).join('')}</div>`);
      if (err.bodyText)           sections.push(`<div class="detail-section"><div class="detail-label">Response body</div><pre class="response-body-pre">${escHtml(err.bodyText.slice(0, 800))}${err.bodyText.length > 800 ? '\n…(truncated)' : ''}</pre></div>`);
      if (err.totalTime)          sections.push(`<div class="detail-section"><div class="detail-label">Timing</div><div class="header-row"><span class="hname">Total time</span><span class="hval">${formatMs(err.totalTime)}</span></div>${err.timings.wait != null ? `<div class="header-row"><span class="hname">Wait (TTFB)</span><span class="hval">${formatMs(err.timings.wait)}</span></div>` : ''}</div>`);
      if (err.reqBodySize > 0)    sections.push(`<div class="detail-section"><div class="detail-label">Request payload size</div><div class="header-row"><span class="hname">Size</span><span class="hval">${formatBytes(err.reqBodySize)}${err.reqBodySize > 1_000_000 ? ' ⚠ over 1MB' : ''}</span></div></div>`);
      detail.innerHTML = sections.join('');
      toggle.addEventListener('click', () => {
        const open = detail.classList.toggle('open');
        toggle.setAttribute('aria-expanded', String(open));
        toggle.querySelector('.err-chevron').classList.toggle('open', open);
      });
      item.appendChild(toggle);
      item.appendChild(detail);
      list.appendChild(item);
    });
    errBlock.appendChild(list);
    card.appendChild(errBlock);
  }

  // ── Session Replay ──
  if (replayRequests.length > 0) {
    const replayBlock = document.createElement('div');
    replayBlock.className = 'section-block';
    replayBlock.innerHTML = `<div class="block-heading"><i class="bi bi-camera-video"></i> Session replay requests</div>`;
    const list = document.createElement('div');
    list.className = 'replay-list';
    replayRequests.forEach(r => {
      const item = document.createElement('div');
      item.className = 'replay-item';
      const statusLabel = r.status === 0 ? 'BLOCKED' : r.status;
      item.innerHTML = `
        <span class="replay-status ${isError(r.status) ? 'err' : 'ok'}">${escHtml(String(statusLabel))}</span>
        <span class="replay-url" title="${escHtml(r.url)}">${escHtml(r.url)}</span>
        <span class="replay-size">${formatBytes(r.reqBodySize || r.bodySize)}</span>
      `;
      list.appendChild(item);
    });
    replayBlock.appendChild(list);
    card.appendChild(replayBlock);
  }

  // ── Additional details ──
  const infoBlock = document.createElement('div');
  infoBlock.className = 'section-block';
  infoBlock.innerHTML = `<div class="block-heading"><i class="bi bi-info-circle"></i> Additional details</div>`;
  const rows = [
    { key: 'HAR creator',          val: `${creator.name || '–'} ${creator.version || ''}`.trim() },
    { key: 'Total intake requests',val: String(intakeErrors.length + intakeSuccess.length) },
    { key: 'SDK init calls',       val: String(sdkInitCount) + (sdkInitCount > 1 ? ' ⚠ duplicate init detected' : '') },
    ...Object.entries(endpointHits).map(([host, count]) => ({ key: `Endpoint: ${host}`, val: `${count} request${count > 1 ? 's' : ''}` })),
  ];
  const detailRows = document.createElement('div');
  detailRows.className = 'detail-rows';
  rows.forEach(({ key, val }) => {
    const row = document.createElement('div');
    row.className = 'detail-row';
    row.innerHTML = `<span class="detail-row-key">${escHtml(key)}</span><span class="detail-row-val">${escHtml(val)}</span>`;
    detailRows.appendChild(row);
  });
  infoBlock.appendChild(detailRows);
  card.appendChild(infoBlock);

  // ── Export bar ──
  const exportBar = document.createElement('div');
  exportBar.className = 'export-bar';
  const copyBtn = document.createElement('button');
  copyBtn.className = 'har-btn';
  copyBtn.innerHTML = '<i class="bi bi-clipboard"></i> Copy summary';
  copyBtn.addEventListener('click', () => {
    copyToClipboard(buildTextSummary(analysis), copyBtn);
    copyBtn.innerHTML = '<i class="bi bi-check-lg"></i> Copied!';
    setTimeout(() => { copyBtn.innerHTML = '<i class="bi bi-clipboard"></i> Copy summary'; }, 2000);
  });
  const downloadBtn = document.createElement('button');
  downloadBtn.className = 'har-btn har-btn-primary';
  downloadBtn.innerHTML = '<i class="bi bi-download"></i> Export JSON';
  downloadBtn.addEventListener('click', () => exportJSON(analysis));
  exportBar.appendChild(copyBtn);
  exportBar.appendChild(downloadBtn);
  card.appendChild(exportBar);

  return card;
}

// ── Export helpers ─────────────────────────────────────────────────────────

function buildTextSummary(a) {
  const warns = a.warnings || [];
  return [
    `=== Datadog HAR Analysis: ${a.filename} ===`,
    ``,
    `Total requests:        ${a.totalEntries}`,
    `Intake ok:             ${a.intakeSuccess.length}`,
    `Intake errors:         ${a.intakeErrors.length}`,
    `Session replay:        ${a.replayRequests.length}`,
    `DD cookies:            ${a.ddCookies.length}`,
    `SDK init calls:        ${a.sdkInitCount}`,
    ``,
    `--- RUM Identifiers ---`,
    `Session ID:    ${a.sessionId || 'not found'}${a.sessionIdSource ? ` (via ${a.sessionIdSource})` : ''}`,
    `Application ID:${a.appId     || 'not found'}${a.appIdSource ? ` (via ${a.appIdSource})` : ''}`,
    a.firstIntakeOffsetMs != null ? `First event at: ${formatMs(a.firstIntakeOffsetMs)} after page start` : '',
    ``,
    `--- SDK ---`,
    ...(a.sdkLoads.length === 0 ? ['No SDK detected.'] : a.sdkLoads.map(s => `${s.type} ${s.version || '?'} — ${s.status === 0 ? 'BLOCKED' : s.status} — ${formatMs(s.loadTimeMs)} — ${s.url}`)),
    ``,
    `--- Init Config ---`,
    a.initConfig ? Object.entries(a.initConfig).map(([k, v]) => `  ${k}: ${v}`).join('\n') : 'Not extracted.',
    ``,
    `--- Event Types ---`,
    ...Object.entries(a.eventTypeCounts).map(([t, c]) => `  ${t}: ${c}`),
    ``,
    `--- Diagnostics ---`,
    ...(warns.length === 0 ? ['No warnings.'] : warns.map(w => `[${w.sev.toUpperCase()}] [${w.cat}] ${w.msg}`)),
    ``,
    `--- DD Cookies ---`,
    ...(a.ddCookies.length === 0 ? ['None found.'] : a.ddCookies.map(c => `${c.name}: ${c.value}\n  URL: ${c.url}`)),
    ``,
    `--- Intake Errors ---`,
    ...(a.intakeErrors.length === 0 ? ['None.'] : a.intakeErrors.map(e => `${e.status || 'BLOCKED'} ${e.method} ${e.url}`)),
    ``,
    `--- Endpoints Hit ---`,
    ...Object.entries(a.endpointHits).map(([h, c]) => `${h}: ${c} request${c > 1 ? 's' : ''}`),
  ].filter(l => l !== '').join('\n');
}

function exportJSON(analysis) {
  const data = {
    filename: analysis.filename, creator: analysis.creator, totalEntries: analysis.totalEntries,
    rum: { sessionId: analysis.sessionId, sessionIdSource: analysis.sessionIdSource, appId: analysis.appId, appIdSource: analysis.appIdSource, firstIntakeOffsetMs: analysis.firstIntakeOffsetMs },
    sdk: { loads: analysis.sdkLoads, initConfig: analysis.initConfig, initCallCount: analysis.sdkInitCount },
    eventTypeCounts: analysis.eventTypeCounts,
    warnings: analysis.warnings,
    ddCookies: analysis.ddCookies.map(c => ({ name: c.name, value: c.value, decodedSegments: c.segments, url: c.url })),
    intakeErrors: analysis.intakeErrors.map(e => ({ status: e.status, method: e.method, url: e.url, requestHeaders: e.reqHeaders, responseHeaders: e.resHeaders, responseBodyPreview: e.bodyText ? e.bodyText.slice(0, 500) : null, reqBodySize: e.reqBodySize })),
    intakeSuccessCount: analysis.intakeSuccess.length,
    sessionReplayRequests: analysis.replayRequests.map(r => ({ status: r.status, method: r.method, url: r.url, payloadSize: r.reqBodySize || r.bodySize })),
    endpointHits: analysis.endpointHits,
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = analysis.filename.replace(/\.har$/i, '') + '-dd-analysis.json';
  document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
}

// ── File handling ──────────────────────────────────────────────────────────

function processFile(file) {
  const results = document.getElementById('results');
  if (!file.name.toLowerCase().endsWith('.har')) {
    const n = document.createElement('div');
    n.className = 'parse-error';
    n.innerHTML = `<i class="bi bi-file-x"></i> <strong>${escHtml(file.name)}</strong> is not a .har file and was skipped.`;
    results.prepend(n); return;
  }
  const reader = new FileReader();
  reader.onload = e => {
    let data;
    try { data = JSON.parse(e.target.result); }
    catch {
      const n = document.createElement('div');
      n.className = 'parse-error';
      n.innerHTML = `<i class="bi bi-exclamation-triangle"></i> <strong>${escHtml(file.name)}</strong> could not be parsed — is it valid JSON/HAR?`;
      results.prepend(n); return;
    }
    const analysis = analyzeHAR(data, file.name);
    if (window.DD_RUM) {
      window.DD_RUM.addAction('har_analyzed', {
        filename: analysis.filename, totalEntries: analysis.totalEntries,
        intakeErrors: analysis.intakeErrors.length, ddCookies: analysis.ddCookies.length,
        hasRumSession: !!analysis.sessionId, replayRequests: analysis.replayRequests.length,
        warnings: analysis.warnings.length, sdkVersion: analysis.sdkLoads[0]?.version || null,
      });
    }
    results.prepend(renderFileCard(analysis));
  };
  reader.readAsText(file);
}

function handleFiles(files) { Array.from(files).forEach(processFile); }

// ── Init ───────────────────────────────────────────────────────────────────

(function init() {
  const dropZone  = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  fileInput.addEventListener('change', e => { handleFiles(e.target.files); e.target.value = ''; });
  dropZone.addEventListener('dragover',  e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', e => { if (!dropZone.contains(e.relatedTarget)) dropZone.classList.remove('drag-over'); });
  dropZone.addEventListener('drop', e => { e.preventDefault(); dropZone.classList.remove('drag-over'); handleFiles(e.dataTransfer.files); });
})();

