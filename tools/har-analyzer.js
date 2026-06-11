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

const DD_COOKIE_NAMES = ['_dd_s', '_dd_s_v2', '_dd_r', '_dd_l', '_dd'];

const KNOWN_OFFICIAL_SDK_HOSTS = [
  'www.datadoghq-browser-agent.com',
  'static.datadoghq.com',
];

// Query Inspector endpoint patterns
const QI_ENDPOINTS = [
  { pattern: /\/api\/ui\/query\/timeseries/, type: 'timeseries', label: 'Timeseries' },
  { pattern: /\/api\/ui\/query\/scalar/,     type: 'scalar',     label: 'Scalar' },
  { pattern: /\/api\/v1\/query/,             type: 'timeseries', label: 'Timeseries (v1)' },
  { pattern: /\/api\/v2\/query\/timeseries/, type: 'timeseries', label: 'Timeseries (v2)' },
  { pattern: /\/api\/v2\/query\/scalar/,     type: 'scalar',     label: 'Scalar (v2)' },
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

function formatTimestamp(ms) {
  if (!ms) return '–';
  return new Date(ms).toLocaleString();
}

function formatInterval(ms) {
  if (!ms) return '–';
  const s = ms / 1000;
  if (s < 60)   return s + 's';
  if (s < 3600) return (s / 60).toFixed(0) + 'm';
  return (s / 3600).toFixed(0) + 'h';
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

function extractSdkVersion(url) {
  const m = url.match(/\/(v\d+(?:\.\d+)*)\//);
  return m ? m[1] : null;
}

function extractSdkType(url) {
  if (/datadog-rum-slim/.test(url)) return 'rum-slim';
  if (/datadog-rum/.test(url))      return 'rum';
  if (/datadog-logs/.test(url))     return 'logs';
  return 'unknown';
}

function extractInitConfig(scriptText) {
  if (!scriptText) return null;
  try {
    const m = scriptText.match(/DD_RUM\s*&&\s*DD_RUM\.init\s*\(\s*(\{[\s\S]*?\})\s*\)/);
    if (!m) return null;
    let obj = m[1]
      .replace(/\/\/.*$/gm, '')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/,\s*([}\]])/g, '$1')
      .replace(/([{,]\s*)([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:/g, '$1"$2":');
    return JSON.parse(obj);
  } catch { return null; }
}

// ── Warnings builder ───────────────────────────────────────────────────────

function buildWarnings(analysis) {
  const warns = [];
  const { sdkLoads, initConfig, intakeErrors, intakeSuccess,
          replayRequests, sessionId, ddCookies, endpointHits } = analysis;

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
    if (rumSdk && logsSdk && rumSdk.version !== logsSdk.version) {
      warns.push({ sev: 'warn', cat: 'SDK', msg: `RUM SDK (${rumSdk.version}) and Logs SDK (${logsSdk.version}) are on different major versions.` });
    }
  }

  if (initConfig) {
    const cfg = initConfig;
    if (cfg.sessionSampleRate === 0) {
      warns.push({ sev: 'error', cat: 'Config', msg: 'sessionSampleRate is 0 — no sessions will be recorded.' });
    } else if (cfg.sessionSampleRate < 100 && cfg.sessionSampleRate > 0) {
      warns.push({ sev: 'info', cat: 'Config', msg: `sessionSampleRate is ${cfg.sessionSampleRate}% — some sessions are intentionally dropped client-side.` });
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
    if (!cfg.version) warns.push({ sev: 'info', cat: 'Config', msg: "No 'version' set in DD_RUM.init() — version faceting in RUM Explorer will not be available." });
    if (!cfg.env)     warns.push({ sev: 'info', cat: 'Config', msg: "No 'env' set in DD_RUM.init() — environment faceting will not be available." });
    if (!cfg.service) warns.push({ sev: 'info', cat: 'Config', msg: "No 'service' set in DD_RUM.init() — service faceting will not be available." });
    if (cfg.trackUserInteractions === false) warns.push({ sev: 'warn', cat: 'Config', msg: "trackUserInteractions is false — click/action events will not be captured." });
    if (cfg.trackResources === false)        warns.push({ sev: 'warn', cat: 'Config', msg: "trackResources is false — resource timing data will not be captured." });
    if (cfg.trackLongTasks === false)        warns.push({ sev: 'info', cat: 'Config', msg: "trackLongTasks is false — long task events will not be captured." });
    if (replayRequests.length > 0 && cfg.sessionReplaySampleRate === 0) {
      warns.push({ sev: 'warn', cat: 'Config', msg: 'Session Replay requests are present but sessionReplaySampleRate is 0 in init config.' });
    }
    if (replayRequests.length === 0 && cfg.sessionReplaySampleRate === 100 && (intakeSuccess.length + intakeErrors.length) > 5) {
      warns.push({ sev: 'warn', cat: 'Config', msg: 'sessionReplaySampleRate is 100% but no Session Replay requests found.' });
    }
  } else if (sdkLoads.length > 0) {
    warns.push({ sev: 'info', cat: 'Config', msg: 'Could not extract DD_RUM.init() config from inline scripts — config review skipped.' });
  }

  if (analysis.sdkInitCount > 1) {
    warns.push({ sev: 'error', cat: 'Config', msg: `DD_RUM.init() called ${analysis.sdkInitCount} times — duplicate initialisation causes double-counting of events.` });
  }

  const blockedSdk = sdkLoads.filter(s => s.status === 0);
  if (blockedSdk.length > 0) {
    warns.push({ sev: 'error', cat: 'CSP/Network', msg: `${blockedSdk.length} SDK script request(s) were blocked (status 0) — likely a Content Security Policy issue.` });
  }

  const blockedIntake = [...intakeErrors, ...intakeSuccess].filter(e => e.status === 0);
  if (blockedIntake.length > 0) {
    warns.push({ sev: 'error', cat: 'CSP/Network', msg: `${blockedIntake.length} intake request(s) were blocked (status 0).` });
  }

  const rateLimited = intakeErrors.filter(e => e.status === 429);
  if (rateLimited.length > 0) {
    warns.push({ sev: 'error', cat: 'Rate Limit', msg: `${rateLimited.length} intake request(s) rate-limited (429).` });
  }

  return warns;
}

// ── Event type breakdown ───────────────────────────────────────────────────

function extractEventTypes(entries) {
  const counts = {};
  entries.forEach(entry => {
    if (!isIntakeUrl(entry.request?.url || '')) return;
    try {
      const u = new URL(entry.request.url);
      const pathMatch = u.pathname.match(/\/api\/v2\/(\w+)/);
      if (pathMatch) { const t = pathMatch[1]; counts[t] = (counts[t] || 0) + 1; return; }
      const src = u.searchParams.get('ddsource') || u.searchParams.get('ddtags');
      if (src) { counts[src] = (counts[src] || 0) + 1; return; }
    } catch {}
    const url = entry.request?.url || '';
    if (/session-replay/.test(url)) { counts['replay'] = (counts['replay'] || 0) + 1; return; }
    if (/logs/.test(url))            { counts['logs']   = (counts['logs']   || 0) + 1; return; }
    if (/rum/.test(url))             { counts['rum']    = (counts['rum']    || 0) + 1; return; }
    counts['intake'] = (counts['intake'] || 0) + 1;
  });
  return counts;
}

// ── Core RUM Analysis ──────────────────────────────────────────────────────

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

  if (pages.length > 0 && pages[0].startedDateTime) {
    pageStartTime = new Date(pages[0].startedDateTime).getTime();
  }

  entries.forEach(entry => {
    const contentType = (entry.response?.headers || []).find(h => h.name.toLowerCase() === 'content-type')?.value || '';
    if (!contentType.includes('text/html') && !contentType.includes('javascript')) return;
    const text = entry.response?.content?.text || '';
    if (!text) return;
    if (!initConfig && text.includes('DD_RUM')) {
      const cfg = extractInitConfig(text);
      if (cfg) initConfig = cfg;
    }
    const initMatches = text.match(/DD_RUM\.init\s*\(/g);
    if (initMatches) sdkInitCount += initMatches.length;
  });

  entries.forEach(entry => {
    const url    = entry.request?.url    || '';
    const method = entry.request?.method || 'GET';
    const status = entry.response?.status || 0;
    const startedMs = entry.startedDateTime ? new Date(entry.startedDateTime).getTime() : null;

    if (isSdkUrl(url)) {
      sdkLoads.push({ url, status, loadTimeMs: entry.time || 0, version: extractSdkVersion(url), type: extractSdkType(url), startedMs });
    }

    const allHeaders = [...(entry.request?.headers || []), ...(entry.response?.headers || [])];
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

    if (!isIntakeUrl(url)) return;
    if (startedMs && !firstIntakeTime) firstIntakeTime = startedMs;

    try {
      const hostname = new URL(url).hostname;
      endpointHits[hostname] = (endpointHits[hostname] || 0) + 1;
    } catch {}

    try {
      const u = new URL(url);
      if (!sessionId) { const v = u.searchParams.get('dd_session_id') || u.searchParams.get('session_id'); if (v) { sessionId = v; sessionIdSource = 'URL param'; } }
      if (!appId)     { const v = u.searchParams.get('dd_app_id') || u.searchParams.get('app_id') || u.searchParams.get('application_id'); if (v) { appId = v; appIdSource = 'URL param'; } }
    } catch {}

    allHeaders.forEach(h => {
      const hn = h.name.toLowerCase();
      if (!appId     && hn === 'x-datadog-application-id') { appId     = h.value; appIdSource     = 'request header'; }
      if (!sessionId && hn === 'x-datadog-session-id')     { sessionId = h.value; sessionIdSource = 'request header'; }
    });

    const WANT_REQ = new Set(['content-type','x-datadog-parent-id','x-datadog-trace-id','x-datadog-sampling-priority','x-datadog-application-id','x-datadog-session-id','dd-api-key','authorization','origin','referer','x-forwarded-for']);
    const WANT_RES = new Set(['content-type','x-ratelimit-limit','x-ratelimit-remaining','x-ratelimit-reset','x-ratelimit-period','x-datadog-trace-id','retry-after','server','access-control-allow-origin']);

    const reqHeaders  = (entry.request?.headers  || []).filter(h => WANT_REQ.has(h.name.toLowerCase()));
    const resHeaders  = (entry.response?.headers || []).filter(h => WANT_RES.has(h.name.toLowerCase()));
    const bodyText    = entry.response?.content?.text || '';
    const bodySize    = entry.response?.bodySize || entry.response?.content?.size || 0;
    const reqBodySize = entry.request?.bodySize || entry.request?.postData?.text?.length || 0;
    const timings     = entry.timings || {};
    const totalTime   = entry.time || 0;

    const entryData = { url, method, status, reqHeaders, resHeaders, bodyText, bodySize, reqBodySize, totalTime, timings, startedMs };
    if (isReplayUrl(url)) replayRequests.push(entryData);
    if (isError(status))  intakeErrors.push(entryData);
    else                  intakeSuccess.push(entryData);
  });

  const firstIntakeOffsetMs = (pageStartTime && firstIntakeTime) ? firstIntakeTime - pageStartTime : null;
  const eventTypeCounts = extractEventTypes(entries);

  const apmCorrelations = [];
  entries.forEach(entry => {
    const url = entry.request?.url || '';
    if (isIntakeUrl(url) || isSdkUrl(url)) return;
    const reqHdrs    = entry.request?.headers || [];
    const traceId    = reqHdrs.find(h => h.name.toLowerCase() === 'x-datadog-trace-id');
    const parentId   = reqHdrs.find(h => h.name.toLowerCase() === 'x-datadog-parent-id');
    const origin     = reqHdrs.find(h => h.name.toLowerCase() === 'x-datadog-origin');
    const sampling   = reqHdrs.find(h => h.name.toLowerCase() === 'x-datadog-sampling-priority');
    const traceparent= reqHdrs.find(h => h.name.toLowerCase() === 'traceparent');
    if (!traceId && !traceparent) return;
    apmCorrelations.push({
      url, method: entry.request?.method || 'GET', status: entry.response?.status || 0,
      traceId: traceId?.value || null, parentId: parentId?.value || null,
      origin: origin?.value || null, sampling: sampling?.value || null,
      traceparent: traceparent?.value || null, sampled: sampling ? sampling.value === '1' : null,
    });
  });

  const warnings = buildWarnings({
    sdkLoads, initConfig, intakeErrors, intakeSuccess, replayRequests,
    sessionId, ddCookies, endpointHits, sdkInitCount,
    totalEntries: entries.length, firstIntakeOffsetMs, apmCorrelations,
  });

  return {
    filename, creator, totalEntries: entries.length,
    ddCookies, intakeErrors, intakeSuccess, replayRequests,
    sessionId, sessionIdSource, appId, appIdSource,
    sdkLoads, initConfig, sdkInitCount,
    eventTypeCounts, endpointHits, warnings,
    firstIntakeOffsetMs, apmCorrelations,
  };
}

// ══════════════════════════════════════════════════════════════════
//  QUERY INSPECTOR
// ══════════════════════════════════════════════════════════════════

function detectQueryEndpoint(url) {
  for (const ep of QI_ENDPOINTS) {
    if (ep.pattern.test(url)) return ep;
  }
  return null;
}

function tryParseJSON(text) {
  if (!text) return null;
  try { return JSON.parse(text); } catch { return null; }
}

function parseQueryEntries(harData) {
  const entries = harData?.log?.entries || [];
  const results = [];

  entries.forEach(entry => {
    const url = entry.request?.url || '';
    const ep  = detectQueryEndpoint(url);
    if (!ep) return;

    const reqText  = entry.request?.postData?.text || '';
    const respText = entry.response?.content?.text || '';
    const reqJSON  = tryParseJSON(reqText);
    const respJSON = tryParseJSON(respText);

    if (!reqJSON && !respJSON) return;

    results.push({
      url,
      type:     ep.type,
      label:    ep.label,
      status:   entry.response?.status || 0,
      reqJSON,
      respJSON,
      rawReq:   reqText,
      rawResp:  respText,
    });
  });

  return results;
}

// Extract queries + metadata from a request JSON
function extractQueriesFromRequest(reqJSON, type) {
  if (!reqJSON) return [];
  const data = reqJSON.data;
  if (!Array.isArray(data)) return [];

  const out = [];
  data.forEach(item => {
    const attrs = item.attributes || {};
    const queries = attrs.queries || [];
    const from = attrs.from;
    const to   = attrs.to;
    const widgetId = reqJSON.meta?.dd_extra_usage_params?.widget_id || null;

    queries.forEach(q => {
      out.push({
        name:       q.name || '?',
        dataSource: q.data_source || '?',
        query:      q.query || q.search?.query || null,
        from, to, widgetId,
        type,
      });
    });
  });
  return out;
}

// Extract series data from a timeseries response
function extractTimeseriesData(respJSON) {
  if (!respJSON) return null;
  const data = respJSON.data;
  if (!Array.isArray(data)) return null;

  const out = [];
  data.forEach(item => {
    if (item.type !== 'timeseries_response') return;
    const attrs  = item.attributes || {};
    const series = attrs.series  || [];
    const times  = attrs.times   || [];
    const values = attrs.values  || [];
    const meta   = respJSON.meta?.responses?.[0] || {};

    series.forEach((s, i) => {
      out.push({
        tags:      s.group_tags || [],
        unit:      s.unit,
        values:    values[i] || [],
        times,
        interval:  meta.interval || null,
        from:      meta.from_date,
        to:        meta.to_date,
      });
    });

    // If no series but times/values present at top level
    if (series.length === 0 && times.length > 0) {
      out.push({ tags: [], unit: null, values: values[0] || [], times, interval: meta.interval, from: meta.from_date, to: meta.to_date });
    }
  });

  return out.length > 0 ? out : null;
}

// Extract columns from a scalar response
function extractScalarData(respJSON) {
  if (!respJSON) return null;
  const data = respJSON.data;
  if (!Array.isArray(data)) return null;

  const out = [];
  data.forEach(item => {
    if (item.type !== 'scalar_response') return;
    const cols = item.attributes?.columns || [];
    out.push(cols);
  });

  return out.length > 0 ? out[0] : null;
}

// Draw a sparkline on a canvas element
function drawSparkline(canvas, values) {
  const ctx  = canvas.getContext('2d');
  const w    = canvas.offsetWidth || 620;
  const h    = canvas.offsetHeight || 52;
  canvas.width  = w * window.devicePixelRatio;
  canvas.height = h * window.devicePixelRatio;
  ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

  const nums = values.filter(v => v != null && !isNaN(v));
  if (nums.length < 2) {
    ctx.fillStyle = '#f5f8fa';
    ctx.fillRect(0, 0, w, h);
    ctx.fillStyle = '#7a95a8';
    ctx.font = '11px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(nums.length === 1 ? `Single value: ${nums[0]}` : 'No data', w / 2, h / 2 + 4);
    return;
  }

  const min  = Math.min(...nums);
  const max  = Math.max(...nums);
  const range = max - min || 1;
  const pad  = 4;

  const getY = v => h - pad - ((v - min) / range) * (h - pad * 2);
  const getX = i => pad + (i / (nums.length - 1)) * (w - pad * 2);

  // Fill
  const gradient = ctx.createLinearGradient(0, 0, 0, h);
  gradient.addColorStop(0, 'rgba(107,47,160,0.18)');
  gradient.addColorStop(1, 'rgba(107,47,160,0)');
  ctx.beginPath();
  ctx.moveTo(getX(0), getY(nums[0]));
  nums.forEach((v, i) => { if (i > 0) ctx.lineTo(getX(i), getY(v)); });
  ctx.lineTo(getX(nums.length - 1), h);
  ctx.lineTo(getX(0), h);
  ctx.closePath();
  ctx.fillStyle = gradient;
  ctx.fill();

  // Line
  ctx.beginPath();
  ctx.moveTo(getX(0), getY(nums[0]));
  nums.forEach((v, i) => { if (i > 0) ctx.lineTo(getX(i), getY(v)); });
  ctx.strokeStyle = '#6b2fa0';
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  ctx.stroke();
}

// Render a single query card
function renderQueryCard(entry) {
  const { url, type, label, status, reqJSON, respJSON, rawReq, rawResp } = entry;

  const queries    = extractQueriesFromRequest(reqJSON, type);
  const firstQuery = queries[0] || {};
  const widgetId   = firstQuery.widgetId || reqJSON?.meta?.dd_extra_usage_params?.widget_id || null;
  const from       = firstQuery.from;
  const to         = firstQuery.to;

  const card = document.createElement('div');
  card.className = 'qi-card';

  // ── Header ──
  const header = document.createElement('div');
  header.className = 'qi-card-header';

  const epBadge = document.createElement('span');
  epBadge.className = `qi-endpoint-badge ${type}`;
  epBadge.textContent = label;
  header.appendChild(epBadge);

  if (firstQuery.dataSource) {
    const ds = document.createElement('span');
    ds.className = 'qi-data-source';
    ds.textContent = firstQuery.dataSource;
    header.appendChild(ds);
  }

  if (widgetId) {
    const wid = document.createElement('span');
    wid.className = 'qi-widget-id';
    wid.textContent = `widget ${widgetId}`;
    header.appendChild(wid);
  }

  if (from && to) {
    const tr = document.createElement('span');
    tr.className = 'qi-time-range';
    const fromD = new Date(from).toLocaleString();
    const toD   = new Date(to).toLocaleString();
    tr.textContent = `${fromD} → ${toD}`;
    header.appendChild(tr);
  }

  card.appendChild(header);

  // ── Queries ──
  queries.forEach(q => {
    if (!q.query) return;
    const block = document.createElement('div');
    block.className = 'qi-query-block';
    const label = document.createElement('div');
    label.className = 'qi-query-label';
    label.textContent = `Query · ${q.name}`;
    const str = document.createElement('div');
    str.className = 'qi-query-str';
    const span = document.createElement('span');
    span.textContent = q.query;
    str.appendChild(span);
    const copyBtn = makeCopyBtn(q.query);
    str.appendChild(copyBtn);
    block.appendChild(label);
    block.appendChild(str);
    card.appendChild(block);
  });

  // ── Response data ──
  if (type === 'timeseries') {
    const seriesData = extractTimeseriesData(respJSON);

    if (!seriesData || seriesData.length === 0) {
      const noData = document.createElement('div');
      noData.className = 'qi-no-data';
      noData.innerHTML = '<i class="bi bi-exclamation-circle"></i> No data returned for this time range.';
      card.appendChild(noData);
    } else {
      const block = document.createElement('div');
      block.className = 'qi-timeseries-block';
      const blockLabel = document.createElement('div');
      blockLabel.className = 'qi-query-label';
      blockLabel.textContent = `${seriesData.length} series · ${seriesData[0]?.times?.length || 0} data points`;
      block.appendChild(blockLabel);

      seriesData.forEach(s => {
        const item = document.createElement('div');
        item.className = 'qi-series-item';

        // Tags / label row
        const meta = document.createElement('div');
        meta.className = 'qi-series-meta';
        const tagsEl = document.createElement('span');
        tagsEl.className = s.tags.length ? 'qi-series-tags' : 'qi-series-tags no-tags';
        tagsEl.textContent = s.tags.length ? s.tags.join(', ') : 'No group tags (aggregate)';
        meta.appendChild(tagsEl);
        if (s.interval) {
          const intEl = document.createElement('span');
          intEl.className = 'qi-series-interval';
          intEl.textContent = `interval: ${formatInterval(s.interval)}`;
          meta.appendChild(intEl);
        }
        item.appendChild(meta);

        // Sparkline
        const canvas = document.createElement('canvas');
        canvas.className = 'qi-sparkline';
        item.appendChild(canvas);
        requestAnimationFrame(() => drawSparkline(canvas, s.values));

        // Value summary
        const nonNull = s.values.filter(v => v != null && !isNaN(v));
        if (nonNull.length > 0) {
          const sum  = nonNull.reduce((a, b) => a + b, 0);
          const avg  = sum / nonNull.length;
          const min  = Math.min(...nonNull);
          const max  = Math.max(...nonNull);
          const last = nonNull[nonNull.length - 1];
          const valSummary = document.createElement('div');
          valSummary.className = 'qi-value-summary';
          valSummary.innerHTML = `
            <span>Min: <strong>${min.toLocaleString(undefined, {maximumFractionDigits: 2})}</strong></span>
            <span>Max: <strong>${max.toLocaleString(undefined, {maximumFractionDigits: 2})}</strong></span>
            <span>Avg: <strong>${avg.toLocaleString(undefined, {maximumFractionDigits: 2})}</strong></span>
            <span>Last: <strong>${last.toLocaleString(undefined, {maximumFractionDigits: 2})}</strong></span>
            ${s.unit ? `<span>Unit: <strong>${escHtml(String(s.unit))}</strong></span>` : ''}
          `;
          item.appendChild(valSummary);
        }

        block.appendChild(item);
      });
      card.appendChild(block);
    }

  } else if (type === 'scalar') {
    const cols = extractScalarData(respJSON);

    if (!cols || cols.length === 0) {
      const noData = document.createElement('div');
      noData.className = 'qi-no-data';
      noData.innerHTML = '<i class="bi bi-exclamation-circle"></i> No scalar data returned.';
      card.appendChild(noData);
    } else {
      const block = document.createElement('div');
      block.className = 'qi-scalar-block';

      const groupCols  = cols.filter(c => c.type === 'group');
      const numCols    = cols.filter(c => c.type === 'number');

      // Determine row count
      const rowCount = numCols.length > 0
        ? (numCols[0].values || []).length
        : (groupCols.length > 0 ? (groupCols[0].values || []).length : 0);

      if (rowCount === 0) {
        block.innerHTML = '<div class="qi-no-data"><i class="bi bi-exclamation-circle"></i> No rows returned.</div>';
      } else {
        // Find max value per numeric col for bar
        const maxVals = numCols.map(nc => Math.max(...(nc.values || []).map(v => Array.isArray(v) ? v[0] : v).filter(v => v != null && !isNaN(v))));

        const table = document.createElement('table');
        table.className = 'qi-scalar-table';

        // Header
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        groupCols.forEach(c => {
          const th = document.createElement('th');
          th.textContent = c.name;
          headerRow.appendChild(th);
        });
        numCols.forEach(c => {
          const th = document.createElement('th');
          th.className = 'numeric';
          th.textContent = c.name;
          headerRow.appendChild(th);
          // bar column
          const thBar = document.createElement('th');
          headerRow.appendChild(thBar);
        });
        thead.appendChild(headerRow);
        table.appendChild(thead);

        // Body
        const tbody = document.createElement('tbody');
        for (let i = 0; i < rowCount; i++) {
          const tr = document.createElement('tr');
          groupCols.forEach(c => {
            const td = document.createElement('td');
            td.className = 'group-val';
            const raw = (c.values || [])[i];
            td.textContent = Array.isArray(raw) ? raw.join(', ') : (raw ?? '–');
            tr.appendChild(td);
          });
          numCols.forEach((c, ci) => {
            const rawVal = (c.values || [])[i];
            const val    = Array.isArray(rawVal) ? rawVal[0] : rawVal;
            const td = document.createElement('td');
            td.className = 'numeric-val';
            td.textContent = val != null ? val.toLocaleString(undefined, { maximumFractionDigits: 2 }) : '–';
            tr.appendChild(td);
            // Bar cell
            const tdBar = document.createElement('td');
            tdBar.className = 'qi-bar-cell';
            const pct = maxVals[ci] > 0 && val != null ? Math.max(0, Math.min(100, (val / maxVals[ci]) * 100)) : 0;
            tdBar.innerHTML = `<div class="qi-bar-wrap"><div class="qi-bar-fill" style="width:${pct}%"></div></div>`;
            tr.appendChild(tdBar);
          });
          tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        block.appendChild(table);
      }
      card.appendChild(block);
    }
  }

  // ── Raw JSON toggle ──
  const rawBlock = document.createElement('div');
  rawBlock.className = 'qi-raw-block';

  const rawToggle = document.createElement('button');
  rawToggle.className = 'qi-raw-toggle';
  rawToggle.innerHTML = '<i class="bi bi-code-slash"></i> View raw JSON <i class="bi bi-chevron-down qi-raw-chevron"></i>';

  const rawPre = document.createElement('pre');
  rawPre.className = 'qi-raw-pre';

  let rawLoaded = false;
  rawToggle.addEventListener('click', () => {
    const open = rawPre.classList.toggle('open');
    rawToggle.querySelector('.qi-raw-chevron').classList.toggle('open', open);
    if (open && !rawLoaded) {
      rawLoaded = true;
      let combined = '';
      if (rawReq)  combined += '// ── REQUEST ──\n'  + (tryParseJSON(rawReq)  ? JSON.stringify(tryParseJSON(rawReq),  null, 2) : rawReq)  + '\n\n';
      if (rawResp) combined += '// ── RESPONSE ──\n' + (tryParseJSON(rawResp) ? JSON.stringify(tryParseJSON(rawResp), null, 2) : rawResp);
      rawPre.textContent = combined || '(empty)';
    }
  });

  rawBlock.appendChild(rawToggle);
  rawBlock.appendChild(rawPre);
  card.appendChild(rawBlock);

  return card;
}

// Process a HAR file for the Query Inspector tab
function processQueryFile(file) {
  const container = document.getElementById('query-results');
  if (!file.name.toLowerCase().endsWith('.har')) {
    const n = document.createElement('div');
    n.className = 'parse-error';
    n.innerHTML = `<i class="bi bi-file-x"></i> <strong>${escHtml(file.name)}</strong> is not a .har file and was skipped.`;
    container.prepend(n);
    return;
  }

  const reader = new FileReader();
  reader.onload = e => {
    let data;
    try { data = JSON.parse(e.target.result); }
    catch {
      const n = document.createElement('div');
      n.className = 'parse-error';
      n.innerHTML = `<i class="bi bi-exclamation-triangle"></i> <strong>${escHtml(file.name)}</strong> could not be parsed — is it valid JSON/HAR?`;
      container.prepend(n);
      return;
    }

    const entries = parseQueryEntries(data);

    // File group wrapper
    const group = document.createElement('div');

    const heading = document.createElement('div');
    heading.className = 'qi-file-heading';
    heading.innerHTML = `<i class="bi bi-file-earmark-text"></i> ${escHtml(file.name)} <span style="font-weight:400;text-transform:none;letter-spacing:0;font-size:0.78rem;color:var(--muted)">(${entries.length} query request${entries.length !== 1 ? 's' : ''} found)</span>`;
    group.appendChild(heading);

    if (entries.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'qi-empty';
      empty.innerHTML = '<i class="bi bi-search"></i> No timeseries or scalar query requests found in this HAR.<br>Make sure the HAR was captured from <code>app.datadoghq.com</code> with a dashboard open.';
      group.appendChild(empty);
    } else {
      entries.forEach(entry => {
        group.appendChild(renderQueryCard(entry));
      });
    }

    container.prepend(group);
  };
  reader.readAsText(file);
}

// ── RUM Render helpers ─────────────────────────────────────────────────────

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

// ── Render: Full RUM File Card ─────────────────────────────────────────────

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
    <div class="stat-cell"><div class="stat-label">Total requests</div><div class="stat-value">${totalEntries.toLocaleString()}</div></div>
    <div class="stat-cell"><div class="stat-label">Intake ok</div><div class="stat-value ${intakeSuccess.length > 0 ? 'v-success' : ''}">${intakeSuccess.length}</div></div>
    <div class="stat-cell"><div class="stat-label">Intake errors</div><div class="stat-value ${intakeErrors.length > 0 ? 'v-danger' : ''}">${intakeErrors.length}</div></div>
    <div class="stat-cell"><div class="stat-label">Session replay</div><div class="stat-value ${replayRequests.length > 0 ? 'v-purple' : ''}">${replayRequests.length}</div></div>
    <div class="stat-cell"><div class="stat-label">SDK version</div><div class="stat-value v-primary" style="font-size:1.1rem">${rumSdk ? escHtml(rumSdk.version || '?') : '–'}</div></div>
    <div class="stat-cell"><div class="stat-label">Warnings</div><div class="stat-value ${warnings.length > 0 ? 'v-warn' : ''}">${warnings.length}</div></div>
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
  sdkBlock.innerHTML = `<div class="block-heading"><i class="bi bi-cpu"></i> SDK health</div><p class="section-caveat"><i class="bi bi-info-circle"></i> SDK script requests are only present if the browser loaded them during the capture window. <strong>Best effort only.</strong></p>`;
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
      ['clientToken',             initConfig.clientToken              || '–'],
      ['applicationId',           initConfig.applicationId            || '–'],
      ['site',                    initConfig.site                     || '–'],
      ['service',                 initConfig.service                  || '–'],
      ['env',                     initConfig.env                      || '–'],
      ['version',                 initConfig.version                  || '–'],
      ['sessionSampleRate',       initConfig.sessionSampleRate        != null ? initConfig.sessionSampleRate + '%' : '–'],
      ['sessionReplaySampleRate', initConfig.sessionReplaySampleRate  != null ? initConfig.sessionReplaySampleRate + '%' : '–'],
      ['defaultPrivacyLevel',     initConfig.defaultPrivacyLevel      || '–'],
      ['trackingConsent',         initConfig.trackingConsent          || '–'],
      ['trackUserInteractions',   initConfig.trackUserInteractions    != null ? String(initConfig.trackUserInteractions) : '–'],
      ['trackResources',          initConfig.trackResources           != null ? String(initConfig.trackResources) : '–'],
      ['trackLongTasks',          initConfig.trackLongTasks           != null ? String(initConfig.trackLongTasks) : '–'],
      ['sessionPersistence',      initConfig.sessionPersistence       || '–'],
    ];
    cfgFields.forEach(([k, v]) => {
      const flagWarn = (k === 'sessionSampleRate' && parseInt(v) < 100) ||
                       (k === 'sessionReplaySampleRate' && parseInt(v) === 0) ||
                       (k === 'trackingConsent' && v === 'not-granted') ||
                       (k === 'trackUserInteractions' && v === 'false') ||
                       (k === 'trackResources' && v === 'false');
      cfgGrid.innerHTML += `<div class="cfg-row"><span class="cfg-key">${escHtml(k)}</span><span class="cfg-val ${flagWarn ? 'cfg-flagged' : ''}">${escHtml(String(v))}</span></div>`;
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
    { label: 'Session ID',     val: sessionId, src: sessionIdSource },
    { label: 'Application ID', val: appId,     src: appIdSource },
  ].forEach(({ label, val, src }) => {
    const box   = document.createElement('div');
    box.className = 'rum-box';
    const keyEl = document.createElement('div');
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
    apmBlock.innerHTML += `<p class="empty-note">No APM propagation headers found on outgoing requests.</p>`;
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
  }
  card.appendChild(apmBlock);

  // ── DD Cookies ──
  const cookiesBlock = document.createElement('div');
  cookiesBlock.className = 'section-block';
  cookiesBlock.innerHTML = `<div class="block-heading"><i class="bi bi-shield-lock"></i> Datadog cookies</div><p class="section-caveat"><i class="bi bi-info-circle"></i> HAR files may not include cookie headers depending on browser and capture settings. <strong>Best effort only.</strong></p>`;
  if (ddCookies.length === 0) {
    cookiesBlock.innerHTML += `<p class="empty-note">No Datadog cookies found. Check DevTools › Application › Cookies directly if needed.</p>`;
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
      if (err.reqHeaders.length) sections.push(`<div class="detail-section"><div class="detail-label">Request headers</div>${err.reqHeaders.map(h => `<div class="header-row"><span class="hname">${escHtml(h.name)}</span><span class="hval">${escHtml(h.value)}</span></div>`).join('')}</div>`);
      if (err.resHeaders.length) sections.push(`<div class="detail-section"><div class="detail-label">Response headers</div>${err.resHeaders.map(h => `<div class="header-row"><span class="hname">${escHtml(h.name)}</span><span class="hval">${escHtml(h.value)}</span></div>`).join('')}</div>`);
      if (err.bodyText)          sections.push(`<div class="detail-section"><div class="detail-label">Response body</div><pre class="response-body-pre">${escHtml(err.bodyText.slice(0, 800))}${err.bodyText.length > 800 ? '\n…(truncated)' : ''}</pre></div>`);
      if (err.totalTime)         sections.push(`<div class="detail-section"><div class="detail-label">Timing</div><div class="header-row"><span class="hname">Total time</span><span class="hval">${formatMs(err.totalTime)}</span></div></div>`);
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
      item.innerHTML = `
        <span class="replay-status ${isError(r.status) ? 'err' : 'ok'}">${escHtml(String(r.status === 0 ? 'BLOCKED' : r.status))}</span>
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
    { key: 'HAR creator',           val: `${creator.name || '–'} ${creator.version || ''}`.trim() },
    { key: 'Total intake requests',  val: String(intakeErrors.length + intakeSuccess.length) },
    { key: 'SDK init calls',         val: String(sdkInitCount) + (sdkInitCount > 1 ? ' ⚠ duplicate init detected' : '') },
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
    `Total requests:        ${a.totalEntries}`,
    `Intake ok:             ${a.intakeSuccess.length}`,
    `Intake errors:         ${a.intakeErrors.length}`,
    `Session replay:        ${a.replayRequests.length}`,
    `DD cookies:            ${a.ddCookies.length}`,
    ``,
    `--- RUM Identifiers ---`,
    `Session ID:    ${a.sessionId || 'not found'}`,
    `Application ID:${a.appId     || 'not found'}`,
    ``,
    `--- Diagnostics ---`,
    ...(warns.length === 0 ? ['No warnings.'] : warns.map(w => `[${w.sev.toUpperCase()}] [${w.cat}] ${w.msg}`)),
  ].join('\n');
}

function exportJSON(analysis) {
  const data = {
    filename: analysis.filename, totalEntries: analysis.totalEntries,
    rum: { sessionId: analysis.sessionId, appId: analysis.appId },
    sdk: { loads: analysis.sdkLoads, initConfig: analysis.initConfig },
    warnings: analysis.warnings,
    ddCookies: analysis.ddCookies.map(c => ({ name: c.name, value: c.value, url: c.url })),
    intakeErrors: analysis.intakeErrors.map(e => ({ status: e.status, method: e.method, url: e.url })),
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
        warnings: analysis.warnings.length,
      });
    }
    results.prepend(renderFileCard(analysis));
  };
  reader.readAsText(file);
}

function handleFiles(files)        { Array.from(files).forEach(processFile); }
function handleQueryFiles(files)   { Array.from(files).forEach(processQueryFile); }

// ── Init ───────────────────────────────────────────────────────────────────

(function init() {
  // ── Tab switching ──
  const tabs    = document.querySelectorAll('.har-tab');
  const tabPanes = {
    rum:     document.getElementById('tab-rum'),
    queries: document.getElementById('tab-queries'),
  };

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');
      Object.entries(tabPanes).forEach(([key, pane]) => {
        pane.style.display = key === tab.dataset.tab ? '' : 'none';
      });
    });
  });

  // ── RUM Analyzer drop zone ──
  const dropZone  = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  fileInput.addEventListener('change', e => { handleFiles(e.target.files); e.target.value = ''; });
  dropZone.addEventListener('dragover',  e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', e => { if (!dropZone.contains(e.relatedTarget)) dropZone.classList.remove('drag-over'); });
  dropZone.addEventListener('drop', e => { e.preventDefault(); dropZone.classList.remove('drag-over'); handleFiles(e.dataTransfer.files); });

  // ── Query Inspector drop zone ──
  const dropZoneQ  = document.getElementById('drop-zone-queries');
  const fileInputQ = document.getElementById('file-input-queries');
  fileInputQ.addEventListener('change', e => { handleQueryFiles(e.target.files); e.target.value = ''; });
  dropZoneQ.addEventListener('dragover',  e => { e.preventDefault(); dropZoneQ.classList.add('drag-over'); });
  dropZoneQ.addEventListener('dragleave', e => { if (!dropZoneQ.contains(e.relatedTarget)) dropZoneQ.classList.remove('drag-over'); });
  dropZoneQ.addEventListener('drop', e => { e.preventDefault(); dropZoneQ.classList.remove('drag-over'); handleQueryFiles(e.dataTransfer.files); });
})();

