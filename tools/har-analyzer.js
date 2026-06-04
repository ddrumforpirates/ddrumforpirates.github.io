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

const DD_COOKIE_NAMES = ['_dd_s', '_dd_s_v2', 'dd_site_auth', '_datadog_session', '_dd_r'];

// ── Utilities ──────────────────────────────────────────────────────────────

function isIntakeUrl(url) {
  return DD_INTAKE_PATTERNS.some(p => p.test(url));
}

function isReplayUrl(url) {
  return SESSION_REPLAY_PATTERNS.some(p => p.test(url));
}

function isError(status) {
  return status === 0 || status >= 400;
}

function formatBytes(bytes) {
  if (!bytes || bytes < 0) return '–';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function parseCookieHeader(str) {
  const result = {};
  str.split(';').forEach(part => {
    const eq = part.indexOf('=');
    if (eq > -1) {
      result[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
    }
  });
  return result;
}

function parseDdSValue(raw) {
  const parts = {};
  raw.split('&').forEach(seg => {
    const eq = seg.indexOf('=');
    if (eq > -1) parts[seg.slice(0, eq)] = seg.slice(eq + 1);
  });
  return parts;
}

function parseDdSV2Value(raw) {
  try {
    return parseDdSValue(atob(raw));
  } catch {
    return {};
  }
}

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    btn.classList.add('copied');
    btn.title = 'Copied!';
    setTimeout(() => { btn.classList.remove('copied'); btn.title = 'Copy'; }, 1800);
  }).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    Object.assign(ta.style, { position: 'fixed', opacity: '0' });
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    btn.classList.add('copied');
    setTimeout(() => btn.classList.remove('copied'), 1800);
  });
}

// ── Core Analysis ──────────────────────────────────────────────────────────

function analyzeHAR(harData, filename) {
  const entries      = harData?.log?.entries || [];
  const creator      = harData?.log?.creator || {};

  const ddCookies      = [];
  const intakeErrors   = [];
  const intakeSuccess  = [];
  const replayRequests = [];
  const seenCookieKeys = new Set();
  const endpointHits   = {};

  let sessionId = null, sessionIdSource = null;
  let appId     = null, appIdSource     = null;

  entries.forEach(entry => {
    const url    = entry.request?.url    || '';
    const method = entry.request?.method || 'GET';
    const status = entry.response?.status || 0;

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

        let segments = {};
        let decoded  = null;
        if (ck === '_dd_s') {
          segments = parseDdSValue(parsed[ck]);
          decoded  = JSON.stringify(segments, null, 2);
        } else if (ck === '_dd_s_v2') {
          segments = parseDdSV2Value(parsed[ck]);
          decoded  = JSON.stringify(segments, null, 2);
        }

        // Pull IDs from cookie segments
        if (!sessionId && segments.id)  { sessionId = segments.id;  sessionIdSource = `${ck} cookie`; }
        if (!sessionId && segments.rum) { sessionId = segments.rum; sessionIdSource = `${ck} cookie (rum segment)`; }

        ddCookies.push({ name: ck, value: parsed[ck], decoded, segments, header: h.name, url });
      });
    });

    // ── Only continue for intake URLs ──
    if (!isIntakeUrl(url)) return;

    try {
      const hostname = new URL(url).hostname;
      endpointHits[hostname] = (endpointHits[hostname] || 0) + 1;
    } catch {}

    // RUM IDs from URL params
    try {
      const u = new URL(url);
      if (!sessionId) {
        const v = u.searchParams.get('dd_session_id') || u.searchParams.get('session_id');
        if (v) { sessionId = v; sessionIdSource = 'URL param'; }
      }
      if (!appId) {
        const v = u.searchParams.get('dd_app_id') || u.searchParams.get('app_id') || u.searchParams.get('application_id');
        if (v) { appId = v; appIdSource = 'URL param'; }
      }
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
          try {
            const parsed = JSON.parse(body);
            if (!appId     && parsed.application_id) { appId     = parsed.application_id; appIdSource     = 'request body'; }
            if (!sessionId && parsed.session_id)      { sessionId = parsed.session_id;     sessionIdSource = 'request body'; }
          } catch {}
        }
        const aidM = body.match(/"application[_-]id"\s*:\s*"([^"]+)"/);
        if (!appId && aidM) { appId = aidM[1]; appIdSource = 'request body'; }
        const sidM = body.match(/"session[_-]id"\s*:\s*"([^"]+)"/);
        if (!sessionId && sidM) { sessionId = sidM[1]; sessionIdSource = 'request body'; }
      }
    } catch {}

    // Collect relevant headers for display
    const WANT_REQ = new Set(['content-type','x-datadog-parent-id','x-datadog-trace-id','x-datadog-sampling-priority','x-datadog-application-id','x-datadog-session-id','dd-api-key','authorization','origin','referer']);
    const WANT_RES = new Set(['content-type','x-ratelimit-limit','x-ratelimit-remaining','x-ratelimit-reset','x-ratelimit-period','x-datadog-trace-id','retry-after','server']);

    const reqHeaders = (entry.request?.headers  || []).filter(h => WANT_REQ.has(h.name.toLowerCase()));
    const resHeaders = (entry.response?.headers || []).filter(h => WANT_RES.has(h.name.toLowerCase()));
    const bodyText   = entry.response?.content?.text || '';
    const bodySize   = entry.response?.bodySize || entry.response?.content?.size || 0;
    const timings    = entry.timings || {};
    const totalTime  = entry.time || 0;

    const entryData = { url, method, status, reqHeaders, resHeaders, bodyText, bodySize, totalTime, timings };

    if (isReplayUrl(url)) replayRequests.push(entryData);
    if (isError(status))  intakeErrors.push(entryData);
    else                  intakeSuccess.push(entryData);
  });

  return {
    filename, creator,
    totalEntries: entries.length,
    ddCookies, intakeErrors, intakeSuccess, replayRequests,
    sessionId, sessionIdSource, appId, appIdSource,
    endpointHits,
  };
}

// ── Render helpers ─────────────────────────────────────────────────────────

function makeCopyBtn(text) {
  const btn = document.createElement('button');
  btn.className = 'copy-btn';
  btn.title = 'Copy';
  btn.setAttribute('aria-label', 'Copy to clipboard');
  btn.innerHTML = '<i class="bi bi-clipboard"></i>';
  btn.addEventListener('click', e => { e.stopPropagation(); copyToClipboard(text, btn); btn.innerHTML = '<i class="bi bi-check-lg"></i>'; setTimeout(() => { btn.innerHTML = '<i class="bi bi-clipboard"></i>'; }, 1800); });
  return btn;
}

// ── Render: Full File Card ─────────────────────────────────────────────────

function renderFileCard(analysis) {
  const { filename, creator, totalEntries, ddCookies, intakeErrors, intakeSuccess, replayRequests, sessionId, sessionIdSource, appId, appIdSource, endpointHits } = analysis;

  const card = document.createElement('div');
  card.className = 'file-card';

  // ── Header ──
  const header = document.createElement('div');
  header.className = 'file-card-header';
  header.innerHTML = `
    <span class="file-card-icon"><i class="bi bi-file-earmark-text"></i></span>
    <span class="file-card-name">${escHtml(filename)}</span>
    <div class="badges">
      ${intakeErrors.length    ? `<span class="badge-pill badge-danger">${intakeErrors.length} intake error${intakeErrors.length > 1 ? 's' : ''}</span>` : ''}
      ${ddCookies.length       ? `<span class="badge-pill badge-info">${ddCookies.length} DD cookie${ddCookies.length > 1 ? 's' : ''}</span>` : ''}
      ${sessionId              ? `<span class="badge-pill badge-success">RUM session</span>` : ''}
      ${replayRequests.length  ? `<span class="badge-pill badge-purple">${replayRequests.length} replay req${replayRequests.length > 1 ? 's' : ''}</span>` : ''}
    </div>
  `;
  card.appendChild(header);

  // ── Summary strip ──
  const strip = document.createElement('div');
  strip.className = 'summary-strip';
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
      <div class="stat-label">DD cookies</div>
      <div class="stat-value v-primary">${ddCookies.length}</div>
    </div>
  `;
  card.appendChild(strip);

  // ── RUM Identifiers ──
  const rumBlock = document.createElement('div');
  rumBlock.className = 'section-block';
  rumBlock.innerHTML = `<div class="block-heading"><i class="bi bi-eye"></i> RUM identifiers</div>`;
  const rumGrid = document.createElement('div');
  rumGrid.className = 'rum-grid';
  [
    { label: 'Session ID', val: sessionId, src: sessionIdSource },
    { label: 'Application ID', val: appId, src: appIdSource },
  ].forEach(({ label, val, src }) => {
    const box = document.createElement('div');
    box.className = 'rum-box';
    const keyEl = document.createElement('div');
    keyEl.className = 'rum-key';
    keyEl.textContent = label + (src ? ` · via ${src}` : '');
    box.appendChild(keyEl);
    const valDiv = document.createElement('div');
    valDiv.className = val ? 'rum-val' : 'rum-val empty';
    if (val) {
      const span = document.createElement('span');
      span.textContent = val;
      valDiv.appendChild(span);
      valDiv.appendChild(makeCopyBtn(val));
    } else {
      valDiv.textContent = 'not found';
    }
    box.appendChild(valDiv);
    rumGrid.appendChild(box);
  });
  rumBlock.appendChild(rumGrid);
  card.appendChild(rumBlock);

  // ── DD Cookies ──
  const cookiesBlock = document.createElement('div');
  cookiesBlock.className = 'section-block';
  cookiesBlock.innerHTML = `<div class="block-heading"><i class="bi bi-shield-lock"></i> Datadog cookies</div>`;
  if (ddCookies.length === 0) {
    cookiesBlock.innerHTML += `<p class="empty-note">No Datadog cookies detected.</p>`;
  } else {
    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    const table = document.createElement('table');
    table.className = 'data-table';
    table.innerHTML = `<thead><tr><th>Cookie name</th><th>Raw value</th><th>Decoded segments</th><th>Associated URL</th><th></th></tr></thead>`;
    const tbody = document.createElement('tbody');
    ddCookies.forEach(c => {
      const decodedStr = c.decoded
        ? Object.entries(JSON.parse(c.decoded)).map(([k, v]) => `${k}=${v}`).join(' · ')
        : '–';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="name-cell">${escHtml(c.name)}</td>
        <td class="mono" title="${escHtml(c.value)}">${escHtml(c.value)}</td>
        <td class="mono" title="${escHtml(decodedStr)}">${escHtml(decodedStr)}</td>
        <td class="mono" title="${escHtml(c.url)}">${escHtml(c.url)}</td>
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
      const item = document.createElement('div');
      item.className = 'error-item';
      const statusLabel = err.status === 0 ? 'ERR' : err.status;
      const toggle = document.createElement('button');
      toggle.className = 'error-toggle';
      toggle.setAttribute('aria-expanded', 'false');
      toggle.innerHTML = `
        <span class="err-status">${escHtml(String(statusLabel))}</span>
        <span class="err-method">${escHtml(err.method)}</span>
        <span class="err-url" title="${escHtml(err.url)}">${escHtml(err.url)}</span>
        <i class="bi bi-chevron-down err-chevron"></i>
      `;
      const detail = document.createElement('div');
      detail.className = 'error-detail';
      const sections = [];
      if (err.reqHeaders.length) {
        sections.push(`<div class="detail-section"><div class="detail-label">Request headers</div>${err.reqHeaders.map(h => `<div class="header-row"><span class="hname">${escHtml(h.name)}</span><span class="hval">${escHtml(h.value)}</span></div>`).join('')}</div>`);
      }
      if (err.resHeaders.length) {
        sections.push(`<div class="detail-section"><div class="detail-label">Response headers</div>${err.resHeaders.map(h => `<div class="header-row"><span class="hname">${escHtml(h.name)}</span><span class="hval">${escHtml(h.value)}</span></div>`).join('')}</div>`);
      }
      if (err.bodyText) {
        sections.push(`<div class="detail-section"><div class="detail-label">Response body</div><pre class="response-body-pre">${escHtml(err.bodyText.slice(0, 800))}${err.bodyText.length > 800 ? '\n…(truncated)' : ''}</pre></div>`);
      }
      if (err.totalTime) {
        sections.push(`<div class="detail-section"><div class="detail-label">Timing</div><div class="header-row"><span class="hname">Total time</span><span class="hval">${Math.round(err.totalTime)} ms</span></div>${err.timings.wait != null ? `<div class="header-row"><span class="hname">Wait (TTFB)</span><span class="hval">${Math.round(err.timings.wait)} ms</span></div>` : ''}</div>`);
      }
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
      const statusLabel = r.status === 0 ? 'FAIL' : r.status;
      item.innerHTML = `
        <span class="replay-status ${isError(r.status) ? 'err' : 'ok'}">${escHtml(String(statusLabel))}</span>
        <span class="replay-url" title="${escHtml(r.url)}">${escHtml(r.url)}</span>
        <span class="replay-size">${formatBytes(r.bodySize)}</span>
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
    { key: 'HAR creator', val: `${creator.name || '–'} ${creator.version || ''}`.trim() },
    { key: 'Total intake requests', val: String(intakeErrors.length + intakeSuccess.length) },
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
  return [
    `=== Datadog HAR Analysis: ${a.filename} ===`,
    ``,
    `Total requests:      ${a.totalEntries}`,
    `Intake ok:           ${a.intakeSuccess.length}`,
    `Intake errors:       ${a.intakeErrors.length}`,
    `Session replay:      ${a.replayRequests.length}`,
    `DD cookies:          ${a.ddCookies.length}`,
    ``,
    `--- RUM Identifiers ---`,
    `Session ID:          ${a.sessionId || 'not found'}${a.sessionIdSource ? ` (via ${a.sessionIdSource})` : ''}`,
    `Application ID:      ${a.appId     || 'not found'}${a.appIdSource ? ` (via ${a.appIdSource})` : ''}`,
    ``,
    `--- DD Cookies ---`,
    ...(a.ddCookies.length === 0 ? ['None found.'] : a.ddCookies.map(c => `${c.name}: ${c.value}\n  URL: ${c.url}`)),
    ``,
    `--- Intake Errors ---`,
    ...(a.intakeErrors.length === 0 ? ['None.'] : a.intakeErrors.map(e => `${e.status || 'ERR'} ${e.method} ${e.url}`)),
    ``,
    `--- Endpoints Hit ---`,
    ...Object.entries(a.endpointHits).map(([h, c]) => `${h}: ${c} request${c > 1 ? 's' : ''}`),
  ].join('\n');
}

function exportJSON(analysis) {
  const data = {
    filename:     analysis.filename,
    creator:      analysis.creator,
    totalEntries: analysis.totalEntries,
    rum: {
      sessionId:       analysis.sessionId,
      sessionIdSource: analysis.sessionIdSource,
      appId:           analysis.appId,
      appIdSource:     analysis.appIdSource,
    },
    ddCookies: analysis.ddCookies.map(c => ({
      name: c.name, value: c.value, decodedSegments: c.segments, url: c.url,
    })),
    intakeErrors: analysis.intakeErrors.map(e => ({
      status: e.status, method: e.method, url: e.url,
      requestHeaders: e.reqHeaders, responseHeaders: e.resHeaders,
      responseBodyPreview: e.bodyText ? e.bodyText.slice(0, 500) : null,
    })),
    intakeSuccessCount: analysis.intakeSuccess.length,
    sessionReplayRequests: analysis.replayRequests.map(r => ({
      status: r.status, method: r.method, url: r.url, bodySize: r.bodySize,
    })),
    endpointHits: analysis.endpointHits,
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = analysis.filename.replace(/\.har$/i, '') + '-dd-analysis.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── File handling ──────────────────────────────────────────────────────────

function processFile(file) {
  const results = document.getElementById('results');

  if (!file.name.toLowerCase().endsWith('.har')) {
    const notice = document.createElement('div');
    notice.className = 'parse-error';
    notice.innerHTML = `<i class="bi bi-file-x"></i> <strong>${escHtml(file.name)}</strong> is not a .har file and was skipped.`;
    results.prepend(notice);
    return;
  }

  const reader = new FileReader();
  reader.onload = e => {
    let data;
    try {
      data = JSON.parse(e.target.result);
    } catch {
      const notice = document.createElement('div');
      notice.className = 'parse-error';
      notice.innerHTML = `<i class="bi bi-exclamation-triangle"></i> <strong>${escHtml(file.name)}</strong> could not be parsed — is it valid JSON/HAR?`;
      results.prepend(notice);
      return;
    }
    const analysis = analyzeHAR(data, file.name);

    // Track in DD RUM
    if (window.DD_RUM) {
      window.DD_RUM.addAction('har_analyzed', {
        filename:       analysis.filename,
        totalEntries:   analysis.totalEntries,
        intakeErrors:   analysis.intakeErrors.length,
        ddCookies:      analysis.ddCookies.length,
        hasRumSession:  !!analysis.sessionId,
        replayRequests: analysis.replayRequests.length,
      });
    }

    results.prepend(renderFileCard(analysis));
  };
  reader.readAsText(file);
}

function handleFiles(files) {
  Array.from(files).forEach(processFile);
}

// ── Init ───────────────────────────────────────────────────────────────────

(function init() {
  const dropZone  = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');

  fileInput.addEventListener('change', e => { handleFiles(e.target.files); e.target.value = ''; });

  dropZone.addEventListener('dragover',  e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', e => { if (!dropZone.contains(e.relatedTarget)) dropZone.classList.remove('drag-over'); });
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    handleFiles(e.dataTransfer.files);
  });
})();
