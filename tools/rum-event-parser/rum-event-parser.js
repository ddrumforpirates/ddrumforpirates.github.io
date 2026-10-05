/* =============================================
   Datadog RUM Event Parser – rum-event-parser.js
   Pure client-side. Pasted / uploaded JSON never leaves the browser.

   How it stays flexible (nothing is tied to one event type):
     1. Input is normalised: RUM Explorer "copy as JSON", Events API v2
        responses, raw SDK intake events, arrays and NDJSON all work.
     2. The event's attributes are flattened into dotted paths
        (session.initial_view.url_host = "...").
     3. Each path is assigned to a section by rule: the requested sections
        match on the top-level key (browser, device, geo ...) or, for
        replay and retention, on the path name. Anything unclaimed becomes
        its own section automatically (view, action, error, resource,
        long_task, usr, ...) so new fields never get dropped.
   ============================================= */

(function () {
  'use strict';

  /* ── Config ─────────────────────────────────────────────────────────── */

  const MAX_INPUT_BYTES   = 25 * 1024 * 1024; // refuse anything bigger
  const MAX_TEXTAREA_SIZE = 1024 * 1024;      // above this, don't echo file into the textarea
  const MAX_ARRAY_ITEMS   = 100;              // arrays of objects: render first N, note the rest

  // Requested sections, in display order. `roots` claims by top-level key;
  // `match` claims by path name (only for roots in AUTO_CLAIM_ROOTS).
  const FIXED_SECTIONS = [
    { id: 'custom',    title: 'Custom attributes / context', icon: 'bi-sliders',
      roots: ['context'], always: true, emptyText: 'None found' },
    { id: 'application', title: 'Application',   icon: 'bi-app-indicator', roots: ['application', 'service'] },
    { id: 'browser',   title: 'Browser',         icon: 'bi-globe2',        roots: ['browser'] },
    { id: 'device',    title: 'Device',          icon: 'bi-laptop',        roots: ['device', 'os'] },
    { id: 'geo',       title: 'Geo',             icon: 'bi-geo-alt',       roots: ['geo'] },
    { id: 'session',   title: 'Session',         icon: 'bi-person-badge',  roots: ['session'] },
    { id: 'replay',    title: 'Session Replay',  icon: 'bi-camera-video',  match: /replay|full_snapshot/i },
    { id: 'retention', title: 'Retention filter', icon: 'bi-funnel',       match: /retention|retained|indexation/i },
  ];

  // Path-name matching is limited to these roots so a custom attribute like
  // `feature_flags.replay_beta` or `action.target.name` is never hijacked.
  const AUTO_CLAIM_ROOTS = new Set(['session', 'view', '_dd']);

  // Tags worth surfacing next to the application identity.
  const APP_TAG_KEYS = ['env', 'version', 'first_version', 'sdk_version', 'source'];

  // Friendly titles for common leftover roots; anything else is prettified.
  const ROOT_TITLES = {
    _dd: 'Datadog internals (_dd)', usr: 'User', account: 'Account', long_task: 'Long task',
    feature_flags: 'Feature flags', connectivity: 'Connectivity', ci_test: 'CI test',
  };
  const ROOT_ICONS = { usr: 'bi-person', account: 'bi-building', _dd: 'bi-cpu', connectivity: 'bi-wifi',
                       feature_flags: 'bi-toggles', view: 'bi-window', action: 'bi-cursor',
                       error: 'bi-exclamation-octagon', resource: 'bi-download', long_task: 'bi-hourglass-split' };

  // Heuristics for human-readable hints next to raw numbers.
  const DURATION_KEY = /(duration|time_spent|loading_time|first_byte|contentful_paint|input_delay|next_paint|dom_complete|dom_interactive|dom_content_loaded|load_event)$/i;
  const TIMING_PATH  = /custom_timings\.|(dns|connect|ssl|first_byte|download|redirect|worker)\.start$/i;
  const DATE_KEY     = /(^|_)(timestamp|date|time|at)$/i;
  const SIZE_KEY     = /(size|bytes)$/i;

  /* ── Small helpers ──────────────────────────────────────────────────── */

  const $ = (id) => document.getElementById(id);
  const isObj  = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  const isPrim = (v) => v === null || typeof v !== 'object';

  // DOM builder. Text is always set via textContent / text nodes, never innerHTML,
  // so pasted JSON can't inject markup.
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v == null || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : v);
      }
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  function icon(name) { return h('i', { class: 'bi ' + name, 'aria-hidden': 'true' }); }

  function fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(2) + ' MB';
  }

  function fmtNs(ns) {
    const abs = Math.abs(ns);
    if (abs < 1e3) return ns + ' ns';
    if (abs < 1e6) return (ns / 1e3).toFixed(1) + ' µs';
    if (abs < 1e9) { const ms = ns / 1e6; return ms.toFixed(ms < 10 ? 2 : 1) + ' ms'; }
    const s = ns / 1e9;
    if (s < 60) return s.toFixed(2) + ' s';
    const total = Math.round(s);
    const m = Math.floor(total / 60), rs = total % 60;
    if (m < 60) return m + 'm ' + rs + 's';
    return Math.floor(m / 60) + 'h ' + (m % 60) + 'm ' + rs + 's';
  }

  const DATE_FMT = { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric',
                     minute: '2-digit', second: '2-digit', timeZoneName: 'short' };

  function fmtDate(d) {
    return d.toLocaleString(undefined, DATE_FMT) + '  ·  ' + d.toISOString();
  }

  function copyText(text, btn) {
    const done = () => {
      if (!btn) return;
      const i = btn.querySelector('i');
      btn.classList.add('copied');
      if (i) i.className = 'bi bi-check2';
      setTimeout(() => { btn.classList.remove('copied'); if (i) i.className = 'bi bi-clipboard'; }, 1500);
    };
    const fallback = () => {
      const ta = Object.assign(document.createElement('textarea'), { value: text });
      Object.assign(ta.style, { position: 'fixed', opacity: '0' });
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); done(); } catch (_) { /* nothing more we can do */ }
      document.body.removeChild(ta);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(fallback);
    } else { fallback(); }
  }

  function copyBtn(getText, label) {
    return h('button', {
      type: 'button', class: 'rp-copy', 'aria-label': label || 'Copy value', title: label || 'Copy value',
      onclick: (e) => copyText(typeof getText === 'function' ? getText() : getText, e.currentTarget),
    }, icon('bi-clipboard'));
  }

  /* ── 1. Parse input ─────────────────────────────────────────────────── */

  // A JSON string that itself contains JSON (e.g. copied out of a log line).
  function unwrapString(v) {
    if (typeof v === 'string') {
      const s = v.trim();
      if (/^[\[{]/.test(s)) { try { return JSON.parse(s); } catch (_) { /* leave as string */ } }
    }
    return v;
  }

  function parseJsonLoose(text) {
    const t = text.replace(/^\uFEFF/, '').trim();
    if (!t) throw new Error('Nothing to parse yet — paste some JSON or drop a file.');
    try {
      return unwrapString(JSON.parse(t));
    } catch (firstErr) {
      // NDJSON: one JSON document per line (how the SDK batches events on the wire)
      const lines = t.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      if (lines.length > 1) {
        try { return lines.map((l) => unwrapString(JSON.parse(l))); } catch (_) { /* fall through */ }
      }
      throw firstErr;
    }
  }

  const LOOKS_LIKE_EVENT = (o) => isObj(o) &&
    ['content', 'attributes', 'application', 'session', 'view', 'type', 'date'].some((k) => k in o);

  function extractEvents(root) {
    if (Array.isArray(root)) return root;
    if (!isObj(root)) return [root];
    // Events API v2 / wrapped responses: { data: [...] } or { data: {...} }
    if (isObj(root.data) && LOOKS_LIKE_EVENT(root.data)) return [root.data];
    if (!LOOKS_LIKE_EVENT(root) || 'data' in root || 'events' in root) {
      for (const key of ['data', 'events', 'hits', 'items', 'results']) {
        const v = root[key];
        if (Array.isArray(v) && v.length && v.every(isObj)) return v;
      }
    }
    return [root];
  }

  /* ── 2. Normalise one event ─────────────────────────────────────────── */

  // Returns { id, timestamp, service, tags, attrs, extras, shape, type, raw }
  function normalize(raw) {
    const extras = {};
    const take = (obj, skip, wrapped) => {
      for (const [k, v] of Object.entries(obj)) {
        if (skip.includes(k)) continue;
        // a wrapper-level "type" (e.g. "rum" in the Events API) is not the event type
        extras[wrapped && k === 'type' ? 'wrapper_type' : k] = v;
      }
    };
    let id, timestamp, service, tags, attrs, shape;

    if (isObj(raw.content)) {                               // RUM Explorer → "Copy as JSON"
      const c = raw.content;
      id = raw.id; timestamp = c.timestamp; service = c.service; tags = c.tags;
      attrs = isObj(c.attributes) ? c.attributes : {};
      take(raw, ['id', 'content'], true); take(c, ['timestamp', 'service', 'tags', 'attributes'], false);
      shape = 'RUM Explorer export';
    } else if (isObj(raw.attributes) && isObj(raw.attributes.attributes)) {  // Events API v2
      const a = raw.attributes;
      id = raw.id; timestamp = a.timestamp; service = a.service; tags = a.tags; attrs = a.attributes;
      take(raw, ['id', 'attributes'], true); take(a, ['timestamp', 'service', 'tags', 'attributes'], false);
      shape = 'Events API v2';
    } else if (isObj(raw.attributes) && ['tags', 'timestamp', 'service', 'id'].some((k) => k in raw)) {
      id = raw.id; timestamp = raw.timestamp; service = raw.service; tags = raw.tags; attrs = raw.attributes;
      take(raw, ['id', 'timestamp', 'service', 'tags', 'attributes'], true);
      shape = 'Wrapped event';
    } else {                                                // raw SDK intake event
      attrs = raw;
      shape = 'Raw event';
    }

    const type = typeof attrs.type === 'string' && attrs.type ? attrs.type : 'event';
    const wrapperTimestamp = timestamp;                       // only this one is shown in General
    if (timestamp == null) timestamp = attrs.date != null ? attrs.date : attrs.timestamp;
    return { id, timestamp, wrapperTimestamp, service, tags, attrs, extras, shape, type, raw };
  }

  /* ── 3. Flatten + classify into sections ────────────────────────────── */

  function flatten(value, path, root, out) {
    if (Array.isArray(value)) {
      if (!value.length) { out.push({ path, root, value }); return; }
      if (value.every(isPrim)) { out.push({ path, root, value }); return; }
      value.slice(0, MAX_ARRAY_ITEMS).forEach((v, i) => flatten(v, path + '[' + i + ']', root, out));
      if (value.length > MAX_ARRAY_ITEMS) {
        out.push({ path: path + '[…]', root, value: '+' + (value.length - MAX_ARRAY_ITEMS) + ' more items (see Raw JSON)', note: true });
      }
    } else if (isObj(value)) {
      const keys = Object.keys(value);
      if (!keys.length) { out.push({ path, root, value }); return; }
      keys.forEach((k) => flatten(value[k], path + '.' + k, root, out));
    } else {
      out.push({ path, root, value });
    }
  }

  function parseTags(tags) {
    let list = tags;
    if (typeof list === 'string') list = list.split(',');
    if (!Array.isArray(list)) return [];
    const grouped = new Map();
    list.forEach((t) => {
      if (typeof t !== 'string') return;
      const s = t.trim(); if (!s) return;
      const i = s.indexOf(':');
      const k = i === -1 ? s : s.slice(0, i);
      const v = i === -1 ? null : s.slice(i + 1);
      if (!grouped.has(k)) grouped.set(k, []);
      grouped.get(k).push(v);
    });
    return [...grouped].map(([k, vs]) => {
      const flag = vs.every((v) => v === null);
      const clean = vs.filter((v) => v !== null);
      return { path: k, root: k, value: flag ? null : (clean.length === 1 ? clean[0] : clean), flag };
    });
  }

  function prettify(key) {
    if (ROOT_TITLES[key]) return ROOT_TITLES[key];
    const s = key.replace(/^_+/, '').replace(/[_-]+/g, ' ').trim();
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : key;
  }

  function sectionIdFor(row) {
    if (AUTO_CLAIM_ROOTS.has(row.root)) {
      for (const d of FIXED_SECTIONS) if (d.match && d.match.test(row.path)) return d.id;
    }
    for (const d of FIXED_SECTIONS) if (d.roots && d.roots.includes(row.root)) return d.id;
    return null;
  }

  function buildSections(ev) {
    const attrRows = [];
    for (const [k, v] of Object.entries(ev.attrs)) flatten(v, k, k, attrRows);

    // General: wrapper fields + any top-level scalar the attributes carry
    const general = [];
    const seen = new Map();
    const addGeneral = (path, value) => {
      if (value === undefined) return;
      const key = JSON.stringify(value);
      if (seen.has(path)) { if (seen.get(path) === key) return; path += ' (attributes)'; }
      seen.set(path, key);
      general.push({ path, root: path, value });
    };
    addGeneral('id', ev.id);
    if (ev.wrapperTimestamp != null) addGeneral('timestamp', ev.wrapperTimestamp);
    // the wrapper's `service` is only shown if the attributes don't carry their own
    const attrsHaveService = 'service' in ev.attrs;
    if (!attrsHaveService && ev.service !== undefined) {
      attrRows.push({ path: 'service', root: 'service', value: Array.isArray(ev.service) && ev.service.length === 1 ? ev.service[0] : ev.service });
    }
    const extraRows = [];
    for (const [k, v] of Object.entries(ev.extras)) flatten(v, k, k, extraRows);
    extraRows.forEach((r) => (r.path === r.root ? addGeneral(r.path, r.value) : general.push(r)));

    const byId = new Map(FIXED_SECTIONS.map((d) => [d.id, { ...d, rows: [] }]));
    const dynamic = new Map(); // root -> section

    attrRows.forEach((row) => {
      const id = sectionIdFor(row);
      if (id) { byId.get(id).rows.push(row); return; }
      if (row.path === row.root) { addGeneral(row.path, row.value); return; }   // top-level scalar → General
      if (!dynamic.has(row.root)) {
        dynamic.set(row.root, { id: 'x-' + row.root, title: prettify(row.root), icon: ROOT_ICONS[row.root] || 'bi-box', roots: [row.root], rows: [] });
      }
      dynamic.get(row.root).rows.push(row);
    });

    // `context: {}` is "no custom attributes", not a custom attribute called context
    const custom = byId.get('custom');
    if (custom.rows.length === 1 && custom.rows[0].path === 'context') custom.rows = [];

    // tag-derived identity rows for the Application section
    const tagRows = parseTags(ev.tags);
    tagRows.filter((r) => APP_TAG_KEYS.includes(r.path)).forEach((r) => {
      byId.get('application').rows.push({ ...r, fromTag: true });
    });

    const sections = [];
    if (general.length) {
      sections.push({ id: 'general', title: 'General', icon: 'bi-info-circle', rows: general, flat: true });
    }
    const fixed = [...byId.values()];
    const dyn = [...dynamic.values()];
    const all = [...fixed, ...dyn];

    // The section that describes this event type goes first (view → View, action → Action, ...)
    const primary = all.find((s) => s.rows.length && s.roots && s.roots.includes(ev.type) && s.id !== 'custom');
    if (primary) { primary.primary = true; sections.push(primary); }

    const missing = [];
    fixed.forEach((s) => {
      if (s === primary) return;
      if (s.rows.length || s.always) sections.push(s);
      else missing.push(s.title);
    });
    dyn.forEach((s) => { if (s !== primary) sections.push(s); });

    if (tagRows.length) {
      sections.push({ id: 'tags', title: 'Tags', icon: 'bi-tags', rows: tagRows, flat: true });
    }
    return { sections, missing };
  }

  /* ── 4. Value presentation ──────────────────────────────────────────── */

  function hintFor(row) {
    const v = row.value;
    const leaf = row.path.split('.').pop();
    if (typeof v === 'number' && isFinite(v)) {
      if (DURATION_KEY.test(leaf) || TIMING_PATH.test(row.path)) {
        return '≈ ' + fmtNs(v) + '  ·  assuming nanoseconds';
      }
      if (DATE_KEY.test(leaf)) {
        if (v >= 1e11 && v <= 1e13) return fmtDate(new Date(v));
        if (v >= 1e9 && v < 1e10)  return fmtDate(new Date(v * 1000));
      }
      if (SIZE_KEY.test(leaf) && v >= 1024) return '≈ ' + fmtBytes(v);
    }
    if (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(v)) {
      const d = new Date(v);
      if (!isNaN(d)) return d.toLocaleString(undefined, DATE_FMT);
    }
    return null;
  }

  function rawText(v) {
    if (v === null) return 'null';
    if (typeof v === 'string') return v;
    return JSON.stringify(v);
  }

  function renderValue(row) {
    const v = row.value;
    if (row.note) return h('span', { class: 'rp-v rp-note-text', text: v });
    if (row.flag) return h('span', { class: 'rp-v rp-muted', text: '(no value)' });
    if (v === null) return h('span', { class: 'rp-v rp-null', text: 'null' });
    if (typeof v === 'boolean') return h('span', { class: 'rp-v rp-bool ' + (v ? 'is-true' : 'is-false'), text: String(v) });
    if (typeof v === 'number') return h('span', { class: 'rp-v rp-num', text: String(v) });
    if (Array.isArray(v)) {
      if (!v.length) return h('span', { class: 'rp-v rp-muted', text: '[ ]' });
      return h('span', { class: 'rp-v rp-list' }, v.map((x) => h('span', { class: 'rp-chip', text: rawText(x) })));
    }
    if (isObj(v)) return h('span', { class: 'rp-v rp-muted', text: '{ }' });
    if (typeof v === 'string') {
      if (v === '') return h('span', { class: 'rp-v rp-muted', text: '(empty string)' });
      if (v.includes('\n') || v.length > 300) return h('pre', { class: 'rp-v rp-pre', text: v });
      return h('span', { class: 'rp-v rp-str', text: v });
    }
    return h('span', { class: 'rp-v', text: String(v) });
  }

  /* ── 5. Render ──────────────────────────────────────────────────────── */

  const state = { events: [], index: 0, sectionEls: [], source: 'paste' };

  function eventLabel(ev) {
    const a = ev.attrs, t = ev.type;
    const g = (o, ...ks) => ks.reduce((x, k) => (x == null ? x : x[k]), o);
    const candidates = [
      g(a, t, 'target', 'name'), g(a, t, 'name'), g(a, t, 'message'), g(a, t, 'url'),
      g(a, 'view', 'name'), g(a, 'view', 'url_path'), g(a, 'session', 'last_view', 'name'),
    ];
    let hit = candidates.find((c) => typeof c === 'string' && c);
    if (!hit) return '';
    // a bare path like "/" or "/checkout" reads better with its host in front
    if (hit.startsWith('/')) {
      const host = g(a, 'view', 'url_host') || g(a, 'session', 'last_view', 'url_host') || g(a, 'session', 'initial_view', 'url_host');
      if (typeof host === 'string' && host) hit = host + hit;
    }
    return hit.length > 90 ? hit.slice(0, 90) + '…' : hit;
  }

  function eventDate(ev) {
    const t = ev.timestamp;
    if (t == null) return null;
    const d = typeof t === 'number' ? new Date(t > 1e11 ? t : t * 1000) : new Date(t);
    return isNaN(d) ? null : d;
  }

  function lookup(attrs, path) {
    return path.split('.').reduce((x, k) => (x == null ? x : x[k]), attrs);
  }

  function renderRow(row, stripRoot) {
    let shown = row.path;
    if (stripRoot && shown.startsWith(stripRoot + '.')) shown = shown.slice(stripRoot.length + 1);
    const cut = shown.lastIndexOf('.');
    const prefix = cut > -1 ? shown.slice(0, cut + 1) : '';
    const leaf = cut > -1 ? shown.slice(cut + 1) : shown;

    const hint = hintFor(row);
    const valueEl = renderValue(row);
    const el = h('div', { class: 'rp-row', role: 'row' },
      h('div', { class: 'rp-k', role: 'rowheader', title: row.path },
        prefix ? h('span', { class: 'rp-k-pre', text: prefix }) : null,
        h('span', { class: 'rp-k-leaf', text: leaf }),
        row.fromTag ? h('span', { class: 'rp-tag-pill', text: 'tag' }) : null),
      h('div', { class: 'rp-val', role: 'cell' }, valueEl, hint ? h('div', { class: 'rp-hint', text: hint }) : null),
      row.note || row.flag ? h('span') : copyBtn(() => rawText(row.value)));
    el.dataset.hay = (row.path + ' ' + (Array.isArray(row.value) ? row.value.map(rawText).join(' ') : rawText(row.value))).toLowerCase();
    return el;
  }

  function renderSection(sec) {
    // Strip a shared top-level key from the labels ("session." on every row) and
    // show it once in the header instead.
    let strip = null;
    if (!sec.flat && sec.rows.length && sec.rows.every((r) => r.path !== r.root)) {
      const roots = new Set(sec.rows.map((r) => r.root));
      if (roots.size === 1) strip = [...roots][0];
    }
    const body = h('div', { class: 'rp-rows', role: 'table' });
    if (!sec.rows.length) {
      body.append(h('div', { class: 'rp-empty', text: sec.emptyText || 'None found' }));
    } else {
      sec.rows.forEach((r) => body.append(renderRow(r, strip)));
    }
    const count = h('span', { class: 'rp-count', text: String(sec.rows.length) });
    const el = h('details', { class: 'rp-section' + (sec.primary ? ' is-primary' : '') + (sec.rows.length ? '' : ' is-empty'), open: true },
      h('summary', null,
        icon('bi-chevron-right'), icon(sec.icon || 'bi-box'),
        h('span', { class: 'rp-section-title', text: sec.title }),
        strip ? h('code', { class: 'rp-root', text: strip + '.*' }) : null,
        sec.primary ? h('span', { class: 'rp-primary-pill', text: 'this event' }) : null,
        count),
      body);
    return { el, count, rows: [...body.querySelectorAll('.rp-row')], sec };
  }

  function idChip(label, value) {
    return h('div', { class: 'rp-idchip' },
      h('span', { class: 'rp-idchip-label', text: label }),
      h('code', { class: 'rp-idchip-val', title: String(value), text: String(value) }),
      copyBtn(String(value), 'Copy ' + label));
  }

  function renderEventHeader(ev) {
    const d = eventDate(ev);
    const label = eventLabel(ev);
    const idPaths = ['application.id', 'session.id', 'view.id', ev.type + '.id'];
    const seenVals = new Set();
    const chips = [];
    idPaths.forEach((p) => {
      const v = lookup(ev.attrs, p);
      if (typeof v === 'string' && v && !seenVals.has(p)) { seenVals.add(p); chips.push(idChip(p, v)); }
    });
    if (ev.id && typeof ev.id === 'string') chips.push(idChip('event id', ev.id));

    return h('div', { class: 'rp-event rp-card', 'data-type': ev.type },
      h('div', { class: 'rp-event-top' },
        h('span', { class: 'rp-type', text: ev.type }),
        h('div', { class: 'rp-event-title' },
          h('div', { class: 'rp-event-name', text: label || (ev.type === 'event' ? 'Event' : ev.type + ' event') }),
          d ? h('div', { class: 'rp-event-time', text: fmtDate(d) }) : null),
        h('span', { class: 'rp-shape', text: ev.shape })),
      chips.length ? h('div', { class: 'rp-ids' }, chips) : null);
  }

  function renderResults() {
    const host = $('rp-results');
    const ev = state.events[state.index];
    host.textContent = '';

    // multi-event switcher
    if (state.events.length > 1) {
      const sel = h('select', { id: 'rp-select', class: 'rp-select', 'aria-label': 'Choose event' },
        state.events.map((e, i) => {
          const d = eventDate(e); const l = eventLabel(e);
          return h('option', { value: String(i), text: '#' + (i + 1) + '  ·  ' + e.type + (l ? '  ·  ' + l : '') + (d ? '  ·  ' + d.toLocaleTimeString() : '') });
        }));
      sel.value = String(state.index);
      sel.addEventListener('change', () => { state.index = +sel.value; renderResults(); });
      const step = (n) => { state.index = (state.index + n + state.events.length) % state.events.length; renderResults(); };
      host.append(h('div', { class: 'rp-switcher rp-card' },
        h('span', { class: 'rp-switch-label', text: state.events.length + ' events found' }),
        h('button', { type: 'button', class: 'rp-btn rp-btn-ghost', 'aria-label': 'Previous event', onclick: () => step(-1) }, icon('bi-chevron-left')),
        sel,
        h('button', { type: 'button', class: 'rp-btn rp-btn-ghost', 'aria-label': 'Next event', onclick: () => step(1) }, icon('bi-chevron-right'))));
    }

    host.append(renderEventHeader(ev));

    const { sections, missing } = buildSections(ev);
    state.sectionEls = sections.map(renderSection);
    const totalRows = state.sectionEls.reduce((n, s) => n + s.rows.length, 0);

    // toolbar
    const filter = h('input', { type: 'search', id: 'rp-filter', class: 'rp-filter', placeholder: 'Filter fields and values…', 'aria-label': 'Filter fields and values', autocomplete: 'off', spellcheck: 'false' });
    const status = h('span', { class: 'rp-filter-status', id: 'rp-filter-status', 'aria-live': 'polite', text: totalRows + ' fields' });
    let timer;
    filter.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => applyFilter(filter.value, status, totalRows), 120); });
    host.append(h('div', { class: 'rp-toolbar' },
      h('div', { class: 'rp-filter-wrap' }, icon('bi-search'), filter),
      status,
      h('button', { type: 'button', class: 'rp-btn rp-btn-ghost', onclick: () => state.sectionEls.forEach((s) => (s.el.open = true)) }, icon('bi-arrows-expand'), ' Expand all'),
      h('button', { type: 'button', class: 'rp-btn rp-btn-ghost', onclick: () => state.sectionEls.forEach((s) => (s.el.open = false)) }, icon('bi-arrows-collapse'), ' Collapse all')));

    const list = h('div', { class: 'rp-sections' }, state.sectionEls.map((s) => s.el));
    host.append(list);

    if (missing.length) {
      host.append(h('p', { class: 'rp-missing' }, h('strong', { text: 'Not present in this event: ' }), missing.join(', ')));
    }

    // Raw JSON, rendered lazily the first time it is opened
    const rawJson = () => JSON.stringify(ev.raw, null, 2);
    const pre = h('pre', { class: 'rp-rawpre' });
    const raw = h('details', { class: 'rp-section rp-raw' },
      h('summary', null, icon('bi-chevron-right'), icon('bi-code-slash'), h('span', { class: 'rp-section-title', text: 'Raw JSON' }),
        copyBtn(rawJson, 'Copy raw JSON')),
      pre);
    raw.addEventListener('toggle', () => { if (raw.open && !pre.textContent) pre.textContent = rawJson(); });
    raw.querySelector('summary .rp-copy').addEventListener('click', (e) => e.stopPropagation());
    host.append(raw);
  }

  function applyFilter(q, statusEl, total) {
    const needle = q.trim().toLowerCase();
    let shown = 0;
    state.sectionEls.forEach((s) => {
      let hits = 0;
      s.rows.forEach((r) => {
        const match = !needle || r.dataset.hay.includes(needle);
        r.hidden = !match;
        if (match) hits++;
      });
      shown += hits;
      s.count.textContent = needle ? hits + '/' + s.rows.length : String(s.rows.length);
      s.el.hidden = !!needle && hits === 0;
      if (needle && hits) s.el.open = true;
    });
    const rawPanel = document.querySelector('#rp-results .rp-raw');
    if (rawPanel) rawPanel.hidden = !!needle;
    statusEl.textContent = needle ? shown + ' of ' + total + ' fields match' : total + ' fields';
  }

  /* ── 6. Input wiring ────────────────────────────────────────────────── */

  const SAMPLE = {
    id: 'AwAAAaENBDHhy9HdlAAAABhBYUVOQkRIaEFBQzZ6Z3YxYnljYjQ5QkkAAAAkZjFhMTBkMDQtZmRjOC00M2YzLTg0MmMtYWZiNzAzZGJiZTBlAAAAAA',
    content: {
      timestamp: '2026-10-05T17:02:21.153Z',
      tags: ['source:browser', 'service:datadogrum-pirates-landing-page', 'env:test', 'sdk_version:7.15.0',
             'datadog.submission_auth:client_token', 'version:2.0.0', 'first_version:2.0.0'],
      service: ['datadogrum-pirates-landing-page'],
      attributes: {
        os: { name: 'Mac OS X', version: '10.15.7', version_major: '10' },
        session: {
          useragent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36',
          long_task: { count: 2 }, has_replay: true, type: 'user', error: { count: 0 }, time_spent: 563467000000,
          view: { count: 2 }, is_replay_available: true,
          initial_view: { url_path_group: '/', name: '/', id: '9a8d695b-bc64-4484-abe2-acd1abc63354', url_host: 'example.com', url_path: '/', url_scheme: 'https' },
          action: { count: 2 }, id: '23b0aefb-00d1-4e8c-b673-1e80bd890c65', plan: 'replay', is_active: false,
          resource: { count: 59 }, ip: '203.0.113.42', frustration: { count: 1 },
          retention_reason: 'rum_retention_filter', has_full_snapshot: true,
          last_view: { url_path_group: '/', name: '/', id: '96b9a08c-c3e0-464a-afd4-872baa749ecd', url_host: 'example.com', url_path: '/', url_scheme: 'https' },
          sampled_for_replay: true, has_forced_replay: false,
          matching_retention_filter: { name: 'Sessions with Replays', id: 'default_sessions' },
        },
        type: 'session',
        last_user_interaction_time: 1791219793334,
        geo: { continent: 'North America', country: 'United States', country_iso_code: 'US', city: 'New York City',
               latitude: 40.71427, longitude: -74.00597, country_subdivision: 'New York', country_subdivision_iso_code: 'US-NY' },
        application: { name: 'DatadogRUM-Pirates', short_name: 'datadogrum_pirates', id: '012a1d19-38df-4e55-9412-6ceb64e72490' },
        connectivity: { effective_type: '4g' },
        service: 'datadogrum-pirates-landing-page',
        browser: { name: 'Chrome', version: '154.0.0.0', version_major: '154' },
        context: { arrrrr: 'im-a-pirate', client_time: { utc_offset: 240, timezone: 'America/New_York', locale: 'en-US' } },
        device: { name: 'Mac', model: 'Mac', type: 'Desktop', brand: 'Apple' },
        _dd: {
          configuration: { session_replay_sample_rate: 100, session_sample_rate: 100, start_session_replay_recording_manually: false },
          session: { excluded: false, lifecycle: { replay_started_after_deactivation: false, reactivation_count: 0 },
                     has_view_marked_as_replay: false, deactivation_reason: 'INACTIVITY_TIMER', plan: 2 },
          replay_stats: { records_count: 112, segments_count: 10, segments_total_raw_size: 830211 },
          retained_at: 1791221530358, reducer_status: 'inactive', document_version: 34, billing_source: 'browser',
          replay_selected_in_pa: true, initial_view_with_replay: { id: '9a8d695b-bc64-4484-abe2-acd1abc63354' },
          indexation_status: 'indexed', sku: 'replay', matching_retention_filter_id: 'Sessions with Replays',
        },
      },
    },
  };

  function showError(msg, detail) {
    const box = $('rp-error');
    box.textContent = '';
    box.append(icon('bi-exclamation-triangle'), h('div', null, h('strong', { text: msg }), detail ? h('div', { class: 'rp-error-detail', text: detail }) : null));
    box.hidden = false;
  }
  function clearError() { const b = $('rp-error'); b.hidden = true; b.textContent = ''; }

  let loadedText = null;     // set when a large file is loaded without echoing it into the textarea
  let loadedName = '';

  function parseAndRender(text, source) {
    clearError();
    if (!text.trim()) {
      $('rp-results').textContent = '';
      showError('Nothing to parse yet.', 'Paste some JSON into the box, or drop a .json file.');
      return;
    }
    let root;
    try {
      root = parseJsonLoose(text);
    } catch (err) {
      $('rp-results').textContent = '';
      showError('That doesn’t look like valid JSON.', err.message);
      return;
    }
    const rawEvents = extractEvents(root);
    const events = [];
    let skipped = 0;
    rawEvents.forEach((e) => { if (isObj(e)) events.push(normalize(e)); else skipped++; });
    if (!events.length) {
      $('rp-results').textContent = '';
      showError('No event objects found in that JSON.', 'Expected an object (or an array of objects) such as a RUM Explorer export, an Events API response, or a raw SDK event.');
      return;
    }
    state.events = events; state.index = 0; state.source = source;
    renderResults();

    const types = [...new Set(events.map((e) => e.type))];
    $('rp-input-status').textContent = events.length + (events.length === 1 ? ' event' : ' events') + ' · ' + types.slice(0, 4).join(', ') + (types.length > 4 ? '…' : '') +
      (loadedName ? ' · ' + loadedName : '') + (skipped ? ' · ' + skipped + ' non-object item(s) skipped' : '');
    $('rp-input').open = false;
    $('rp-results').scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Telemetry for this site's own RUM: counts only, never the pasted content.
    if (window.DD_RUM) {
      window.DD_RUM.addAction('rum_event_parsed', { source, event_count: events.length, event_types: types.slice(0, 10), input_bytes: text.length });
    }
  }

  function currentText() { return loadedText != null ? loadedText : $('rp-text').value; }

  async function loadFile(file) {
    if (!file) return;
    if (file.size > MAX_INPUT_BYTES) { showError('That file is too large.', fmtBytes(file.size) + ' — the limit is ' + fmtBytes(MAX_INPUT_BYTES) + '.'); return; }
    let text;
    try { text = await file.text(); } catch (e) { showError('Couldn’t read that file.', e.message); return; }
    loadedName = file.name;
    if (text.length > MAX_TEXTAREA_SIZE) {
      loadedText = text; $('rp-text').value = '';
      $('rp-text').placeholder = 'Loaded ' + file.name + ' (' + fmtBytes(file.size) + ') — too large to display here.';
    } else {
      loadedText = null; $('rp-text').value = text;
    }
    parseAndRender(text, 'file');
  }

  function init() {
    const text = $('rp-text');
    const drop = $('rp-drop');

    $('rp-parse').addEventListener('click', () => { loadedName = loadedText != null ? loadedName : ''; parseAndRender(currentText(), 'paste'); });
    $('rp-sample').addEventListener('click', () => {
      loadedText = null; loadedName = '';
      text.value = JSON.stringify(SAMPLE, null, 2);
      parseAndRender(text.value, 'sample');
    });
    $('rp-clear').addEventListener('click', () => {
      loadedText = null; loadedName = ''; text.value = ''; text.placeholder = text.dataset.placeholder;
      $('rp-file').value = ''; $('rp-results').textContent = ''; $('rp-input-status').textContent = '';
      clearError(); $('rp-input').open = true; text.focus();
    });

    text.addEventListener('input', () => { loadedText = null; loadedName = ''; });
    text.addEventListener('paste', () => { setTimeout(() => { loadedText = null; loadedName = ''; if (text.value.trim()) parseAndRender(text.value, 'paste'); }, 0); });
    text.addEventListener('keydown', (e) => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); parseAndRender(text.value, 'paste'); } });

    $('rp-file').addEventListener('change', (e) => loadFile(e.target.files[0]));
    ['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('drag-over'); }));
    ['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove('drag-over'); }));
    drop.addEventListener('drop', (e) => loadFile(e.dataTransfer.files[0]));
    // a stray drop elsewhere on the page shouldn't navigate the tab away to the file
    window.addEventListener('dragover', (e) => e.preventDefault());
    window.addEventListener('drop', (e) => { if (!drop.contains(e.target)) { e.preventDefault(); if (e.dataTransfer.files[0]) loadFile(e.dataTransfer.files[0]); } });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
