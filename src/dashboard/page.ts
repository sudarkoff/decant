/**
 * Dashboard HTML page: one self-contained document (inline CSS + JS, no external requests).
 * The client renders all server-provided strings with textContent / createTextNode only.
 *
 * The page is a String.raw template, so the client code below must not contain backticks or
 * dollar-brace sequences.
 */

const CSP =
  "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'";

const STYLE = String.raw`
:root {
  color-scheme: light dark;
  --bg: #f6f7f9; --surface: #ffffff; --text: #15171b; --muted: #555c68;
  --accent: #0e6e5c; --on-accent: #ffffff; --warn: #8a4a06; --danger: #a1290f;
  --border: #e3e6ea; --control: #868e99;
  --danger-edge: #f0c9c0; --warn-edge: #ecd9b5;
  --c-served: #0e6e5c; --c-cooldown: #b0650a; --c-blocked: #a1290f; --c-stale: #4b62a8; --c-failed: #6b2a7a;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #111315; --surface: #1a1d21; --text: #e8eaed; --muted: #a8afba;
    --accent: #4fc3a8; --on-accent: #0b1a16; --warn: #f0a54a; --danger: #ff8f78;
    --border: #2d3238; --control: #6b737e;
    --danger-edge: #6a2a1e; --warn-edge: #5e4320;
    --c-served: #4fc3a8; --c-cooldown: #f0a54a; --c-blocked: #ff8f78; --c-stale: #8ea6f0; --c-failed: #d39ae2;
  }
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
body { margin: 0; background: var(--bg); color: var(--text);
  font-family: Inter, ui-sans-serif, system-ui, sans-serif; font-size: 15px; line-height: 1.45; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 32px 40px; display: flex; flex-direction: column; gap: 24px; }
h1, h2 { font-family: "Space Grotesk", Inter, ui-sans-serif, system-ui, sans-serif; font-weight: 600; margin: 0; }
h1 { font-size: 24px; }
h2 { font-size: 18px; }
header { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between; }
.controls { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }
label { font-size: 14px; display: inline-flex; align-items: center; gap: 8px; }
select, input, button { font: inherit; font-size: 14px; color: var(--text); background: var(--surface);
  border: 1px solid var(--control); border-radius: 8px; padding: 9px 12px; }
button { cursor: pointer; }
button:disabled { cursor: default; opacity: 0.55; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.range { display: inline-flex; }
.range button { border-radius: 0; margin-left: -1px; }
.range button:first-child { border-radius: 8px 0 0 8px; margin-left: 0; }
.range button:last-child { border-radius: 0 8px 8px 0; }
.range button[aria-pressed="true"] { background: var(--accent); border-color: var(--accent); color: var(--on-accent); position: relative; }
section { display: flex; flex-direction: column; gap: 10px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; }
.head { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between; }
.muted { color: var(--muted); font-size: 14px; }
.status { color: var(--muted); font-size: 14px; margin: 0; }
.error { color: var(--danger); font-size: 14px; margin: 0; }
.warn { color: var(--warn); }
.danger { color: var(--danger); }
ul.plain { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
.body { display: flex; flex-direction: column; gap: 8px; }
.body p { margin: 0; }
.items { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
.item { background: var(--surface); border: 1px solid var(--border); border-left-width: 4px; border-radius: 12px;
  padding: 14px 18px; display: flex; flex-wrap: wrap; gap: 6px 14px; align-items: baseline; }
.item.sev-danger { border-color: var(--danger-edge); border-left-color: var(--danger); }
.item.sev-warn { border-color: var(--warn-edge); border-left-color: var(--warn); }
.item.sev-muted { border-left-color: var(--muted); }
.label { font-weight: 600; font-size: 13px; text-transform: uppercase; letter-spacing: 0.04em; min-width: 6.5em; }
.item .main { flex: 1 1 280px; min-width: 0; overflow-wrap: anywhere; }
.item .detail { display: block; color: var(--muted); font-size: 14px; }
.item .since { color: var(--muted); font-size: 13px; }
.grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.chart { width: 100%; height: 140px; display: block; }
.axis { display: flex; justify-content: space-between; color: var(--muted); font-size: 13px; }
.legend { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 14px; }
.legend li { display: inline-flex; align-items: center; gap: 6px; }
.swatch { width: 12px; height: 12px; border-radius: 3px; display: inline-block; }
.table-wrap { overflow-x: auto; max-width: 100%; }
.card, .body { min-width: 0; }
table { border-collapse: collapse; width: 100%; min-width: 560px; font-size: 14px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
th { color: var(--muted); font-weight: 600; }
td.name { white-space: normal; overflow-wrap: anywhere; }
.pager { display: flex; gap: 10px; align-items: center; justify-content: flex-end; }
@media (max-width: 719px) {
  .wrap { padding: 20px 16px; gap: 20px; }
  .grid { grid-template-columns: minmax(0, 1fr); }
}
@media (max-width: 479px) {
  .col-project, .col-published { display: none; }
  table { min-width: 0; }
}
`;

const BODY = String.raw`
<div class="wrap">
  <header>
    <h1>decant</h1>
    <div class="controls">
      <label for="project">Project</label>
      <select id="project"><option value="all">All projects</option></select>
      <div class="range" role="group" aria-label="Date range">
        <button type="button" data-range="7" aria-pressed="false">7 days</button>
        <button type="button" data-range="30" aria-pressed="true">30 days</button>
        <button type="button" data-range="90" aria-pressed="false">90 days</button>
      </div>
    </div>
  </header>

  <section aria-labelledby="h-attention">
    <h2 id="h-attention">Needs attention<span id="attention-count"></span></h2>
    <div id="attention" class="body" aria-live="polite"></div>
  </section>

  <section class="card" aria-labelledby="h-activity">
    <h2 id="h-activity">Activity</h2>
    <div id="activity" class="body"></div>
    <svg id="chart" class="chart" role="img" aria-labelledby="chart-desc" hidden><desc id="chart-desc">Requests per day by outcome</desc></svg>
    <div id="chart-axis" class="axis" hidden></div>
  </section>

  <div class="grid">
    <section class="card" aria-labelledby="h-security"><h2 id="h-security">Security</h2><div id="security" class="body"></div></section>
    <section class="card" aria-labelledby="h-freshness"><h2 id="h-freshness">Freshness</h2><div id="freshness" class="body"></div></section>
    <section class="card" aria-labelledby="h-uptime"><h2 id="h-uptime">Uptime</h2><div id="uptime" class="body"></div></section>
    <section class="card" aria-labelledby="h-policy"><h2 id="h-policy">Policy</h2><div id="policy" class="body"></div></section>
  </div>

  <section class="card" aria-labelledby="h-packages">
    <div class="head">
      <h2 id="h-packages">Packages</h2>
      <label for="q">Search <input id="q" type="search" placeholder="name" maxlength="200" autocomplete="off"></label>
    </div>
    <div id="packages" class="body"></div>
    <div class="pager">
      <span id="page-label" class="muted"></span>
      <button type="button" id="prev" disabled>Prev</button>
      <button type="button" id="next" disabled>Next</button>
    </div>
  </section>

  <section class="card" aria-labelledby="h-resolved">
    <h2 id="h-resolved">Recently resolved</h2>
    <p class="muted">An item resolves when its cause is gone. That includes the package simply having no installs in the last 30 days, not only a fix.</p>
    <div id="resolved" class="body"></div>
  </section>
</div>
`;

const SCRIPT = String.raw`
(function () {
  'use strict';
  var RANGES = ['7', '30', '90'];
  var OUTCOMES = [
    { key: 'served', label: 'Served' },
    { key: 'cooldown', label: 'Held by cooldown' },
    { key: 'blocked', label: 'Blocked' },
    { key: 'stale', label: 'Served stale' },
    { key: 'failed', label: 'Failed' }
  ];
  var $ = function (id) { return document.getElementById(id); };
  var chart = $('chart');
  var SVG_NS = chart.namespaceURI;
  var SECTIONS = ['attention', 'activity', 'security', 'freshness', 'uptime', 'policy', 'packages', 'resolved'];
  var state = { project: 'all', range: '30', q: '', page: 1 };
  var seq = {};

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }
  function svg(tag, attrs) {
    var n = document.createElementNS(SVG_NS, tag);
    for (var k in attrs) n.setAttribute(k, String(attrs[k]));
    return n;
  }
  function show(node, on) { if (on) node.removeAttribute('hidden'); else node.setAttribute('hidden', ''); }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function fmt(n) { return Number(n || 0).toLocaleString(); }
  function plural(n, one, many) { return fmt(n) + ' ' + (n === 1 ? one : many); }
  function shortDate(iso) {
    var d = new Date(iso.length === 10 ? iso + 'T00:00:00Z' : iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' });
  }
  function daysAgo(iso) {
    if (!iso) return '-';
    var t = Date.parse(iso);
    if (isNaN(t)) return '-';
    var d = Math.floor((Date.now() - t) / 86400000);
    return d <= 0 ? 'today' : d === 1 ? '1 day ago' : fmt(d) + ' days ago';
  }
  function line(parent, text, cls) { var p = el('p', cls, text); parent.appendChild(p); return p; }

  function readUrl() {
    var u = new URLSearchParams(location.search);
    var r = u.get('range');
    state.range = RANGES.indexOf(r) >= 0 ? r : '30';
    state.project = u.get('project') || 'all';
  }
  function writeUrl() {
    var u = new URLSearchParams();
    u.set('project', state.project);
    u.set('range', state.range);
    history.replaceState(null, '', location.pathname + '?' + u.toString());
  }
  function scope() {
    return 'project=' + encodeURIComponent(state.project) + '&range=' + encodeURIComponent(state.range);
  }

  function getJson(path) {
    return fetch('/dashboard/api/' + path, { credentials: 'same-origin', headers: { accept: 'application/json' } }).then(
      function (res) {
        if (res.status === 403 || res.status === 404) throw new Error('Not authorized or dashboard not configured.');
        if (!res.ok) {
          return res.json().then(
            function (b) { throw new Error('Could not load: ' + (b && typeof b.error === 'string' ? b.error : 'HTTP ' + res.status) + '.'); },
            function () { throw new Error('Could not load: HTTP ' + res.status + '.'); }
          );
        }
        return res.json();
      },
      function () { throw new Error('Could not load: network error.'); }
    );
  }

  /** Loads one section, ignoring responses that arrive after a newer request for the same section. */
  function load(name, path, targets, render, onError) {
    var n = (seq[name] || 0) + 1;
    seq[name] = n;
    var fail = function (msg) {
      targets.forEach(function (t) { clear(t); line(t, msg, 'error'); });
      if (onError) onError();
    };
    targets.forEach(function (t) { clear(t); line(t, 'Loading…', 'status'); });
    return getJson(path).then(
      function (data) {
        if (seq[name] !== n) return;
        targets.forEach(clear);
        try { render(data); } catch (e) { fail('Could not render.'); }
      },
      function (e) { if (seq[name] === n) fail(e.message); }
    );
  }
  /** One line of counts; each count is its own span, coloured only when it is non-zero. */
  function counts(parent, prefix, parts) {
    var p = el('p');
    if (prefix) p.appendChild(document.createTextNode(prefix));
    parts.forEach(function (x, i) {
      if (i) p.appendChild(document.createTextNode(' · '));
      p.appendChild(el('span', x[0] > 0 ? x[2] : null, fmt(x[0]) + ' ' + x[1]));
    });
    parent.appendChild(p);
  }

  // ---- Needs attention / Recently resolved ----
  function severity(item) {
    if (item.kind === 'malicious') return { word: 'Malicious', cls: 'danger' };
    if (item.kind === 'blocked') return { word: 'Blocked', cls: 'danger' };
    if (item.kind === 'vuln') {
      return item.detail.indexOf('critical') === 0 ? { word: 'Critical', cls: 'danger' } : { word: 'High', cls: 'warn' };
    }
    if (item.kind === 'flagged') return { word: 'Flagged', cls: 'warn' };
    if (item.kind === 'conflict') return { word: 'Republished', cls: 'warn' };
    if (item.kind === 'silent') return { word: 'Silent', cls: 'muted' };
    return { word: item.kind, cls: 'muted' };
  }
  function titleWithProject(item) {
    return (item.project ? item.project + ' · ' : 'all · ') + item.title;
  }
  function renderAttention(data) {
    var box = $('attention');
    $('attention-count').textContent = ' (' + data.open.length + ')';
    if (data.open.length === 0) { line(box, 'Nothing needs attention', 'status'); }
    else {
      var ul = el('ul', 'items');
      data.open.forEach(function (item) {
        var s = severity(item);
        var li = el('li', 'item sev-' + s.cls);
        li.appendChild(el('span', 'label ' + s.cls, s.word));
        var main = el('span', 'main');
        main.appendChild(el('strong', null, titleWithProject(item)));
        if (item.detail) main.appendChild(el('span', 'detail', item.detail));
        li.appendChild(main);
        li.appendChild(el('span', 'since', 'since ' + shortDate(item.firstSeen)));
        ul.appendChild(li);
      });
      box.appendChild(ul);
    }
    var rb = $('resolved');
    if (data.resolved.length === 0) { line(rb, 'Nothing resolved in this range.', 'status'); return; }
    var rl = el('ul', 'plain');
    data.resolved.forEach(function (item) {
      var li = el('li');
      li.appendChild(el('span', null, titleWithProject(item)));
      li.appendChild(el('span', 'muted', ' · open since ' + shortDate(item.firstSeen) + ' · resolved ' + shortDate(item.resolvedAt)));
      rl.appendChild(li);
    });
    rb.appendChild(rl);
  }

  // ---- Activity ----
  function renderActivity(data) {
    var box = $('activity');
    var tot = { served: 0, cooldown: 0, blocked: 0, stale: 0, failed: 0 };
    var max = 0;
    data.days.forEach(function (d) {
      var sum = 0;
      OUTCOMES.forEach(function (o) { tot[o.key] += d[o.key]; sum += d[o.key]; });
      if (sum > max) max = sum;
    });
    var all = OUTCOMES.reduce(function (a, o) { return a + tot[o.key]; }, 0);
    line(box, plural(all, 'request', 'requests') + ' · ' + plural(data.distinctPackages, 'package', 'packages') + ' · ' +
      plural(data.distinctVersions, 'version', 'versions') + ' · ' + fmt(tot.cooldown) + ' held by cooldown · ' + fmt(tot.blocked) + ' blocked');
    var legend = el('ul', 'legend');
    OUTCOMES.forEach(function (o) {
      var li = el('li');
      var sw = el('span', 'swatch');
      sw.style.background = 'var(--c-' + o.key + ')';
      li.appendChild(sw);
      li.appendChild(el('span', null, o.label + ' ' + fmt(tot[o.key])));
      legend.appendChild(li);
    });
    box.appendChild(legend);

    var axis = $('chart-axis');
    while (chart.lastChild && chart.lastChild.nodeName !== 'desc') chart.removeChild(chart.lastChild);
    clear(axis);
    if (all === 0) { line(box, 'No requests in this range.', 'status'); show(chart, false); show(axis, false); return; }
    var n = data.days.length, slot = 10, bw = 8, h = 100;
    chart.setAttribute('viewBox', '0 0 ' + n * slot + ' ' + h);
    chart.setAttribute('preserveAspectRatio', 'none');
    data.days.forEach(function (d, i) {
      var g = svg('g', {});
      var t = svg('title', {});
      t.textContent = d.day + ': ' + OUTCOMES.map(function (o) { return fmt(d[o.key]) + ' ' + o.label.toLowerCase(); }).join(', ');
      g.appendChild(t);
      var y = h;
      OUTCOMES.forEach(function (o) {
        if (!d[o.key]) return;
        var bh = (d[o.key] / max) * h;
        y -= bh;
        var r = svg('rect', { x: i * slot + (slot - bw) / 2, y: y, width: bw, height: bh });
        r.style.fill = 'var(--c-' + o.key + ')';
        g.appendChild(r);
      });
      // Full-height transparent hit area so the tooltip works on short bars too.
      g.appendChild(svg('rect', { x: i * slot, y: 0, width: slot, height: h, fill: 'transparent' }));
      chart.appendChild(g);
    });
    axis.appendChild(el('span', null, shortDate(data.days[0].day)));
    axis.appendChild(el('span', null, shortDate(data.days[n - 1].day)));
    show(chart, true);
    show(axis, true);
  }

  // ---- Security / Freshness / Uptime / Policy ----
  function renderSecurity(s) {
    var box = $('security');
    counts(box, '', [
      [s.blocksHit, s.blocksHit === 1 ? 'block hit' : 'blocks hit', 'danger'],
      [s.maliciousHits, s.maliciousHits === 1 ? 'malicious hit' : 'malicious hits', 'danger']
    ]);
    var v = s.vulnsBySeverity;
    counts(box, 'Known vulnerabilities installed: ', [
      [v.critical, 'critical', 'danger'], [v.high, 'high', 'warn'], [v.moderate, 'moderate', 'warn'],
      [v.low, 'low', null], [v.unknown, 'unknown', null]
    ]);
    counts(box, '', [[s.flagged.length, s.flagged.length === 1 ? 'scanner flag' : 'scanner flags', 'warn']]);
    if (s.flagged.length) {
      var fl = el('ul', 'plain muted');
      s.flagged.forEach(function (f) { fl.appendChild(el('li', null, f.package + ' · ' + f.scanner)); });
      box.appendChild(fl);
    }
    var hrs = s.fastLane.map(function (x) { return x.hoursToFix; }).sort(function (a, b) { return a - b; });
    var med = hrs.length ? (hrs.length % 2 ? hrs[(hrs.length - 1) / 2] : (hrs[hrs.length / 2 - 1] + hrs[hrs.length / 2]) / 2) : null;
    line(box, plural(s.fastLane.length, 'security fix', 'security fixes') + ' allowed early' + (med === null ? '' : ' · median time-to-fix ' + fmt(Math.round(med * 10) / 10) + ' h'));
    if (s.fastLane.length) {
      var ul = el('ul', 'plain muted');
      s.fastLane.forEach(function (x) { ul.appendChild(el('li', null, x.project + ' · ' + x.package + ' · ' + x.advisory + ' · ' + fmt(x.hoursToFix) + ' h')); });
      box.appendChild(ul);
    }
  }
  function renderFreshness(f) {
    var box = $('freshness');
    line(box, f.medianAgeDays === null ? 'Median dependency age: no data' : 'Median dependency age ' + plural(f.medianAgeDays, 'day', 'days'));
    var direct = f.majorBehind.direct, transitive = f.majorBehind.transitive;
    line(box, plural(direct.length, 'direct dependency', 'direct dependencies') + ' a major version behind', direct.length ? 'warn' : null);
    if (direct.length) {
      var ul = el('ul', 'plain muted');
      direct.forEach(function (x) { ul.appendChild(el('li', null, x.project + ' · ' + x.package + ' ' + x.version + ' → ' + x.latest)); });
      box.appendChild(ul);
    }
    if (transitive.length) {
      var det = el('details', null);
      det.appendChild(el('summary', null, plural(f.transitiveMajorBehindCount, 'transitive', 'transitive') + ' (held back by their parents)'));
      var tl = el('ul', 'plain muted');
      transitive.forEach(function (x) {
        tl.appendChild(el('li', null, x.project + ' · ' + x.package + ' ' + x.version + ' → ' + x.latest + (x.via.length ? ' · via ' + x.via.join(', ') : '')));
      });
      det.appendChild(tl);
      box.appendChild(det);
    }
    if (direct.some(function (x) { return x.classified === false; })) {
      line(box, 'Sync policy from the default branch to classify direct vs transitive.', 'muted');
    }
    line(box, plural(f.minorAvailable, 'minor update', 'minor updates') + ' available');
  }
  function renderUptime(u) {
    var box = $('uptime');
    var n = u.outageDays.length;
    line(box, n === 0 ? 'No days with stale serves or failures' : plural(n, 'day', 'days') + ' with stale serves or failures: ' + u.outageDays.map(shortDate).join(', '), n ? 'warn' : null);
    line(box, plural(u.staleServed, 'request', 'requests') + ' served from cache after an upstream error');
    line(box, plural(u.failed, 'failed install', 'failed installs'), u.failed ? 'danger' : null);
  }
  function renderPolicy(p) {
    var box = $('policy');
    if (p.policies.length === 0) { line(box, 'No synced policy.', 'status'); return; }
    p.policies.forEach(function (x) {
      var ship = x.autoShip && typeof x.autoShip === 'object'
        ? Object.keys(x.autoShip).map(function (k) { return k + ' ' + x.autoShip[k]; }).join(', ')
        : String(x.autoShip);
      var div = el('div');
      div.appendChild(el('p', null, x.project + ': cooldown ' + plural(x.cooldownDays, 'day', 'days')));
      div.appendChild(el('p', 'muted', 'Auto-ship: ' + ship));
      div.appendChild(el('p', 'muted', plural(x.allows, 'allow entry', 'allow entries') + ' · ' + plural(x.blocks, 'block entry', 'block entries') +
        ' · synced ' + shortDate(x.syncedAt) + ' · ' + String(x.sha).slice(0, 7)));
      box.appendChild(div);
    });
  }

  // ---- Packages ----
  function renderPackages(data) {
    var box = $('packages');
    $('page-label').textContent = 'Page ' + data.page;
    $('prev').disabled = data.page <= 1;
    $('next').disabled = !data.hasMore;
    if (data.items.length === 0) { line(box, state.q ? 'No packages match.' : 'No packages served in this range.', 'status'); return; }
    var wrap = el('div', 'table-wrap');
    wrap.tabIndex = 0;
    wrap.setAttribute('role', 'region');
    wrap.setAttribute('aria-label', 'Packages table');
    var table = el('table');
    var head = el('tr');
    [['Package', ''], ['Project', 'col-project'], ['Version', ''], ['Published', 'col-published'], ['Latest', ''], ['Last served', '']].forEach(function (h) {
      var th = el('th', h[1] || null, h[0]); th.scope = 'col'; head.appendChild(th);
    });
    var thead = el('thead'); thead.appendChild(head); table.appendChild(thead);
    var tb = el('tbody');
    data.items.forEach(function (x) {
      var tr = el('tr');
      tr.appendChild(el('td', 'name', x.eco + ':' + x.name));
      tr.appendChild(el('td', 'col-project', x.project));
      tr.appendChild(el('td', null, x.version));
      tr.appendChild(el('td', 'col-published', daysAgo(x.published)));
      tr.appendChild(el('td', null, x.latest === null ? '-' : x.latest));
      tr.appendChild(el('td', null, shortDate(x.lastServed)));
      tb.appendChild(tr);
    });
    table.appendChild(tb);
    wrap.appendChild(table);
    box.appendChild(wrap);
  }
  /** fromPage: the page shown before a Prev/Next click, restored if that request fails. */
  function loadPackages(fromPage) {
    $('prev').disabled = true;
    $('next').disabled = true;
    return load('packages', 'packages?' + scope() + '&page=' + state.page + '&q=' + encodeURIComponent(state.q), [$('packages')], renderPackages,
      function () {
        if (fromPage !== undefined) state.page = fromPage;
        $('prev').disabled = state.page <= 1;
        $('next').disabled = false;
      });
  }

  function loadAll() {
    $('attention-count').textContent = '';
    show(chart, false);
    show($('chart-axis'), false);
    var s = scope();
    return Promise.all([
      load('attention', 'attention?' + s, [$('attention'), $('resolved')], renderAttention),
      load('activity', 'activity?' + s, [$('activity')], renderActivity),
      load('security', 'security?' + s, [$('security')], renderSecurity),
      load('freshness', 'freshness?' + s, [$('freshness')], renderFreshness),
      load('uptime', 'uptime?' + s, [$('uptime')], renderUptime),
      load('policy', 'policy?' + s, [$('policy')], renderPolicy),
      loadPackages()
    ]);
  }

  function syncControls() {
    $('project').value = state.project;
    document.querySelectorAll('.range button').forEach(function (b) {
      b.setAttribute('aria-pressed', b.getAttribute('data-range') === state.range ? 'true' : 'false');
    });
  }

  function onChange() { state.page = 1; writeUrl(); syncControls(); loadAll(); }

  $('project').addEventListener('change', function (e) { state.project = e.target.value; onChange(); });
  document.querySelectorAll('.range button').forEach(function (b) {
    b.addEventListener('click', function () { state.range = b.getAttribute('data-range'); onChange(); });
  });
  var timer = null;
  $('q').addEventListener('input', function (e) {
    clearTimeout(timer);
    var v = e.target.value;
    timer = setTimeout(function () { state.q = v.trim(); state.page = 1; loadPackages(); }, 300);
  });
  $('prev').addEventListener('click', function () { if (state.page > 1) { state.page--; loadPackages(state.page + 1); } });
  $('next').addEventListener('click', function () { state.page++; loadPackages(state.page - 1); });

  function start() {
    readUrl();
    syncControls();
    SECTIONS.forEach(function (id) { line($(id), 'Loading…', 'status'); });
    var sel = $('project');
    getJson('projects').then(
      function (data) {
        var ids = data.projects.map(function (p) { return p.id; });
        ids.forEach(function (id) { var o = el('option', null, id); o.value = id; sel.appendChild(o); });
        if (state.project !== 'all' && ids.indexOf(state.project) < 0) state.project = 'all';
        writeUrl();
        syncControls();
        loadAll();
      },
      function (e) {
        SECTIONS.forEach(function (id) {
          clear($(id)); line($(id), e.message, 'error');
        });
      }
    );
  }
  start();
})();
`;

export const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>decant dashboard</title>
<style>${STYLE}</style>
</head>
<body>
${BODY}
<script>${SCRIPT}</script>
</body>
</html>
`;

export function dashboardPage(): Response {
  return new Response(DASHBOARD_HTML, {
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'content-security-policy': CSP },
  });
}
