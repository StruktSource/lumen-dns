(() => {
'use strict';
const L = window.L, h = L.h, F = L.fmt;
const NS = 'http://www.w3.org/2000/svg';
const sv = (tag, a = {}, ...k) => { const e = document.createElementNS(NS, tag); for (const [x, y] of Object.entries(a)) e.setAttribute(x, y); k.forEach(c => e.append(c)); return e; };

function spark(vals, color) {
  if (vals.length < 2) return null;
  const w = 120, hh = 46, mx = Math.max(...vals), mn = Math.min(...vals), r = mx - mn || 1;
  const pts = vals.map((v, i) => `${(i / (vals.length - 1) * w).toFixed(1)},${(hh - 4 - (v - mn) / r * (hh - 10)).toFixed(1)}`).join(' ');
  return sv('svg', { class: 'spark', viewBox: `0 0 ${w} ${hh}`, preserveAspectRatio: 'none', 'aria-hidden': 'true' }, sv('polyline', { points: pts, fill: 'none', stroke: color || 'currentColor', 'stroke-width': 2, 'vector-effect': 'non-scaling-stroke' }));
}
function area(points) {
  const series = points.map(p => ({ t: p.t, blocked: Math.min(p.blocked, p.queries), allowed: Math.max(0, p.queries - p.blocked) }));
  const W = 800, H = 240, pl = 40, pb = 24, pt = 10, pr = 8, iw = W - pl - pr, ih = H - pb - pt;
  const tot = series.map(s => s.allowed + s.blocked), mx = Math.max(10, Math.ceil(Math.max(...tot) / 10) * 10);
  const n = series.length, x = i => pl + (n === 1 ? iw : i / (n - 1) * iw), y = v => pt + ih - v / mx * ih;
  const svg = sv('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Queries per minute, allowed and blocked' });
  for (let g = 0; g <= 4; g++) { const v = mx / 4 * g, yy = y(v); svg.append(sv('line', { x1: pl, x2: W - pr, y1: yy, y2: yy, stroke: 'var(--rule)', 'stroke-dasharray': g ? '3 4' : '' }), Object.assign(sv('text', { x: pl - 8, y: yy + 4, 'text-anchor': 'end', fill: 'var(--text-2)', 'font-size': 10, 'font-family': 'var(--mono)' }), { textContent: Math.round(v) })); }
  [0, Math.floor((n - 1) / 2), n - 1].forEach((i, k) => { if (series[i]) svg.append(Object.assign(sv('text', { x: x(i), y: H - 6, 'text-anchor': k === 0 ? 'start' : k === 2 ? 'end' : 'middle', fill: 'var(--text-2)', 'font-size': 10, 'font-family': 'var(--mono)' }), { textContent: i === n - 1 ? 'now' : `-${n - 1 - i}m` })); });
  const allowed = series.map((s, i) => `${x(i)},${y(s.allowed)}`), base = series.map((s, i) => `${x(i)},${y(s.allowed + s.blocked)}`);
  svg.append(sv('polygon', { points: `${x(0)},${y(0)} ${allowed.join(' ')} ${x(n - 1)},${y(0)}`, fill: 'var(--text)', opacity: .12 }), sv('polyline', { points: allowed.join(' '), fill: 'none', stroke: 'var(--text)', 'stroke-width': 2 }),
    sv('polygon', { points: `${allowed.join(' ')} ${base.slice().reverse().join(' ')}`, fill: '#d8ff36', stroke: 'none', opacity: .95 }), sv('polyline', { points: base.join(' '), fill: 'none', stroke: 'var(--ink)', 'stroke-width': 1.25 }));
  const guide = sv('line', { y1: pt, y2: pt + ih, stroke: 'var(--text)', 'stroke-width': 1, opacity: 0 }); svg.append(guide);
  const tt = h('div', { class: 'tt' }); const wrap = h('div', { class: 'chart' }, svg, tt);
  svg.addEventListener('mousemove', e => { const r = svg.getBoundingClientRect(), px = (e.clientX - r.left) / r.width * W; const i = Math.max(0, Math.min(n - 1, Math.round((px - pl) / iw * (n - 1)))); const s = series[i];
    guide.setAttribute('x1', x(i)); guide.setAttribute('x2', x(i)); guide.setAttribute('opacity', 1); tt.style.display = 'block'; tt.style.left = (x(i) / W * r.width) + 'px'; tt.style.top = (y(s.allowed + s.blocked) / H * r.height) + 'px';
    tt.textContent = `${n - 1 - i ? '-' + (n - 1 - i) + ' min' : 'last minute'} · ${s.allowed} allowed · ${s.blocked} blocked`; });
  svg.addEventListener('mouseleave', () => { guide.setAttribute('opacity', 0); tt.style.display = 'none'; });
  return wrap;
}
const barRows = (entries, acc) => { const mx = Math.max(1, ...entries.map(e => e[1])); return h('div', { class: 'bars' }, entries.map(([k, v], i) => h('div', { class: 'bar-row' + (acc === i ? ' acc' : '') }, h('span', {}, k), h('div', { class: 't' }, h('i', { style: `width:${v ? Math.max(1, v / mx * 100) : 0}%` })), h('span', { class: 'v' }, F.n(v))))); };
const EDGES = ['≤1 ms', '≤5 ms', '≤10 ms', '≤50 ms', '≤100 ms', '≤500 ms', '≤1 s', '>1 s'];
const UPPER = [1, 5, 10, 50, 100, 500, 1000, Infinity];

L.views.overview = () => {
  const s = L.S.status, c = s.counters, f = s.filter, cfg = L.S.cfg, admin = L.can('admin');
  const pts = L.S.series, last = pts.at(-1);
  const lat = c.latency, ln = lat.reduce((a, b) => a + b, 0);
  const pc = p => { let acc = 0; for (let i = 0; i < lat.length; i++) { acc += lat[i]; if (acc / ln >= p) return i; } return lat.length - 1; };
  const lbl = i => UPPER[i] === Infinity ? '>1 s' : `≤${UPPER[i]} ms`;
  const decided = f.blocked + f.allowed, blockedPct = decided ? f.blocked / decided * 100 : 0;
  const servfailPct = c.responses ? c.rcodes.servfail / c.responses * 100 : 0;
  const rules = f.lists.reduce((a, l) => a + l.rules, 0) + (cfg ? cfg.filtering.rules.allow.length + cfg.filtering.rules.block.length : 0);

  const alerts = [];
  if (s.daemon !== 'running') alerts.push(['bad', `Daemon status: ${s.daemon}.`]);
  if (s.last_error) alerts.push(['warn', `Last control message: ${s.last_error}`]);
  if (f.refresh_failures > 0) alerts.push(['warn', `${f.refresh_failures} filter list refresh${f.refresh_failures > 1 ? 'es' : ''} failed since start. The previous rules stay active.`, admin ? 'Open lists' : null, () => L.go('filtering', 'lists')]);
  if (servfailPct > 1 && c.responses > 100) alerts.push(['warn', `${servfailPct.toFixed(1)}% of answers are SERVFAIL. Check your network and upstreams.`]);
  if (admin && cfg) {
    if (!cfg.resolver.dnssec) alerts.push(['bad', 'DNSSEC validation is off.', 'Open resolver', () => L.go('dns', 'resolver')]);
    if (cfg.listen.allow_clients.some(x => x === '0.0.0.0/0' || x === '::/0')) alerts.push(['bad', 'Open resolver: allowed networks include the whole internet.', 'Open listeners', () => L.go('dns', 'listeners')]);
  }

  const control = async (path, msg) => { try { await L.api('POST', path); L.toast(msg); setTimeout(async () => { try { await L.loadStatus(); L.paintMain(); } catch { /* next refresh */ } }, 1500); } catch (e) { L.toast(e.message, 'bad'); } };
  const rollback = async () => { if (await L.confirm({ title: 'Roll back filter lists', text: 'Swap to the previous successful generation. Automatic refresh pauses until the next successful manual refresh.', label: 'Roll back' })) control('/api/filter/rollback', 'Rollback queued.'); };

  return [
    L.pageHead('Overview', 'Live totals since Lumen started. Domains and devices are never part of these numbers.', [
      h('span', { class: 'pill ' + (s.daemon === 'running' ? 'ok' : 'bad') }, s.daemon === 'running' ? 'Running' : s.daemon), h('span', { class: 'pill plain' }, 'Uptime ' + F.dur(s.uptime_secs)), h('span', { class: 'pill plain' }, 'Revision ' + s.revision)]),
    alerts.length ? h('div', { class: 'stack', style: 'margin-bottom:16px' }, alerts.map(([k, t, label, fn]) => h('div', { class: 'note ' + k }, L.ic('alert'), h('p', {}, t), label ? h('button', { class: 'btn sm', style: 'margin-left:auto', onclick: fn }, label) : null))) : null,
    h('div', { class: 'grid g4' },
      h('div', { class: 'kpi' }, h('span', { class: 'mono' }, last ? 'Queries · last minute' : 'Queries · total'), h('strong', {}, F.n(last ? last.queries : c.queries), last ? h('small', {}, '/min') : null), h('span', { class: 'sub' }, `${F.n(c.queries)} since start`), spark(pts.map(p => p.queries), 'var(--text)')),
      h('div', { class: 'kpi' }, h('span', { class: 'mono' }, 'Blocked'), h('strong', {}, decided ? blockedPct.toFixed(1) : '0', h('small', {}, '%')), h('span', { class: 'sub' }, `${F.n(f.blocked)} of ${F.n(decided)} lookups`), spark(pts.map(p => p.blocked), 'var(--text)')),
      h('div', { class: 'kpi' }, h('span', { class: 'mono' }, 'Failed answers'), h('strong', {}, c.responses ? servfailPct.toFixed(2) : '0', h('small', {}, '%')), h('span', { class: 'sub' }, `${F.n(c.rcodes.servfail)} SERVFAIL · ${F.n(c.timeouts)} timeouts`)),
      h('div', { class: 'kpi' }, h('span', { class: 'mono' }, 'Latency p50 / p95'), h('strong', {}, ln ? lbl(pc(.5)).replace('≤', '<') : '—', ln ? h('small', {}, ' / ' + lbl(pc(.95)).replace('≤', '<')) : null), h('span', { class: 'sub' }, 'End to end, all transports'))),
    h('div', { class: 'grid g-main', style: 'margin-top:16px' },
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', {}, 'Query rate'), h('div', { class: 'legend' }, h('span', {}, h('i', { style: 'background:var(--text)' }), 'Allowed'), h('span', {}, h('i', { style: 'background:var(--acid);border:1px solid var(--ink)' }), 'Blocked'))),
        h('div', { class: 'card-b' }, pts.length >= 2 ? area(pts) : L.empty('Collecting data', 'Lumen records one point a minute. The chart fills in as time passes.'))),
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', {}, 'Resolver')), h('div', { class: 'card-b' }, h('dl', { class: 'kv' },
        cfg ? [h('dt', {}, 'Mode'), h('dd', {}, cfg.resolver.mode), h('dt', {}, 'DNSSEC'), h('dd', {}, cfg.resolver.dnssec ? 'validating' : 'OFF'), h('dt', {}, 'Prefetch'), h('dd', {}, cfg.resolver.prefetch.enabled ? 'on' : 'off'), h('dt', {}, 'Priming'), h('dd', {}, cfg.resolver.warm.enabled ? cfg.resolver.warm.zones.length + ' zones' : 'off')] : null,
        s.rss_bytes ? [h('dt', {}, 'Memory'), h('dd', {}, (s.rss_bytes / 1048576).toFixed(1) + ' MiB')] : null,
        h('dt', {}, 'In flight'), h('dd', {}, cfg ? `${c.active} / ${cfg.limits.max_in_flight}` : String(c.active)), h('dt', {}, 'Refused'), h('dd', {}, F.n(c.refused)), h('dt', {}, 'Malformed'), h('dd', {}, F.n(c.malformed)), h('dt', {}, 'Version'), h('dd', {}, s.version))))),
    h('div', { class: 'grid g3', style: 'margin-top:16px' },
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', {}, 'By transport')), h('div', { class: 'card-b' }, barRows(Object.entries({ UDP: c.transports.udp, TCP: c.transports.tcp, DoT: c.transports.tls, DoH: c.transports.https, DoQ: c.transports.quic }), 0))),
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', {}, 'Answers')), h('div', { class: 'card-b' }, barRows([['NOERROR', c.rcodes.noerror], ['NXDOMAIN', c.rcodes.nxdomain], ['SERVFAIL', c.rcodes.servfail], ['REFUSED', c.rcodes.refused], ['Other', c.rcodes.other]], 0))),
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', {}, 'Latency')), h('div', { class: 'card-b' }, barRows(EDGES.map((e, i) => [e, lat[i]]), 0)))),
    h('div', { class: 'grid g2', style: 'margin-top:16px' },
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', {}, 'Filtering'), h('span', { class: 'pill ' + (f.refresh_failures ? 'warn' : 'ok') }, 'Generation ' + f.generation)), h('div', { class: 'card-b' },
        h('dl', { class: 'kv' }, h('dt', {}, 'Rules loaded'), h('dd', {}, F.n(rules)), h('dt', {}, 'Lists'), h('dd', {}, String(f.lists.length)), h('dt', {}, 'Refreshes'), h('dd', {}, `${f.refresh_successes} ok · ${f.refresh_failures} failed`), h('dt', {}, 'Rollbacks'), h('dd', {}, String(f.rollbacks))),
        h('div', { class: 'row', style: 'margin-top:16px' }, h('button', { class: 'btn primary', disabled: !admin, title: admin ? '' : 'Administrators only', onclick: () => control('/api/filter/refresh', 'Filter refresh queued.') }, L.ic('refresh'), 'Refresh now'), h('button', { class: 'btn', disabled: !admin, onclick: rollback }, L.ic('undo'), 'Roll back')))),
      cfg ? h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', {}, 'Listeners')), h('div', { class: 'card-b flush' }, h('table', { class: 'tbl' }, h('tbody', {}, ['udp', 'tcp', 'dot', 'doh', 'doq'].map(k => h('tr', {}, h('td', { class: 'mono' }, k.toUpperCase()), h('td', { class: 'mono-c' }, cfg.listen[k].join(', ') || '—'), h('td', { class: 'r' }, h('span', { class: 'pill ' + (cfg.listen[k].length ? 'ok' : 'off') }, cfg.listen[k].length ? 'Listening' : 'Off')))))))) : null)
  ];
};
})();
