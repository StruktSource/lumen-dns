/* Traffic map module: an interactive tree of DNS traffic. Lumen at the top, then top-level domains,
   then the domains and services under them. Built from the query history, so it needs history on. */
(() => {
'use strict';
const L = window.L, h = L.h, F = L.fmt;
const NS = 'http://www.w3.org/2000/svg';
const sv = (tag, a = {}, ...k) => { const e = document.createElementNS(NS, tag); for (const [x, y] of Object.entries(a)) e.setAttribute(x, y); k.forEach(c => e.append(c)); return e; };

const LIVE_MS = 5000, MAX_PAGES = 5;
const MAX_TLD = 10, DOMS = 6, DOMS_MORE = 24;
const SLOT = 188, PAD = 28, SIZE = { root: [236, 68], tld: [152, 52], dom: [136, 44], more: [136, 30] };
const WINDOWS = [[15 * 60e3, '15 min'], [3600e3, '1 hour'], [86400e3, '24 hours'], [0, 'All loaded']];
const RESULTS = [['all', 'All'], ['allowed', 'Allowed'], ['blocked', 'Blocked']];

/* View state lives here, so a redraw of the page keeps the selection, the filters and the zoom. */
const S = { items: null, mode: 'off', detail: 'full', savedRows: 0, truncated: false, loadedAt: 0,
  win: 0, result: 'all', search: '', expanded: null, moreDoms: new Set(), allTlds: false, selected: null,
  view: null /* { x, y, k }: where the map is and how far it is zoomed */, auto: true /* keep fitting until the user moves or zooms */, full: false, intro: true, working: false };
/* Live refresh is remembered in this browser. */
const LIVE_KEY = 'lumen.trafficmap.live';
let live = true;
try { live = localStorage.getItem(LIVE_KEY) !== '0'; } catch { /* storage blocked */ }
const isLive = () => live;

/* ---------- data ---------- */
/* The last 1,000 lookups when history is kept in memory; a few pages of saved lookups otherwise. */
L.loadTraffic = async () => {
  let r = await L.api('GET', '/api/history?limit=1000'), items = r.items;
  for (let n = 1; r.next_before && n < MAX_PAGES; n++) { r = await L.api('GET', '/api/history?limit=1000&before=' + r.next_before); items = items.concat(r.items); }
  Object.assign(S, { items, mode: r.mode, detail: r.detail, savedRows: r.saved?.rows || 0, truncated: !!r.next_before, loadedAt: Date.now() });
};

/* Two-label public suffixes such as co.uk. A short list covers the common cases; it is a drawing aid, not a security check. */
const SECOND = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'gob', 'nom']);
const split = domain => {
  const labels = domain.replace(/\.$/, '').toLowerCase().split('.').filter(Boolean);
  if (labels.length < 2) return { tld: labels[0] || '(root)', name: labels[0] || '(root)' };
  const two = labels.length > 2 && labels.at(-1).length === 2 && SECOND.has(labels.at(-2));
  const n = two ? 3 : 2;
  return { tld: labels.slice(-(n - 1)).join('.'), name: labels.slice(-n).join('.') };
};

const bump = (m, key, blocked) => { const e = m.get(key) || { q: 0, b: 0 }; e.q++; if (blocked) e.b++; m.set(key, e); return e; };

/* Group lookups into the tree: server > top-level domain > domain, with the detail the side panel shows. */
function aggregate() {
  const now = Date.now(), q = S.search.trim().toLowerCase();
  const tree = { q: 0, b: 0, ms: 0, tlds: new Map() };
  for (const r of S.items || []) {
    if (S.win && now - r.t > S.win) continue;
    if (S.result === 'blocked' && !r.blocked) continue;
    if (S.result === 'allowed' && r.blocked) continue;
    if (q && !r.domain.toLowerCase().includes(q)) continue;
    const { tld, name } = split(r.domain);
    tree.q++; tree.ms += r.ms; if (r.blocked) tree.b++;
    const t = tree.tlds.get(tld) || { id: 't:' + tld, label: '.' + tld, q: 0, b: 0, doms: new Map() };
    t.q++; if (r.blocked) t.b++; tree.tlds.set(tld, t);
    const d = t.doms.get(name) || { id: 'd:' + name, label: name, tld, q: 0, b: 0, ms: 0, last: 0, types: new Map(), devices: new Map(), subs: new Map() };
    d.q++; d.ms += r.ms; if (r.blocked) d.b++; d.last = Math.max(d.last, r.t); t.doms.set(name, d);
    bump(d.types, r.type, r.blocked); bump(d.subs, r.domain.replace(/\.$/, '').toLowerCase(), r.blocked);
    const who = r.device || r.client; if (who) bump(d.devices, who, r.blocked);
  }
  tree.list = [...tree.tlds.values()].sort((a, b) => b.q - a.q || a.label.localeCompare(b.label));
  for (const t of tree.list) t.list = [...t.doms.values()].sort((a, b) => b.q - a.q || a.label.localeCompare(b.label));
  return tree;
}

/* ---------- layout ---------- */
const trunc = (s, n) => s.length > n ? s.slice(0, n - 1) + '…' : s;
const tone = (q, b) => !b ? 'clean' : b / q > .5 ? 'blocked' : 'mixed';

function layout(tree) {
  const nodes = [], edges = [];
  const shown = S.allTlds ? tree.list : tree.list.slice(0, MAX_TLD), hiddenTlds = tree.list.length - shown.length;
  const cols = shown.length + (hiddenTlds > 0 ? 1 : 0);
  const width = Math.max(PAD * 2 + SLOT * cols, SIZE.root[0] + PAD * 2), rootX = width / 2, rootY = 20, tldY = 150;
  const root = { id: 'root', kind: 'root', x: rootX - SIZE.root[0] / 2, y: rootY, w: SIZE.root[0], h: SIZE.root[1], q: tree.q, b: tree.b };
  nodes.push(root);
  let bottom = tldY + SIZE.tld[1], order = 0;
  const maxQ = Math.max(1, ...tree.list.map(t => t.q));
  /* Space the columns out when there are few, so the tree stays centered under the server. */
  const offset = (width - PAD * 2 - SLOT * cols) / 2;
  shown.forEach((t, i) => {
    const cx = PAD + offset + SLOT * (i + .5), [tw, th] = SIZE.tld;
    const open = S.expanded.has(t.id);
    const tn = { id: t.id, kind: 'tld', parent: 'root', x: cx - tw / 2, y: tldY, w: tw, h: th, label: t.label, q: t.q, b: t.b, open, count: t.list.length, delay: 80 + order++ * 45, data: t };
    nodes.push(tn);
    edges.push({ id: 'e:' + t.id, parent: 'root', to: t.id, delay: 60 + i * 45, w: 1.5 + 4.5 * Math.sqrt(t.q / maxQ), tone: tone(t.q, t.b),
      d: `M${rootX} ${root.y + root.h}C${rootX} ${(root.y + root.h + tldY) / 2} ${cx} ${(root.y + root.h + tldY) / 2} ${cx} ${tldY}` });
    if (!open) return;
    const cap = S.moreDoms.has(t.id) ? DOMS_MORE : DOMS, list = t.list.slice(0, cap), spineX = cx - 64;
    let y = tldY + th + 26;
    const maxD = Math.max(1, t.list[0]?.q || 1);
    list.forEach((d, k) => {
      const [dw, dh] = SIZE.dom, dx = cx - 44, cy = y + dh / 2;
      nodes.push({ id: d.id, kind: 'dom', parent: t.id, x: dx, y, w: dw, h: dh, label: d.label, q: d.q, b: d.b, delay: 220 + order++ * 40, data: d });
      edges.push({ id: 'e:' + d.id, parent: t.id, to: d.id, delay: 200 + k * 40, w: 1.2 + 3.2 * Math.sqrt(d.q / maxD), tone: tone(d.q, d.b), spine: spineX,
        d: `M${spineX} ${cy - 10}Q${spineX} ${cy} ${spineX + 10} ${cy}H${dx}` });
      y += dh + 12;
    });
    if (list.length) edges.push({ id: 'sp:' + t.id, parent: t.id, to: 'sp:' + t.id, delay: 180, w: 1.5, tone: 'spine', d: `M${spineX} ${tldY + th}V${y - 12 - SIZE.dom[1] / 2 - 10}` });
    const rest = t.list.length - list.length;
    if (rest > 0 || S.moreDoms.has(t.id) && t.list.length > DOMS) {
      const [mw, mh] = SIZE.more;
      nodes.push({ id: 'm:' + t.id, kind: 'more', parent: t.id, x: cx - 44, y, w: mw, h: mh, label: rest > 0 ? L.t('+{n} more', { n: rest }) : L.t('Show fewer'), delay: 260 + order++ * 40, tld: t.id });
      y += mh + 12;
    }
    bottom = Math.max(bottom, y);
  });
  if (hiddenTlds > 0) {
    const cx = PAD + offset + SLOT * (cols - .5);
    nodes.push({ id: 'm:tlds', kind: 'more', parent: 'root', x: cx - SIZE.tld[0] / 2, y: tldY + 10, w: SIZE.tld[0], h: 32, label: L.t('+{n} more endings', { n: hiddenTlds }), delay: 120 + order++ * 45 });
  }
  return { nodes, edges, width, height: bottom + PAD, shown, hiddenTlds };
}

/* ---------- drawing ---------- */
const ancestry = (nodes, id) => { const by = new Map(nodes.map(n => [n.id, n])), path = []; for (let n = by.get(id); n; n = by.get(n.parent)) path.push(n); return path; };

function drawTree(tree, lay) {
  const svg = sv('svg', { class: 'tm-svg' + (S.intro ? ' intro' : ''), width: '100%', height: '100%', role: 'group', 'aria-label': L.t('Traffic tree. Lumen at the top, then top-level domains, then domains.') });
  const world = sv('g', { class: 'tm-world' }), gE = sv('g', { class: 'tm-edges' }), gN = sv('g', { class: 'tm-nodes' });
  world.append(gE, gN); svg.append(world);
  const hot = id => {
    const keep = new Set(); if (id) for (const n of ancestry(lay.nodes, id)) { keep.add(n.id); keep.add('e:' + n.id); if (n.parent) keep.add('sp:' + n.parent); }
    svg.classList.toggle('has-hot', !!id);
    svg.querySelectorAll('[data-id]').forEach(el => el.classList.toggle('hot', keep.has(el.dataset.id)));
  };
  for (const e of lay.edges) {
    const g = sv('g', { class: 'edge ' + e.tone, 'data-id': e.id });
    const base = sv('path', { class: 'edge-base', d: e.d, fill: 'none', pathLength: '1', 'stroke-width': e.w.toFixed(2) });
    const flow = sv('path', { class: 'edge-flow', d: e.d, fill: 'none', 'stroke-width': Math.max(1.5, e.w * .55).toFixed(2) });
    base.style.setProperty('--d', e.delay + 'ms'); flow.style.setProperty('--d', (e.delay + 500) + 'ms');
    g.append(base); if (e.tone !== 'spine') g.append(flow); gE.append(g);
  }
  for (const n of lay.nodes) {
    const sel = S.selected === n.id;
    const label = n.kind === 'root' ? L.t('Lumen server, {n} lookups', { n: F.n(n.q) }) : n.kind === 'more' ? n.label : L.t('{name}, {n} lookups, {p} blocked', { name: n.label, n: F.n(n.q), p: F.pct(n.q ? n.b / n.q : 0) });
    const g = sv('g', { class: `node ${n.kind} ${n.q != null ? tone(n.q, n.b) : ''}${sel ? ' sel' : ''}${n.open ? ' open' : ''}`, 'data-id': n.id, tabindex: '0', role: 'button', 'aria-label': label, transform: `translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})` });
    if (n.kind === 'tld') g.setAttribute('aria-expanded', String(!!n.open));
    const inner = sv('g', { class: 'node-in' }); inner.style.setProperty('--d', (n.delay || 0) + 'ms');
    inner.append(sv('rect', { class: 'node-box', width: n.w, height: n.h, rx: n.kind === 'root' ? 10 : 8 }));
    if (n.kind === 'root') {
      inner.append(sv('circle', { class: 'pulse', cx: 22, cy: n.h / 2, r: 5 }), sv('circle', { class: 'pulse-ring', cx: 22, cy: n.h / 2, r: 5 }),
        sv('text', { class: 'n-title', x: 40, y: 28 }, 'LUMEN'),
        sv('text', { class: 'n-sub', x: 40, y: 47 }, L.t('{n} lookups · {p} blocked', { n: F.n(n.q), p: F.pct(n.q ? n.b / n.q : 0) })));
    } else if (n.kind === 'more') {
      inner.append(sv('text', { class: 'n-more', x: n.w / 2, y: n.h / 2 + 4, 'text-anchor': 'middle' }, n.label));
    } else {
      const big = n.kind === 'tld';
      if (big) inner.append(sv('path', { class: 'chev', d: n.open ? 'M14 20l5 5 5-5' : 'M17 16l5 5-5 5', fill: 'none' }));
      inner.append(sv('text', { class: 'n-title', x: big ? 32 : 12, y: big ? 24 : 18 }, trunc(n.label, big ? 14 : 17)),
        sv('text', { class: 'n-sub', x: big ? 32 : 12, y: big ? 41 : 33 }, big ? L.t('{n} lookups · {c} domains', { n: F.n(n.q), c: F.n(n.count) }) : L.t('{n} lookups', { n: F.n(n.q) })));
      /* The red part of the bar is the share that was blocked. */
      const bw = n.w - (big ? 32 : 24), bx = big ? 16 : 12;
      inner.append(sv('rect', { class: 'bar-bg', x: bx, y: n.h - 7, width: bw, height: 3, rx: 1.5 }), sv('rect', { class: 'bar-bad', x: bx, y: n.h - 7, width: Math.max(n.b ? 2 : 0, bw * n.b / (n.q || 1)), height: 3, rx: 1.5 }));
      const tip = sv('title'); tip.textContent = `${n.label} · ${F.n(n.q)} · ${F.pct(n.q ? n.b / n.q : 0)}`; g.append(tip);
    }
    g.append(inner);
    const activate = () => pick(n, lay);
    g.addEventListener('click', activate);
    g.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(); } });
    g.addEventListener('pointerenter', () => hot(n.id)); g.addEventListener('pointerleave', () => hot(null));
    g.addEventListener('focus', () => hot(n.id)); g.addEventListener('blur', () => hot(null));
    gN.append(g);
  }
  return svg;
}

/* A click chooses the node. A top-level domain also opens or closes its branch. */
function pick(n) {
  S.intro = false;
  if (n.kind === 'more') { if (n.id === 'm:tlds') S.allTlds = true; else S.moreDoms.has(n.tld) ? S.moreDoms.delete(n.tld) : S.moreDoms.add(n.tld); S.intro = true; }
  else if (n.kind === 'tld') { if (S.expanded.has(n.id)) S.expanded.delete(n.id); else { S.expanded.add(n.id); S.intro = true; } S.selected = n.id; }
  else S.selected = S.selected === n.id && n.kind !== 'root' ? null : n.id;
  paint();
}

/* ---------- side panel ---------- */
const kv = (k, v) => [h('dt', {}, k), h('dd', {}, v)];
const share = (q, b) => q ? b / q : 0;
const chip = (t, extra) => h('span', { class: 'chip' }, t, extra ? h('b', {}, extra) : null);
const bars = (rows, total) => h('div', { class: 'bars' }, rows.map(([name, e]) => h('div', { class: 'bar-row' + (e.b / e.q > .5 ? '' : ' acc') }, h('span', { class: 't-name mono-c', title: name }, trunc(name, 30)),
  h('span', { class: 't' }, h('i', { style: `width:${Math.max(3, e.q / total * 100).toFixed(1)}%` })), h('span', { class: 'v' }, F.n(e.q) + (e.b ? ' · ' + F.pct(e.b / e.q) : '')))));
const top = (m, n = 6) => [...m.entries()].sort((a, b) => b[1].q - a[1].q || a[0].localeCompare(b[0])).slice(0, n);

function panel(tree) {
  const find = id => {
    if (!id) return null;
    if (id === 'root') return { root: true };
    if (id.startsWith('t:')) return tree.tlds.get(id.slice(2)) || null;
    if (id.startsWith('d:')) return tree.list.map(t => t.doms.get(id.slice(2))).find(Boolean) || null;
    return null;
  };
  const sel = S.selected ? find(S.selected) : null;
  const wrap = body => h('aside', { class: 'tm-panel card', 'aria-live': 'polite' }, body);
  if (!sel || sel.root) {
    const blockedTop = tree.list.flatMap(t => t.list).filter(d => d.b).sort((a, b) => b.b - a.b)[0];
    return wrap([h('div', { class: 'card-h' }, h('h3', {}, 'Lumen server')),
      h('div', { class: 'card-b stack' },
        h('dl', { class: 'kv' }, kv('Lookups', F.n(tree.q)), kv('Blocked', `${F.n(tree.b)} (${F.pct(share(tree.q, tree.b))})`), kv('Average speed', tree.q ? (tree.ms / tree.q).toFixed(1) + ' ms' : '—'),
          kv('Domain endings', F.n(tree.list.length)), kv('Domains', F.n(tree.list.reduce((n, t) => n + t.doms.size, 0))), blockedTop ? kv('Most blocked', blockedTop.label) : null),
        h('p', { class: 'hint', style: 'margin:0' }, 'Click a domain ending to open or close it. Click a domain for its details. Thicker lines mean more lookups; red means mostly blocked.'),
        tree.list.length ? h('div', {}, h('div', { class: 'lbl mono', style: 'margin-bottom:8px' }, 'Busiest endings'), bars(tree.list.slice(0, 6).map(t => [t.label, t]), tree.list[0].q)) : null)]);
  }
  const close = h('button', { class: 'btn', 'aria-label': 'Close details', onclick: () => { S.selected = null; S.intro = false; paint(); } }, L.ic('x'));
  if (sel.doms) { // top-level domain
    return wrap([h('div', { class: 'card-h' }, h('h3', {}, sel.label), close),
      h('div', { class: 'card-b stack' }, h('dl', { class: 'kv' }, kv('Lookups', F.n(sel.q)), kv('Blocked', `${F.n(sel.b)} (${F.pct(share(sel.q, sel.b))})`), kv('Domains', F.n(sel.doms.size)), kv('Share of traffic', F.pct(share(tree.q, sel.q)))),
        h('div', {}, h('div', { class: 'lbl mono', style: 'margin-bottom:8px' }, 'Top domains'), bars(sel.list.slice(0, 8).map(d => [d.label, d]), sel.list[0].q)),
        h('button', { class: 'btn', onclick: () => { S.intro = true; S.expanded.has(sel.id) ? S.expanded.delete(sel.id) : S.expanded.add(sel.id); paint(); } }, L.ic(S.expanded.has(sel.id) ? 'up' : 'down'), S.expanded.has(sel.id) ? 'Close branch' : 'Open branch'))]);
  }
  const subs = top(sel.subs, 8), devices = top(sel.devices, 6);
  return wrap([h('div', { class: 'card-h' }, h('h3', { class: 'ellip', title: sel.label }, sel.label), close),
    h('div', { class: 'card-b stack' },
      h('div', { class: 'row' }, h('span', { class: 'pill ' + (sel.b === 0 ? 'ok' : sel.b / sel.q > .5 ? 'bad' : 'warn') }, sel.b === 0 ? 'Allowed' : sel.b === sel.q ? 'Blocked' : 'Partly blocked')),
      h('dl', { class: 'kv' }, kv('Lookups', F.n(sel.q)), kv('Blocked', `${F.n(sel.b)} (${F.pct(share(sel.q, sel.b))})`), kv('Average speed', (sel.ms / sel.q).toFixed(1) + ' ms'), kv('Last lookup', F.ago(sel.last))),
      h('div', {}, h('div', { class: 'lbl mono', style: 'margin-bottom:8px' }, 'Record types'), h('div', { class: 'chips' }, top(sel.types, 8).map(([t, e]) => chip(t, F.n(e.q))))),
      subs.length > 1 || subs[0]?.[0] !== sel.label ? h('div', {}, h('div', { class: 'lbl mono', style: 'margin-bottom:8px' }, 'Names under it'), bars(subs, subs[0][1].q)) : null,
      devices.length ? h('div', {}, h('div', { class: 'lbl mono', style: 'margin-bottom:8px' }, 'Asked by'), bars(devices, devices[0][1].q)) : S.detail === 'anonymous' ? h('p', { class: 'hint', style: 'margin:0' }, 'History is anonymous, so it does not record who asked.') : null)]);
}

/* ---------- page ---------- */
const empty = () => {
  const admin = L.can('admin'), off = S.mode === 'off' && !S.savedRows;
  if (off) return L.empty('Query history is off', 'The traffic map is drawn from your query history, which is off by default so no browsing data exists to leak. Recent-only history stays in memory and disappears on restart.',
    admin ? h('button', { class: 'btn primary', disabled: S.working, onclick: enableHistory }, L.ic('check'), 'Turn on recent history') : h('p', { class: 'hint' }, 'Ask an administrator to turn it on.'));
  return L.empty('No traffic yet', 'Lookups appear here as devices use Lumen. Point a device at this server to see the tree grow.');
};

async function enableHistory() {
  if (!(await L.confirm({ title: 'Show recent queries?', text: 'This keeps which domains were looked up in memory until you turn it off or restart Lumen. Who asked is not recorded unless you change that under Activity.', label: 'Turn on' }))) return;
  S.working = true; L.rerender();
  try { await L.api('PUT', '/api/history', { mode: 'memory', detail: 'anonymous' }); await L.loadTraffic(); L.toast('Recent history is on.'); }
  catch (e) { L.toast(e.message, 'bad'); }
  S.working = false; L.rerender();
}

function stage() {
  const tree = aggregate();
  if (S.expanded === null && tree.list.length) S.expanded = new Set(tree.list.slice(0, 2).map(t => t.id));
  S.expanded ??= new Set();
  const out = h('div', { id: 'tm-stage' });
  if (!tree.q) {
    out.append(h('div', { class: 'card' }, S.items?.length ? L.empty('Nothing matches', 'No lookups fit the current filters. Try a longer time window or clear the search.', h('button', { class: 'btn', onclick: () => { S.win = 0; S.result = 'all'; S.search = ''; S.intro = true; L.rerender(); } }, 'Clear filters')) : empty()));
    return out;
  }
  const lay = layout(tree), svg = drawTree(tree, lay);
  const view = viewport(svg, lay);
  out.append(h('div', { class: 'tm-grid' }, h('div', { class: 'card tm-card' + (S.full ? ' full' : '') }, h('div', { class: 'tm-legend' },
    h('span', {}, h('i', { class: 'lg ok' }), 'Allowed'), h('span', {}, h('i', { class: 'lg bad' }), 'Mostly blocked'), h('span', {}, h('i', { class: 'lg line' }), 'Thicker line = more lookups'),
    S.truncated ? h('span', { class: 'hint' }, L.t('Showing the newest {n} lookups.', { n: F.n(S.items.length) })) : null), view), panel(tree)));
  return out;
}

/* The map is a free canvas: drag to move, scroll or pinch to zoom, double-click to fit. It always fills the space it
   is given, so it follows the window and the sidebar. It keeps fitting itself until the user moves or zooms it. */
const K_MIN = .15, K_MAX = 3;
function viewport(svg, lay) {
  const world = svg.querySelector('.tm-world');
  const pct = h('span', { class: 'tm-zoom mono', 'aria-live': 'off' });
  const vp = h('div', { class: 'tm-view' + (S.used ? ' used' : ''), tabindex: '0', role: 'application', 'aria-label': L.t('Traffic map. Drag to move, scroll to zoom, press 0 to fit.') }, svg);
  S.view ??= { x: 0, y: 0, k: 1 };
  const apply = smooth => {
    const { x, y, k } = S.view;
    world.classList.toggle('smooth', !!smooth);
    world.style.transform = `translate(${x.toFixed(1)}px,${y.toFixed(1)}px) scale(${k.toFixed(4)})`;
    let g = 24 * k; while (g < 14) g *= 2;
    vp.style.backgroundSize = `${g}px ${g}px`; vp.style.backgroundPosition = `${x}px ${y}px`;
    pct.textContent = Math.round(k * 100) + '%';
  };
  const box = () => ({ w: vp.clientWidth || 800, h: vp.clientHeight || 500 });
  const fitView = smooth => {
    const { w, h: ht } = box(), k = Math.min(Math.max(Math.min((w - 56) / lay.width, (ht - 56) / lay.height), K_MIN), 1.15);
    S.view = { k, x: (w - lay.width * k) / 2, y: Math.max(20, (ht - lay.height * k) / 2) }; S.auto = true; apply(smooth);
  };
  const zoomAt = (f, cx, cy, smooth) => {
    const v = S.view, k = Math.min(K_MAX, Math.max(K_MIN, v.k * f)), r = k / v.k;
    S.view = { k, x: cx - (cx - v.x) * r, y: cy - (cy - v.y) * r }; S.auto = false; used(); apply(smooth);
  };
  const used = () => { S.used = true; vp.classList.add('used'); };
  const centre = () => { const { w, h: ht } = box(); return [w / 2, ht / 2]; };
  const rel = e => { const r = vp.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; };

  vp.addEventListener('wheel', e => {
    e.preventDefault();
    const [x, y] = rel(e), dy = e.deltaY * (e.deltaMode === 1 ? 16 : 1);
    zoomAt(Math.exp(-dy * (e.ctrlKey ? .01 : .0016)), x, y, false);
  }, { passive: false });

  const ptrs = new Map(); let moved = false;
  vp.addEventListener('pointerdown', e => {
    if ((e.pointerType === 'mouse' && e.button !== 0) || e.target.closest('.tm-ctl')) return;
    ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY }); moved = false;
  });
  vp.addEventListener('pointermove', e => {
    const p = ptrs.get(e.pointerId); if (!p) return;
    const dx = e.clientX - p.x, dy = e.clientY - p.y;
    if (ptrs.size === 1) {
      if (!moved && Math.hypot(dx, dy) < 4) return;
      if (!moved) { moved = true; vp.setPointerCapture(e.pointerId); vp.classList.add('grab'); used(); }
      S.view = { ...S.view, x: S.view.x + dx, y: S.view.y + dy }; S.auto = false; p.x = e.clientX; p.y = e.clientY; apply(false);
    } else if (ptrs.size === 2) {
      /* Pinch: zoom around the point between the two fingers. */
      const o = [...ptrs.entries()].find(([id]) => id !== e.pointerId)[1];
      const before = Math.hypot(p.x - o.x, p.y - o.y); p.x = e.clientX; p.y = e.clientY;
      const after = Math.hypot(p.x - o.x, p.y - o.y), r = vp.getBoundingClientRect();
      moved = true; if (before > 0) zoomAt(after / before, (p.x + o.x) / 2 - r.left, (p.y + o.y) / 2 - r.top, false);
    }
  });
  const end = e => { ptrs.delete(e.pointerId); if (!ptrs.size) vp.classList.remove('grab'); };
  vp.addEventListener('pointerup', end); vp.addEventListener('pointercancel', end);
  /* A drag that ends on a node must not count as a click on it. */
  vp.addEventListener('click', e => { if (moved) { e.stopPropagation(); e.preventDefault(); moved = false; } }, true);
  vp.addEventListener('dblclick', e => { if (!e.target.closest('.node')) fitView(true); });

  const goFull = on => { S.full = on; vp.closest('.tm-card')?.classList.toggle('full', on); document.body.classList.toggle('tm-lock', on); };
  vp.addEventListener('keydown', e => {
    const step = 64, [cx, cy] = centre(); let ok = true;
    if (e.key === 'ArrowLeft') S.view.x += step; else if (e.key === 'ArrowRight') S.view.x -= step;
    else if (e.key === 'ArrowUp') S.view.y += step; else if (e.key === 'ArrowDown') S.view.y -= step;
    else if (e.key === '+' || e.key === '=') return void (e.preventDefault(), zoomAt(1.25, cx, cy, true));
    else if (e.key === '-') return void (e.preventDefault(), zoomAt(1 / 1.25, cx, cy, true));
    else if (e.key === '0') return void (e.preventDefault(), fitView(true));
    else if (e.key === 'f' || e.key === 'F') return void (e.preventDefault(), goFull(!S.full));
    else if (e.key === 'Escape' && S.full) return void (e.preventDefault(), goFull(false));
    else ok = false;
    if (ok) { e.preventDefault(); S.auto = false; used(); apply(true); }
  });

  const btn = (label, icon, fn) => h('button', { class: 'tm-btn', 'aria-label': label, title: L.t(label), onclick: fn }, icon);
  vp.append(
    h('div', { class: 'tm-ctl' }, btn('Zoom in', '+', () => { const [x, y] = centre(); zoomAt(1.3, x, y, true); }), pct, btn('Zoom out', '−', () => { const [x, y] = centre(); zoomAt(1 / 1.3, x, y, true); }),
      btn('Fit to window', L.ic('fit'), () => fitView(true)), btn(S.full ? 'Exit full screen' : 'Full screen', L.ic('expand'), e => { goFull(!S.full); e.currentTarget.blur(); })),
    h('div', { class: 'tm-hint' }, 'Drag to move · Scroll to zoom · Double-click to fit'));
  /* Follow the size of the box: the window, the sidebar and full screen all change it. */
  new ResizeObserver(() => { if (S.auto) fitView(false); else apply(false); vp.classList.add('ready'); }).observe(vp);
  apply(false);
  return vp;
}
addEventListener('hashchange', () => { S.full = false; document.body.classList.remove('tm-lock'); });

/* Redraw only the picture and its panel. The toolbar, with its search box, is left alone. */
function paint() { const old = L.$('#tm-stage'); if (old) old.replaceWith(stage()); S.intro = false; }

const setLive = () => { live = !live; try { localStorage.setItem(LIVE_KEY, live ? '1' : '0'); } catch { /* storage blocked */ } L.rerender(); };

const toolbar = () => h('div', { class: 'tm-bar' },
  h('input', { class: 'input', placeholder: 'Search domains', 'aria-label': 'Search domains', value: S.search, oninput: e => { S.search = e.target.value; S.intro = true; clearTimeout(toolbar.t); toolbar.t = setTimeout(paint, 200); } }),
  h('div', { class: 'seg', role: 'group', 'aria-label': 'Result' }, RESULTS.map(([k, t]) => h('button', { 'aria-pressed': String(S.result === k), onclick: () => { S.result = k; S.intro = true; L.rerender(); } }, t))),
  h('div', { class: 'seg', role: 'group', 'aria-label': 'Time window' }, WINDOWS.map(([k, t]) => h('button', { 'aria-pressed': String(S.win === k), onclick: () => { S.win = k; S.intro = true; L.rerender(); } }, t))),
  h('div', { class: 'seg', role: 'group', 'aria-label': 'Branches' },
    h('button', { onclick: () => { S.expanded = new Set(aggregate().list.map(t => t.id)); S.intro = true; L.rerender(); } }, 'Open all'), h('button', { onclick: () => { S.expanded = new Set(); S.selected = null; S.intro = true; L.rerender(); } }, 'Close all')));

L.views.trafficmap = () => {
  const head = L.pageHead('Traffic map', 'Where your DNS traffic goes: Lumen at the top, then domain endings, then the domains under them.', h('div', { class: 'row' },
    h('button', { class: 'btn' + (isLive() ? ' primary' : ''), 'aria-pressed': String(isLive()), title: 'Live view refreshes the map every few seconds.', onclick: setLive }, h('i', { class: 'live-dot' + (isLive() ? ' on' : ''), 'aria-hidden': 'true' }), 'Live'),
    h('button', { class: 'btn', onclick: async () => { try { await L.loadTraffic(); S.intro = true; L.rerender(); } catch (e) { L.toast(e.message, 'bad'); } } }, L.ic('refresh'), 'Refresh')));
  /* The entrance animation plays once per change, not on every redraw. */
  const body = [head, S.items?.length || S.mode !== 'off' || S.savedRows ? toolbar() : null, stage()];
  S.intro = false;
  return body;
};

/* One quiet refresh. The picture is repainted in place without replaying the entrance animation. */
let polling = false;
setInterval(async () => {
  if (!isLive() || polling || document.hidden || !L.session || L.route().page !== 'trafficmap' || L.$('dialog[open]') || S.working || S.mode === 'off' && !S.savedRows) return;
  polling = true;
  try { await L.loadTraffic(); paint(); } catch { /* next tick */ }
  polling = false;
}, LIVE_MS);
})();
