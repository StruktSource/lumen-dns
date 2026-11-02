/* Live activity panel: shows applies and list downloads on every page, tells you when they finish or fail. */
(() => {
'use strict';
const L = window.L, h = L.h, F = L.fmt;
const BUSY = new Set(['checking', 'downloading', 'starting']);
const STATE = { waiting: 'Waiting', downloading: 'Downloading', parsing: 'Reading rules', ready: 'Ready', failed: 'Failed' };
const mb = n => (n / 1048576).toFixed(n >= 10485760 ? 0 : 1) + ' MB';
let panel = null, timer = null, seen = null, wasBusy = false, collapsed = false, offline = 0; let last = null;
const dismissed = () => sessionStorage.getItem('lumen.act.dismissed');

/* A bundle chosen during setup is installed through the normal config flow, so it is visible and retryable. */
L.pendingBundle = () => localStorage.getItem('lumen.pendingBundle');
L.runPendingBundle = async () => {
  const id = L.pendingBundle(); if (!id || !L.catalog) return;
  const bundle = L.catalog.bundles.find(b => b.key === id); if (!bundle) { localStorage.removeItem('lumen.pendingBundle'); return; }
  try {
    await L.loadConfig(); const cfg = L.clone(L.S.cfg); const have = new Set(cfg.filtering.lists.map(l => l.id));
    for (const c of L.catalog.items.filter(c => bundle.ids.includes(c.id) && !have.has(c.id))) cfg.filtering.lists.push({ id: c.id, format: c.format, url: c.url, path: '', text: '', category: '', refresh_secs: 86400 });
    for (const p of cfg.filtering.profiles) if (p.lists.length) p.lists = [...new Set([...p.lists, ...bundle.ids])];
    await L.api('PUT', '/api/config', L.toServer(cfg)); sessionStorage.removeItem('lumen.act.dismissed'); L.activity.poke();
  } catch (e) { L.toast('Could not start installing the block lists: ' + e.message, 'bad'); }
};

function render(a) {
  const busy = BUSY.has(a.phase), failed = a.phase === 'failed' && dismissed() !== String(a.since) && (a.since === 0 || Date.now() / 1000 - a.since < 900);
  const show = busy || failed || (a.lists.some(l => l.state === 'downloading' || l.state === 'parsing'));
  if (!show) { panel?.remove(); panel = null; return; }
  const title = failed ? 'Not applied' : a.phase === 'starting' ? 'Restarting DNS' : 'Working on it';
  const rows = a.lists.map(l => { const pct = l.total ? Math.min(100, l.bytes / l.total * 100) : null; const sub = l.state === 'downloading' ? (l.total ? `${mb(l.bytes)} of ${mb(l.total)}` : l.bytes ? mb(l.bytes) : 'connecting…') : l.state === 'ready' ? F.n(l.rules) + ' rules' : l.state === 'failed' ? (l.error || 'failed') : STATE[l.state];
    return h('li', { class: 'act-' + l.state }, h('div', { class: 'act-row' }, h('b', { class: 'mono' }, l.id), h('span', {}, sub)), h('div', { class: 'bar' + (l.state === 'downloading' && pct == null ? ' ind' : ''), role: 'progressbar', 'aria-label': l.id, 'aria-valuenow': pct == null ? null : Math.round(pct) }, h('i', { style: `width:${l.state === 'ready' ? 100 : l.state === 'parsing' ? 100 : pct ?? 35}%` }))); });
  const next = h('aside', { id: 'actbar', class: 'actbar' + (failed ? ' bad' : '') + (collapsed ? ' min' : ''), role: failed ? 'alert' : 'status', 'aria-live': 'polite' },
    h('div', { class: 'act-h' }, busy ? h('i', { class: 'spin', 'aria-hidden': 'true' }) : null, h('strong', {}, title), h('span', { class: 'sp' }), h('button', { class: 'linkish', type: 'button', onclick: () => { collapsed = !collapsed; render(a); } }, collapsed ? 'Show' : 'Hide')),
    collapsed ? null : h('div', { class: 'act-b' }, h('p', {}, a.message || ''), rows.length ? h('ul', {}, rows) : null,
      failed ? h('div', { class: 'row' }, L.pendingBundle() ? h('button', { class: 'btn sm primary', onclick: () => L.runPendingBundle() }, 'Try again') : null, h('button', { class: 'btn sm', onclick: () => { sessionStorage.setItem('lumen.act.dismissed', String(a.since)); render(a); } }, 'Dismiss')) : null));
  if (panel) panel.replaceWith(next); else document.body.append(next); panel = next;
}

async function tick() {
  clearTimeout(timer); let delay = 8000;
  if (L.session && !document.hidden) {
    try {
      const s = await L.api('GET', '/api/status'); offline = 0; last = s; const a = s.activity; const busy = BUSY.has(a.phase) || s.pending_revision != null;
      if (a.phase === 'idle' && s.pending_revision != null) { a.phase = 'checking'; a.message = a.message || 'Applying your changes'; }
      render(a); delay = busy ? 1000 : 8000;
      if (wasBusy && !busy) {
        if (a.phase === 'done') { const n = a.lists.filter(l => l.state === 'ready').length; L.toast(n ? `Done. ${n} block list${n > 1 ? 's' : ''} loaded, ${F.n(a.lists.reduce((x, l) => x + l.rules, 0))} rules in total.` : a.message, 'ok'); if (L.pendingBundle()) localStorage.removeItem('lumen.pendingBundle'); L.S.draft || L.loadConfig().catch(() => {}); if (L.route().page === 'filtering') L.rerender(); }
        else if (a.phase === 'failed') L.toast(a.message || 'The change was not applied.', 'bad');
      }
      wasBusy = busy;
      // The setup wizard hands its block-list choice over once the first settings are live.
      if (L.pendingBundle() && !busy && s.pending_revision == null && a.phase !== 'failed' && s.revision >= 1 && !L.pendingStarted) { L.pendingStarted = true; await L.runPendingBundle(); delay = 600; }
      if (!L.pendingBundle()) L.pendingStarted = false;
    } catch (e) { if (e.status !== 401 && wasBusy) { offline++; render({ phase: 'starting', message: 'Lumen is restarting its listeners. This page reconnects by itself.', lists: last?.activity?.lists || [], since: 0 }); delay = 1000; } }
  }
  timer = setTimeout(tick, delay);
}
L.activity = { poke: () => { clearTimeout(timer); timer = setTimeout(tick, 150); }, start: () => { L.activity.poke(); } };
L.activity.start();
})();
