(() => {
'use strict';
const L = window.L, h = L.h;
let q = '', flt = 'all', shown = 50;
const rows = () => L.S.history.items;
const match = r => (flt === 'all' || (flt === 'blocked') === r.blocked) && (!q || (r.domain + (r.device || '') + r.client).toLowerCase().includes(q.toLowerCase()));
const table = () => {
  const list = rows().filter(match);
  return h('div', { id: 'hist-body' },
    h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Time (UTC)', 'Domain', 'Type', 'Device', 'Result', 'Latency'].map((x, i) => h('th', { class: i === 5 ? 'r' : '' }, x)))),
      h('tbody', {}, list.length ? list.slice(0, shown).map(r => h('tr', {}, h('td', { class: 'mono-c' }, new Date(r.t).toISOString().slice(11, 19)), h('td', {}, r.domain), h('td', { class: 'mono-c' }, r.type),
        h('td', {}, r.device || r.client, r.device ? h('div', { class: 'hint mono' }, r.client) : null), h('td', {}, h('span', { class: 'pill ' + (r.blocked ? 'bad' : r.rcode === 'SERVFAIL' ? 'warn' : 'ok') }, r.blocked ? 'Blocked' : r.rcode === 'NOERROR' ? 'Allowed' : r.rcode)), h('td', { class: 'mono-c r' }, r.ms.toFixed(1) + ' ms'))) : h('tr', {}, h('td', { colspan: 6, class: 'muted' }, rows().length ? 'No matching entries.' : 'No queries yet. They appear here as devices look things up.'))))),
    list.length > shown ? h('div', { class: 'card-b row', style: 'justify-content:center' }, h('button', { class: 'btn', onclick: () => { shown += 50; L.$('#hist-body').replaceWith(table()); } }, `Show more (${list.length - shown})`)) : null);
};
L.views.activity = () => {
  const on = L.S.history.enabled;
  const toggle = h('div', { class: 'card' }, h('div', { class: 'card-b row' },
    h('div', { class: 'sp' }, h('strong', {}, 'Recent queries'), h('div', { class: 'hint' }, on ? 'Keeps the last 1,000 lookups (domain, device, result) in memory only. They are never written to disk and disappear when you turn this off or restart Lumen.' : 'Off by default. Lumen keeps only counters, so no browsing data exists to leak.')),
    L.f.sw({ v: on }, 'v', on ? 'On' : 'Off', { disabled: !L.can('admin'), onChange: async v => {
      if (v && !(await L.confirm({ title: 'Show recent queries?', text: 'This keeps which device looked up which domain, in memory, until you turn it off or restart Lumen. Only enable it if everyone on the network knows.', label: 'Turn on' }))) return L.rerender();
      try { await L.api('PUT', '/api/history', { enabled: v }); await L.loadHistory(); L.rerender(); } catch (e) { L.toast(e.message, 'bad'); L.rerender(); } } })));
  if (!on) return [L.pageHead('Activity', 'Which devices asked for what, and what happened to it.'), toggle,
    h('div', { class: 'card', style: 'margin-top:16px' }, L.empty('Recent queries are off', 'Per-domain activity is opt-in. While it is off, the Overview still shows rates, blocked share, latency and answers, none of which identify a person.'))];
  return [L.pageHead('Activity', 'Newest first. Nothing here is stored on disk.', h('button', { class: 'btn', onclick: async () => { try { await L.loadHistory(); shown = 50; L.rerender(); } catch (e) { L.toast(e.message, 'bad'); } } }, L.ic('refresh'), 'Refresh')), toggle,
    h('div', { class: 'card', style: 'margin-top:16px' }, h('div', { class: 'card-h' },
      h('div', { class: 'row' }, h('input', { class: 'input', style: 'width:260px', placeholder: 'Search domain, device or IP', value: q, 'aria-label': 'Search', oninput: e => { q = e.target.value; shown = 50; L.$('#hist-body').replaceWith(table()); } }),
        h('div', { class: 'seg' }, ['all', 'allowed', 'blocked'].map(k => h('button', { 'aria-pressed': String(flt === k), onclick: () => { flt = k; shown = 50; L.rerender(); } }, k[0].toUpperCase() + k.slice(1))))),
      h('span', { class: 'mono muted' }, `${rows().length} recent`)), table())];
};
})();
