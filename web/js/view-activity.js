/* Activity: which devices asked for what, with the opt-in query history controls. */
(() => {
'use strict';
const L = window.L, h = L.h;
let q = { search: '', filter: 'all' }, timer = null, form = null, working = false;

const MODES = [
  ['off', 'Off', 'Only counters are kept. No lookups are recorded.'],
  ['memory', 'Recent only', 'Keeps the last 1,000 lookups in memory. Nothing is written to disk, and they disappear when you switch this off or restart Lumen.'],
  ['saved', 'Saved', 'Saves lookups in the state database until the retention period ends, so you can look back over days.']];
const day = ms => new Date(ms).toISOString().slice(0, 10);

const reload = async more => {
  try { await L.loadHistory(q, more); L.$('#hist-body')?.replaceWith(table()); } catch (e) { L.toast(e.message, 'bad'); }
};

const table = () => {
  const H = L.S.history, rows = H.items, anon = H.detail === 'anonymous';
  return h('div', { id: 'hist-body' },
    h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Time (UTC)', 'Domain', 'Type', 'Device', 'Result', 'Latency'].map((x, i) => h('th', { class: i === 5 ? 'r' : '' }, x)))),
      h('tbody', {}, rows.length ? rows.map(r => h('tr', {}, h('td', { class: 'mono-c' }, new Date(r.t).toISOString().slice(11, 19)), h('td', {}, r.domain), h('td', { class: 'mono-c' }, r.type),
        h('td', {}, r.device || r.client || h('span', { class: 'muted', title: 'Anonymous history does not record who asked.' }, '—'), r.device && r.client ? h('div', { class: 'hint mono' }, r.client) : null),
        h('td', {}, h('span', { class: 'pill ' + (r.blocked ? 'bad' : r.rcode === 'SERVFAIL' ? 'warn' : 'ok') }, r.blocked ? 'Blocked' : r.rcode === 'NOERROR' ? 'Allowed' : r.rcode)), h('td', { class: 'mono-c r' }, r.ms.toFixed(1) + ' ms')))
        : h('tr', {}, h('td', { colspan: 6, class: 'muted' }, q.search || q.filter !== 'all' ? 'No matching entries.' : 'No queries yet. They appear here as devices look things up.'))))),
    H.next_before ? h('div', { class: 'card-b row', style: 'justify-content:center' }, h('button', { class: 'btn', onclick: () => reload(true) }, 'Show more')) : null,
    anon && rows.length ? h('div', { class: 'card-b hint' }, 'This history is anonymous: it does not record which device asked.') : null);
};

const apply = async () => {
  const f = form, days = f.retention_days;
  if (f.mode === 'saved' && !(Number.isInteger(days) && days >= 1 && days <= 90)) return L.toast('Keep lookups for 1 to 90 days.', 'bad');
  if (f.mode !== 'off' && !(await L.confirm({
    title: f.mode === 'saved' ? 'Save query history?' : 'Show recent queries?',
    text: f.mode === 'saved'
      ? L.t(f.detail === 'full' ? 'Lumen will save which device looked up which domain, for {days} days, in the state database on this machine. Only enable it if everyone on the network knows.' : 'Lumen will save which domains were looked up, without who asked, for {days} days, in the state database on this machine.', { days })
      : L.t(f.detail === 'full' ? 'This keeps which device looked up which domain, in memory, until you turn it off or restart Lumen. Only enable it if everyone on the network knows.' : 'This keeps which domains were looked up, without who asked, in memory until you turn it off or restart Lumen.'),
    label: 'Turn on' }))) return;
  working = true; L.rerender();
  try {
    await L.api('PUT', '/api/history', { mode: f.mode, detail: f.detail, retention_days: days });
    form = null; await L.loadHistory(q); L.toast('History settings saved.');
  } catch (e) { L.toast(e.message, 'bad'); }
  working = false; L.rerender();
};

const wipe = async () => {
  if (!(await L.confirm({ title: 'Delete saved history?', text: L.t('This permanently deletes all {n} saved lookups. It cannot be undone.', { n: L.fmt.n(L.S.history.saved.rows) }), label: 'Delete everything', danger: true }))) return;
  try { const r = await L.api('DELETE', '/api/history'); await L.loadHistory(q); L.toast(L.t('Deleted {n} saved lookups.', { n: L.fmt.n(r.removed) })); L.rerender(); } catch (e) { L.toast(e.message, 'bad'); }
};

const controls = () => {
  const H = L.S.history, admin = L.can('admin');
  form ??= { mode: H.mode, detail: H.detail, retention_days: H.retention_days };
  const f = form, saved = H.saved?.rows || 0;
  const summary = H.mode === 'saved' || saved
    ? h('div', { class: 'hint' }, saved ? L.t('{n} lookups saved, from {from} to {to}.', { n: L.fmt.n(saved), from: day(H.saved.oldest), to: day(H.saved.newest) }) : 'Nothing saved yet.',
      ' ', L.t('Kept for {days} days, at most {max} lookups.', { days: H.retention_days, max: L.fmt.n(H.max_rows) }))
    : null;
  if (!admin) return h('div', { class: 'card' }, h('div', { class: 'card-b' }, h('strong', {}, 'Query history'),
    h('div', { class: 'hint' }, H.mode === 'off' ? 'Off. Only an administrator can turn it on.' : L.t(H.mode === 'saved' ? 'Saved lookups are kept for {days} days.' : 'Recent lookups are kept in memory.', { days: H.retention_days })), summary));
  const dirty = f.mode !== H.mode || f.detail !== H.detail || (f.mode === 'saved' && f.retention_days !== H.retention_days);
  return h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Query history'), h('span', { class: 'pill ' + (H.mode === 'off' ? 'plain' : 'warn') }, H.mode === 'off' ? 'Off' : H.mode === 'saved' ? 'Saved' : 'Recent only')),
    h('div', { class: 'card-b stack' },
      h('p', { class: 'muted', style: 'margin:0' }, 'Off by default. Without it, Lumen keeps only counters, so no browsing data exists to leak.'),
      h('div', { class: 'picks' }, MODES.map(([v, t, d]) => h('label', { class: 'pick' }, h('input', { type: 'radio', name: 'hmode', checked: f.mode === v, disabled: working, onchange: () => { f.mode = v; L.rerender(); } }), h('div', {}, h('b', {}, t), h('span', {}, d))))),
      f.mode === 'off' ? null : h('div', { class: 'field' }, h('label', {}, 'Who asked'),
        L.f.seg(f, 'detail', [['anonymous', 'Anonymous'], ['full', 'Device and address']], { disabled: working, onChange: () => L.rerender() }),
        h('div', { class: 'hint' }, f.detail === 'anonymous' ? 'Records the domain, type, result and speed only. It does not record which device or address asked.' : 'Also records the device name and IP address, so you can see who asked for what.')),
      f.mode === 'saved' ? h('div', { class: 'field' }, h('label', {}, 'Keep lookups for'), h('div', { class: 'unit' }, h('input', { class: 'input mono-in', type: 'number', min: 1, max: 90, step: 1, value: f.retention_days, disabled: working, oninput: e => { f.retention_days = e.target.value === '' ? NaN : +e.target.value; } }), h('span', {}, 'days')),
        h('div', { class: 'hint' }, L.t('Older lookups are deleted automatically. At most {max} lookups are kept, whatever the period.', { max: L.fmt.n(H.max_rows) }))) : null,
      summary,
      h('div', { class: 'row' }, h('button', { class: 'btn primary', disabled: working || !dirty, onclick: apply }, L.ic('check'), 'Save'),
        saved ? h('button', { class: 'btn danger', disabled: working, onclick: wipe }, L.ic('trash'), 'Delete saved history') : null)));
};

L.views.activity = () => {
  const H = L.S.history, showTable = H.mode !== 'off' || (H.saved?.rows || 0) > 0;
  const head = L.pageHead('Activity', H.mode === 'saved' ? 'Newest first. Saved in the state database.' : 'Which devices asked for what, and what happened to it.',
    showTable ? h('button', { class: 'btn', onclick: () => reload(false) }, L.ic('refresh'), 'Refresh') : null);
  if (!showTable) return [head, controls(), h('div', { class: 'card', style: 'margin-top:16px' }, L.empty('Query history is off', 'Per-domain activity is opt-in. While it is off, the Overview still shows rates, blocked share, latency and answers, none of which identify a person.'))];
  return [head, controls(),
    h('div', { class: 'card', style: 'margin-top:16px' }, h('div', { class: 'card-h' },
      h('div', { class: 'row' }, h('input', { class: 'input', style: 'width:260px', placeholder: 'Search domain, device or IP', value: q.search, 'aria-label': 'Search', oninput: e => { q.search = e.target.value; clearTimeout(timer); timer = setTimeout(() => reload(false), 250); } }),
        h('div', { class: 'seg' }, [['all', 'All'], ['allowed', 'Allowed'], ['blocked', 'Blocked']].map(([k, t]) => h('button', { 'aria-pressed': String(q.filter === k), onclick: () => { q.filter = k; reload(false).then(() => L.rerender()); } }, t)))),
      h('span', { class: 'mono muted' }, L.t('{n} shown', { n: H.items.length }))), table())];
};
})();
