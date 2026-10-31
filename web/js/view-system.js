(() => {
'use strict';
const L = window.L, h = L.h, F = L.fmt;
const act = async (path, msg, opt) => { if (await L.confirm(opt)) { try { await L.api('POST', path); L.toast(msg); setTimeout(() => L.refreshPage(), 1800); } catch (e) { L.toast(e.message, 'bad'); } } };
L.views.system = () => {
  const s = L.S.status, cfg = L.S.cfg, revs = L.S.revisions;
  const restore = async r => {
    if (!(await L.confirm({ title: `Restore revision ${r.revision}`, text: 'This applies those settings as a new revision. Lumen restarts its listeners and clears DNS caches. Devices are not changed.', label: 'Restore and reload' }))) return;
    try { const out = await L.api('POST', '/api/config/restore', { revision: r.revision }); L.toast(`Applying revision ${out.revision}…`); const res = await L.waitForConfig(out.revision); L.S.draft = null; if (res.ok) L.toast('Restored.'); else L.toast(res.error || 'Lumen refused those settings.', 'bad'); await L.refreshPage(); } catch (e) { L.toast(e.message, 'bad'); }
  };
  return [L.pageHead('System', 'Daemon status, control actions and configuration history.', h('span', { class: 'pill ' + (s.daemon === 'running' ? 'ok' : 'bad') }, s.daemon === 'running' ? 'Healthy' : s.daemon)),
    h('div', { class: 'grid g2' },
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Daemon')), h('div', { class: 'card-b' }, h('dl', { class: 'kv' },
        h('dt', {}, 'Version'), h('dd', {}, 'Lumen ' + s.version), h('dt', {}, 'Uptime'), h('dd', {}, F.dur(s.uptime_secs)), h('dt', {}, 'State'), h('dd', {}, s.daemon), h('dt', {}, 'Active revision'), h('dd', {}, '#' + s.revision),
        s.pending_revision ? [h('dt', {}, 'Applying'), h('dd', {}, '#' + s.pending_revision)] : null, h('dt', {}, 'Last control message'), h('dd', {}, s.last_error || 'none'),
        s.rss_bytes ? [h('dt', {}, 'Memory'), h('dd', {}, (s.rss_bytes / 1048576).toFixed(1) + ' MiB')] : null,
        h('dt', {}, 'Health'), h('dd', {}, cfg?.metrics ? cfg.metrics + '/healthz' : 'metrics endpoint off'), h('dt', {}, 'Metrics'), h('dd', {}, cfg?.metrics ? cfg.metrics + '/metrics' : 'off')))),
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Control')), h('div', { class: 'card-b stack' },
        h('div', { class: 'row' }, h('div', { class: 'sp' }, h('strong', {}, 'Refresh filter lists'), h('div', { class: 'hint' }, 'Fetch every source and publish a new generation.')), h('button', { class: 'btn', onclick: () => act('/api/filter/refresh', 'Filter refresh queued.', { title: 'Refresh filter lists', text: 'Every list is downloaded again. Nothing changes if any of them fails.', label: 'Refresh' }) }, L.ic('refresh'), 'Refresh')),
        h('div', { class: 'row' }, h('div', { class: 'sp' }, h('strong', {}, 'Roll back filter lists'), h('div', { class: 'hint' }, 'Swap to the previous successful generation.')), h('button', { class: 'btn', onclick: () => act('/api/filter/rollback', 'Rollback queued.', { title: 'Roll back filter lists', text: 'Automatic refresh pauses until the next successful manual refresh.', label: 'Roll back' }) }, L.ic('undo'), 'Roll back')),
        h('div', { class: 'row' }, h('div', { class: 'sp' }, h('strong', {}, 'Reload configuration'), h('div', { class: 'hint' }, 'Restarts listeners, closes connections, clears caches.')), h('button', { class: 'btn', onclick: () => act('/api/reload', 'Reload queued.', { title: 'Reload configuration', text: 'Listeners restart briefly and DNS caches clear.', label: 'Reload' }) }, L.ic('refresh'), 'Reload')),
        h('div', { class: 'row' }, h('div', { class: 'sp' }, h('strong', {}, 'Shut down'), h('div', { class: 'hint' }, 'Stops DNS for every device until the service is started again.')), h('button', { class: 'btn danger', onclick: () => act('/api/shutdown', 'Shutdown queued.', { title: 'Shut down Lumen', text: 'This stops Lumen and this console. DNS stops working for every device on your network until you start the service again.', label: 'Shut down', danger: true, typed: 'SHUTDOWN' }) }, L.ic('power'), 'Shut down'))))),
    h('div', { class: 'sec-title' }, h('h2', {}, 'Configuration history'), h('span', { class: 'mono muted' }, `${revs.length} kept`)),
    h('div', { class: 'card' }, h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Revision', 'Applied', 'By', ''].map(x => h('th', {}, x)))), h('tbody', {}, revs.map((r, i) => h('tr', {}, h('td', {}, h('strong', {}, '#' + r.revision), r.revision === s.revision ? h('span', { class: 'pill ok', style: 'margin-left:8px' }, 'Active') : null), h('td', {}, F.ago(r.t * 1000)), h('td', {}, r.actor || 'startup file'),
      h('td', { class: 'act' }, h('button', { class: 'btn sm flat', onclick: () => L.modal({ title: 'Revision #' + r.revision, wide: true, body: [h('pre', { class: 'code' }, r.toml)], actions: [{ label: 'Close' }] }) }, L.ic('file'), 'View'),
        r.revision !== s.revision ? h('button', { class: 'btn sm', onclick: () => restore(r) }, L.ic('undo'), 'Restore') : null)))))))];
};
})();
