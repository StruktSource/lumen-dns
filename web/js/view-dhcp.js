/* DHCP module: the scopes Lumen serves and the leases it has handed out. Read-only; the
   configuration file decides what is served. */
(() => {
'use strict';
const L = window.L, h = L.h;
let q = '';

L.loadDhcp = async () => { L.S.dhcp = await L.api('GET', '/api/dhcp'); };

const summary = d => {
  const active = d.scopes.reduce((n, s) => n + s.active, 0), capacity = d.scopes.reduce((n, s) => n + s.capacity, 0);
  const tile = (label, value) => h('div', { class: 'card' }, h('div', { class: 'card-b' }, h('div', { class: 'muted' }, label), h('div', { style: 'font-size:1.6em;font-weight:600' }, value)));
  return h('div', { class: 'grid g3' }, tile('Networks', L.fmt.n(d.scopes.length)), tile('Leases', L.fmt.n(active)), tile('Free addresses', L.fmt.n(Math.max(0, capacity - active))));
};

const renew = async l => {
  try { await L.api('POST', '/api/dhcp/reconfigure', { ip: l.ip }); L.toast(L.t('{ip} was asked to renew.', { ip: l.ip })); }
  catch (e) { L.toast(e.message, 'bad'); }
};

L.views.dhcp = () => {
  const d = L.S.dhcp;
  const head = L.pageHead('DHCP', 'Addresses handed out on your network, and the DNS names they become.',
    h('button', { class: 'btn', onclick: async () => { try { await L.loadDhcp(); L.rerender(); } catch (e) { L.toast(e.message, 'bad'); } } }, 'Refresh'));
  if (!d) return [head, L.empty('Loading', 'One moment.')];
  if (!d.running) return [head, L.empty('The DHCP server is not running', 'Turn it on in the configuration (dhcp.enabled). Lumen never hands out addresses on its own.')];
  const leases = d.leases.filter(l => !q || (l.ip + l.client + (l.hostname || '')).toLowerCase().includes(q.toLowerCase()));
  const fo = d.failover ? h('div', { class: 'note', style: 'margin-top:16px' }, L.ic('info'), h('p', {}, L.t(d.failover.active ? 'Failover: this is the {role} server and it is answering clients.' : 'Failover: this is the {role} server and it is standing by.', { role: d.failover.role === 'primary' ? L.t('primary') : L.t('secondary') }))) : null;
  return [head, summary(d), fo,
    h('div', { class: 'card', style: 'margin-top:16px' }, h('div', { class: 'card-h' }, h('strong', {}, 'Networks')),
      h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Network', 'Range', 'In use'].map(x => h('th', {}, x)))),
        h('tbody', {}, d.scopes.map(s => h('tr', {}, h('td', {}, h('strong', {}, s.network), ' ', h('span', { class: 'chip' }, 'IPv' + s.family), s.interface ? [' ', h('span', { class: 'hint' }, s.interface)] : null),
          h('td', { class: 'mono-c' }, s.range), h('td', {}, L.fmt.n(s.active) + ' / ' + L.fmt.n(s.capacity)))))))),
    h('div', { class: 'card', style: 'margin-top:16px' },
      h('div', { class: 'card-h' }, h('input', { class: 'input', style: 'width:280px', placeholder: 'Search leases', 'aria-label': 'Search leases', value: q, oninput: e => { q = e.target.value; L.paintMain(); const i = L.$('input[aria-label="Search leases"]'); i.focus(); i.setSelectionRange(q.length, q.length); } }), h('span', { class: 'mono muted' }, L.fmt.n(d.leases.length))),
      leases.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Address', 'Name', 'Device', 'Expires', ''].map(x => h('th', {}, x)))),
        h('tbody', {}, leases.map(l => h('tr', {}, h('td', { class: 'mono-c' }, l.prefix_len ? l.ip + '/' + l.prefix_len : l.ip, l.temporary ? [' ', h('span', { class: 'chip' }, 'Temporary')] : null), h('td', {}, l.hostname ? h('strong', {}, l.hostname) : h('span', { class: 'muted' }, '—')), h('td', { class: 'mono-c' }, l.client), h('td', { class: 'mono-c' }, L.fmt.time(l.expires * 1000)), h('td', { class: 'act' }, l.reconfigurable ? h('button', { class: 'btn sm flat', onclick: () => renew(l) }, 'Ask to renew') : null))))))
        : L.empty('No leases yet', q ? 'Nothing matches your search.' : 'Devices that ask for an address will show up here.'))];
};
})();
