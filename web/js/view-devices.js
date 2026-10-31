(() => {
'use strict';
const L = window.L, h = L.h;
let q = '';
function edit(dev) {
  const isNew = !dev; const d = dev ? L.clone(dev) : { id: '', addresses: [], profile: '', group: '' }; d.profile ||= ''; d.group ||= ''; const F = L.S.cfg.filtering; const err = h('div', { class: 'err' });
  L.modal({ title: isNew ? 'Add device' : 'Edit ' + dev.id, body: [
    L.f.field('Device name', L.f.text(d, 'id', { mono: true, placeholder: 'kids-tablet', disabled: !isNew, validate: L.v.id }), 'Letters, digits, dash and underscore.'),
    L.f.field('IP addresses', L.f.tags(d.addresses, { validate: L.v.ip, placeholder: '192.168.1.31 or 2001:db8::31', max: 32, what: 'as an IP address' }), 'Policy matches on source IP. Give the device a fixed address (DHCP reservation) so it keeps its rules. A proxy or NAT can hide the real device.'),
    h('div', { class: 'fgrid' }, L.f.field('Profile', L.f.sel(d, 'profile', [['', '— none —'], ...F.profiles.map(p => p.id)])), L.f.field('Group', L.f.sel(d, 'group', [['', '— none —'], ...F.groups.map(g => g.id)]))),
    err],
    actions: [{ label: 'Cancel' }, { label: isNew ? 'Add device' : 'Save', kind: 'primary', onClick: async () => {
      if (!L.v.id(d.id)) { err.textContent = 'Enter a valid device name.'; return false; }
      if (isNew && L.S.devices.some(x => x.id === d.id)) { err.textContent = 'A device with this name exists.'; return false; }
      if (!d.addresses.length) { err.textContent = 'Add at least one IP address.'; return false; }
      if (!d.profile && !d.group) { err.textContent = 'Choose a profile, a group, or both.'; return false; }
      const dup = L.S.devices.find(x => x.id !== d.id && x.addresses.some(a => d.addresses.includes(a))); if (dup) { err.textContent = `An address is already used by ${dup.id}.`; return false; }
      try { await L.api('PUT', '/api/devices', { id: d.id, addresses: d.addresses, profile: d.profile || null, group: d.group || null }); } catch (e) { err.textContent = e.message; return false; }
      L.toast(`${d.id} saved. Applying…`); await L.refreshPage(); } }] });
}
L.views.devices = () => {
  const admin = L.can('admin'); const list = L.S.devices.filter(d => !q || (d.id + d.addresses.join(' ') + (d.group || '') + (d.profile || '')).toLowerCase().includes(q.toLowerCase()));
  const F = L.S.cfg?.filtering;
  return [L.pageHead('Devices', 'Give a device or group its own filter profile. Matching uses the source IP address.', admin ? h('button', { class: 'btn primary', onclick: () => edit(null) }, L.ic('plus'), 'Add device') : null),
    h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('input', { class: 'input', style: 'width:280px', placeholder: 'Search devices', 'aria-label': 'Search devices', value: q, oninput: e => { q = e.target.value; L.paintMain(); const i = L.$('input[aria-label="Search devices"]'); i.focus(); i.setSelectionRange(q.length, q.length); } }), h('span', { class: 'mono muted' }, `${L.S.devices.length} of 1024`)),
      list.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Device', 'Addresses', 'Group', 'Profile', ''].map(x => h('th', {}, x)))), h('tbody', {}, list.map(d => {
        const eff = d.profile || F?.groups.find(g => g.id === d.group)?.profile || '—';
        return h('tr', {}, h('td', {}, h('strong', {}, d.id)), h('td', { class: 'mono-c' }, d.addresses.join(', ')), h('td', {}, d.group ? h('span', { class: 'chip' }, d.group) : h('span', { class: 'muted' }, '—')),
          h('td', {}, h('span', { class: 'chip' }, eff), d.profile ? null : h('span', { class: 'hint' }, ' via group')),
          h('td', { class: 'act' }, admin ? [h('button', { class: 'btn sm flat', 'aria-label': 'Edit ' + d.id, onclick: () => edit(d) }, L.ic('pencil')), h('button', { class: 'btn sm flat danger', 'aria-label': 'Remove ' + d.id, onclick: async () => { if (await L.confirm({ title: 'Remove ' + d.id, text: 'The device falls back to subnet and default profile policy.', label: 'Remove', danger: true })) { try { await L.api('DELETE', '/api/devices/' + encodeURIComponent(d.id)); L.toast('Device removed. Applying…'); await L.refreshPage(); } catch (e) { L.toast(e.message, 'bad'); } } } }, L.ic('trash'))] : null));
      })))) : L.empty('No devices', q ? 'Nothing matches your search.' : 'Unknown clients use the default profile.', admin && !q ? h('button', { class: 'btn primary', onclick: () => edit(null) }, 'Add device') : null)),
    F ? h('div', { class: 'note', style: 'margin-top:16px' }, L.ic('info'), h('p', {}, h('b', {}, 'How a client picks its policy: '), 'the device’s own profile, then its group’s profile, then the longest matching subnet, then the default profile (', h('code', {}, F.default_profile || 'none'), '). Device changes apply after a short reload.')) : null];
};
})();
