/* IPAM module: subnets, IP addresses, VLANs and locations. It is bookkeeping: nothing here
   configures a device, hands out a DHCP lease, or changes a network interface. */
(() => {
'use strict';
const L = window.L, h = L.h;

const TABS = [['overview', 'Overview'], ['subnets', 'Subnets'], ['addresses', 'IP addresses'], ['vlans', 'VLANs'], ['locations', 'Locations']];
const KINDS = [['site', 'Site'], ['building', 'Building'], ['floor', 'Floor'], ['room', 'Room'], ['rack', 'Rack']];
const af = { subnet: '', state: '', q: '', location: '' };
let busy = false;

const qs = () => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(af)) if (v) p.set(k, v);
  return p.toString();
};
L.loadIpam = async () => {
  const [home, locations, vlans, subnets, conflicts, addresses] = await Promise.all([
    L.api('GET', '/api/ipam'), L.api('GET', '/api/ipam/locations'), L.api('GET', '/api/ipam/vlans'),
    L.api('GET', '/api/ipam/subnets'), L.api('GET', '/api/ipam/conflicts'), L.api('GET', '/api/ipam/addresses?' + qs())]);
  L.S.ipam = { ...home, locations, vlans, subnets, conflicts, addresses };
};
const reload = async () => { try { await L.loadIpam(); L.rerender(); } catch (e) { L.toast(e.message, 'bad'); } };

/* ---------- lookups ---------- */
const I = () => L.S.ipam;
const byId = (list, id) => list.find(x => x.id === id);
const locPath = id => { const out = []; for (let at = byId(I().locations, id), n = 0; at && n < 20; at = at.parent_id ? byId(I().locations, at.parent_id) : null, n++) out.unshift(at.name); return out.join(' › '); };
const vlanText = id => { const v = byId(I().vlans, id); return v ? 'VLAN ' + v.vid + ' · ' + v.name : ''; };
const depth = s => { let n = 0; for (let at = s; at && at.parent_id && n < 20; at = byId(I().subnets, at.parent_id)) n++; return n; };
const statsOf = id => I().overview.subnets.find(s => s.subnet_id === id);
const dash = h('span', { class: 'muted' }, '—');

/* ---------- a small form dialog ---------- */
/* fields: [{ key, label, type: text|select|switch|area, options, hint, mono, placeholder }] */
const form = ({ title, fields, value, label = 'Save', onSave, wide = false }) => {
  const o = { ...value };
  const body = h('div', { class: 'stack' }, fields.filter(f => !f.hide || !f.hide(o)).map(f => {
    let control;
    if (f.type === 'select') control = L.f.sel(o, f.key, f.options);
    else if (f.type === 'switch') return h('div', { class: 'field' }, L.f.sw(o, f.key, f.label), f.hint ? h('div', { class: 'hint' }, f.hint) : null);
    else if (f.type === 'area') control = h('textarea', { class: 'input mono-in', rows: 4, spellcheck: false, oninput: e => { o[f.key] = e.target.value; } }, o[f.key] || '');
    else control = L.f.text(o, f.key, { mono: f.mono, placeholder: f.placeholder, disabled: f.disabled });
    return L.f.field(f.label, control, f.hint);
  }));
  L.modal({ title, body, wide, actions: [{ label: 'Cancel' }, { label, kind: 'primary', onClick: async () => {
    try { await onSave(o); return true; } catch (e) { L.toast(e.message, 'bad'); return false; } } }] });
};
const send = async (method, path, payload, done) => { await L.api(method, path, payload); await L.loadIpam(); L.rerender(); if (done) L.toast(L.t(done)); };
const none = v => v === '' || v == null ? null : v;
const num = v => v === '' || v == null ? null : Number(v);
const locOptions = () => [['', '— None —'], ...I().locations.map(l => [String(l.id), locPath(l.id)])];
const vlanOptions = () => [['', '— None —'], ...I().vlans.map(v => [String(v.id), vlanText(v.id)])];
const subnetOptions = () => I().subnets.map(s => [String(s.id), s.cidr + (s.name ? ' · ' + s.name : '')]);
const remove = async (what, name, path) => {
  if (!(await L.confirm({ title: L.t('Delete {what}?', { what }), text: L.t('{name} will be removed from the inventory. Nothing changes on your network.', { name }), label: 'Delete', danger: true }))) return;
  try { await send('DELETE', path, null, 'Deleted.'); } catch (e) { L.toast(e.message, 'bad'); }
};

/* ---------- locations ---------- */
const editLocation = loc => form({
  title: loc ? 'Edit location' : 'Add location', value: loc ? { ...loc, parent_id: loc.parent_id ? String(loc.parent_id) : '' } : { kind: 'site', name: '', description: '', parent_id: '' },
  fields: [{ key: 'kind', label: 'Kind', type: 'select', options: KINDS }, { key: 'name', label: 'Name' },
    { key: 'parent_id', label: 'Inside', type: 'select', options: locOptions().filter(([id]) => !loc || id !== String(loc.id)) }, { key: 'description', label: 'Description' }],
  onSave: o => send(loc ? 'PUT' : 'POST', loc ? '/api/ipam/locations/' + loc.id : '/api/ipam/locations', { kind: o.kind, name: o.name, description: o.description || '', parent_id: num(o.parent_id) }, 'Saved.') });

const locationsTab = () => {
  const rows = [];
  const walk = (parent, level) => I().locations.filter(l => (l.parent_id || null) === parent).forEach(l => { rows.push([l, level]); walk(l.id, level + 1); });
  walk(null, 0);
  return [h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('strong', {}, 'Locations'), h('button', { class: 'btn primary', onclick: () => editLocation(null) }, L.ic('plus'), 'Add location')),
    rows.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Name', 'Kind', 'Description', ''].map(x => h('th', {}, x)))),
      h('tbody', {}, rows.map(([l, level]) => h('tr', {}, h('td', { style: 'padding-left:' + (12 + level * 22) + 'px' }, h('strong', {}, l.name)), h('td', {}, h('span', { class: 'chip' }, KINDS.find(k => k[0] === l.kind)?.[1] || l.kind)), h('td', {}, l.description || dash),
        h('td', { class: 'act' }, h('button', { class: 'btn sm flat', onclick: () => editLocation(l) }, 'Edit'), h('button', { class: 'btn sm flat', onclick: () => remove('location', l.name, '/api/ipam/locations/' + l.id) }, 'Delete')))))))
      : L.empty('No locations yet', 'Add sites, buildings, floors, rooms and racks to organize VLANs, subnets and addresses.'))];
};

/* ---------- VLANs ---------- */
const editVlan = vlan => form({
  title: vlan ? 'Edit VLAN' : 'Add VLAN', value: vlan ? { ...vlan, location_id: vlan.location_id ? String(vlan.location_id) : '' } : { vid: '', name: '', description: '', location_id: '' },
  fields: [{ key: 'vid', label: 'VLAN ID', hint: '1 to 4094. Unique within a location.', mono: true }, { key: 'name', label: 'Name' },
    { key: 'location_id', label: 'Location', type: 'select', options: locOptions() }, { key: 'description', label: 'Description' }],
  onSave: o => send(vlan ? 'PUT' : 'POST', vlan ? '/api/ipam/vlans/' + vlan.id : '/api/ipam/vlans', { vid: Number(o.vid), name: o.name, description: o.description || '', location_id: num(o.location_id) }, 'Saved.') });

const vlansTab = () => [h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('strong', {}, 'VLANs'), h('button', { class: 'btn primary', onclick: () => editVlan(null) }, L.ic('plus'), 'Add VLAN')),
  I().vlans.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['ID', 'Name', 'Location', 'Subnets', ''].map(x => h('th', {}, x)))),
    h('tbody', {}, I().vlans.map(v => h('tr', {}, h('td', { class: 'mono-c' }, v.vid), h('td', {}, h('strong', {}, v.name), v.description ? [' ', h('span', { class: 'hint' }, v.description)] : null), h('td', {}, v.location_id ? locPath(v.location_id) : dash),
      h('td', { class: 'mono-c' }, I().subnets.filter(s => s.vlan_id === v.id).map(s => s.cidr).join(', ') || '—'),
      h('td', { class: 'act' }, h('button', { class: 'btn sm flat', onclick: () => editVlan(v) }, 'Edit'), h('button', { class: 'btn sm flat', onclick: () => remove('VLAN', String(v.vid), '/api/ipam/vlans/' + v.id) }, 'Delete')))))))
    : L.empty('No VLANs yet', 'Add the VLANs your network uses, then link subnets to them.'))];

/* ---------- subnets ---------- */
const metaText = m => Object.entries(m || {}).map(([k, v]) => k + '=' + v).join('\n');
const metaParse = t => Object.fromEntries((t || '').split('\n').map(x => x.trim()).filter(Boolean).map(x => { const i = x.indexOf('='); return i < 0 ? [x, ''] : [x.slice(0, i).trim(), x.slice(i + 1).trim()]; }));
const editSubnet = s => form({
  title: s ? 'Edit subnet' : 'Add subnet', wide: true,
  value: s ? { ...s, vlan_id: s.vlan_id ? String(s.vlan_id) : '', location_id: s.location_id ? String(s.location_id) : '', gateway: s.gateway || '', meta: metaText(s.metadata) }
    : { cidr: '', name: '', description: '', group: '', vlan_id: '', location_id: '', gateway: '', meta: '' },
  fields: [{ key: 'cidr', label: 'Network (CIDR)', mono: true, placeholder: '192.168.1.0/24 or 2001:db8::/64', disabled: !!s, hint: s ? 'A subnet keeps its network. Delete it and add a new one to change it.' : 'IPv4 or IPv6. A subnet inside a larger one nests under it.' },
    { key: 'name', label: 'Name' }, { key: 'group', label: 'Group', hint: 'Optional. Organize subnets by this name.' },
    { key: 'vlan_id', label: 'VLAN', type: 'select', options: vlanOptions() }, { key: 'location_id', label: 'Location', type: 'select', options: locOptions() },
    { key: 'gateway', label: 'Gateway', mono: true, hint: 'Optional. Kept out of automatic allocation and counted as in use.' },
    { key: 'description', label: 'Description' }, { key: 'meta', label: 'Custom metadata', type: 'area', hint: 'One key=value per line, up to 16.' }],
  onSave: o => send(s ? 'PUT' : 'POST', s ? '/api/ipam/subnets/' + s.id : '/api/ipam/subnets', { cidr: o.cidr || '', name: o.name, description: o.description || '', group: o.group || '', vlan_id: num(o.vlan_id), location_id: num(o.location_id), gateway: none(o.gateway), metadata: metaParse(o.meta) }, 'Saved.') });

const usage = id => {
  const s = statsOf(id); if (!s) return dash;
  return h('div', { style: 'min-width:140px' }, h('div', { class: 'row', style: 'justify-content:space-between;gap:8px' }, h('span', { class: 'mono' }, s.percent_used + '%'), h('span', { class: 'hint' }, L.t('{n} free', { n: Number(s.free).toLocaleString() }))),
    h('div', { class: 'bar', role: 'progressbar', 'aria-label': L.t('Used in {cidr}', { cidr: s.cidr }), 'aria-valuenow': Math.round(s.percent_used) }, h('i', { style: 'width:' + Math.min(100, s.percent_used) + '%' })));
};

const subnetsTab = () => [h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('strong', {}, 'Subnets'), h('button', { class: 'btn primary', onclick: () => editSubnet(null) }, L.ic('plus'), 'Add subnet')),
  I().subnets.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Network', 'Name', 'VLAN', 'Location', 'Used', ''].map(x => h('th', {}, x)))),
    h('tbody', {}, I().subnets.map(s => h('tr', {},
      h('td', { class: 'mono-c', style: 'padding-left:' + (12 + depth(s) * 20) + 'px' }, h('strong', {}, s.cidr), s.gateway ? [' ', h('span', { class: 'hint' }, L.t('gateway {ip}', { ip: s.gateway }))] : null),
      h('td', {}, s.name, s.group ? [' ', h('span', { class: 'chip' }, s.group)] : null), h('td', {}, s.vlan_id ? vlanText(s.vlan_id) : dash), h('td', {}, s.location_id ? locPath(s.location_id) : dash), h('td', {}, usage(s.id)),
      h('td', { class: 'act' }, h('button', { class: 'btn sm flat', onclick: () => allocate(String(s.id)) }, 'Allocate'), h('button', { class: 'btn sm flat', onclick: () => { af.subnet = String(s.id); L.go('ipam', 'addresses'); } }, 'Addresses'),
        h('button', { class: 'btn sm flat', onclick: () => editSubnet(s) }, 'Edit'), h('button', { class: 'btn sm flat', onclick: () => remove('subnet', s.cidr, '/api/ipam/subnets/' + s.id) }, 'Delete')))))))
    : L.empty('No subnets yet', 'Add the networks you manage. IPv4 and IPv6 both work, and smaller subnets nest inside larger ones.'))];

/* ---------- addresses ---------- */
const dnsHint = () => I().dns_domain ? L.t('Publish {name}.{domain} in DNS, with a matching reverse name.', { name: '<name>', domain: I().dns_domain }) : 'Needs ipam.dns_domain in the configuration.';
const addressFields = () => [{ key: 'hostname', label: 'Host name', hint: 'Optional. Letters, digits and hyphens.' }, { key: 'device', label: 'Device' },
  { key: 'location_id', label: 'Location', type: 'select', options: locOptions() }, { key: 'description', label: 'Description' },
  { key: 'dns', label: 'Publish in DNS', type: 'switch', hint: dnsHint() }];
const body = o => ({ hostname: none(o.hostname), device: o.device || '', description: o.description || '', location_id: num(o.location_id), dns: !!o.dns });

const editAddress = (row, state) => form({
  title: row ? 'Edit address' : 'Assign or reserve an address', wide: true,
  value: row ? { ...row, location_id: row.location_id ? String(row.location_id) : '' } : { ip: '', state: state || 'assigned', hostname: '', device: '', location_id: '', description: '', dns: false },
  fields: [{ key: 'ip', label: 'Address', mono: true, disabled: !!row }, { key: 'state', label: 'State', type: 'select', options: [['assigned', 'Assigned'], ['reserved', 'Reserved']] }, ...addressFields()],
  onSave: o => send('PUT', '/api/ipam/addresses', { ip: o.ip, state: o.state, ...body(o) }, 'Saved.') });

function allocate(subnet) {
  const cur = subnet || af.subnet || (I().subnets[0] ? String(I().subnets[0].id) : '');
  if (!cur) { L.toast('Add a subnet first.', 'bad'); return; }
  form({ title: 'Allocate the next free address', label: 'Allocate', wide: true, value: { subnet: cur, strategy: 'first', state: 'assigned', hostname: '', device: '', location_id: '', description: '', dns: false },
    fields: [{ key: 'subnet', label: 'Subnet', type: 'select', options: subnetOptions() },
      { key: 'strategy', label: 'Which address', type: 'select', options: [['first', 'The lowest free address'], ['last', 'The highest free address'], ['random', 'Any free address']] },
      { key: 'state', label: 'State', type: 'select', options: [['assigned', 'Assigned'], ['reserved', 'Reserved']] }, ...addressFields()],
    onSave: async o => { const r = await L.api('POST', '/api/ipam/subnets/' + o.subnet + '/allocate', { strategy: o.strategy, state: o.state, ...body(o) }); await L.loadIpam(); L.rerender(); L.toast(L.t('{ip} is now yours. Nothing was configured on any device.', { ip: r.ip })); } });
}

const release = async row => {
  if (!(await L.confirm({ title: 'Release this address?', text: L.t('{ip} becomes available again. Nothing changes on any device.', { ip: row.ip }), label: 'Release', danger: true }))) return;
  try { await send('DELETE', '/api/ipam/addresses/' + encodeURIComponent(row.ip), null, 'Released.'); } catch (e) { L.toast(e.message, 'bad'); }
};

const STATES = [['', 'Any state'], ['assigned', 'Assigned'], ['reserved', 'Reserved'], ['leased', 'DHCP leased'], ['available', 'Available']];
const stateChip = s => h('span', { class: 'chip' }, L.t({ assigned: 'Assigned', reserved: 'Reserved', leased: 'DHCP leased', available: 'Available' }[s] || s));
const refilter = async () => { busy = true; try { await L.loadIpam(); } catch (e) { L.toast(e.message, 'bad'); } busy = false; L.paintMain(); };

const addressesTab = () => {
  const rows = I().addresses;
  const filters = h('div', { class: 'row' },
    h('select', { class: 'select', 'aria-label': 'Subnet', onchange: e => { af.subnet = e.target.value; refilter(); } }, [h('option', { value: '' }, L.t('All subnets')), ...subnetOptions().map(([v, t]) => h('option', { value: v, selected: v === af.subnet }, t))]),
    h('select', { class: 'select', 'aria-label': 'State', onchange: e => { af.state = e.target.value; refilter(); } }, STATES.map(([v, t]) => h('option', { value: v, selected: v === af.state }, L.t(t)))),
    h('select', { class: 'select', 'aria-label': 'Location', onchange: e => { af.location = e.target.value; refilter(); } }, locOptions().map(([v, t]) => h('option', { value: v, selected: v === af.location }, L.t(t)))),
    h('input', { class: 'input', style: 'width:220px', placeholder: 'Search addresses', 'aria-label': 'Search addresses', value: af.q, onchange: e => { af.q = e.target.value; refilter(); } }));
  return [h('div', { class: 'card' }, h('div', { class: 'card-h' }, filters, h('div', { class: 'row' }, h('button', { class: 'btn', onclick: () => editAddress(null) }, 'Assign or reserve'), h('button', { class: 'btn primary', onclick: () => allocate() }, L.ic('plus'), 'Allocate next free'))),
    af.state === 'available' && !af.subnet ? h('div', { class: 'note', style: 'margin:12px' }, L.ic('info'), h('p', {}, 'Pick one subnet to list its free addresses.')) : null,
    rows.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Address', 'State', 'Name', 'Device', 'Subnet', 'DNS', ''].map(x => h('th', {}, x)))),
      h('tbody', {}, rows.map(r => h('tr', {}, h('td', { class: 'mono-c' }, r.ip), h('td', {}, stateChip(r.state)), h('td', {}, r.hostname ? h('strong', {}, r.hostname) : dash), h('td', {}, r.device || dash),
        h('td', { class: 'mono-c' }, byId(I().subnets, r.subnet_id)?.cidr || '—'), h('td', {}, r.dns ? h('span', { class: 'chip' }, 'Published') : dash),
        h('td', { class: 'act' }, r.state === 'assigned' || r.state === 'reserved' ? [h('button', { class: 'btn sm flat', onclick: () => editAddress(r) }, 'Edit'), h('button', { class: 'btn sm flat', onclick: () => release(r) }, 'Release')]
          : r.state === 'available' ? h('button', { class: 'btn sm flat', onclick: () => editAddress({ ip: r.ip, state: 'assigned', hostname: '', device: '', location_id: null, description: '', dns: false, new: true }) }, 'Assign') : null))))))
      : L.empty('No addresses', busy ? 'Loading.' : 'Nothing matches. Allocate an address from a subnet, or record one you assigned by hand.'))];
};

/* ---------- overview ---------- */
const tile = (label, value, hint) => h('div', { class: 'card' }, h('div', { class: 'card-b' }, h('div', { class: 'muted' }, label), h('div', { style: 'font-size:1.6em;font-weight:600' }, value), hint ? h('div', { class: 'hint' }, hint) : null));
const conflictText = { 'leased-and-assigned': 'Recorded here and leased by DHCP', 'name-held-by-dhcp': 'Name also given out by DHCP' };

const overviewTab = () => {
  const o = I().overview;
  const conflicts = I().conflicts;
  return [h('div', { class: 'grid g4' }, tile('Subnets', L.fmt.n(o.subnets.length)), tile('Assigned', L.fmt.n(o.assigned)), tile('Reserved', L.fmt.n(o.reserved)), tile('DHCP leased', L.fmt.n(o.leased), I().dhcp ? null : 'The DHCP module is not running.')),
    conflicts.length ? h('div', { class: 'card', style: 'margin-top:16px' }, h('div', { class: 'card-h' }, h('strong', {}, 'Conflicts')),
      h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Address', 'Problem', 'Detail'].map(x => h('th', {}, x)))),
        h('tbody', {}, conflicts.map(c => h('tr', {}, h('td', { class: 'mono-c' }, c.ip), h('td', {}, h('span', { class: 'chip bad' }, conflictText[c.kind] || c.kind)), h('td', {}, c.detail))))))) : null,
    h('div', { class: 'card', style: 'margin-top:16px' }, h('div', { class: 'card-h' }, h('strong', {}, 'Subnet utilization')),
      o.subnets.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Network', 'Assigned', 'Reserved', 'Leased', 'Free', 'Used'].map(x => h('th', {}, x)))),
        h('tbody', {}, o.subnets.map(s => h('tr', {}, h('td', { class: 'mono-c' }, h('strong', {}, s.cidr)), h('td', {}, L.fmt.n(s.assigned)), h('td', {}, L.fmt.n(s.reserved)), h('td', {}, L.fmt.n(s.leased)), h('td', { class: 'mono-c' }, Number(s.free).toLocaleString()), h('td', {}, usage(s.subnet_id)))))))
        : L.empty('No subnets yet', 'Add a subnet to see its utilization here.', h('button', { class: 'btn primary', onclick: () => L.go('ipam', 'subnets') }, 'Add a subnet')))];
};

/* ---------- page ---------- */
const VIEWS = new Map(Object.entries({ overview: overviewTab, subnets: subnetsTab, addresses: addressesTab, vlans: vlansTab, locations: locationsTab }));
L.views.ipam = () => {
  const head = L.pageHead('IPAM', 'Subnets, addresses, VLANs and locations in one inventory. It records what you use; it never changes a device.',
    h('button', { class: 'btn', onclick: reload }, 'Refresh'));
  if (!I()) return [head, L.empty('Loading', 'One moment.')];
  const tab = VIEWS.has(L.route().sub) ? L.route().sub : 'overview';
  return [head, L.tabs(TABS, tab, id => L.go('ipam', id)), h('div', { style: 'margin-top:16px' }, VIEWS.get(tab)())];
};
})();
