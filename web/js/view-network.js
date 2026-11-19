/* Network module: discovery, the device inventory, topology and monitoring. It looks only at the
   networks the configuration lists, and it never changes a device. */
(() => {
'use strict';
const L = window.L, h = L.h;
const NS = 'http://www.w3.org/2000/svg';
const sv = (tag, a = {}, ...k) => { const e = document.createElementNS(NS, tag); for (const [x, y] of Object.entries(a)) if (y != null && y !== false) e.setAttribute(x, y); k.flat().forEach(c => { if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(c)); }); return e; };

const TABS = [['overview', 'Overview'], ['devices', 'Devices'], ['rooms', 'Rooms'], ['topology', 'Topology'], ['monitoring', 'Monitoring'], ['discovery', 'Discovery']];
const KINDS = ['router', 'switch', 'access-point', 'firewall', 'server', 'workstation', 'laptop', 'phone', 'tablet', 'printer', 'nas', 'camera', 'tv', 'iot', 'other', 'unknown'];
const ICONS = ['router', 'switch', 'wifi', 'shield', 'server', 'desktop', 'laptop', 'phone', 'tablet', 'printer', 'storage', 'camera', 'tv', 'chip', 'device'];
const KIND_ICON = { router: 'router', switch: 'switch', 'access-point': 'wifi', firewall: 'shield', server: 'server', workstation: 'desktop', laptop: 'laptop', phone: 'phone', tablet: 'tablet', printer: 'printer', nas: 'storage', camera: 'camera', tv: 'tv', iot: 'chip' };
/* Small line drawings on a 24 x 24 grid. */
const GLYPH = {
  router: 'M4 14h16v5H4zM8 14V9M16 14V9M7 6a7 7 0 0 1 10 0M9.5 8a4 4 0 0 1 5 0M7 17h.01M10 17h.01',
  switch: 'M3 8h18v8H3zM6 12h.01M9 12h.01M12 12h.01M15 12h.01M18 12h.01',
  wifi: 'M2 9a15 15 0 0 1 20 0M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M12 19.5h.01',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
  server: 'M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01',
  desktop: 'M3 4h18v12H3zM8 20h8M12 16v4',
  laptop: 'M5 5h14v10H5zM2 19h20',
  phone: 'M8 3h8v18H8zM11 18h2',
  tablet: 'M5 3h14v18H5zM11 18h2',
  printer: 'M7 9V3h10v6M5 9h14v8H5zM8 14h8v7H8z',
  storage: 'M4 6c0-2 16-2 16 0v12c0 2-16 2-16 0zM4 12c0 2 16 2 16 0M4 6c0 2 16 2 16 0',
  camera: 'M3 8h4l2-3h6l2 3h4v11H3zM12 17a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z',
  tv: 'M3 6h18v12H3zM8 21h8',
  chip: 'M7 7h10v10H7zM10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4',
  device: 'M4 5h16v11H4zM9 20h6M12 16v4'
};
const glyph = (name, size = 20) => sv('svg', { viewBox: '0 0 24 24', width: size, height: size, fill: 'none', stroke: 'currentColor', 'stroke-width': 1.6, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' }, sv('path', { d: GLYPH[name] || GLYPH.device }));
const iconOf = d => d.icon || KIND_ICON[d.kind] || 'device';
const cap = s => s.charAt(0).toUpperCase() + s.slice(1).replace('-', ' ');
const STATUS = { online: ['ok', 'Online'], degraded: ['warn', 'Degraded'], offline: ['bad', 'Offline'], unknown: ['off', 'Unknown'] };
const pill = status => h('span', { class: 'pill ' + (STATUS[status]?.[0] || 'off') }, STATUS[status]?.[1] || 'Unknown');
const dash = h('span', { class: 'muted' }, '—');
const ago = t => t ? L.fmt.ago(t * 1000) : dash;
const rate = bps => bps == null ? '—' : bps >= 1e9 ? (bps / 1e9).toFixed(2) + ' Gb/s' : bps >= 1e6 ? (bps / 1e6).toFixed(1) + ' Mb/s' : bps >= 1e3 ? (bps / 1e3).toFixed(0) + ' kb/s' : Math.round(bps) + ' b/s';
const speed = bps => bps == null ? '—' : bps >= 1e9 ? (bps / 1e9) + ' Gb/s' : (bps / 1e6) + ' Mb/s';
const pct = v => v == null ? '—' : v.toFixed(v < 10 ? 1 : 0) + '%';

const fl = { q: '', kind: '', status: '', subnet: '', location: '', vlan: '', sort: 'last_seen', dir: '', group: 'none', gone: false };
const tf = { subnet: '', vlan: '', location: '', kind: '', loose: true, labels: false };
let timer = null, view = { x: 0, y: 0, k: 1 };

const qs = o => { const p = new URLSearchParams(); for (const [k, v] of Object.entries(o)) if (v) p.set(k, v === true ? '1' : v); return p.toString(); };
const N = () => L.S.network;
const send = async (method, path, payload, done) => { const r = await L.api(method, '/api/network' + path, payload); await L.loadNetwork(); L.rerender(); if (done) L.toast(L.t(done)); return r; };

L.loadNetwork = async () => {
  const sub = L.route().sub || 'overview';
  const [home, list, rooms] = await Promise.all([L.api('GET', '/api/network'), L.api('GET', '/api/network/devices?' + qs({ q: fl.q, kind: fl.kind, status: fl.status, subnet: fl.subnet, location: fl.location, vlan: fl.vlan, sort: fl.sort, dir: fl.dir, gone: fl.gone, limit: 2000 })), L.api('GET', '/api/network/rooms')]);
  const every = await L.api('GET', '/api/network/devices?limit=5000&gone=1').catch(() => list);
  const locations = home.ipam ? await L.api('GET', '/api/network/locations').catch(() => []) : [];
  const topology = sub === 'topology' ? await L.api('GET', '/api/network/topology?' + qs({ subnet: tf.subnet, vlan: tf.vlan, location: tf.location, kind: tf.kind })) : (N()?.topology || null);
  const events = sub === 'monitoring' ? await L.api('GET', '/api/network/events?limit=100') : (N()?.events || []);
  const scans = sub === 'discovery' ? await L.api('GET', '/api/network/scans') : (N()?.scans || []);
  L.S.network = { ...home, devices: list.devices, total: list.total, everyone: every.devices, locations, rooms, topology, allEvents: events, allScans: scans };
};
const reload = async () => { try { await L.loadNetwork(); L.rerender(); } catch (e) { L.toast(e.message, 'bad'); } };
const start = () => {
  if (timer) return;
  timer = setInterval(async () => {
    if (L.route().page !== 'network') { clearInterval(timer); timer = null; return; }
    if (document.hidden || L.$('dialog[open]')) return;
    try { await L.loadNetwork(); L.paintMain(); } catch { /* try again next time */ }
  }, 20000);
};
L.stopModule = (old => id => { if (id === 'network' && timer) { clearInterval(timer); timer = null; } old?.(id); })(L.stopModule);

const locName = id => { const l = N().locations.find(x => x.id === id); if (!l) return ''; const out = []; for (let at = l, n = 0; at && n < 20; at = at.parent_id ? N().locations.find(x => x.id === at.parent_id) : null, n++) out.unshift(at.name); return out.join(' › '); };
const roomName = id => { const room = N().rooms.find(x => x.id === id); if (!room) return ''; const out = []; for (let at = room, n = 0; at && n < 20; at = at.parent_id ? N().rooms.find(x => x.id === at.parent_id) : null, n++) out.unshift(at.name); return out.join(' › '); };
const byId = id => N().everyone.find(d => d.id === id);
const addr = d => d.addresses.length ? d.addresses.map(a => a.ip) : [];

/* ---------- a small form dialog ---------- */
const form = ({ title, fields, value, label = 'Save', onSave, wide = true }) => {
  const o = { ...value };
  const body = h('div', { class: 'stack' }, fields.map(f => {
    if (f.type === 'switch') return h('div', { class: 'field' }, L.f.sw(o, f.key, f.label), f.hint ? h('div', { class: 'hint' }, f.hint) : null);
    let control;
    if (f.type === 'select') control = L.f.sel(o, f.key, f.options);
    else if (f.type === 'area') control = h('textarea', { class: 'input', rows: 3, spellcheck: false, oninput: e => { o[f.key] = e.target.value; } }, o[f.key] || '');
    else if (f.type === 'tags') control = L.f.tags(o[f.key], { validate: f.validate, what: f.what, max: 16, placeholder: f.placeholder });
    else control = L.f.text(o, f.key, { mono: f.mono, placeholder: f.placeholder });
    return L.f.field(f.label, control, f.hint);
  }));
  L.modal({ title, body, wide, actions: [{ label: 'Cancel' }, { label, kind: 'primary', onClick: async () => { try { await onSave(o); return true; } catch (e) { L.toast(e.message, 'bad'); return false; } } }] });
};
const num = v => v === '' || v == null ? null : Number(v);
const none = v => v === '' || v == null ? null : v;
const locOptions = () => [['', '— None —'], ...N().locations.map(l => [String(l.id), locName(l.id)])];
const roomOptions = except => [['', '— None —'], ...N().rooms.filter(r => r.id !== except).map(r => [String(r.id), roomName(r.id)])];
const MAC = /^([0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}$|^[0-9a-f]{12}$/i;
const IPV = s => /^[0-9a-f:.]+$/i.test(s) && (s.includes('.') || s.includes(':'));

/* ---------- editing ---------- */
const editDevice = d => form({
  title: d ? 'Edit device' : 'Add device',
  value: d ? { name: d.name, hostname: d.hostname || '', kind: d.kind, icon: d.icon || '', os: d.os || '', description: d.description, notes: d.notes, location_id: d.location_id ? String(d.location_id) : '', room_id: d.room_id ? String(d.room_id) : '', enabled: d.monitoring.enabled, method: d.monitoring.method, tcp_port: d.monitoring.tcp_port ? String(d.monitoring.tcp_port) : '', interval: d.monitoring.interval_secs ? String(d.monitoring.interval_secs) : '', snmp_profile: d.snmp_profile || '', addresses: [], macs: [], dhcp_ids: d.dhcp_ids || [] }
    : { name: '', hostname: '', kind: 'unknown', icon: '', os: '', description: '', notes: '', location_id: '', room_id: '', enabled: true, method: 'icmp', tcp_port: '', interval: '', snmp_profile: '', addresses: [], macs: [], dhcp_ids: [] },
  fields: [{ key: 'name', label: 'Name' }, { key: 'hostname', label: 'Host name', hint: 'Optional. Discovery fills this in when you leave it empty.' },
    { key: 'kind', label: 'Type', type: 'select', options: KINDS.map(k => [k, cap(k)]) }, { key: 'icon', label: 'Icon', type: 'select', options: [['', 'Automatic'], ...ICONS.map(i => [i, cap(i)])] },
    { key: 'os', label: 'Operating system' }, { key: 'location_id', label: 'Location', type: 'select', options: locOptions(), hint: N().ipam ? 'Locations come from IPAM.' : 'Turn on the IPAM module to organize devices by location.' },
    { key: 'room_id', label: 'Room', type: 'select', options: roomOptions(), hint: 'Rooms are independent from IPAM locations and can be nested.' },
    { key: 'addresses', label: d ? 'Add addresses' : 'IP addresses', type: 'tags', validate: IPV, what: 'IP address', placeholder: 'Add an IPv4 or IPv6 address' },
    { key: 'macs', label: d ? 'Add hardware addresses' : 'MAC addresses', type: 'tags', validate: s => MAC.test(s), what: 'MAC address', placeholder: 'Add a MAC address' },
    { key: 'dhcp_ids', label: 'DHCP client IDs', type: 'tags', validate: s => /^[0-9a-f:-]{2,256}$/i.test(s), what: 'DHCP client ID', placeholder: 'Stable client ID from DHCP' },
    { key: 'description', label: 'Description' }, { key: 'notes', label: 'Notes', type: 'area' },
    { key: 'enabled', label: 'Monitor availability', type: 'switch', hint: 'Check this device regularly and tell you when it stops answering.' },
    { key: 'method', label: 'Check with', type: 'select', options: [['icmp', 'Ping (ICMP)'], ['tcp', 'TCP connection'], ['snmp', 'SNMP']] },
    { key: 'tcp_port', label: 'TCP port', mono: true, hint: 'Only for TCP checks.' }, { key: 'interval', label: 'Check interval (seconds)', mono: true, hint: 'Empty uses the module default. 10 to 3600.' },
    { key: 'snmp_profile', label: 'SNMP profile', type: 'select', options: [['', 'From the scope'], ...(N().engine?.snmp_profiles || []).map(p => [p, p])], hint: 'Profiles are set up in the configuration; their secrets stay in files.' }],
  onSave: o => send(d ? 'PUT' : 'POST', d ? '/devices/' + d.id : '/devices', {
    name: o.name, hostname: none(o.hostname), kind: d ? o.kind : (o.kind === 'unknown' ? null : o.kind), icon: none(o.icon), os: none(o.os), description: o.description || '', notes: o.notes || '', location_id: num(o.location_id), room_id: num(o.room_id),
    monitoring: { enabled: !!o.enabled, method: o.method, tcp_port: num(o.tcp_port), interval_secs: num(o.interval) }, snmp_profile: none(o.snmp_profile), addresses: o.addresses, macs: o.macs, dhcp_ids: o.dhcp_ids }, 'Saved.') });

const removeDevice = async d => {
  if (!(await L.confirm({ title: 'Delete this device?', text: L.t('{name} and its history are removed. If it is still on the network, discovery may add it again.', { name: d.name }), label: 'Delete', danger: true }))) return;
  try { await send('DELETE', '/devices/' + d.id, null, 'Deleted.'); } catch (e) { L.toast(e.message, 'bad'); }
};
const mergeDevice = d => form({ title: L.t('Merge into {name}', { name: d.name }), label: 'Merge', wide: false, value: { other: '' },
  fields: [{ key: 'other', label: 'The other entry for the same device', type: 'select', options: [['', 'Choose a device'], ...N().everyone.filter(x => x.id !== d.id).map(x => [String(x.id), x.name + ' · ' + (x.addresses[0]?.ip || x.macs[0]?.mac || '')])], hint: 'Its addresses, hardware addresses, links and history move here. What you set on this device stays.' }],
  onSave: async o => { if (!o.other) throw new Error('Choose a device.'); await send('POST', '/devices/' + d.id + '/merge', { other: Number(o.other) }, 'Merged.'); } });
const detach = async (d, value) => {
  if (!(await L.confirm({ title: 'Remove this identity value?', text: L.t('{value} no longer belongs to {name}. Use this to correct a wrong match; discovery may match it again if it still points here.', { value, name: d.name }), label: 'Remove', danger: true }))) return;
  try { await L.api('DELETE', '/api/network/devices/' + d.id + '/addresses/' + encodeURIComponent(value)); L.toast('Removed.'); await L.loadNetwork(); L.rerender(); } catch (e) { L.toast(e.message, 'bad'); }
};
const toIpam = async (d, ip) => {
  try { await L.api('POST', '/api/network/devices/' + d.id + '/ipam', { ip }); L.toast(L.t('{ip} is recorded in IPAM.', { ip })); } catch (e) { L.toast(e.message, 'bad'); }
};

/* ---------- links ---------- */
const editLink = link => {
  const opts = [['', 'Choose a device'], ...N().everyone.map(x => [String(x.id), x.name])];
  form({ title: link ? 'Correct link' : 'Add link', wide: false, label: 'Save',
    value: link ? { a: String(link.a), a_port: link.a_port, b: String(link.b), b_port: link.b_port, speed: link.speed_mbps ? String(link.speed_mbps) : '' } : { a: '', a_port: '', b: '', b_port: '', speed: '' },
    fields: [{ key: 'a', label: 'Device', type: 'select', options: opts }, { key: 'a_port', label: 'Port on it', hint: 'Optional, such as eth0 or port 5.' }, { key: 'b', label: 'Connected to', type: 'select', options: opts }, { key: 'b_port', label: 'Port on that one' }, { key: 'speed', label: 'Link speed (Mb/s)', mono: true, hint: 'Optional.' }],
    onSave: async o => {
      if (!o.a || !o.b) throw new Error('Choose both devices.');
      await send(link ? 'PUT' : 'POST', link ? '/links/' + link.id : '/links', { a_device: Number(o.a), a_port: o.a_port || '', b_device: Number(o.b), b_port: o.b_port || '', speed_mbps: num(o.speed) }, 'Saved.');
    } });
};
const removeLink = async link => {
  if (!(await L.confirm({ title: 'Remove this link?', text: 'Only the record is removed. Nothing changes on the network. Discovery may report it again if a device still lists it.', label: 'Remove', danger: true }))) return;
  try { await send('DELETE', '/links/' + link.id, null, 'Removed.'); } catch (e) { L.toast(e.message, 'bad'); }
};

/* ---------- one device ---------- */
const strip = checks => {
  const list = [...checks].reverse().slice(-120), w = 3, g = 1;
  const s = sv('svg', { class: 'net-strip', viewBox: `0 0 ${Math.max(1, list.length) * (w + g)} 22`, preserveAspectRatio: 'none', role: 'img', 'aria-label': L.t('Recent checks: {n}', { n: list.length }) });
  list.forEach((c, i) => s.append(sv('rect', { x: i * (w + g), y: c.ok ? 2 : 6, width: w, height: c.ok ? 18 : 14, fill: c.ok ? (c.loss_percent > 0 ? 'var(--warn)' : 'var(--ok)') : 'var(--bad)' }, sv('title', {}, L.fmt.time(c.ts * 1000) + (c.ok ? ' · ' + (c.rtt_ms ?? 0).toFixed(1) + ' ms' : ' · no answer')))));
  return s;
};
const lineChart = (samples, w = 480, hgt = 120) => {
  const max = Math.max(1, ...samples.flatMap(s => [s.in_bps, s.out_bps])), t0 = samples[0]?.ts || 0, t1 = samples[samples.length - 1]?.ts || 1;
  const pt = (s, key) => `${((s.ts - t0) / Math.max(1, t1 - t0) * (w - 8) + 4).toFixed(1)},${(hgt - 6 - s[key] / max * (hgt - 14)).toFixed(1)}`;
  const svg = sv('svg', { class: 'net-chart', viewBox: `0 0 ${w} ${hgt}`, role: 'img', 'aria-label': 'Traffic over time' });
  svg.append(sv('polyline', { points: samples.map(s => pt(s, 'in_bps')).join(' '), fill: 'none', stroke: 'var(--ok)', 'stroke-width': 1.6 }), sv('polyline', { points: samples.map(s => pt(s, 'out_bps')).join(' '), fill: 'none', stroke: 'var(--text)', 'stroke-width': 1.6 }), sv('text', { x: 4, y: 12, fill: 'var(--text-2)', 'font-size': 10 }, 'peak ' + rate(max)));
  return svg;
};
const showInterface = async (d, i) => {
  try {
    const rows = await L.api('GET', `/api/network/devices/${d.id}/interfaces/${i.index}/history?limit=500`);
    L.modal({ title: `${d.name} · ${i.name}`, wide: true, body: rows.length > 1 ? [h('p', { class: 'muted', style: 'margin-top:0' }, L.t('{in} in (green), {out} out, over the last day.', { in: rate(i.in_bps), out: rate(i.out_bps) })), lineChart(rows)] : L.empty('Not enough data yet', 'Rates appear after two polls.'), actions: [{ label: 'Close' }] });
  } catch (e) { L.toast(e.message, 'bad'); }
};

const openDevice = async id => {
  let r;
  try { r = await L.api('GET', '/api/network/devices/' + id); } catch (e) { L.toast(e.message, 'bad'); return; }
  const d = r.device, sys = d.sys;
  const fact = (k, v) => v == null || v === '' ? null : h('div', { class: 'net-fact' }, h('span', { class: 'muted' }, k), h('span', {}, v));
  const body = h('div', { class: 'stack' },
    h('div', { class: 'row', style: 'justify-content:space-between' }, h('div', { class: 'row' }, h('span', { class: 'net-ic' }, glyph(iconOf(d), 26)), h('div', {}, h('strong', {}, d.name), h('div', { class: 'hint' }, [cap(d.kind), d.vendor, d.os].filter(Boolean).join(' · ')))), pill(d.status)),
    h('div', { class: 'net-facts' }, fact('Host name', d.hostname), fact('Subnet', d.subnet), fact('VLAN', d.vlan), fact('Location', d.location_id ? locName(d.location_id) : ''), fact('Room', d.room_id ? roomName(d.room_id) : ''), fact('Identity match', cap(d.identity_confidence)), fact('First seen', L.fmt.time(d.first_seen * 1000)), fact('Last seen', L.fmt.time(d.last_seen * 1000)), fact('Last answer', d.last_ok ? L.fmt.time(d.last_ok * 1000) : ''), fact('Description', d.description), fact('Notes', d.notes),
      d.gone ? fact('State', 'Gone: not seen in the last discovery runs. It is kept, with its history.') : null,
      fact('Availability, 24 hours', r.availability_24h == null ? '' : pct(r.availability_24h)), fact('Availability, 7 days', r.availability_7d == null ? '' : pct(r.availability_7d)),
      fact('Monitoring', d.monitoring.enabled ? L.t('{method} every {n} s', { method: d.monitoring.method.toUpperCase() + (d.monitoring.tcp_port ? ':' + d.monitoring.tcp_port : ''), n: d.monitoring.interval_secs || N().engine?.monitor_interval_secs || '—' }) : 'Off')),
    h('div', {}, h('h3', { class: 'net-h' }, 'Identity and addresses'), d.addresses.length || d.macs.length || d.dhcp_ids.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('tbody', {},
      d.addresses.map(a => h('tr', {}, h('td', { class: 'mono-c' }, a.ip), h('td', {}, h('span', { class: 'chip' }, a.source)), h('td', { class: 'act' }, N().ipam ? h('button', { class: 'btn sm flat', onclick: () => toIpam(d, a.ip) }, 'Record in IPAM') : null, h('button', { class: 'btn sm flat', onclick: () => detach(d, a.ip) }, 'Remove')))),
      d.macs.map(m => h('tr', {}, h('td', { class: 'mono-c' }, m.mac), h('td', {}, m.vendor || h('span', { class: 'muted' }, 'Private or unknown maker')), h('td', { class: 'act' }, h('button', { class: 'btn sm flat', onclick: () => detach(d, m.mac) }, 'Remove')))),
      d.dhcp_ids.map(id => h('tr', {}, h('td', { class: 'mono-c' }, id), h('td', {}, h('span', { class: 'chip' }, 'DHCP client ID')), h('td', { class: 'act' }, h('button', { class: 'btn sm flat', onclick: () => detach(d, id) }, 'Remove'))))))) : h('p', { class: 'muted' }, 'No identity data.')),
    r.checks.length ? h('div', {}, h('h3', { class: 'net-h' }, 'Recent checks'), strip(r.checks), h('div', { class: 'hint' }, L.t('Green answered, amber answered with lost packets, red did not answer. Newest at the right.'))) : null,
    sys ? h('div', {}, h('h3', { class: 'net-h' }, 'Reported by the device (SNMP)'), h('div', { class: 'net-facts' }, fact('Name', sys.name), fact('Description', sys.descr), fact('Uptime', sys.uptime_secs != null ? L.fmt.dur(sys.uptime_secs) : ''), fact('Contact', sys.contact), fact('Location', sys.location), fact('CPU', sys.cpu_percent != null ? pct(sys.cpu_percent) : ''), fact('Memory', sys.memory_percent != null ? pct(sys.memory_percent) : ''), fact('Temperature', sys.temperature_c != null ? sys.temperature_c.toFixed(0) + ' °C' : ''), fact('Updated', ago(sys.updated)))) : null,
    r.interfaces.length ? h('div', {}, h('h3', { class: 'net-h' }, 'Interfaces'), h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Port', 'State', 'Speed', 'In', 'Out', 'Used', 'Errors', 'Discards'].map(x => h('th', {}, x)))),
      h('tbody', {}, r.interfaces.map(i => h('tr', { class: 'net-click', tabindex: 0, onclick: () => showInterface(d, i), onkeydown: e => { if (e.key === 'Enter') showInterface(d, i); } },
        h('td', {}, h('strong', {}, i.name), i.alias ? [' ', h('span', { class: 'hint' }, i.alias)] : null), h('td', {}, h('span', { class: 'pill ' + (i.oper_up ? 'ok' : i.admin_up ? 'bad' : 'off') }, i.oper_up ? 'Up' : i.admin_up ? 'Down' : 'Disabled')), h('td', { class: 'mono-c' }, speed(i.speed_bps)),
        h('td', { class: 'mono-c' }, rate(i.in_bps)), h('td', { class: 'mono-c' }, rate(i.out_bps)),
        h('td', {}, i.utilization_percent == null ? dash : h('div', { style: 'min-width:80px' }, h('span', { class: 'mono' }, pct(i.utilization_percent)), h('div', { class: 'bar' }, h('i', { style: 'width:' + Math.min(100, i.utilization_percent) + '%' })))),
        h('td', { class: 'mono-c' }, L.fmt.n(i.in_errors + i.out_errors)), h('td', { class: 'mono-c' }, L.fmt.n(i.in_discards + i.out_discards))))))), h('div', { class: 'hint' }, 'Click a port to see its traffic over time.')) : null,
    r.links.length ? h('div', {}, h('h3', { class: 'net-h' }, 'Connections'), h('ul', { class: 'net-list' }, r.links.map(l => { const mine = l.a_device === d.id, other = byId(mine ? l.b_device : l.a_device); return h('li', {}, h('span', {}, h('strong', {}, other?.name || '?'), ' ', h('span', { class: 'hint' }, [mine ? l.a_port : l.b_port, '→', mine ? l.b_port : l.a_port].filter(Boolean).join(' '))), ' ', h('span', { class: 'chip' + (l.confirmed ? '' : ' warn') }, l.confirmed ? (l.kind === 'manual' ? 'Set by you' : 'Reported by a device') : 'Inferred, not confirmed')); }))) : null,
    r.events.length ? h('div', {}, h('h3', { class: 'net-h' }, 'History'), h('ul', { class: 'net-list' }, r.events.slice(0, 12).map(e => h('li', {}, h('span', { class: 'mono muted' }, L.fmt.time(e.ts * 1000)), ' ', e.detail)))) : null);
  const close = L.modal({ title: d.name, wide: true, body, actions: [{ label: 'Close' }, { label: 'Merge…', onClick: () => { mergeDevice(d); } }, { label: 'Delete', kind: 'danger', onClick: () => { removeDevice(d); } }, { label: 'Edit', kind: 'primary', onClick: () => { editDevice(d); } }] });
  void close;
};

/* ---------- overview ---------- */
const tile = (label, value, kind) => h('div', { class: 'card' }, h('div', { class: 'card-b' }, h('div', { class: 'muted' }, label), h('div', { style: 'font-size:1.6em;font-weight:600' + (kind ? ';color:var(--' + kind + ')' : '') }, value)));
const eventRow = e => h('li', {}, h('span', { class: 'mono muted' }, L.fmt.time(e.ts * 1000)), ' ', h('span', { class: 'pill plain ' + ({ offline: 'bad', degraded: 'warn', recovered: 'ok', online: 'ok', gone: 'bad', returned: 'ok', 'snmp-down': 'warn' }[e.kind] || 'off') }, e.kind), ' ', e.device_id ? h('a', { href: '#', onclick: ev => { ev.preventDefault(); openDevice(e.device_id); } }, e.detail) : e.detail);

const runScan = async () => {
  try { await L.api('POST', '/api/network/scan'); L.toast('Discovery will start within a few seconds.'); setTimeout(reload, 6000); setTimeout(reload, 20000); } catch (e) { L.toast(e.message, 'bad'); }
};

const overviewTab = () => {
  const c = N().counts, eng = N().engine, last = N().scans[0];
  return [h('div', { class: 'grid g4' }, tile('Devices', L.fmt.n(c.total)), tile('Online', L.fmt.n(c.online), 'ok'), tile('Degraded', L.fmt.n(c.degraded), c.degraded ? 'warn' : ''), tile('Offline', L.fmt.n(c.offline), c.offline ? 'bad' : '')),
    !eng ? h('div', { class: 'note', style: 'margin-top:16px' }, L.ic('info'), h('p', {}, 'Discovery and monitoring are off. Add devices by hand, or set network.enabled with the networks to look at in the configuration. Lumen never scans anything you did not list.')) : null,
    eng && !eng.icmp_v4 ? h('div', { class: 'note', style: 'margin-top:16px' }, L.ic('alert'), h('p', {}, 'This account cannot send ICMP echo requests, so Lumen cannot ping. Discovery relies on the neighbor table and DHCP, and availability checks need the TCP or SNMP method. On Linux, allow it with net.ipv4.ping_group_range.')) : null,
    h('div', { class: 'grid g2', style: 'margin-top:16px' },
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('strong', {}, 'Device types')), h('div', { class: 'card-b' }, Object.keys(c.by_kind).length ? h('div', { class: 'chips' }, Object.entries(c.by_kind).sort((a, b) => b[1] - a[1]).map(([k, n]) => h('button', { class: 'chip', onclick: () => { fl.kind = k; L.go('network', 'devices'); } }, glyph(KIND_ICON[k] || 'device', 14), cap(k), ' ', h('b', {}, n)))) : h('p', { class: 'muted', style: 'margin:0' }, 'Nothing here yet.'))),
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('strong', {}, 'Last discovery'), eng ? h('button', { class: 'btn sm', disabled: eng.scanning, onclick: runScan }, eng.scanning ? 'Running…' : 'Run now') : null),
        h('div', { class: 'card-b' }, last ? h('div', { class: 'net-facts' }, h('div', { class: 'net-fact' }, h('span', { class: 'muted' }, 'State'), h('span', {}, last.state)), h('div', { class: 'net-fact' }, h('span', { class: 'muted' }, 'Started'), h('span', {}, ago(last.started))), h('div', { class: 'net-fact' }, h('span', { class: 'muted' }, 'Seen'), h('span', {}, L.fmt.n(last.seen))), h('div', { class: 'net-fact' }, h('span', { class: 'muted' }, 'New'), h('span', {}, L.fmt.n(last.new_devices))), last.detail ? h('div', { class: 'net-fact' }, h('span', { class: 'muted' }, 'Notes'), h('span', {}, last.detail)) : null) : h('p', { class: 'muted', style: 'margin:0' }, eng ? 'No run yet.' : 'Discovery is off.')))),
    h('div', { class: 'card', style: 'margin-top:16px' }, h('div', { class: 'card-h' }, h('strong', {}, 'Recent events')), N().events.length ? h('ul', { class: 'net-list card-b' }, N().events.map(eventRow)) : L.empty('No events yet', 'Devices appearing, going offline, and coming back are listed here.'))];
};

/* ---------- devices ---------- */
const GROUPS = [['none', 'No grouping'], ['room', 'Room'], ['kind', 'Type'], ['status', 'Status'], ['subnet', 'Subnet'], ['vlan', 'VLAN'], ['location', 'Location']];
const groupKey = d => ({ none: '', room: d.room_id ? roomName(d.room_id) : 'No room', kind: cap(d.kind), status: STATUS[d.status]?.[1] || '', subnet: d.subnet || 'No subnet', vlan: d.vlan || 'No VLAN', location: d.location_id ? locName(d.location_id) : 'No location' })[fl.group];
const refilter = async () => { try { await L.loadNetwork(); } catch (e) { L.toast(e.message, 'bad'); } L.paintMain(); };
const sel = (label, value, options, on) => h('select', { class: 'select', 'aria-label': label, onchange: e => on(e.target.value) }, options.map(([v, t]) => h('option', { value: v, selected: v === value }, L.t(t))));

const deviceRow = d => h('tr', { class: 'net-click' + (d.gone ? ' net-gone' : ''), tabindex: 0, onclick: () => openDevice(d.id), onkeydown: e => { if (e.key === 'Enter') openDevice(d.id); } },
  h('td', {}, h('div', { class: 'row', style: 'flex-wrap:nowrap' }, h('span', { class: 'net-ic' }, glyph(iconOf(d))), h('div', {}, h('strong', {}, d.name), d.hostname && d.hostname !== d.name ? h('div', { class: 'hint' }, d.hostname) : null))),
  h('td', { class: 'mono-c' }, addr(d).slice(0, 3).map(a => h('div', {}, a)), d.addresses.length > 3 ? h('div', { class: 'hint' }, L.t('+{n} more', { n: d.addresses.length - 3 })) : null),
  h('td', {}, d.macs[0] ? [h('div', { class: 'mono-c' }, d.macs[0].mac), h('div', { class: 'hint' }, d.vendor || '')] : dash),
  h('td', {}, cap(d.kind)), h('td', {}, d.gone ? h('span', { class: 'pill off' }, 'Gone') : pill(d.status)), h('td', {}, d.subnet ? [h('div', { class: 'mono-c' }, d.subnet), d.vlan ? h('div', { class: 'hint' }, d.vlan) : null] : dash), h('td', {}, ago(d.last_seen)));

const devicesTab = () => {
  const list = N().devices, groups = new Map();
  for (const d of list) { const k = groupKey(d); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(d); }
  const subnets = [...new Set(N().everyone.map(d => d.subnet).filter(Boolean))].sort();
  const bar = h('div', { class: 'row' },
    h('input', { class: 'input', style: 'width:220px', placeholder: 'Search devices', 'aria-label': 'Search devices', value: fl.q, onchange: e => { fl.q = e.target.value; refilter(); } }),
    sel('Type', fl.kind, [['', 'Any type'], ...KINDS.map(k => [k, cap(k)])], v => { fl.kind = v; refilter(); }),
    sel('Status', fl.status, [['', 'Any status'], ['online', 'Online'], ['degraded', 'Degraded'], ['offline', 'Offline'], ['unknown', 'Unknown']], v => { fl.status = v; refilter(); }),
    subnets.length ? sel('Subnet', fl.subnet, [['', 'Any subnet'], ...subnets.map(s => [s, s])], v => { fl.subnet = v; refilter(); }) : null,
    N().locations.length ? sel('Location', fl.location, locOptions().map(([v, t]) => [v, v ? t : 'Any location']), v => { fl.location = v; refilter(); }) : null,
    sel('Sort by', fl.sort, [['last_seen', 'Last seen'], ['name', 'Name'], ['ip', 'Address'], ['status', 'Status'], ['kind', 'Type'], ['first_seen', 'First seen']], v => { fl.sort = v; refilter(); }),
    h('button', { class: 'btn sm flat', 'aria-label': 'Reverse the order', onclick: () => { fl.dir = fl.dir === 'desc' ? 'asc' : 'desc'; refilter(); } }, fl.dir === 'desc' ? '↓' : '↑'),
    sel('Group by', fl.group, GROUPS, v => { fl.group = v; L.paintMain(); }),
    h('label', { class: 'switch' }, h('input', { type: 'checkbox', checked: fl.gone, onchange: e => { fl.gone = e.target.checked; refilter(); } }), h('i'), 'Show gone devices'));
  const head = h('thead', {}, h('tr', {}, ['Device', 'Addresses', 'Hardware', 'Type', 'Status', 'Subnet', 'Last seen'].map(x => h('th', {}, x))));
  return [h('div', { class: 'card' }, h('div', { class: 'card-h' }, bar, h('div', { class: 'row' }, h('span', { class: 'mono muted' }, L.fmt.n(N().total)), h('button', { class: 'btn primary', onclick: () => editDevice(null) }, L.ic('plus'), 'Add device'))),
    list.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, head, [...groups.entries()].map(([name, rows]) => h('tbody', {}, fl.group !== 'none' ? h('tr', { class: 'net-group' }, h('td', { colspan: 7 }, h('strong', {}, name), ' ', h('span', { class: 'muted' }, rows.length))) : null, rows.map(deviceRow)))))
      : L.empty('No devices', fl.q || fl.kind || fl.status || fl.subnet ? 'Nothing matches the filters.' : 'Devices show up here once discovery finds them. You can also add one by hand.'))];
};

/* ---------- rooms ---------- */
const editRoom = room => form({
  title: room ? 'Edit room' : 'Add room', wide: false,
  value: room ? { name: room.name, parent_id: room.parent_id ? String(room.parent_id) : '', description: room.description || '' } : { name: '', parent_id: '', description: '' },
  fields: [{ key: 'name', label: 'Name' }, { key: 'parent_id', label: 'Inside', type: 'select', options: roomOptions(room?.id), hint: 'Use a parent for a floor, building, or area.' }, { key: 'description', label: 'Description', type: 'area' }],
  onSave: o => send(room ? 'PUT' : 'POST', room ? '/rooms/' + room.id : '/rooms', { name: o.name, parent_id: num(o.parent_id), description: o.description || '' }, 'Saved.')
});
const removeRoom = async room => {
  if (!(await L.confirm({ title: 'Delete this room?', text: 'Devices and child rooms are kept, but they will no longer be assigned to this room.', label: 'Delete', danger: true }))) return;
  try { await send('DELETE', '/rooms/' + room.id, null, 'Deleted.'); } catch (e) { L.toast(e.message, 'bad'); }
};
const roomsTab = () => {
  const rows = [...N().rooms].sort((a, b) => roomName(a.id).localeCompare(roomName(b.id)));
  return [h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('div', {}, h('strong', {}, 'Rooms'), h('div', { class: 'hint' }, 'Group devices by room, floor, building, or any nested place.')), h('button', { class: 'btn primary', onclick: () => editRoom(null) }, L.ic('plus'), 'Add room')),
    rows.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Room', 'Description', 'Devices', ''].map(x => h('th', {}, x)))), h('tbody', {}, rows.map(room => {
      const count = N().everyone.filter(d => d.room_id === room.id).length;
      return h('tr', {}, h('td', {}, h('strong', {}, roomName(room.id))), h('td', {}, room.description || dash), h('td', {}, L.fmt.n(count)), h('td', { class: 'act' }, h('button', { class: 'btn sm flat', onclick: () => editRoom(room) }, 'Edit'), h('button', { class: 'btn sm flat danger', onclick: () => removeRoom(room) }, 'Delete')));
    })))) : L.empty('No rooms yet', 'Add rooms, then assign devices from the device editor.'))];
};

/* ---------- monitoring ---------- */
const toggleMonitor = async (d, on) => {
  try { await send('PUT', '/devices/' + d.id, { name: d.name, description: d.description, notes: d.notes, location_id: d.location_id, room_id: d.room_id, snmp_profile: d.snmp_profile, monitoring: { ...d.monitoring, enabled: on } }, on ? 'Monitoring is on.' : 'Monitoring is off.'); } catch (e) { L.toast(e.message, 'bad'); }
};
const monitoringTab = () => {
  const order = { offline: 0, degraded: 1, unknown: 2, online: 3 };
  const rows = N().everyone.filter(d => !d.gone).sort((a, b) => order[a.status] - order[b.status] || a.name.localeCompare(b.name));
  const eng = N().engine;
  return [!eng?.monitor_enabled ? h('div', { class: 'note' }, L.ic('info'), h('p', {}, eng ? 'Availability checks are turned off in the configuration (network.monitor.enabled).' : 'Monitoring runs once network.enabled is set in the configuration.')) : null,
    h('div', { class: 'card', style: 'margin-top:16px' }, h('div', { class: 'card-h' }, h('strong', {}, 'Availability'), h('span', { class: 'hint' }, eng ? L.t('One lost packet is never an outage: a device is offline only after {n} failed checks in a row.', { n: eng.failures_before_offline ?? 3 }) : '')),
      rows.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Device', 'Status', 'Check', 'Last answer', 'Monitor'].map(x => h('th', {}, x)))),
        h('tbody', {}, rows.map(d => h('tr', {}, h('td', {}, h('a', { href: '#', onclick: e => { e.preventDefault(); openDevice(d.id); } }, h('strong', {}, d.name)), ' ', h('span', { class: 'hint' }, addr(d)[0] || '')), h('td', {}, d.monitoring.enabled ? pill(d.status) : h('span', { class: 'pill off' }, 'Not monitored')),
          h('td', { class: 'mono-c' }, d.monitoring.method.toUpperCase() + (d.monitoring.tcp_port ? ':' + d.monitoring.tcp_port : '')), h('td', {}, ago(d.last_ok)),
          h('td', {}, h('label', { class: 'switch' }, h('input', { type: 'checkbox', checked: d.monitoring.enabled, 'aria-label': L.t('Monitor {name}', { name: d.name }), onchange: e => toggleMonitor(d, e.target.checked) }), h('i'))))))))
        : L.empty('Nothing to monitor yet', 'Devices with an address are checked automatically once they are found or added.')),
    h('div', { class: 'card', style: 'margin-top:16px' }, h('div', { class: 'card-h' }, h('strong', {}, 'Events')), N().allEvents.length ? h('ul', { class: 'net-list card-b' }, N().allEvents.map(eventRow)) : L.empty('No events yet', 'Outages and recoveries are listed here.'))];
};

/* ---------- discovery ---------- */
const discoveryTab = () => {
  const eng = N().engine;
  if (!eng) return [L.empty('Discovery is off', 'Set network.enabled and list the networks to look at in the configuration. Lumen only looks at networks you name, and never scans anything else.')];
  return [h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('strong', {}, 'Networks Lumen looks at'), h('button', { class: 'btn primary', disabled: eng.scanning, onclick: runScan }, eng.scanning ? 'Running…' : 'Run discovery now')),
    h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Scope', 'Networks', 'Excluded', 'Interface', 'SNMP profile'].map(x => h('th', {}, x)))),
      h('tbody', {}, eng.scopes.map(s => h('tr', {}, h('td', {}, h('strong', {}, s.name)), h('td', { class: 'mono-c' }, s.networks.join(', ')), h('td', { class: 'mono-c' }, s.excluded.join(', ') || '—'), h('td', { class: 'mono-c' }, s.interface || '—'), h('td', {}, s.snmp_profile || '—'))))))),
    h('div', { class: 'card', style: 'margin-top:16px' }, h('div', { class: 'card-b net-facts' },
      h('div', { class: 'net-fact' }, h('span', { class: 'muted' }, 'Automatic runs'), h('span', {}, eng.scan_interval_secs ? L.t('every {n} min', { n: Math.round(eng.scan_interval_secs / 60) }) : 'Only when you ask')),
      h('div', { class: 'net-fact' }, h('span', { class: 'muted' }, 'Next run'), h('span', {}, eng.next_scan ? L.fmt.time(eng.next_scan * 1000) : '—')),
      h('div', { class: 'net-fact' }, h('span', { class: 'muted' }, 'Ping (IPv4 / IPv6)'), h('span', {}, (eng.icmp_v4 ? 'Available' : 'Not allowed') + ' / ' + (eng.icmp_v6 ? 'Available' : 'Not allowed'))),
      h('div', { class: 'net-fact' }, h('span', { class: 'muted' }, 'Availability checks'), h('span', {}, eng.monitor_enabled ? L.t('every {n} s', { n: eng.monitor_interval_secs }) : 'Off')),
      h('div', { class: 'net-fact' }, h('span', { class: 'muted' }, 'SNMP profiles'), h('span', {}, eng.snmp_profiles.join(', ') || 'None')),
      eng.fritzbox ? h('div', { class: 'net-fact' }, h('span', { class: 'muted' }, 'FRITZ!Box'),
        h('span', {}, eng.fritzbox.error ? h('span', { class: 'pill bad', title: eng.fritzbox.error }, 'Failed') : eng.fritzbox.last_import ? L.t('{model} · {n} devices, {t}', { model: eng.fritzbox.model || eng.fritzbox.host, n: eng.fritzbox.imported, t: L.fmt.time(eng.fritzbox.last_import * 1000) }) : 'Waiting for the first import')) : null,
      eng.fritzbox?.error ? h('div', { class: 'note warn', style: 'grid-column:1/-1' }, L.ic('alert'), h('p', {}, eng.fritzbox.error)) : null)),
    h('div', { class: 'card', style: 'margin-top:16px' }, h('div', { class: 'card-h' }, h('strong', {}, 'Recent runs')),
      N().allScans.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Started', 'Result', 'Probed', 'Seen', 'New', 'Gone', 'Notes'].map(x => h('th', {}, x)))),
        h('tbody', {}, N().allScans.map(s => h('tr', {}, h('td', { class: 'mono-c' }, L.fmt.time(s.started * 1000)), h('td', {}, h('span', { class: 'pill ' + (s.state === 'finished' ? 'ok' : s.state === 'failed' ? 'bad' : 'warn') }, s.state)), h('td', {}, L.fmt.n(s.probed)), h('td', {}, L.fmt.n(s.seen)), h('td', {}, L.fmt.n(s.new_devices)), h('td', {}, L.fmt.n(s.gone_devices)), h('td', {}, s.detail || '—'))))))
        : L.empty('No runs yet', 'The first run starts a few seconds after Lumen starts, or press Run discovery now.'))];
};

/* ---------- topology ---------- */
/* Tiers by distance from the gateways, over links that exist. Devices with no link are set apart
   below, because their place in the network is unknown. */
const layout = (nodes, links) => {
  const adj = new Map(nodes.map(n => [n.id, []]));
  links.forEach(l => { adj.get(l.a)?.push(l.b); adj.get(l.b)?.push(l.a); });
  const linked = nodes.filter(n => adj.get(n.id).length), loose = nodes.filter(n => !adj.get(n.id).length);
  const roots = linked.filter(n => n.kind === 'router' || n.kind === 'firewall');
  if (!roots.length && linked.length) roots.push([...linked].sort((a, b) => b.links - a.links)[0]);
  const level = new Map(), order = [];
  const queue = roots.map(r => (level.set(r.id, 0), r.id));
  while (queue.length) { const id = queue.shift(); order.push(id); for (const next of adj.get(id)) if (!level.has(next)) { level.set(next, level.get(id) + 1); queue.push(next); } }
  linked.filter(n => !level.has(n.id)).forEach(n => { level.set(n.id, 0); order.push(n.id); });
  const tiers = []; order.forEach(id => { const t = level.get(id); (tiers[t] ||= []).push(id); });
  const pos = new Map(), X = 150, Y = 150, widest = Math.max(1, ...tiers.map(t => t?.length || 0));
  tiers.forEach((ids, t) => { if (!ids) return; const parentX = id => { const ps = adj.get(id).filter(p => pos.has(p) && level.get(p) < t); return ps.length ? ps.reduce((s, p) => s + pos.get(p).x, 0) / ps.length : 0; };
    const sorted = [...ids].sort((a, b) => parentX(a) - parentX(b)); sorted.forEach((id, i) => pos.set(id, { x: (i - (sorted.length - 1) / 2) * X + (widest * X) / 2, y: 70 + t * Y })); });
  const baseY = 70 + tiers.length * Y + 20, perRow = Math.max(4, Math.min(10, Math.round(widest + 2)));
  loose.forEach((n, i) => pos.set(n.id, { x: (i % perRow) * 120 + 60, y: baseY + Math.floor(i / perRow) * 100 }));
  return { pos, loose, baseY, width: Math.max(widest * X, perRow * 120) + 120, height: baseY + Math.ceil(loose.length / perRow) * 100 + 40 };
};
const utilColor = p => p == null ? 'var(--text-2)' : p >= 80 ? 'var(--bad)' : p >= 50 ? 'var(--warn)' : 'var(--ok)';

const topologyTab = () => {
  const t = N().topology || { nodes: [], links: [] };
  const subnets = [...new Set(N().everyone.map(d => d.subnet).filter(Boolean))].sort(), vlans = [...new Set(N().everyone.map(d => d.vlan).filter(Boolean))].sort();
  const reTopo = async () => { try { await L.loadNetwork(); } catch (e) { L.toast(e.message, 'bad'); } L.paintMain(); };
  const bar = h('div', { class: 'row' },
    subnets.length ? sel('Subnet', tf.subnet, [['', 'All subnets'], ...subnets.map(s => [s, s])], v => { tf.subnet = v; reTopo(); }) : null,
    vlans.length ? sel('VLAN', tf.vlan, [['', 'All VLANs'], ...vlans.map(s => [s.replace(/^VLAN (\d+).*/, '$1'), s])], v => { tf.vlan = v; reTopo(); }) : null,
    N().locations.length ? sel('Location', tf.location, locOptions().map(([v, t2]) => [v, v ? t2 : 'All locations']), v => { tf.location = v; reTopo(); }) : null,
    sel('Type', tf.kind, [['', 'All types'], ...KINDS.map(k => [k, cap(k)])], v => { tf.kind = v; reTopo(); }),
    h('label', { class: 'switch' }, h('input', { type: 'checkbox', checked: tf.loose, onchange: e => { tf.loose = e.target.checked; L.paintMain(); } }), h('i'), 'Show devices with no link'),
    h('label', { class: 'switch' }, h('input', { type: 'checkbox', checked: tf.labels, onchange: e => { tf.labels = e.target.checked; L.paintMain(); } }), h('i'), 'Show speed and use'));
  const nodes = t.nodes.filter(n => tf.loose || n.links > 0);
  if (!nodes.length) return [h('div', { class: 'card' }, h('div', { class: 'card-h' }, bar, h('button', { class: 'btn', onclick: () => editLink(null) }, 'Add link')), L.empty('Nothing to draw', 'Add devices, or run discovery. Connections appear when switches report them over SNMP (LLDP), or when you add them.'))];
  const shown = new Set(nodes.map(n => n.id));
  const links = t.links.filter(l => shown.has(l.a) && shown.has(l.b));
  const { pos, loose, baseY, width, height } = layout(nodes, links);
  const svg = sv('svg', { class: 'net-topo', viewBox: `0 0 ${Math.max(640, width)} ${Math.max(360, height)}`, role: 'img', 'aria-label': 'Network topology' });
  const g = sv('g', {}); svg.append(g);
  const apply = () => g.setAttribute('transform', `translate(${view.x} ${view.y}) scale(${view.k})`); apply();
  const edgeG = sv('g', {}), nodeG = sv('g', {}); g.append(edgeG, nodeG);
  if (loose.length && tf.loose) g.prepend(sv('text', { x: 20, y: baseY - 22, class: 'net-cap' }, 'No known connection'));
  links.forEach(l => {
    const a = pos.get(l.a), b = pos.get(l.b); if (!a || !b) return;
    const util = Math.max(l.a_stats?.utilization_percent ?? -1, l.b_stats?.utilization_percent ?? -1), has = util >= 0;
    const line = sv('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: 'net-edge' + (l.confirmed ? '' : ' inferred'), stroke: tf.labels && has ? utilColor(util) : null, tabindex: 0, role: 'button', 'aria-label': L.t('Link {a} to {b}', { a: byId(l.a)?.name || l.a, b: byId(l.b)?.name || l.b }) },
      sv('title', {}, [`${byId(l.a)?.name || ''} ${l.a_port} ↔ ${byId(l.b)?.name || ''} ${l.b_port}`, l.confirmed ? (l.kind === 'manual' ? L.t('Set by you') : L.t('Reported by a device')) : L.t('Inferred, not confirmed'), l.speed_mbps ? l.speed_mbps + ' Mb/s' : '', has ? L.t('{n}% used', { n: util.toFixed(0) }) : ''].filter(Boolean).join('\n')));
    const open = () => { const link = { id: l.id, a: l.a, a_port: l.a_port, b: l.b, b_port: l.b_port, speed_mbps: l.speed_mbps };
      L.modal({ title: 'Link', body: h('div', { class: 'stack' }, h('p', { style: 'margin:0' }, h('strong', {}, byId(l.a)?.name), ' ', l.a_port, ' ↔ ', h('strong', {}, byId(l.b)?.name), ' ', l.b_port), h('p', { class: 'muted', style: 'margin:0' }, l.confirmed ? (l.kind === 'manual' ? 'You set this link.' : 'A device reported this link (LLDP).') : 'Lumen inferred this from the addresses a switch has learned on a port. It may pass through another switch. Correct it to confirm.')), actions: [{ label: 'Close' }, { label: 'Remove', kind: 'danger', onClick: () => { removeLink(link); } }, { label: 'Correct…', kind: 'primary', onClick: () => { editLink(link); } }] }); };
    line.addEventListener('click', e => { e.stopPropagation(); open(); }); line.addEventListener('keydown', e => { if (e.key === 'Enter') open(); });
    edgeG.append(line);
    if (tf.labels) { const text = [l.speed_mbps ? (l.speed_mbps >= 1000 ? l.speed_mbps / 1000 + 'G' : l.speed_mbps + 'M') : '', has ? util.toFixed(0) + '%' : ''].filter(Boolean).join(' · '); if (text) edgeG.append(sv('text', { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 - 4, class: 'net-cap', 'text-anchor': 'middle' }, text)); }
  });
  nodes.forEach(n => {
    const p = pos.get(n.id); if (!p) return;
    const color = { online: 'var(--ok)', degraded: 'var(--warn)', offline: 'var(--bad)', unknown: 'var(--text-2)' }[n.status];
    const open = () => openDevice(n.id);
    const node = sv('g', { class: 'net-node', transform: `translate(${p.x} ${p.y})`, tabindex: 0, role: 'button', 'aria-label': `${n.name}, ${n.status}` },
      sv('title', {}, [n.name, cap(n.kind), n.ip, n.vendor, n.vlan, L.t(STATUS[n.status][1])].filter(Boolean).join('\n')),
      sv('circle', { r: 24, class: 'net-disc', stroke: color }), sv('g', { transform: 'translate(-11 -11)', color: 'var(--text)' }, glyph(iconOf(n), 22)), sv('circle', { cx: 18, cy: -18, r: 5, fill: color, class: 'net-dot' }),
      sv('text', { y: 42, 'text-anchor': 'middle', class: 'net-name' }, n.name.length > 18 ? n.name.slice(0, 17) + '…' : n.name), n.ip ? sv('text', { y: 55, 'text-anchor': 'middle', class: 'net-cap' }, n.ip) : null);
    node.addEventListener('click', e => { e.stopPropagation(); open(); }); node.addEventListener('keydown', e => { if (e.key === 'Enter') open(); });
    nodeG.append(node);
  });
  /* Zoom with the wheel, pan by dragging the background. */
  const toSvg = (e) => { const r = svg.getBoundingClientRect(), vb = svg.viewBox.baseVal; return { x: (e.clientX - r.left) / r.width * vb.width, y: (e.clientY - r.top) / r.height * vb.height }; };
  const zoom = (f, at) => { const k = Math.min(4, Math.max(0.25, view.k * f)), c = at || { x: svg.viewBox.baseVal.width / 2, y: svg.viewBox.baseVal.height / 2 }; view.x = c.x - (c.x - view.x) * (k / view.k); view.y = c.y - (c.y - view.y) * (k / view.k); view.k = k; apply(); };
  svg.addEventListener('wheel', e => { e.preventDefault(); zoom(e.deltaY < 0 ? 1.15 : 1 / 1.15, toSvg(e)); }, { passive: false });
  let drag = null;
  svg.addEventListener('pointerdown', e => { if (e.target !== svg) return; drag = { from: toSvg(e), x: view.x, y: view.y }; svg.setPointerCapture(e.pointerId); svg.classList.add('drag'); });
  svg.addEventListener('pointermove', e => { if (!drag) return; const p = toSvg(e); view.x = drag.x + p.x - drag.from.x; view.y = drag.y + p.y - drag.from.y; apply(); });
  const end = () => { drag = null; svg.classList.remove('drag'); }; svg.addEventListener('pointerup', end); svg.addEventListener('pointercancel', end);
  const legend = h('div', { class: 'net-legend' }, h('span', {}, sv('svg', { width: 34, height: 8 }, sv('line', { x1: 0, y1: 4, x2: 34, y2: 4, class: 'net-edge' })), ' Confirmed: reported by a device or set by you'),
    h('span', {}, sv('svg', { width: 34, height: 8 }, sv('line', { x1: 0, y1: 4, x2: 34, y2: 4, class: 'net-edge inferred' })), ' Inferred: not confirmed'));
  return [h('div', { class: 'card' }, h('div', { class: 'card-h' }, bar, h('div', { class: 'row' }, h('button', { class: 'btn sm', 'aria-label': 'Zoom in', onclick: () => zoom(1.25) }, '+'), h('button', { class: 'btn sm', 'aria-label': 'Zoom out', onclick: () => zoom(0.8) }, '−'), h('button', { class: 'btn sm', onclick: () => { view = { x: 0, y: 0, k: 1 }; apply(); } }, L.ic('fit'), 'Fit'), h('button', { class: 'btn', onclick: () => editLink(null) }, L.ic('plus'), 'Add link'))),
    h('div', { class: 'net-topo-wrap' }, svg), h('div', { class: 'card-b' }, legend, h('p', { class: 'hint', style: 'margin:8px 0 0' }, 'Pings and neighbor tables cannot show how devices are wired. A link is confirmed only when a switch reports it (LLDP) or you add it; the rest is inferred and drawn dashed.')))];
};

/* An explicit switch, not a lookup by the route's name, so a route can only ever select one of these. */
const renderTab = tab => {
  switch (tab) {
    case 'devices': return devicesTab();
    case 'rooms': return roomsTab();
    case 'topology': return topologyTab();
    case 'monitoring': return monitoringTab();
    case 'discovery': return discoveryTab();
    default: return overviewTab();
  }
};
L.views.network = () => {
  start();
  const head = L.pageHead('Network', 'Devices on your networks, how they connect, and whether they are up. Lumen only looks at networks you list, and it never changes a device.', h('button', { class: 'btn', onclick: reload }, 'Refresh'));
  if (!N()) return [head, L.empty('Loading', 'One moment.')];
  const tab = TABS.some(([id]) => id === L.route().sub) ? L.route().sub : 'overview';
  return [head, L.tabs(TABS, tab, id => L.go('network', id)), h('div', { style: 'margin-top:16px' }, renderTab(tab))];
};
})();
