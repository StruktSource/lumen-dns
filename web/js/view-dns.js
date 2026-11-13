(() => {
'use strict';
const L = window.L, h = L.h, f = L.f;
const card = (title, right, ...body) => h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, title), right || null), h('div', { class: 'card-b stack' }, ...body));
const num = (o, k, path, label, hint, opt) => f.field(label, f.num(o, k, path, opt), hint);

/* ---------- listeners ---------- */
const TRANSPORTS = [['udp', 'UDP', 'Plain DNS. Falls back to TCP when truncated.', '0.0.0.0:53'], ['tcp', 'TCP', 'Plain DNS over TCP.', '0.0.0.0:53'], ['dot', 'DNS over TLS', 'Encrypted, TCP 853. Needs a certificate.', '0.0.0.0:853'], ['doh', 'DNS over HTTPS', 'Encrypted, HTTP/2. Needs a certificate.', '0.0.0.0:443'], ['doq', 'DNS over QUIC', 'Encrypted, UDP 853. Needs a certificate.', '0.0.0.0:853']];
function listenersTab() {
  const c = L.D().listen; const enc = c.dot.length || c.doh.length || c.doq.length;
  const open = c.allow_clients.some(x => x === '0.0.0.0/0' || x === '::/0');
  return h('div', { class: 'stack' },
    h('div', { class: 'grid g2' }, TRANSPORTS.map(([k, name, desc, ph]) => card(name, h('span', { class: 'pill ' + (c[k].length ? 'ok' : 'off') }, c[k].length ? c[k].length + ' on' : 'Off'), h('div', { class: 'hint', style: 'margin:0' }, desc), f.tags(c[k], { validate: L.v.socket, placeholder: ph + ' then Enter', what: 'as address:port', max: 16 })))),
    card('Who may ask', h('span', { class: 'mono muted' }, `${c.allow_clients.length} / 128`),
      h('p', { class: 'hint', style: 'margin:0' }, 'Every client must match an allowed network, on every transport. Binding 0.0.0.0 does not grant access by itself.'), f.tags(c.allow_clients, { validate: L.v.cidr, placeholder: '192.168.1.0/24', what: 'as CIDR', max: 128 }),
      open ? h('div', { class: 'note bad' }, L.ic('alert'), h('p', {}, 'This makes Lumen an open resolver reachable by the whole internet. Restrict it to your own networks.')) : null),
    card('TLS certificate', enc ? h('span', { class: 'pill warn' }, 'Required') : h('span', { class: 'pill off' }, 'Not needed'), h('div', { class: 'fgrid' }, f.field('Certificate (PEM)', f.text(c, 'certificate', { mono: true, placeholder: 'tls/dns-cert.pem', validate: L.v.path })), f.field('Private key (PEM)', f.text(c, 'private_key', { mono: true, placeholder: 'tls/dns-key.pem', validate: L.v.path }))),
      h('p', { class: 'hint', style: 'margin:0' }, 'TLS 1.3 only, no early data. Lumen does not issue or renew certificates; paths are relative to the config file. Restart after rotation.')));
}

/* ---------- resolver ---------- */
let stash = null;
/* Recursive mode takes no forwarding upstreams, so park them while it is selected. */
function switchMode(r) {
  if (r.mode === 'recursive') { if (r.providers.length || r.upstreams.length) stash = { providers: r.providers, upstreams: r.upstreams }; r.providers = []; r.upstreams = []; }
  else if (stash) { r.providers = stash.providers; r.upstreams = stash.upstreams; stash = null; }
  else if (!r.providers.length && !r.upstreams.length) { const p = L.S.providers.find(x => x.id === 'quad9-unfiltered') || L.S.providers[0]; if (p) { r.providers = [newProvider(p)]; r.strategy = 'failover'; } }
  L.touch(); L.rerender();
}
function resolverTab() {
  const r = L.D().resolver, rec = r.mode === 'recursive';
  return h('div', { class: 'stack' },
    card('Resolution', null, h('div', { class: 'row' }, h('div', {}, h('div', { class: 'mono muted', style: 'margin-bottom:6px' }, 'Mode'), f.seg(r, 'mode', [['recursive', 'Recursive'], ['forward', 'Forward']], { onChange: () => switchMode(r) }))), h('p', { class: 'hint', style: 'margin:0' }, rec ? 'Lumen walks the DNS hierarchy itself from the root servers. Nothing is sent to a third-party resolver. This is the private default.' : 'Lumen forwards to the upstreams you choose on the next tab. Those operators see your queries.'),
      f.sw(r, 'dnssec', 'Validate DNSSEC locally'), f.sw(r, 'local_zones', 'Handle local-only names'), f.sw(r, 'diagnostics', 'Extra private-safe resolver metrics', { disabled: !rec }), !r.dnssec ? h('div', { class: 'note warn' }, L.ic('alert'), h('p', {}, 'Without validation, forged answers are accepted.')) : null),
    card('Cache', null, h('div', { class: 'fgrid' }, num(r, 'cache_entries', 'resolver.cache_entries', 'Answer cache', 'Entries, not bytes.'), num(r, 'nameserver_cache_entries', 'resolver.nameserver_cache_entries', 'Delegation cache', rec ? 'Recursive delegation cache.' : 'Recursive mode only.', { disabled: !rec }), num(r, 'validation_cache_entries', 'resolver.validation_cache_entries', 'DNSSEC validation cache', ''),
      num(r, 'positive_ttl_secs', 'resolver.positive_ttl_secs', 'Max positive TTL', 'A ceiling, never a forced minimum.'), num(r, 'negative_ttl_secs', 'resolver.negative_ttl_secs', 'Max negative TTL', 'NXDOMAIN and NODATA ceiling.'), rec ? num(r, 'recursion_depth', 'resolver.recursion_depth', 'Recursion depth', '') : null, num(r, 'attempts', 'resolver.attempts', rec ? 'Walk attempts' : 'Forward attempts', 'Only timeout failures retry.'), num(r, 'upstream_timeout_ms', 'resolver.upstream_timeout_ms', rec ? 'Walk timeout' : 'Upstream timeout', 'Per attempt.'))),
    rec ? [
      card('Startup priming', f.sw(r.warm, 'enabled', '', { onChange: L.rerender }), h('p', { class: 'hint', style: 'margin:0' }, 'Once at startup, Lumen resolves NS and DNSKEY for these zones so the first real query is faster. It never sends client data.'), f.tags(r.warm.zones, { validate: L.v.domain, placeholder: 'com', max: 64, disabled: !r.warm.enabled })),
      card('Expiry prefetch', f.sw(r.prefetch, 'enabled', '', { onChange: L.rerender }), h('p', { class: 'hint', style: 'margin:0' }, 'Refreshes repeatedly requested names just after their TTL ends. Tracked names live in memory only and are forgotten after an hour.'),
        h('div', { class: 'fgrid' }, [['min_hits', 'Min cache hits'], ['max_tracked', 'Tracked names'], ['max_concurrent', 'Concurrent refreshes'], ['budget_per_minute', 'Budget']].map(([k, t]) => num(r.prefetch, k, 'resolver.prefetch.' + k, t, '', { disabled: !r.prefetch.enabled })))),
      card('Hedged recursion', h('span', { class: 'pill off' }, 'Experimental'), h('div', { class: 'fgrid' }, f.field('Hedge after', f.num(r, 'hedge_ms', '', { min: 100, max: 5000, unit: 'ms', zero: true }), '0 = off, or 100–5000 ms. Starts a second recursion for slow lookups; first usable answer wins. Measurements were inconclusive.')))] : null);
}

/* ---------- upstreams ---------- */
const PROTOS = ['udp', 'tcp', 'tls', 'https', 'h3', 'quic'];
function upstreamTable(arr, max, title, addBtnLabel) {
  const draft = { address: '', protocol: 'tls', server_name: '', doh_path: '' };
  const rows = h('tbody', {});
  const draw = () => { rows.replaceChildren(...arr.map((u, i) => h('tr', {}, h('td', { class: 'mono-c' }, u.address), h('td', { class: 'mono-c' }, u.protocol), h('td', { class: 'mono-c' }, u.server_name || '—'), h('td', { class: 'act' }, h('button', { class: 'btn sm flat danger', 'aria-label': 'Remove', onclick: () => { arr.splice(i, 1); L.touch(); L.rerender(); } }, L.ic('trash'))))));
    if (!arr.length) rows.append(h('tr', {}, h('td', { colspan: 4, class: 'muted' }, 'None yet.'))); };
  draw(); const err = h('div', { class: 'err' });
  return h('div', {}, h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Address', 'Protocol', 'Server name', ''].map(x => h('th', {}, x)))), rows)),
    h('div', { class: 'card-b stack', style: 'border-top:1px solid var(--rule)' }, h('div', { class: 'fgrid' }, f.field('Address:port', f.text(draft, 'address', { mono: true, placeholder: '9.9.9.9:853', validate: L.v.socket }), 'Explicit IP, no bootstrap lookup.'), f.field('Protocol', f.sel(draft, 'protocol', PROTOS)), f.field('Server name', f.text(draft, 'server_name', { mono: true, placeholder: 'dns.example' }), 'Required for tls, https, quic.'), f.field('DoH path', f.text(draft, 'doh_path', { mono: true, placeholder: '/dns-query' }), 'Only for https. Leave empty for /dns-query.')), err,
      h('div', {}, h('button', { class: 'btn', onclick: () => { if (arr.length >= max) { err.textContent = L.t('At most {n} here.', { n: max }); return; } if (!L.v.socket(draft.address)) { err.textContent = 'Address must be IP:port, e.g. 9.9.9.9:853.'; return; } if (['tls', 'h3', 'https', 'quic'].includes(draft.protocol) && !draft.server_name) { err.textContent = 'Encrypted protocols need a server name.'; return; } const u = { address: draft.address, protocol: draft.protocol }; if (draft.server_name) u.server_name = draft.server_name; if (['https', 'h3'].includes(draft.protocol) && draft.doh_path) u.doh_path = draft.doh_path; arr.push(u); L.touch(); L.rerender(); } }, L.ic('plus'), addBtnLabel))));
}
const ENCRYPTED = ['quic', 'https', 'h3', 'tls'];
const encrypted = p => p.transports.some(t => ENCRYPTED.includes(t));
/* A provider is added with automatic, encrypted-only transport: QUIC, then HTTPS, then HTTP/3, then TLS. */
const newProvider = p => ({ id: p.id, protocol: 'auto', address_family: 'any', transport_priority: ENCRYPTED.filter(t => p.transports.includes(t)) });
const STRATEGIES = [
  ['failover', 'Ranked fallback', 'The first provider answers. The next one is used only when it does not respond, in the order you set. Lowest exposure: only one provider sees a lookup.'],
  ['fastest', 'Fastest first', 'The provider that has answered fastest recently takes the query, and the others stand by. A provider that fails is left alone for a short while.'],
  ['round_robin', 'Round-robin', 'Each query goes to the next provider in turn, so the load and what each provider sees are spread evenly. A provider that fails is skipped.'],
  ['race', 'Race', 'Every provider gets every query at the same time and the first answer wins. The fastest answers, but every provider sees all your lookups.']];
/* Settings from before strategies existed keep their old behavior until you choose one. */
const strategyOf = r => r.strategy || (r.providers.length && r.providers.every(x => x.protocol === 'auto') ? 'failover' : 'fastest');
function providerList(r) {
  const move = (i, by) => { const j = i + by; if (j < 0 || j >= r.providers.length) return; [r.providers[i], r.providers[j]] = [r.providers[j], r.providers[i]]; L.touch(); L.rerender(); };
  return r.providers.map((sel, i) => {
    const p = L.S.providers.find(x => x.id === sel.id);
    return h('div', { class: 'card' }, h('div', { class: 'card-b stack' },
      h('div', { class: 'row' }, h('span', { class: 'rank', 'aria-label': L.t('Rank {n}', { n: i + 1 }) }, String(i + 1)),
        h('div', { class: 'sp' }, h('strong', {}, p ? p.name : sel.id), p ? h('div', { class: 'hint' }, `${p.country} · ${p.scope.replace(/_/g, ' ')} · ${p.filter}`) : null),
        h('button', { class: 'btn sm flat', 'aria-label': 'Move up', disabled: i === 0, onclick: () => move(i, -1) }, L.ic('up')),
        h('button', { class: 'btn sm flat', 'aria-label': 'Move down', disabled: i === r.providers.length - 1, onclick: () => move(i, 1) }, L.ic('down')),
        h('button', { class: 'btn sm flat danger', 'aria-label': L.t('Remove {item}', { item: p ? p.name : sel.id }), onclick: () => { r.providers.splice(i, 1); L.touch(); L.rerender(); } }, L.ic('trash'))),
      p ? h('div', { class: 'chips' }, p.transports.map(t => h('span', { class: 'chip' }, t))) : null,
      p ? h('div', { class: 'fgrid' }, f.field('Protocol', f.sel(sel, 'protocol', ['auto', ...p.transports], { onChange: L.rerender }), sel.protocol === 'auto' ? 'Auto prefers QUIC, then HTTPS, then TLS, and requires encryption.' : 'Fixed protocol, no automatic failover.'), f.field('Address family', f.sel(sel, 'address_family', ['any', 'ipv4', 'ipv6'], { onChange: L.rerender }))) : null));
  });
}
function upstreamsTab() {
  const r = L.D().resolver, rec = r.mode === 'recursive', addresses = L.providerUpstreams(r.providers) + r.upstreams.length;
  const chosen = new Set(r.providers.map(x => x.id)), full = r.providers.length >= 8;
  const choices = L.S.providers.filter(p => !chosen.has(p.id)).map(p => h('div', { class: 'card' }, h('div', { class: 'card-b stack' },
    h('div', { class: 'row' }, h('div', { class: 'sp' }, h('strong', {}, p.name), h('div', { class: 'hint' }, `${p.country} · ${p.scope.replace(/_/g, ' ')} · ${p.filter}`)),
      encrypted(p) ? h('button', { class: 'btn sm', disabled: full, onclick: () => { r.providers.push(newProvider(p)); if (!r.strategy) r.strategy = r.providers.length > 1 ? 'failover' : null; L.touch(); L.rerender(); } }, L.ic('plus'), 'Add') : h('span', { class: 'pill off' }, 'No encrypted transport')),
    h('div', { class: 'chips' }, p.transports.map(t => h('span', { class: 'chip' }, t))))));
  const groups = r.providers.length + r.upstreams.length, current = strategyOf(r);
  return h('div', { class: 'stack' },
    rec ? h('div', { class: 'note' }, L.ic('info'), h('p', {}, 'Recursive mode does not use forwarding upstreams. Switch to forward mode on the Resolver tab to use these, or configure a timeout-only fallback below.')) : null,
    !rec ? [h('div', { class: 'note' }, L.ic('info'), h('p', {}, 'Choose up to 8 bundled providers and rank them. Your own upstreams come after them. Every provider is used over an encrypted connection; “Auto” prefers QUIC, then HTTPS, then TLS.')),
      h('div', { class: 'sec-title' }, h('h2', {}, 'Your providers'), h('span', { class: 'pill ' + (r.providers.length > 8 || addresses > 128 ? 'bad' : 'plain') }, L.t('{n} of 8 providers · {a} addresses', { n: r.providers.length, a: addresses }))),
      r.providers.length ? providerList(r) : h('div', { class: 'card' }, L.empty('No provider chosen', 'Add a provider below, or add your own upstream further down.')),
      h('div', { class: 'sec-title' }, h('h2', {}, 'How to use them')),
      groups < 2 ? h('p', { class: 'hint', style: 'margin:0' }, 'With one provider there is nothing to choose between. Add a second provider or upstream to pick how queries are shared.') : null,
      h('div', { class: 'picks' }, STRATEGIES.map(([v, t, d]) => h('label', { class: 'pick' }, h('input', { type: 'radio', name: 'strategy', checked: current === v, onchange: () => { r.strategy = v; L.touch(); L.rerender(); } }), h('div', {}, h('b', {}, t), h('span', {}, d))))),
      groups >= 2 ? h('p', { class: 'hint', style: 'margin:0' }, 'Only a connection failure or a timeout moves on to another provider. A DNS answer, including “no such domain” and a DNSSEC failure, is final.') : null,
      h('div', { class: 'sec-title' }, h('h2', {}, 'Add a provider'), h('span', { class: 'mono muted' }, full ? 'all 8 chosen' : `${8 - r.providers.length} more`)),
      choices.length ? h('div', { class: 'grid g2' }, choices) : h('div', { class: 'card' }, L.empty('Every bundled provider is in use', 'Remove one above to add another.')),
      h('div', { class: 'sec-title' }, h('h2', {}, 'Custom upstreams'), h('span', { class: 'mono muted' }, `${r.upstreams.length} / 8`)), h('div', { class: 'card' }, upstreamTable(r.upstreams, 8, 'Upstreams', 'Add upstream'))] : null,
    rec ? [h('div', { class: 'sec-title' }, h('h2', {}, 'Timeout-only fallback'), f.sw(r.fallback, 'enabled', 'Enabled', { onChange: L.rerender })),
      h('p', { class: 'hint', style: 'margin:0' }, 'If recursion times out, ask these upstreams instead. It never triggers on NXDOMAIN, SERVFAIL, DNSSEC failures or filtering. Those operators will see the names that timed out.'),
      r.fallback.enabled ? [card('Fallback budget', null, h('div', { class: 'fgrid' }, num(r.fallback, 'recursive_timeout_ms', 'resolver.fallback.recursive_timeout_ms', 'Recursive budget', 'Before fallback is allowed.'), num(r.fallback, 'timeout_ms', 'resolver.fallback.timeout_ms', 'Fallback budget', 'Whole fallback lookup.'), num(r.fallback, 'attempts', 'resolver.fallback.attempts', 'Attempts', ''))),
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Fallback upstreams'), h('span', { class: 'mono muted' }, `${r.fallback.upstreams.length} / 8`)), upstreamTable(r.fallback.upstreams, 8, 'Fallback', 'Add fallback upstream'))] : null] : null);
}

/* ---------- limits ---------- */
function limitsTab() {
  const l = L.D().limits;
  return h('div', { class: 'stack' }, card('Admission control', null, h('div', { class: 'fgrid' },
    num(l, 'queries_per_second', 'limits.queries_per_second', 'Per-client rate', 'Per source IP, all transports.'), num(l, 'max_clients', 'limits.max_clients', 'Tracked clients', 'Rate-limit entries in memory.'), num(l, 'max_in_flight', 'limits.max_in_flight', 'Concurrent resolutions', 'Beyond this: REFUSED.'), num(l, 'max_connections', 'limits.max_connections', 'Connections', 'TCP, TLS, HTTP/2, QUIC, metrics.'))),
    card('Deadlines & sizes', null, h('div', { class: 'fgrid' }, num(l, 'query_timeout_ms', 'limits.query_timeout_ms', 'Query deadline', 'Whole resolution. Timeout → SERVFAIL.'), num(l, 'io_timeout_ms', 'limits.io_timeout_ms', 'I/O deadline', 'Frames, handshakes, writes.'), num(l, 'max_message_bytes', 'limits.max_message_bytes', 'Max message size', 'DNS message bytes.'))),
    h('div', { class: 'note' }, L.ic('info'), h('p', {}, 'These cap work per client and per process. They are not a memory ceiling; use container or OS limits for a hard RSS cap.')));
}

/* ---------- local DNS ---------- */
const RR_TYPES = ['a', 'aaaa', 'cname', 'txt', 'mx', 'srv', 'ptr', 'caa', 'tlsa'];
const rrLabel = type => type.toUpperCase();
const newRecord = (type = 'a') => ({ name: '@', ttl: null, type, ...({
  a: { address: '' }, aaaa: { address: '' }, cname: { target: '' }, txt: { value: '' }, ptr: { target: '' },
  mx: { priority: 10, exchange: '' }, srv: { priority: 0, weight: 0, port: 443, target: '' },
  caa: { flags: 0, tag: 'issue', value: '' }, tlsa: { usage: 3, selector: 1, matching_type: 1, certificate_association_data: '' }
}[type] || {}) });
const relativeName = value => value === '@' || (value.length <= 253 && !value.endsWith('.') && value.split('.').every((part, i) => part.length > 0 && part.length <= 63 && ((i === 0 && part === '*') || /^[a-z0-9_-]+$/i.test(part))));
const targetName = value => value === '@' || L.v.domain(String(value).replace(/\.$/, ''));
const uint = (value, max) => Number.isInteger(value) && value >= 0 && value <= max;
const recordData = record => {
  const base = { name: record.name.trim().toLowerCase(), ttl: record.ttl == null ? null : record.ttl, type: record.type };
  const fields = { a: ['address'], aaaa: ['address'], cname: ['target'], txt: ['value'], ptr: ['target'], mx: ['priority', 'exchange'], srv: ['priority', 'weight', 'port', 'target'], caa: ['flags', 'tag', 'value'], tlsa: ['usage', 'selector', 'matching_type', 'certificate_association_data'] }[record.type] || [];
  for (const key of fields) base[key] = typeof record[key] === 'string' ? record[key].trim() : record[key];
  return base;
};
const recordIdentity = record => {
  const data = recordData(record); delete data.ttl;
  for (const key of ['target', 'exchange', 'tag', 'certificate_association_data']) if (typeof data[key] === 'string') data[key] = data[key].toLowerCase();
  return JSON.stringify(data);
};
function validRecord(record) {
  if (!relativeName(record.name)) return 'Record name must be @, a host name, or a wildcard.';
  if (!RR_TYPES.includes(record.type)) return 'Record type is not supported by this form.';
  if (record.ttl != null && !(Number.isInteger(record.ttl) && record.ttl >= 1 && record.ttl <= 604800)) return 'Record TTL must be empty or 1–604800 seconds.';
  if (record.type === 'a' && (!L.v.ip(record.address) || record.address.includes(':'))) return 'A records need an IPv4 address.';
  if (record.type === 'aaaa' && (!L.v.ip(record.address) || !record.address.includes(':'))) return 'AAAA records need an IPv6 address.';
  if (['cname', 'ptr', 'srv'].includes(record.type) && !targetName(record.target)) return `${rrLabel(record.type)} records need a valid target name.`;
  if (record.type === 'mx' && !targetName(record.exchange)) return 'MX records need a valid exchange name.';
  if (record.type === 'txt' && (new TextEncoder().encode(record.value).length > 255 || /[\x00-\x1f\x7f]/.test(record.value))) return 'TXT values must be at most 255 plain-text bytes.';
  if (record.type === 'mx' && !uint(record.priority, 65535)) return 'MX priority must be 0–65535.';
  if (record.type === 'srv' && (!uint(record.priority, 65535) || !uint(record.weight, 65535) || !uint(record.port, 65535))) return 'SRV priority, weight, and port must be 0–65535.';
  if (record.type === 'caa' && (!uint(record.flags, 255) || !/^[a-z0-9]{1,15}$/i.test(record.tag) || new TextEncoder().encode(record.value).length > 255 || /[\x00-\x1f\x7f]/.test(record.value))) return 'CAA flags, tag, or value is invalid.';
  if (record.type === 'tlsa' && (!uint(record.usage, 3) || !uint(record.selector, 1) || !uint(record.matching_type, 2) || !/^(?:[0-9a-f]{2})+$/i.test(record.certificate_association_data) || record.certificate_association_data.length > 4096)) return 'TLSA fields or certificate data are invalid.';
  return '';
}
function zoneProblems(zone, zones, ownIndex) {
  const out = [], name = String(zone.name || '').trim().replace(/\.$/, '').toLowerCase(), managed = zone.managed;
  if (!L.v.domain(name)) out.push('Zone name must be a valid DNS name.');
  if (name === 'local' || name.endsWith('.local')) out.push('.local belongs to mDNS. Use another private zone.');
  if (zones.some((item, index) => index !== ownIndex && String(item.name || '').replace(/\.$/, '').toLowerCase() === name)) out.push('Another zone already uses this name.');
  if (String(managed.description || '').length > 200 || /[\x00-\x1f\x7f]/.test(managed.description || '')) out.push('Description must be at most 200 plain characters.');
  if (!(Number.isInteger(managed.default_ttl) && managed.default_ttl >= 1 && managed.default_ttl <= 604800)) out.push('Default TTL must be 1–604800 seconds.');
  if (!Array.isArray(managed.records) || managed.records.length > 1024) out.push('A zone may contain at most 1024 records.');
  for (const record of managed.records || []) { const error = validRecord(record); if (error) out.push(error); }
  const names = new Map();
  const identities = new Set();
  for (const record of managed.records || []) { const key = record.name.toLowerCase(); const state = names.get(key) || { cname: false, count: 0 }; state.cname ||= record.type === 'cname'; state.count++; names.set(key, state); const identity = recordIdentity(record); if (identities.has(identity)) out.push('Duplicate records are not allowed.'); identities.add(identity); }
  for (const state of names.values()) if (state.cname && state.count > 1) out.push('A CNAME name cannot have other records.');
  return [...new Set(out)];
}
const recordFields = record => {
  const input = (key, label, placeholder = '', attrs = {}) => { const { numeric, ...html } = attrs; return f.field(L.t(label), h('input', { class: 'input mono-in', value: record[key] ?? '', placeholder, oninput: event => { record[key] = numeric ? Number(event.target.value) : event.target.value; }, ...html })); };
  if (record.type === 'a' || record.type === 'aaaa') return [input('address', 'Address', record.type === 'a' ? '192.168.1.10' : 'fd00::10')];
  if (record.type === 'cname' || record.type === 'ptr') return [input('target', 'Target', 'server.home.arpa.')];
  if (record.type === 'txt') return [input('value', 'Value', 'Text value')];
  if (record.type === 'mx') return [input('priority', 'Priority', '', { type: 'number', min: 0, max: 65535, numeric: true }), input('exchange', 'Exchange', 'mail.home.arpa.')];
  if (record.type === 'srv') return [input('priority', 'Priority', '', { type: 'number', min: 0, max: 65535, numeric: true }), input('weight', 'Weight', '', { type: 'number', min: 0, max: 65535, numeric: true }), input('port', 'Port', '', { type: 'number', min: 0, max: 65535, numeric: true }), input('target', 'Target', 'server.home.arpa.')];
  if (record.type === 'caa') return [input('flags', 'Flags', '', { type: 'number', min: 0, max: 255, numeric: true }), input('tag', 'Tag', 'issue'), input('value', 'Value', 'letsencrypt.org')];
  return [input('usage', 'Usage', '', { type: 'number', min: 0, max: 3, numeric: true }), input('selector', 'Selector', '', { type: 'number', min: 0, max: 1, numeric: true }), input('matching_type', 'Matching type', '', { type: 'number', min: 0, max: 2, numeric: true }), input('certificate_association_data', 'Certificate data', 'hexadecimal data')];
};
function openZoneEditor(zones, index) {
  const editing = index != null;
  const zone = editing ? L.clone(zones[index]) : { name: '', managed: { description: '', default_ttl: 300, records: [] } };
  const managed = zone.managed;
  const body = h('div', { class: 'stack' });
  const error = h('div', { class: 'err' });
  const records = h('div', { class: 'rr-list' });
  const drawRecords = () => {
    records.replaceChildren(...managed.records.map((record, recordIndex) => {
      const ttl = h('input', { class: 'input mono-in', type: 'number', min: 1, max: 604800, placeholder: String(managed.default_ttl), value: record.ttl ?? '', oninput: event => { record.ttl = event.target.value === '' ? null : Number(event.target.value); } });
      return h('div', { class: 'rr-row' },
        h('div', { class: 'rr-head' },
          f.field(L.t('Name'), h('input', { class: 'input mono-in', value: record.name, placeholder: '@ or host', oninput: event => { record.name = event.target.value.trim(); } })),
          f.field(L.t('Type'), h('select', { class: 'select mono-in', onchange: event => { managed.records[recordIndex] = { ...newRecord(event.target.value), name: record.name, ttl: record.ttl }; drawRecords(); } }, RR_TYPES.map(type => h('option', { value: type, selected: record.type === type }, rrLabel(type))))),
          f.field('TTL', ttl), h('button', { type: 'button', class: 'btn sm flat danger', onclick: () => { managed.records.splice(recordIndex, 1); drawRecords(); } }, L.ic('trash'), L.t('Delete'))),
        h('div', { class: 'rr-data' }, ...recordFields(record)));
    }));
    if (!managed.records.length) records.append(L.empty(L.t('No records yet'), L.t('Add a host record such as router → 192.168.1.1.')));
  };
  const origin = h('input', { class: 'input mono-in', value: zone.name, placeholder: 'home.arpa', oninput: event => { zone.name = event.target.value.trim(); } });
  const description = h('input', { class: 'input', value: managed.description || '', placeholder: L.t('Optional note for administrators'), maxlength: 200, oninput: event => { managed.description = event.target.value; } });
  const defaultTtl = h('input', { class: 'input mono-in', type: 'number', min: 1, max: 604800, value: managed.default_ttl, oninput: event => { managed.default_ttl = Number(event.target.value); } });
  drawRecords();
  body.append(h('div', { class: 'fgrid' }, f.field(L.t('Zone name'), origin, L.t('Use a private name such as home.arpa. Avoid .local; it belongs to mDNS.')), f.field(L.t('Description'), description), f.field(L.t('Default TTL'), defaultTtl, L.t('Used when a record has no custom TTL.'))),
    h('div', { class: 'row' }, h('b', {}, L.t('Records')), h('span', { class: 'sp' }), h('span', { class: 'mono muted' }, `${managed.records.length} / 1024`), h('button', { type: 'button', class: 'btn sm', disabled: managed.records.length >= 1024, onclick: () => { managed.records.push(newRecord()); drawRecords(); } }, L.ic('plus'), L.t('Add record'))), records, error);
  L.modal({ title: L.t(editing ? 'Edit local zone' : 'Add local zone'), wide: true, body, actions: [
    { label: L.t('Cancel') },
    { label: L.t('Save'), kind: 'primary', onClick: () => {
      const problems = zoneProblems(zone, zones, index);
      if (problems.length) { error.textContent = problems.join(' '); return false; }
      zone.name = zone.name.trim().replace(/\.$/, '').toLowerCase();
      managed.description = String(managed.description || '').trim();
      managed.records = managed.records.map(recordData);
      if (editing) zones[index] = zone; else zones.push(zone);
      L.touch(); L.rerender();
    } }
  ] });
}
function openQuickHost(zones) {
  const managedZones = zones.map((zone, index) => ({ zone, index })).filter(item => item.zone.managed);
  if (!managedZones.length) { openZoneEditor(zones, null); return; }
  const draft = { zone: managedZones[0].index, name: '', address: '' }, error = h('div', { class: 'err' });
  const body = h('div', { class: 'stack' }, f.field(L.t('Zone'), h('select', { class: 'select mono-in', onchange: event => { draft.zone = Number(event.target.value); } }, managedZones.map(item => h('option', { value: item.index }, item.zone.name)))), f.field(L.t('Host name'), h('input', { class: 'input mono-in', placeholder: 'router', oninput: event => { draft.name = event.target.value.trim(); } })), f.field(L.t('IP address'), h('input', { class: 'input mono-in', placeholder: '192.168.1.1', oninput: event => { draft.address = event.target.value.trim(); } })), error);
  L.modal({ title: L.t('Quick hostname'), body, actions: [{ label: L.t('Cancel') }, { label: L.t('Add'), kind: 'primary', onClick: () => {
    const zone = zones[draft.zone], type = draft.address.includes(':') ? 'aaaa' : 'a', record = { ...newRecord(type), name: draft.name, address: draft.address };
    const candidate = L.clone(zone); candidate.managed.records.push(recordData(record));
    const problem = validRecord(record) || zoneProblems(candidate, zones, draft.zone)[0]; if (problem || !L.v.ip(draft.address)) { error.textContent = problem || L.t('Enter a relative host name and a valid IP address.'); return false; }
    zone.managed.records.push(recordData(record)); L.touch(); L.rerender();
  } }] });
}
function localDnsTab() {
  const config = L.D(); config.zones ??= [];
  const zones = config.zones;
  const remove = async (zone, index) => {
    if (!await L.confirm({ title: L.t('Delete local zone'), text: L.t('Remove {zone} and all records from the draft configuration?', { zone: zone.name }), label: L.t('Delete'), danger: true })) return;
    zones.splice(index, 1); L.touch(); L.rerender();
  };
  return h('div', { class: 'stack' },
    h('div', { class: 'note' }, L.ic('info'), h('p', {}, L.t('Local zones answer on your network without sending these names upstream. Changes stay in the draft until you apply the configuration.'))),
    h('div', { class: 'sec-title' }, h('h2', {}, L.t('Local zones')), h('div', { class: 'row' }, h('button', { class: 'btn', onclick: () => openQuickHost(zones) }, L.ic('plus'), L.t('Quick hostname')), h('button', { class: 'btn primary', onclick: () => openZoneEditor(zones, null) }, L.ic('plus'), L.t('Add zone')))),
    zones.length ? h('div', { class: 'zone-list' }, zones.map((zone, index) => {
      const managed = zone.managed, origin = zone.name || L.t('Unnamed zone');
      return h('div', { class: 'card zone-card' }, h('div', { class: 'card-b' },
        h('div', { class: 'row' }, h('div', { class: 'sp' }, h('h3', {}, origin), managed?.description ? h('p', { class: 'hint' }, managed.description) : null), h('span', { class: 'pill ' + (managed ? 'ok' : 'off') }, managed ? L.t('{n} records', { n: managed.records.length }) : L.t('Advanced'))),
        managed ? h('div', { class: 'zone-meta' }, h('span', {}, L.t('Default TTL')), h('code', {}, `${managed.default_ttl}s`), h('span', {}, L.t('Names stay local'))) : h('p', { class: 'hint' }, L.t('This zone uses advanced file, view, signing, update, or transfer settings. Edit it in TOML.')),
        h('div', { class: 'row zone-actions' }, managed ? h('button', { class: 'btn sm', onclick: () => openZoneEditor(zones, index) }, L.ic('settings'), L.t('Edit')) : null, managed ? h('button', { class: 'btn sm danger', onclick: () => remove(zone, index) }, L.ic('trash'), L.t('Delete')) : null)));
    })) : h('div', { class: 'card' }, L.empty(L.t('No local zones'), L.t('Add one to give devices stable names such as router.home.arpa.'))),
    h('div', { class: 'note warn' }, L.ic('alert'), h('p', {}, L.t('Clients must use Lumen as their DNS server. Local records do not change router, DHCP, or device settings by themselves.'))));
}

L.views.dns = sub => {
  const tab = sub || 'listeners'; const body = { listeners: listenersTab, resolver: resolverTab, local: localDnsTab, upstreams: upstreamsTab, limits: limitsTab }[tab] || listenersTab;
  return [L.pageHead('DNS settings', 'Everything the daemon reads from its TOML, as a form. Nothing goes live until you apply.'), L.tabs([['listeners', 'Listeners'], ['resolver', 'Resolver'], ['local', L.t('Local DNS')], ['upstreams', 'Upstreams'], ['limits', 'Limits']], tab, id => L.go('dns', id)), body()];
};
})();
