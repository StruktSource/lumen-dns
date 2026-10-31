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
function resolverTab() {
  const r = L.D().resolver, rec = r.mode === 'recursive';
  return h('div', { class: 'stack' },
    card('Resolution', null, h('div', { class: 'row' }, h('div', {}, h('div', { class: 'mono muted', style: 'margin-bottom:6px' }, 'Mode'), f.seg(r, 'mode', [['recursive', 'Recursive'], ['forward', 'Forward']], { onChange: L.rerender }))), h('p', { class: 'hint', style: 'margin:0' }, rec ? 'Lumen walks the DNS hierarchy itself from the root servers. Nothing is sent to a third-party resolver. This is the private default.' : 'Lumen forwards to the upstreams you choose on the next tab. Those operators see your queries.'),
      f.sw(r, 'dnssec', 'Validate DNSSEC locally'), !r.dnssec ? h('div', { class: 'note warn' }, L.ic('alert'), h('p', {}, 'Without validation, forged answers are accepted.')) : null),
    card('Cache', null, h('div', { class: 'fgrid' }, num(r, 'cache_entries', 'resolver.cache_entries', 'Answer cache', 'Entries, not bytes.'), num(r, 'nameserver_cache_entries', 'resolver.nameserver_cache_entries', 'Delegation cache', rec ? 'Recursive delegation cache.' : 'Recursive mode only.', { disabled: !rec }), num(r, 'validation_cache_entries', 'resolver.validation_cache_entries', 'DNSSEC validation cache', ''),
      num(r, 'positive_ttl_secs', 'resolver.positive_ttl_secs', 'Max positive TTL', 'A ceiling, never a forced minimum.'), num(r, 'negative_ttl_secs', 'resolver.negative_ttl_secs', 'Max negative TTL', 'NXDOMAIN and NODATA ceiling.'), rec ? num(r, 'recursion_depth', 'resolver.recursion_depth', 'Recursion depth', '') : num(r, 'attempts', 'resolver.attempts', 'Forward attempts', ''), !rec ? num(r, 'upstream_timeout_ms', 'resolver.upstream_timeout_ms', 'Upstream timeout', 'Per attempt.') : null)),
    rec ? [
      card('Startup priming', f.sw(r.warm, 'enabled', '', { onChange: L.rerender }), h('p', { class: 'hint', style: 'margin:0' }, 'Once at startup, Lumen resolves NS and DNSKEY for these zones so the first real query is faster. It never sends client data.'), f.tags(r.warm.zones, { validate: L.v.domain, placeholder: 'com', max: 64, disabled: !r.warm.enabled })),
      card('Expiry prefetch', f.sw(r.prefetch, 'enabled', '', { onChange: L.rerender }), h('p', { class: 'hint', style: 'margin:0' }, 'Refreshes repeatedly requested names just after their TTL ends. Tracked names live in memory only and are forgotten after an hour.'),
        h('div', { class: 'fgrid' }, [['min_hits', 'Min cache hits'], ['max_tracked', 'Tracked names'], ['max_concurrent', 'Concurrent refreshes'], ['budget_per_minute', 'Budget']].map(([k, t]) => num(r.prefetch, k, 'resolver.prefetch.' + k, t, '', { disabled: !r.prefetch.enabled })))),
      card('Hedged recursion', h('span', { class: 'pill off' }, 'Experimental'), h('div', { class: 'fgrid' }, f.field('Hedge after', f.num(r, 'hedge_ms', '', { min: 100, max: 5000, unit: 'ms', zero: true }), '0 = off, or 100–5000 ms. Starts a second recursion for slow lookups; first usable answer wins. Measurements were inconclusive.')))] : null);
}

/* ---------- upstreams ---------- */
const PROTOS = ['udp', 'tcp', 'tls', 'https', 'quic'];
function upstreamTable(arr, max, title, addBtnLabel) {
  const draft = { address: '', protocol: 'tls', server_name: '', doh_path: '' };
  const rows = h('tbody', {});
  const draw = () => { rows.replaceChildren(...arr.map((u, i) => h('tr', {}, h('td', { class: 'mono-c' }, u.address), h('td', { class: 'mono-c' }, u.protocol), h('td', { class: 'mono-c' }, u.server_name || '—'), h('td', { class: 'act' }, h('button', { class: 'btn sm flat danger', 'aria-label': 'Remove', onclick: () => { arr.splice(i, 1); L.touch(); L.rerender(); } }, L.ic('trash'))))));
    if (!arr.length) rows.append(h('tr', {}, h('td', { colspan: 4, class: 'muted' }, 'None yet.'))); };
  draw(); const err = h('div', { class: 'err' });
  return h('div', {}, h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Address', 'Protocol', 'Server name', ''].map(x => h('th', {}, x)))), rows)),
    h('div', { class: 'card-b stack', style: 'border-top:1px solid var(--rule)' }, h('div', { class: 'fgrid' }, f.field('Address:port', f.text(draft, 'address', { mono: true, placeholder: '9.9.9.9:853', validate: L.v.socket }), 'Explicit IP, no bootstrap lookup.'), f.field('Protocol', f.sel(draft, 'protocol', PROTOS)), f.field('Server name', f.text(draft, 'server_name', { mono: true, placeholder: 'dns.example' }), 'Required for tls, https, quic.')), err,
      h('div', {}, h('button', { class: 'btn', onclick: () => { if (arr.length >= max) { err.textContent = `At most ${max}.`; return; } if (!L.v.socket(draft.address)) { err.textContent = 'Address must be IP:port, e.g. 9.9.9.9:853.'; return; } if (['tls', 'https', 'quic'].includes(draft.protocol) && !draft.server_name) { err.textContent = 'Encrypted protocols need a server name.'; return; } arr.push({ ...draft }); L.touch(); L.rerender(); } }, L.ic('plus'), addBtnLabel))));
}
function upstreamsTab() {
  const r = L.D().resolver, rec = r.mode === 'recursive', usingProv = r.providers.length > 0, usingCustom = r.upstreams.length > 0;
  const catalog = h('div', { class: 'grid g2' }, L.S.providers.map(p => { const sel = r.providers.find(x => x.id === p.id); return h('div', { class: 'card', style: sel ? 'border-color:var(--text);box-shadow:inset 0 0 0 1px var(--text)' : '' }, h('div', { class: 'card-b stack' },
    h('div', { class: 'row' }, h('div', { class: 'sp' }, h('strong', {}, p.name), h('div', { class: 'hint' }, `${p.country} · ${p.scope.replace(/_/g, ' ')} · ${p.filter}`)), f.sw({ on: !!sel }, 'on', '', { disabled: usingCustom, onChange: on => { if (on) r.providers.push(L.fitProvider(r.providers, p)); else r.providers = r.providers.filter(x => x.id !== p.id); L.touch(); L.rerender(); } })),
    h('div', { class: 'chips' }, p.transports.map(t => h('span', { class: 'chip' }, t))), sel ? h('div', { class: 'fgrid' }, f.field('Protocol', f.sel(sel, 'protocol', ['auto', ...p.transports], { onChange: L.rerender }), sel.protocol === 'auto' ? 'Auto prefers QUIC, then HTTPS, then TLS, and requires encryption.' : 'Fixed protocol, no automatic failover.'), f.field('Address family', f.sel(sel, 'address_family', ['any', 'ipv4', 'ipv6'], { onChange: L.rerender }))) : null)); }));
  return h('div', { class: 'stack' },
    rec ? h('div', { class: 'note' }, L.ic('info'), h('p', {}, 'Recursive mode does not use forwarding upstreams. Switch to forward mode on the Resolver tab to use these, or configure a timeout-only fallback below.')) : null,
    !rec ? [h('div', { class: 'note' }, L.ic('info'), h('p', {}, 'Pick bundled providers or your own upstreams, not both. “Auto” prefers QUIC, then HTTPS, then TLS, and requires encryption.')),
      h('div', { class: 'sec-title' }, h('h2', {}, 'Bundled providers'), h('span', { class: 'pill ' + (L.providerUpstreams(r.providers) > 8 ? 'bad' : 'plain') }, usingProv ? `${r.providers.length} selected · ${L.providerUpstreams(r.providers)} of 8 upstreams` : 'none selected')), catalog,
      h('div', { class: 'sec-title' }, h('h2', {}, 'Custom upstreams'), h('span', { class: 'mono muted' }, `${r.upstreams.length} / 8`)), usingProv ? h('div', { class: 'note warn' }, L.ic('alert'), h('p', {}, 'Remove selected providers before adding custom upstreams.')) : h('div', { class: 'card' }, upstreamTable(r.upstreams, 8, 'Upstreams', 'Add upstream'))] : null,
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

L.views.dns = sub => {
  const tab = sub || 'listeners'; const body = { listeners: listenersTab, resolver: resolverTab, upstreams: upstreamsTab, limits: limitsTab }[tab] || listenersTab;
  return [L.pageHead('DNS settings', 'Everything the daemon reads from its TOML, as a form. Nothing goes live until you apply.'), L.tabs([['listeners', 'Listeners'], ['resolver', 'Resolver'], ['upstreams', 'Upstreams'], ['limits', 'Limits']], tab, id => L.go('dns', id)), body()];
};
})();
