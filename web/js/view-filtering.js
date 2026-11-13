(() => {
'use strict';
const L = window.L, h = L.h, F = L.fmt;
const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const REFRESH = [[0, 'Never'], [3600, 'Every hour'], [21600, 'Every 6 hours'], [86400, 'Daily'], [604800, 'Weekly']];
const refreshLabel = s => (REFRESH.find(r => r[0] === s) || [0, s + ' s'])[1];

/* ---------- small pieces ---------- */
const timeline = s => { const cells = [h('span', {}, '')]; for (let i = 0; i < 24; i++) { const m = i * 60; const on = s.start_minute < s.end_minute ? m >= s.start_minute && m < s.end_minute : m >= s.start_minute || m < s.end_minute; cells.push(h('i', { class: on ? 'on' : '', title: `${String(i).padStart(2, '0')}:00` })); } return h('div', { class: 'timeline', 'aria-hidden': 'true' }, cells); };
const scheduleText = s => `${s.days.length === 7 ? 'Every day' : s.days.map(d => DAYS[d - 1]).join(' ')} · ${F.hm(s.start_minute)} → ${F.hm(s.end_minute)} UTC`;

/* ---------- lists ---------- */
function listModal(item) {
  const D = L.D().filtering, isNew = !item; const l = item ? L.clone(item) : { id: '', format: 'domains', url: '', path: '', text: '', category: '', refresh_secs: 86400 }; const err = h('div', { class: 'err' });
  const kind = { v: l.url ? 'url' : l.path ? 'path' : l.text ? 'text' : 'url' }; const srcBox = h('div', {});
  const drawSrc = () => srcBox.replaceChildren(kind.v === 'url' ? L.f.field('Source URL', L.f.text(l, 'url', { mono: true, placeholder: 'https://lists.example/list.txt' }), 'HTTPS on port 443 with a valid public certificate. No credentials, redirects or private addresses. Up to 64 MiB. For Hagezi use the raw adblock address, e.g. https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt')
    : kind.v === 'path' ? L.f.field('File path', L.f.text(l, 'path', { mono: true, placeholder: 'lists/mine.txt' }), 'Relative to the configuration file. Replace the file atomically when you update it.')
    : L.f.field('Rules', h('textarea', { class: 'input mono-in', rows: 5, spellcheck: false, value: l.text, oninput: e => { l.text = e.target.value; } }), 'One rule per line, in the format chosen above.'));
  drawSrc();
  L.modal({ title: isNew ? 'Add list' : 'Edit list ' + item.id, body: [
    h('div', { class: 'fgrid' }, L.f.field('List ID', L.f.text(l, 'id', { mono: true, disabled: !isNew, placeholder: 'ads', validate: L.v.id })), L.f.field('Format', L.f.sel(l, 'format', [['domains', 'Domains'], ['hosts', 'Hosts file'], ['adblock', 'Adblock DNS']]), 'Hosts imports become block rules. Adblock supports ||domain^ and @@||domain^ only.')),
    h('div', { class: 'field' }, h('label', {}, 'Source'), L.f.seg(kind, 'v', [['url', 'Web address'], ['path', 'File'], ['text', 'Type it in']], { onChange: drawSrc })), srcBox,
    h('div', { class: 'fgrid' }, L.f.field('Category', L.f.text(l, 'category', { mono: true, placeholder: 'optional, e.g. adult', validate: s => L.v.id(s) }), 'Categorized lists only apply to profiles that select the category.'), L.f.field('Refresh', L.f.sel(l, 'refresh_secs', REFRESH.map(([v, t]) => [String(v), t]), { onChange: () => { l.refresh_secs = +l.refresh_secs; } }))), err],
    actions: [{ label: 'Cancel' }, { label: isNew ? 'Add list' : 'Save', kind: 'primary', onClick: async () => {
      l.refresh_secs = +l.refresh_secs; if (!L.v.id(l.id)) { err.textContent = 'Enter a valid list ID.'; return false; } if (isNew && D.lists.some(x => x.id === l.id)) { err.textContent = 'List ID already exists.'; return false; }
      if (kind.v === 'url' && !/^https:\/\/[^@#\s/]+\/?\S*$/.test(l.url)) { err.textContent = 'The address must start with https:// and contain no credentials or fragment.'; return false; }
      if (kind.v === 'path' && !l.path.trim()) { err.textContent = 'Enter a file path.'; return false; } if (kind.v === 'text' && !l.text.trim()) { err.textContent = 'Enter at least one rule.'; return false; }
      if (isNew && D.lists.length >= 64) { err.textContent = 'At most 64 lists.'; return false; }
      for (const k of ['url', 'path', 'text']) if (k !== kind.v) l[k] = '';
      const saved = await L.changeLists(f => {
        const i = f.lists.findIndex(x => x.id === l.id), old = i < 0 ? null : f.lists[i];
        if (i < 0) f.lists.push(L.clone(l)); else f.lists[i] = L.clone(l);
        return g => { const j = g.lists.findIndex(x => x.id === l.id); if (!old) { if (j >= 0) g.lists.splice(j, 1); } else if (j >= 0) g.lists[j] = old; };
      });
      return saved ? undefined : false; } }] });
}

/* ---------- one-click catalog ---------- */
const HZ = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/';
const CATALOG = [
  { group: 'Ads, trackers and telemetry', note: 'Choose one level of the same family. Higher levels contain the lower ones and block more, with more risk of broken sites.', items: [
    { id: 'hagezi-light', name: 'Hagezi Light', info: 'Gentle. Ads, trackers and malware with almost no breakage.', rules: 78000, format: 'adblock', url: HZ + 'light.txt' },
    { id: 'hagezi-normal', name: 'Hagezi Normal', info: 'Balanced all-rounder.', rules: 175000, format: 'adblock', url: HZ + 'multi.txt' },
    { id: 'hagezi-pro', name: 'Hagezi Pro', info: 'Recommended. Strong blocking, still safe for daily use.', rules: 213000, format: 'adblock', url: HZ + 'pro.txt', star: true },
    { id: 'hagezi-pro-plus', name: 'Hagezi Pro++', info: 'Aggressive. Occasionally breaks a site.', rules: 225000, format: 'adblock', url: HZ + 'pro.plus.txt' },
    { id: 'hagezi-ultimate', name: 'Hagezi Ultimate', info: 'Maximum. Expect to allow some domains yourself.', rules: 283000, format: 'adblock', url: HZ + 'ultimate.txt' },
    { id: 'oisd-small', name: 'OISD Small', info: 'Light, built to never break sites.', rules: 59000, format: 'adblock', url: 'https://small.oisd.nl' },
    { id: 'oisd-big', name: 'OISD Big', info: 'Large and well maintained.', rules: 232000, format: 'adblock', url: 'https://big.oisd.nl', star: true },
    { id: 'adguard-dns', name: 'AdGuard DNS filter', info: 'AdGuard’s default DNS list.', rules: 186000, format: 'adblock', url: 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt' },
    { id: 'stevenblack', name: 'StevenBlack Unified', info: 'The classic hosts list: ads and malware.', rules: 79000, format: 'hosts', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts' },
    { id: '1hosts-lite', name: '1Hosts Lite', info: 'Compact ads and tracking list.', rules: 102000, format: 'adblock', url: 'https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt' }] },
  { group: 'Security: malware, phishing and scams', note: 'Safe for everyone. Add one of these next to your ad list.', items: [
    { id: 'hagezi-tif', name: 'Hagezi Threat Intelligence', info: 'Recommended. Malware, phishing, scams and C2 servers. Large.', rules: 1170000, format: 'adblock', url: HZ + 'tif.txt', star: true },
    { id: 'hagezi-tif-medium', name: 'Hagezi Threat Intelligence Medium', info: 'The same feeds, trimmed.', rules: 326000, format: 'adblock', url: HZ + 'tif.medium.txt' },
    { id: 'hagezi-tif-mini', name: 'Hagezi Threat Intelligence Mini', info: 'Smallest threat list, for small devices.', rules: 194000, format: 'adblock', url: HZ + 'tif.mini.txt' },
    { id: 'phishing-army', name: 'Phishing Army', info: 'Phishing domains.', rules: 152000, format: 'domains', url: 'https://phishing.army/download/phishing_army_blocklist.txt' },
    { id: 'hagezi-fake', name: 'Hagezi Fake shops and scams', info: 'Fake stores, scams and fraud.', rules: 18000, format: 'adblock', url: HZ + 'fake.txt' }] },
  { group: 'Extras', note: 'Applied to every device. To limit one to certain devices, restrict it in a profile.', items: [
    { id: 'hagezi-popupads', name: 'Hagezi Pop-up ads', info: 'Pop-ups, redirects and aggressive ad networks.', rules: 51000, format: 'adblock', url: HZ + 'popupads.txt' },
    { id: 'hagezi-bypass', name: 'Hagezi DoH/VPN/Proxy bypass', info: 'Stops devices from sidestepping Lumen with their own DNS-over-HTTPS or VPN.', rules: 17000, format: 'adblock', url: HZ + 'doh-vpn-proxy-bypass.txt' },
    { id: 'hagezi-apple', name: 'Hagezi Apple telemetry', info: 'Apple tracking endpoints. May affect some Apple services.', rules: 110, format: 'adblock', url: HZ + 'native.apple.txt' },
    { id: 'hagezi-windows', name: 'Hagezi Windows/Office telemetry', info: 'Microsoft telemetry endpoints.', rules: 384, format: 'adblock', url: HZ + 'native.winoffice.txt' }] }];
const BLP = 'https://blocklistproject.github.io/Lists/alt-version/';
/* Child safety: every list here carries a category, so it applies only to profiles that select that category. */
CATALOG.push({ group: 'Child safety', note: 'Each list has its own category and applies only to profiles that select it, so adults on the network are not affected. Installing creates or extends a profile called child-safe. Put a child’s device or group in that profile (Devices) for it to apply.', items: [
  { id: 'hagezi-nsfw', name: 'Adult content', category: 'adult', info: 'Pornography. Hagezi.', rules: 92000, format: 'adblock', url: HZ + 'nsfw.txt' },
  { id: 'hagezi-gambling', name: 'Gambling', category: 'gambling', info: 'Betting and casino sites. Hagezi. Large.', rules: 627000, format: 'adblock', url: HZ + 'gambling.txt' },
  { id: 'hagezi-social', name: 'Social networks', category: 'social', info: 'Social networks and messengers. Hagezi.', rules: 8000, format: 'adblock', url: HZ + 'social.txt' },
  { id: 'blp-drugs', name: 'Drugs', category: 'drugs', info: 'Drug sales and promotion. BlocklistProject.', rules: 26000, format: 'domains', url: BLP + 'drugs-nl.txt' },
  { id: 'hagezi-piracy', name: 'Piracy', category: 'piracy', info: 'Pirate streaming and download sites. Hagezi.', rules: 62000, format: 'adblock', url: HZ + 'anti.piracy.txt' },
  { id: 'blp-torrent', name: 'Torrents', category: 'torrent', info: 'Torrent trackers and sites. BlocklistProject.', rules: 2600, format: 'domains', url: BLP + 'torrent-nl.txt' },
  { id: 'blp-tiktok', name: 'TikTok', category: 'tiktok', info: 'TikTok domains. BlocklistProject.', rules: 3700, format: 'domains', url: BLP + 'tiktok-nl.txt' },
  { id: 'blp-youtube', name: 'YouTube', category: 'youtube', info: 'YouTube domains, including video delivery. BlocklistProject.', rules: 24000, format: 'domains', url: BLP + 'youtube-nl.txt' },
  { id: 'blp-facebook', name: 'Facebook and Instagram', category: 'facebook', info: 'Facebook family domains. BlocklistProject.', rules: 22000, format: 'domains', url: BLP + 'facebook-nl.txt' }] });
const BUNDLES = [
  { key: 'recommended', name: 'Recommended', info: 'Hagezi Pro and Threat Intelligence', ids: ['hagezi-pro', 'hagezi-tif'] },
  { key: 'light', name: 'Light', info: 'Hagezi Light and Threat Intelligence Mini', ids: ['hagezi-light', 'hagezi-tif-mini'] },
  { key: 'strict', name: 'Strict', info: 'Hagezi Ultimate, Threat Intelligence and OISD Big', ids: ['hagezi-ultimate', 'hagezi-tif', 'oisd-big'] }];
const CATALOG_ITEMS = CATALOG.flatMap(g => g.items), BUDGET = 4000000;
L.catalog = { items: CATALOG_ITEMS, bundles: BUNDLES };
const rulesLabel = n => n >= 1e6 ? (n / 1e6).toFixed(1) + ' M' : n >= 1e3 ? Math.round(n / 1e3) + ' k' : String(n);
/* Install catalog entries. Profiles that restrict themselves to named lists get the new ones too, otherwise the list would silently never apply. */
async function installLists(ids) {
  const D = L.D().filtering; const add = CATALOG_ITEMS.filter(c => ids.includes(c.id) && !D.lists.some(l => l.id === c.id));
  if (!add.length) return L.toast('Already installed.');
  if (D.lists.length + add.length > 64) return L.toast('At most 64 lists.', 'bad');
  const est = CATALOG_ITEMS.filter(c => D.lists.some(l => l.id === c.id) || add.includes(c)).reduce((a, c) => a + c.rules, 0);
  if (est > BUDGET) return L.toast(L.t('That would be about {n} rules, over the {max} limit. Remove a list first.', { n: rulesLabel(est), max: rulesLabel(BUDGET) }), 'bad');
  const what = add.length === 1 ? add[0].name : L.t('{n} lists', { n: add.length });
  if (!(await L.confirm({ title: L.t('Install {what}?', { what }), text: 'Lumen downloads it in the background and starts blocking when it is ready. DNS keeps working, lists you already have are not downloaded again, and you can cancel in the progress panel.', label: 'Install' }))) return;
  /* Profiles that restrict themselves to named lists get the new ones too, otherwise the list would silently never apply. */
  await L.changeLists(f => {
    const added = [], widened = [], addedCategories = []; let createdSafe = false;
    for (const c of add) if (!f.lists.some(l => l.id === c.id)) { f.lists.push({ id: c.id, format: c.format, url: c.url, path: '', text: '', category: c.category || '', refresh_secs: 86400 }); added.push(c.id); }
    /* Categorized lists only apply to profiles that select the category: put them in child-safe. */
    const categories = [...new Set(CATALOG_ITEMS.filter(c => added.includes(c.id) && c.category).map(c => c.category))];
    if (categories.length) {
      let safe = f.profiles.find(p => p.id === 'child-safe');
      if (!safe) { safe = { id: 'child-safe', lists: [], categories: [], rules: { allow: [], block: [] }, schedules: [] }; f.profiles.push(safe); createdSafe = true; }
      for (const c of categories) if (!safe.categories.includes(c)) { safe.categories.push(c); addedCategories.push(c); }
    }
    for (const p of f.profiles) if (p.lists.length) { const missing = added.filter(id => !p.lists.includes(id)); if (missing.length) { p.lists = [...p.lists, ...missing]; widened.push([p.id, missing]); } }
    return g => { g.lists = g.lists.filter(x => !added.includes(x.id)); const safe = g.profiles.find(p => p.id === 'child-safe'); if (safe) { safe.categories = safe.categories.filter(c => !addedCategories.includes(c)); if (createdSafe && !safe.categories.length) g.profiles = g.profiles.filter(p => p !== safe); } for (const [pid, extra] of widened) { const p = g.profiles.find(x => x.id === pid); if (p) p.lists = p.lists.filter(x => !extra.includes(x)); } };
  });
}
function catalogCard() {
  const D = L.D().filtering, have = id => D.lists.some(l => l.id === id);
  return h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Quick install'), h('span', { class: 'mono muted' }, 'one click')),
    h('div', { class: 'card-b stack' },
      h('div', { class: 'grid g3' }, BUNDLES.map(b => { const done = b.ids.every(have); return h('div', { class: 'card' }, h('div', { class: 'card-b stack' }, h('div', {}, h('strong', {}, b.name), h('div', { class: 'hint' }, b.info)), done ? h('span', { class: 'pill ok' }, 'Installed') : h('button', { class: 'btn primary sm', onclick: () => installLists(b.ids) }, L.ic('plus'), 'Install ' + b.name.toLowerCase()))); })),
      CATALOG.map(g => h('div', { class: 'stack' }, h('div', { class: 'sec-title' }, h('h2', {}, g.group)), h('p', { class: 'hint', style: 'margin:0' }, g.note),
        h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('tbody', {}, g.items.map(c => h('tr', {}, h('td', {}, h('strong', {}, c.name), c.star ? h('span', { class: 'chip', style: 'margin-left:8px' }, 'recommended') : null, h('div', { class: 'hint' }, c.info)), h('td', { class: 'mono-c' }, '≈ ' + rulesLabel(c.rules)), h('td', { class: 'act' }, have(c.id) ? h('span', { class: 'pill ok' }, 'Installed') : h('button', { class: 'btn sm', onclick: () => installLists([c.id]) }, L.ic('plus'), 'Install'))))))))),
      h('p', { class: 'hint', style: 'margin:0' }, 'Lists are fetched over HTTPS from their publishers when you install them, then refreshed daily. Rule counts are approximate.')));
}
const sourceText = l => l.url ? l.url.replace('https://', '') : l.path ? l.path : l.text ? `typed in · ${l.text.split('\n').filter(Boolean).length} lines` : '—';
/* Why a list might not block for the default profile. */
const skipped = l => { const D = L.D().filtering, p = D.profiles.find(x => x.id === D.default_profile); if (!p) return ''; if (p.lists.length && !p.lists.includes(l.id)) return `Not enabled in profile ${p.id}`; if (l.category && !p.categories.includes(l.category)) return `Needs category ${l.category} in profile ${p.id}`; return ''; };
function listsTab() {
  const D = L.D().filtering, live = L.S.status.filter.lists; const total = live.reduce((a, x) => a + x.rules, 0) + D.rules.allow.length + D.rules.block.length;
  return h('div', { class: 'stack' },
    h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Imported lists'), h('div', { class: 'row' }, h('span', { class: 'mono muted' }, `${F.n(total)} of 4,000,000 rules · ${D.lists.length} of 64 lists`), h('button', { class: 'btn primary sm', onclick: () => listModal(null) }, L.ic('plus'), 'Add list'))),
      D.lists.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['List', 'Format', 'Category', 'Refresh', 'Rules', 'Status', ''].map(x => h('th', {}, x)))), h('tbody', {}, D.lists.map(l => { const rt = live.find(x => x.id === l.id);
        return h('tr', {}, h('td', {}, h('strong', {}, l.id), h('div', { class: 'hint mono' }, sourceText(l))), h('td', { class: 'mono-c' }, l.format), h('td', {}, l.category ? h('span', { class: 'chip' }, l.category) : h('span', { class: 'muted' }, 'none')), h('td', {}, refreshLabel(l.refresh_secs)),
          h('td', { class: 'mono-c' }, rt ? F.n(rt.rules) : '—', rt && rt.unsupported ? h('div', { class: 'hint' }, rt.unsupported + ' unsupported') : null, rt && rt.duplicates ? h('div', { class: 'hint' }, rt.duplicates + ' duplicates') : null),
          h('td', {}, rt ? h('span', { class: 'pill ok' }, 'Loaded') : h('span', { class: 'pill off' }, 'Waiting to load'), skipped(l) ? h('div', { class: 'hint' }, skipped(l)) : null),
          h('td', { class: 'act' }, h('button', { class: 'btn sm flat', 'aria-label': 'Edit ' + l.id, onclick: () => listModal(l) }, L.ic('pencil')), h('button', { class: 'btn sm flat danger', 'aria-label': 'Delete ' + l.id, onclick: async () => {
            const used = D.profiles.filter(p => p.lists.includes(l.id)); if (used.length) return L.toast(L.t('Used by profile {id}. Remove it there first.', { id: used[0].id }), 'bad');
            if (!(await L.confirm({ title: L.t('Remove {id}?', { id: l.id }), text: 'It stops blocking right away. Your other lists stay loaded and are not downloaded again.', label: 'Remove', danger: true }))) return;
            await L.changeLists(f => { const old = f.lists.find(x => x.id === l.id); f.lists = f.lists.filter(x => x.id !== l.id); return g => { if (old && !g.lists.some(x => x.id === old.id)) g.lists.push(old); }; }); } }, L.ic('trash'))));
      })))) : L.empty('No lists', 'No third-party list is enabled by default. Add a source you trust.')),
    catalogCard(),
    h('div', { class: 'note' }, L.ic('info'), h('p', {}, 'Refresh is atomic: Lumen builds a whole new generation and swaps it in only if every due source parses and the rule budget holds. A failed download keeps the live generation.')));
}

/* ---------- rules ---------- */
function rulesTab() {
  const D = L.D().filtering; const a = D.action; const kinds = [['nxdomain', 'NXDOMAIN'], ['nodata', 'NODATA'], ['refused', 'REFUSED'], ['address', 'Sinkhole address'], ['cname', 'CNAME']];
  const card = (title, key, desc) => h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, title), h('span', { class: 'mono muted' }, `${D.rules[key].length} / 4096`)), h('div', { class: 'card-b stack' }, h('p', { class: 'hint', style: 'margin:0' }, desc),
    L.f.tags(D.rules[key], { validate: L.v.rule, placeholder: 'example.com, *.example.com or =exact.example.com', max: 4096, what: '(use a domain, *.domain or =domain; no URLs or regex)' })));
  return h('div', { class: 'stack' }, h('div', { class: 'grid g2' }, card('Always allow', 'allow', 'Beats any block rule in the same tier. Use it for false positives.'), card('Always block', 'block', 'Applies to every client, even outside a profile’s schedule.')),
    h('div', { class: 'note' }, L.ic('info'), h('div', {}, h('p', {}, h('b', {}, 'Precedence. '), '1) active profile’s rules, 2) global rules, 3) imported lists, 4) allow. Inside a tier, any allow beats every block; the most specific suffix wins.'), h('p', { class: 'hint', style: 'margin-top:4px' }, '`example.com` and `*.example.com` match the domain and its subdomains; `=example.com` matches only that name.'))),
    h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Block response')), h('div', { class: 'card-b stack' },
      h('div', { class: 'fgrid' }, L.f.field('Answer for blocked names', L.f.sel(a, 'kind', kinds, { onChange: L.rerender }), 'Synthetic answers have TTL 0 and are never cached. Validating clients may reject them.'),
        a.kind === 'address' ? [L.f.field('IPv4', L.f.text(a, 'ipv4', { mono: true, placeholder: '0.0.0.0', validate: L.v.ip })), L.f.field('IPv6', L.f.text(a, 'ipv6', { mono: true, placeholder: '::', validate: L.v.ip }))] : null,
        a.kind === 'cname' ? L.f.field('Target', L.f.text(a, 'target', { mono: true, placeholder: 'blocked.home.example', validate: L.v.domain })) : null),
      h('div', {}, L.f.sw(D, 'decision_log', 'Write decisions to stderr (decision_log)'), h('div', { class: 'hint', style: 'margin-top:6px' }, 'Off by default. When on, names and client IPs go to the process log; retention is then up to your log collector.')))));
}

/* ---------- profiles ---------- */
function profileModal(item) {
  const D = L.D().filtering, isNew = !item; const p = item ? L.clone(item) : { id: '', lists: [], categories: [], rules: { allow: [], block: [] }, schedules: [] }; const err = h('div', { class: 'err' });
  const sch = h('div', { class: 'stack' });
  const drawSch = () => sch.replaceChildren(...p.schedules.map((s, i) => h('div', { class: 'card' }, h('div', { class: 'card-b stack' },
    h('div', { class: 'row' }, ...DAYS.map((d, k) => h('button', { type: 'button', class: 'btn sm', 'aria-pressed': String(s.days.includes(k + 1)), style: s.days.includes(k + 1) ? 'background:var(--acid);color:var(--ink);border-color:var(--ink)' : '', onclick: () => { const n = k + 1; s.days = s.days.includes(n) ? s.days.filter(x => x !== n) : [...s.days, n].sort(); drawSch(); } }, d)), h('span', { class: 'sp' }), h('button', { type: 'button', class: 'btn sm flat danger', 'aria-label': 'Remove window', onclick: () => { p.schedules.splice(i, 1); drawSch(); } }, L.ic('trash'))),
    h('div', { class: 'row' }, h('label', { class: 'mono muted' }, 'From'), h('input', { type: 'time', class: 'input mono-in', style: 'width:130px', value: F.hm(s.start_minute), onchange: e => { const [a, b] = e.target.value.split(':'); s.start_minute = +a * 60 + +b; drawSch(); } }), h('label', { class: 'mono muted' }, 'Until'), h('input', { type: 'time', class: 'input mono-in', style: 'width:130px', value: F.hm(s.end_minute), onchange: e => { const [a, b] = e.target.value.split(':'); s.end_minute = +a * 60 + +b; drawSch(); } }), h('span', { class: 'mono muted' }, 'UTC')),
    timeline(s)))), p.schedules.length ? null : h('p', { class: 'hint', style: 'margin:0' }, 'No windows: the profile is always active.'));
  drawSch();
  L.modal({ title: isNew ? 'Add profile' : 'Edit profile ' + item.id, wide: true, body: [
    h('div', { class: 'fgrid' }, L.f.field('Profile ID', L.f.text(p, 'id', { mono: true, disabled: !isNew, placeholder: 'bedtime', validate: L.v.id })),
      L.f.field('Categories', L.f.tags(p.categories, { validate: L.v.id, placeholder: 'adult, games…' }), 'Lists with a category only apply when the profile selects it.')),
    L.f.field('Restrict to lists', h('div', { class: 'chips', style: 'gap:12px 26px' }, D.lists.map(l => h('label', { class: 'switch' }, h('input', { type: 'checkbox', checked: p.lists.includes(l.id), onchange: e => { p.lists = e.target.checked ? [...p.lists, l.id] : p.lists.filter(x => x !== l.id); } }), h('i'), h('span', {}, l.id)))), 'Leave all off to use every eligible list.'),
    h('div', { class: 'grid g2' }, L.f.field('Profile allow rules', L.f.tags(p.rules.allow, { validate: L.v.rule, placeholder: 'domain' })), L.f.field('Profile block rules', L.f.tags(p.rules.block, { validate: L.v.rule, placeholder: 'domain' }))),
    h('div', { class: 'field' }, h('label', {}, 'Schedule windows (UTC)'), sch, h('div', { class: 'row' }, h('button', { type: 'button', class: 'btn sm', onclick: () => { if (p.schedules.length >= 32) return; p.schedules.push({ days: [1, 2, 3, 4, 5, 6, 7], start_minute: 1260, end_minute: 420 }); drawSch(); } }, L.ic('plus'), 'Add window')),
      h('div', { class: 'hint' }, 'Outside every window, the profile’s rules and all imported lists are off for that client; global rules still apply. Overnight windows belong to their start day. No DST: times are UTC.')), err],
    actions: [{ label: 'Cancel' }, { label: isNew ? 'Add profile' : 'Save', kind: 'primary', onClick: () => {
      if (!L.v.id(p.id)) { err.textContent = 'Enter a valid profile ID.'; return false; } if (isNew && D.profiles.some(x => x.id === p.id)) { err.textContent = 'Profile ID already exists.'; return false; }
      if (p.schedules.some(s => !s.days.length)) { err.textContent = 'Each window needs at least one day.'; return false; } if (p.schedules.some(s => s.start_minute === s.end_minute)) { err.textContent = 'Start and end must differ.'; return false; }
      const i = D.profiles.findIndex(x => x.id === p.id); if (i < 0) D.profiles.push(p); else D.profiles[i] = p; L.touch(); L.rerender(); } }] });
}
const refsTo = id => { const D = L.D().filtering; return [D.default_profile === id && 'default profile', ...D.groups.filter(g => g.profile === id).map(g => 'group ' + g.id), ...D.subnets.filter(s => s.profile === id).map(s => 'subnet ' + s.network), ...L.S.devices.filter(d => d.profile === id).map(d => 'device ' + d.id)].filter(Boolean); };
function profilesTab() {
  const D = L.D().filtering; const prof = D.profiles.map(p => p.id);
  const grp = { id: '', profile: prof[0] || '' }, sub = { network: '', profile: prof[0] || '' };
  return h('div', { class: 'stack' },
    h('div', { class: 'row' }, h('div', { style: 'width:260px' }, L.f.field('Default profile', L.f.sel(D, 'default_profile', [['', '— none —'], ...prof]), 'Used when nothing else matches.')), h('span', { class: 'sp' }), h('button', { class: 'btn primary', onclick: () => profileModal(null) }, L.ic('plus'), 'Add profile')),
    h('div', { class: 'grid g2' }, D.profiles.map(p => h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, p.id), h('div', { class: 'row' }, D.default_profile === p.id ? h('span', { class: 'pill plain' }, 'Default') : null,
      h('button', { class: 'btn sm flat', 'aria-label': 'Edit ' + p.id, onclick: () => profileModal(p) }, L.ic('pencil')),
      h('button', { class: 'btn sm flat danger', 'aria-label': 'Delete ' + p.id, onclick: () => { const r = refsTo(p.id); if (r.length) return L.toast(`In use by ${r[0]}${r.length > 1 ? ` and ${r.length - 1} more` : ''}. Reassign it first.`, 'bad'); D.profiles = D.profiles.filter(x => x.id !== p.id); L.touch(); L.rerender(); } }, L.ic('trash')))),
      h('div', { class: 'card-b stack' }, h('div', {}, h('div', { class: 'mono muted', style: 'margin-bottom:6px' }, 'Categories'), p.categories.length ? h('div', { class: 'chips' }, p.categories.map(c => h('span', { class: 'chip' }, c))) : h('span', { class: 'muted' }, 'None: uncategorized lists only')),
        h('dl', { class: 'kv' }, h('dt', {}, 'Lists'), h('dd', {}, p.lists.join(', ') || 'all eligible'), h('dt', {}, 'Own rules'), h('dd', {}, `${p.rules.allow.length} allow · ${p.rules.block.length} block`), h('dt', {}, 'Used by'), h('dd', {}, refsTo(p.id).length || 'nothing')),
        p.schedules.length ? h('div', { class: 'stack' }, p.schedules.map(s => h('div', {}, h('div', { class: 'hint', style: 'margin-bottom:5px' }, scheduleText(s)), timeline(s)))) : h('span', { class: 'pill ok plain' }, 'Always active'))))),
    h('div', { class: 'grid g2' },
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Groups'), h('span', { class: 'mono muted' }, `${D.groups.length} / 128`)), h('div', { class: 'card-b flush' }, h('table', { class: 'tbl' }, h('tbody', {}, D.groups.map(g => h('tr', {}, h('td', {}, h('strong', {}, g.id), h('div', { class: 'hint' }, (n => n + (n === 1 ? ' device' : ' devices'))(L.S.devices.filter(d => d.group === g.id).length))), h('td', {}, L.f.sel(g, 'profile', prof)), h('td', { class: 'act' }, h('button', { class: 'btn sm flat danger', 'aria-label': 'Delete group ' + g.id, onclick: () => { if (L.S.devices.some(d => d.group === g.id)) return L.toast('Devices still use this group.', 'bad'); D.groups = D.groups.filter(x => x.id !== g.id); L.touch(); L.rerender(); } }, L.ic('trash'))))),
        h('tr', {}, h('td', {}, L.f.text(grp, 'id', { mono: true, placeholder: 'new group id', validate: L.v.id })), h('td', {}, L.f.sel(grp, 'profile', prof)), h('td', { class: 'act' }, h('button', { class: 'btn sm', onclick: () => { if (!L.v.id(grp.id) || D.groups.some(g => g.id === grp.id) || !grp.profile) return L.toast('Enter a unique group ID and pick a profile.', 'bad'); D.groups.push({ ...grp }); L.touch(); L.rerender(); } }, L.ic('plus'), 'Add'))))))),
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Subnets'), h('span', { class: 'mono muted' }, `${D.subnets.length} / 256`)), h('div', { class: 'card-b flush' }, h('table', { class: 'tbl' }, h('tbody', {}, D.subnets.map(s => h('tr', {}, h('td', { class: 'mono-c' }, s.network), h('td', {}, L.f.sel(s, 'profile', prof)), h('td', { class: 'act' }, h('button', { class: 'btn sm flat danger', 'aria-label': 'Delete ' + s.network, onclick: () => { D.subnets = D.subnets.filter(x => x !== s); L.touch(); L.rerender(); } }, L.ic('trash'))))),
        h('tr', {}, h('td', {}, L.f.text(sub, 'network', { mono: true, placeholder: '192.168.30.0/24', validate: L.v.cidr })), h('td', {}, L.f.sel(sub, 'profile', prof)), h('td', { class: 'act' }, h('button', { class: 'btn sm', onclick: () => { if (!L.v.cidr(sub.network) || D.subnets.some(s => s.network === sub.network) || !sub.profile) return L.toast('Enter a unique CIDR and pick a profile.', 'bad'); D.subnets.push({ ...sub }); L.touch(); L.rerender(); } }, L.ic('plus'), 'Add')))))))));
}

/* ---------- explain ---------- */
const now = new Date();
const ex = { domain: '', client: '', day: String(now.getUTCDay() || 7), time: now.toISOString().slice(11, 16) };
function explainTab() {
  const out = h('div', {}); const err = h('div', { class: 'err' });
  const dev = L.S.devices.flatMap(d => d.addresses.filter(a => !a.includes(':')).map(a => [a, `${a} · ${d.id}`]));
  if (!ex.client && dev.length) ex.client = dev[0][0];
  const run = async () => {
    err.textContent = ''; out.replaceChildren(); if (!ex.domain.trim() || !L.v.ip(ex.client)) return;
    const [a, b] = ex.time.split(':');
    try {
      const r = await L.api('POST', '/api/explain', { domain: ex.domain.trim(), client: ex.client.trim(), day: +ex.day, minute: +a * 60 + +b });
      out.replaceChildren(h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, ex.domain.trim()), h('span', { class: 'pill ' + (r.blocked ? 'bad' : 'ok') }, r.blocked ? 'Blocked' : 'Allowed')),
        h('div', { class: 'card-b' }, h('dl', { class: 'kv' }, h('dt', {}, 'Decided by'), h('dd', {}, r.rule ? `${r.rule}${r.list ? ' (list ' + r.list + ')' : ' (manual rule)'}` : 'no rule matched'), r.category ? [h('dt', {}, 'Category'), h('dd', {}, r.category)] : null,
          h('dt', {}, 'Profile'), h('dd', {}, r.profile || 'none'), h('dt', {}, 'Device'), h('dd', {}, r.device || 'not a listed device'), r.group ? [h('dt', {}, 'Group'), h('dd', {}, r.group)] : null, h('dt', {}, 'Policy generation'), h('dd', {}, String(r.generation))))));
    } catch (e) { err.textContent = e.message; }
  };
  setTimeout(run, 0);
  return h('div', { class: 'stack' }, h('div', { class: 'card' }, h('div', { class: 'card-b' }, h('div', { class: 'fgrid' },
    L.f.field('Domain', L.f.text(ex, 'domain', { mono: true, onChange: run, placeholder: 'ads.example' })),
    L.f.field('Device IP', h('div', {}, L.f.text(ex, 'client', { mono: true, onChange: run, validate: L.v.ip, placeholder: '192.168.1.20' }), dev.length ? h('div', { class: 'chips', style: 'margin-top:6px' }, dev.map(([a, t]) => h('button', { class: 'chip', style: 'cursor:pointer', onclick: () => { ex.client = a; L.rerender(); run(); } }, t))) : null)),
    L.f.field('Weekday (UTC)', L.f.sel(ex, 'day', DAYS.map((d, i) => [String(i + 1), d]), { onChange: run })), L.f.field('Time (UTC)', h('input', { type: 'time', class: 'input mono-in', value: ex.time, onchange: e => { ex.time = e.target.value || '00:00'; run(); } }))), err,
    h('p', { class: 'hint', style: 'margin:12px 0 0' }, 'Asks the running daemon what it would do. It uses the rules that are live now, not unsaved changes, and sends no DNS query. Schedules use UTC.'))), out);
}

L.views.filtering = sub => {
  const tab = sub || 'lists'; const go = id => L.go('filtering', id);
  const body = { lists: listsTab, rules: rulesTab, profiles: profilesTab, explain: explainTab }[tab] || listsTab;
  return [L.pageHead('Filtering', 'Lists install right away, in the background. Rules, profiles and schedules stay in a draft until you apply them.'),
    L.tabs([['lists', 'Lists'], ['rules', 'Rules & response'], ['profiles', 'Profiles'], ['explain', 'Explain']], tab, go), body()];
};
})();
