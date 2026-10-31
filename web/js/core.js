/* Lumen console — core helpers: DOM, forms, validation, config model. */
(() => {
'use strict';
const L = window.L = { views: {} };

/* ---------- dom ---------- */
L.h = (tag, props, ...kids) => {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'style') el.style.cssText = v;
    else if (k === 'html') el.innerHTML = v;
    else if (k === 'for') el.htmlFor = v;
    else if (['value', 'checked', 'disabled', 'type', 'placeholder', 'min', 'max', 'step', 'title', 'id', 'name', 'rows', 'autocomplete', 'spellcheck', 'readOnly'].includes(k)) el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  kids.flat(9).forEach(c => { if (c != null && c !== false) el.append(c.nodeType ? c : document.createTextNode(c)); });
  return el;
};
const h = L.h;
L.$ = (s, r = document) => r.querySelector(s);
L.clone = o => JSON.parse(JSON.stringify(o));

const ICONS = {
  overview: '<rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/>',
  activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>', filter: '<path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z"/>',
  devices: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
  server: '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6 6h.01M6 18h.01"/>',
  key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="M21 2l-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
  power: '<path d="M18.36 6.64a9 9 0 1 1-12.73 0M12 2v10"/>', plus: '<path d="M12 5v14M5 12h14"/>',
  trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v6M14 11v6"/>', pencil: '<path d="M17 3l4 4L7 21H3v-4L17 3z"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5"/>', undo: '<path d="M3 7v6h6M3 13a9 9 0 1 0 3-7.7"/>',
  check: '<path d="M20 6L9 17l-5-5"/>', x: '<path d="M18 6L6 18M6 6l12 12"/>', search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
  eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>', menu: '<path d="M3 6h18M3 12h18M3 18h18"/>',
  alert: '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>', download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>', copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>', settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>', file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>'
};
L.ic = (name, size) => {
  const s = h('span', { html: `<svg class="i" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ''}</svg>` }).firstChild;
  if (size) { s.style.width = s.style.height = size + 'px'; }
  return s;
};

/* ---------- formatting ---------- */
L.fmt = {
  n: v => Math.round(v).toLocaleString('en-US'),
  pct: v => (v * 100).toFixed(1) + '%',
  dur: s => { const d = Math.floor(s / 86400), hh = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? `${d}d ${hh}h` : hh ? `${hh}h ${m}m` : `${m}m`; },
  ago: t => { const s = Math.max(0, (Date.now() - t) / 1000); return s < 60 ? 'just now' : s < 3600 ? Math.floor(s / 60) + ' min ago' : s < 86400 ? Math.floor(s / 3600) + ' h ago' : Math.floor(s / 86400) + ' d ago'; },
  time: t => new Date(t).toISOString().replace('T', ' ').slice(0, 19) + 'Z',
  hm: m => String(Math.floor(m / 60)).padStart(2, '0') + ':' + String(m % 60).padStart(2, '0')
};

/* ---------- validation ---------- */
const ipv4 = s => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(s);
const ipv6 = s => /^[0-9a-f:.]+$/i.test(s) && s.includes(':') && s.split('::').length <= 2 && s.split(':').length <= 8 && s.split(':').length >= 3;
L.v = {
  ip: s => ipv4(s) || ipv6(s),
  socket: s => { let m = /^\[([^\]]+)\]:(\d{1,5})$/.exec(s); if (m) return ipv6(m[1]) && +m[2] > 0 && +m[2] < 65536; m = /^([\d.]+):(\d{1,5})$/.exec(s); return !!m && ipv4(m[1]) && +m[2] > 0 && +m[2] < 65536; },
  cidr: s => { const [a, p, ...r] = s.split('/'); if (r.length || p === undefined || !/^\d{1,3}$/.test(p)) return false; return ipv4(a) ? +p <= 32 : ipv6(a) && +p <= 128; },
  label: s => /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/i.test(s),
  domain: s => s.length <= 253 && s.split('.').every(l => L.v.label(l)),
  rule: s => { if (/[\/:\\^$|@\s()[\]{}+?]/.test(s)) return false; const b = s.replace(/^=/, '').replace(/^\*\./, ''); return !!b && L.v.domain(b); },
  id: s => /^[A-Za-z0-9_-]{1,64}$/.test(s),
  path: s => s.length > 0 && s.length < 256 && !/[\0]/.test(s)
};
L.bounds = {
  'resolver.cache_entries': [1, 65536, ''], 'resolver.nameserver_cache_entries': [1, 4096, ''], 'resolver.validation_cache_entries': [1, 65536, ''],
  'resolver.positive_ttl_secs': [1, 604800, 's'], 'resolver.negative_ttl_secs': [1, 86400, 's'], 'resolver.recursion_depth': [1, 64, ''],
  'resolver.attempts': [1, 5, ''], 'resolver.upstream_timeout_ms': [1, 30000, 'ms'],
  'resolver.fallback.recursive_timeout_ms': [1, 60000, 'ms'], 'resolver.fallback.timeout_ms': [1, 30000, 'ms'], 'resolver.fallback.attempts': [1, 5, ''],
  'resolver.prefetch.min_hits': [1, 100, ''], 'resolver.prefetch.max_tracked': [16, 8192, ''], 'resolver.prefetch.max_concurrent': [1, 16, ''], 'resolver.prefetch.budget_per_minute': [1, 6000, '/min'],
  'limits.max_in_flight': [1, 4096, ''], 'limits.max_connections': [1, 1024, ''], 'limits.max_clients': [1, 65536, ''], 'limits.queries_per_second': [1, 10000, 'qps'],
  'limits.query_timeout_ms': [1, 60000, 'ms'], 'limits.io_timeout_ms': [1, 30000, 'ms'], 'limits.max_message_bytes': [512, 65535, 'B'],
  'web.max_connections': [1, 1024, '']
};
L.get = (o, p) => p.split('.').reduce((a, k) => a == null ? a : a[k], o);
L.set = (o, p, v) => { const ks = p.split('.'); const last = ks.pop(); ks.reduce((a, k) => a[k], o)[last] = v; };

/* ---------- state ---------- */
L.S = { cfg: null, draft: null, devices: [], users: [], status: null, series: [], audit: [], history: { enabled: false, items: [] }, settings: { session_idle_minutes: 30 }, providers: [], revisions: [] };
L.session = null; L.csrf = '';
L.D = () => L.S.draft || (L.S.draft = L.clone(L.S.cfg));
L.isDirty = () => !!L.S.draft && JSON.stringify(L.S.draft) !== JSON.stringify(L.S.cfg);
const RANK = { user: 1, admin: 2 };
L.can = r => !!L.session && RANK[L.session.role] >= RANK[r];
L.ROLE_LABEL = { admin: 'Administrator', user: 'User' };

/* ---------- config model ---------- */
/* The server returns the effective config (the daemon's own defaults filled in). Nulls become empty strings for form fields. */
const NULL_STRINGS = [['metrics'], ['listen', 'certificate'], ['listen', 'private_key'], ['web', 'certificate'], ['web', 'private_key'], ['filtering', 'default_profile'], ['resolver', 'root_hints'], ['resolver', 'trust_anchor'], ['resolver', 'upstream_ca']];
L.normalizeConfig = cfg => {
  const c = L.clone(cfg);
  for (const path of NULL_STRINGS) { let o = c; for (const k of path.slice(0, -1)) o = o && o[k]; const last = path.at(-1); if (o && o[last] == null) o[last] = ''; }
  for (const l of c.filtering.lists) for (const k of ['category', 'url', 'path', 'text']) if (l[k] == null) l[k] = '';
  const a = c.filtering.action; if (a.kind === 'address') { a.ipv4 ??= ''; a.ipv6 ??= ''; } if (a.kind === 'cname') a.target ??= '';
  return c;
};
L.toServer = cfg => {
  const c = L.clone(cfg); const blank = (o, k) => { if (o && o[k] === '') o[k] = null; };
  blank(c, 'metrics'); ['certificate', 'private_key'].forEach(k => { blank(c.listen, k); blank(c.web, k); });
  blank(c.filtering, 'default_profile'); ['root_hints', 'trust_anchor', 'upstream_ca'].forEach(k => blank(c.resolver, k));
  for (const l of c.filtering.lists) for (const k of ['category', 'url', 'path', 'text']) blank(l, k);
  const a = c.filtering.action; if (a.kind === 'address') { blank(a, 'ipv4'); blank(a, 'ipv6'); } else { delete a.ipv4; delete a.ipv6; } if (a.kind !== 'cname') delete a.target;
  if (c.resolver.mode === 'forward') { c.resolver.warm.enabled = false; c.resolver.prefetch.enabled = false; c.resolver.fallback.enabled = false; c.resolver.hedge_ms = 0; }
  return { config: c };
};

/* ---------- toast + modal ---------- */
L.toast = (msg, kind = '') => {
  let box = L.$('.toasts'); if (!box) { box = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' }); document.body.append(box); }
  const t = h('div', { class: 'toast ' + kind }, L.ic(kind === 'bad' ? 'alert' : 'check'), h('span', {}, msg)); box.append(t); setTimeout(() => t.remove(), 4200);
};
L.modal = ({ title, body, actions = [], wide = false }) => {
  const dlg = h('dialog', { class: wide ? 'wide' : '' });
  const close = () => { dlg.close(); dlg.remove(); };
  dlg.append(h('div', { class: 'dlg-h' }, h('h2', {}, title), h('button', { class: 'btn icon flat', 'aria-label': 'Close', onclick: close }, L.ic('x'))),
    h('div', { class: 'dlg-b' }, body),
    actions.length ? h('div', { class: 'dlg-f' }, actions.map(a => h('button', { class: 'btn ' + (a.kind || ''), disabled: a.disabled, onclick: async () => { if (!a.onClick || (await a.onClick()) !== false) close(); } }, a.label))) : null);
  dlg.addEventListener('cancel', e => { e.preventDefault(); close(); });
  dlg.addEventListener('click', e => { if (e.target === dlg) close(); });
  document.body.append(dlg); dlg.showModal(); return close;
};
L.confirm = ({ title, text, label = 'Confirm', danger = false, typed = null }) => new Promise(res => {
  let ok = !typed; const btnRef = {};
  const input = typed ? h('input', { class: 'input mono-in', placeholder: typed, autocomplete: 'off', oninput: e => { ok = e.target.value === typed; btnRef.b.disabled = !ok; } }) : null;
  const close = L.modal({ title, body: [h('p', { style: 'margin:0' }, text), typed ? h('div', { class: 'field' }, h('label', {}, `Type ${typed} to continue`), input) : null],
    actions: [{ label: 'Cancel', onClick: () => { res(false); } }, { label, kind: danger ? 'danger' : 'primary', onClick: () => { if (!ok) return false; res(true); } }] });
  setTimeout(() => { btnRef.b = L.$('dialog:last-of-type .dlg-f .btn:last-child'); if (typed && btnRef.b) btnRef.b.disabled = true; input?.focus(); }, 0);
  void close;
});

/* ---------- form controls ---------- */
L.touch = () => { L.renderSaveBar(); };
L.f = {
  field: (label, control, hint, err) => h('div', { class: 'field' }, h('label', {}, label), control, hint ? h('div', { class: 'hint' }, hint) : null, err || null),
  text: (o, k, opt = {}) => h('input', { class: 'input' + (opt.mono ? ' mono-in' : ''), value: o[k] ?? '', placeholder: opt.placeholder || '', disabled: opt.disabled, spellcheck: false, autocomplete: 'off',
    oninput: e => { o[k] = e.target.value; e.target.setAttribute('aria-invalid', opt.validate && e.target.value && !opt.validate(e.target.value)); L.touch(); opt.onChange && opt.onChange(); } }),
  num: (o, k, path, opt = {}) => {
    const [min, max, unit] = L.bounds[path] || [opt.min, opt.max, opt.unit || ''];
    const err = h('div', { class: 'err' }); const inp = h('input', { class: 'input mono-in', type: 'number', value: o[k], min, max, step: 1, disabled: opt.disabled,
      oninput: e => { const v = e.target.value === '' ? NaN : +e.target.value; o[k] = v; const bad = !(Number.isInteger(v) && v >= min && v <= max) && !(opt.zero && v === 0); e.target.setAttribute('aria-invalid', bad); err.textContent = bad ? `Allowed ${opt.zero ? '0 or ' : ''}${min}–${max}` : ''; L.touch(); } });
    return h('div', {}, unit ? h('div', { class: 'unit' }, inp, h('span', {}, unit)) : inp, err);
  },
  sw: (o, k, label, opt = {}) => h('label', { class: 'switch' }, h('input', { type: 'checkbox', checked: !!o[k], disabled: opt.disabled, onchange: e => { o[k] = e.target.checked; L.touch(); opt.onChange ? opt.onChange(e.target.checked) : null; } }), h('i'), label ? h('span', {}, label) : null),
  sel: (o, k, options, opt = {}) => h('select', { class: 'select', disabled: opt.disabled, onchange: e => { o[k] = e.target.value; L.touch(); opt.onChange && opt.onChange(); } }, options.map(x => { const [v, t] = Array.isArray(x) ? x : [x, x]; return h('option', { value: v, selected: o[k] === v }, t); })),
  seg: (o, k, options, opt = {}) => { const wrap = h('div', { class: 'seg', role: 'group' }); const paint = () => [...wrap.children].forEach((b, i) => b.setAttribute('aria-pressed', String((Array.isArray(options[i]) ? options[i][0] : options[i]) === o[k])));
    options.forEach(x => { const [v, t] = Array.isArray(x) ? x : [x, x]; wrap.append(h('button', { type: 'button', disabled: opt.disabled, onclick: () => { o[k] = v; paint(); L.touch(); opt.onChange && opt.onChange(v); } }, t)); }); paint(); return wrap; },
  tags: (arr, opt = {}) => {
    const box = h('div', { class: 'tagbox' }); const chips = h('div', { class: 'chips' }); const msg = h('div', { class: 'err' });
    const draw = () => { chips.replaceChildren(...arr.map((v, i) => h('span', { class: 'chip' }, v, opt.disabled ? null : h('button', { type: 'button', 'aria-label': 'Remove ' + v, onclick: () => { arr.splice(i, 1); draw(); L.touch(); opt.onChange && opt.onChange(); } }, L.ic('x', 12))))); chips.hidden = !arr.length; };
    const add = raw => { for (const v of raw.split(/[\s,]+/).filter(Boolean)) { if (opt.validate && !opt.validate(v)) { msg.textContent = `“${v}” is not valid${opt.what ? ' ' + opt.what : ''}.`; return false; } if (arr.includes(v)) continue; if (opt.max && arr.length >= opt.max) { msg.textContent = `At most ${opt.max} entries.`; return false; } arr.push(v); } msg.textContent = ''; draw(); L.touch(); opt.onChange && opt.onChange(); return true; };
    const inp = h('input', { placeholder: opt.placeholder || 'Add and press Enter', spellcheck: false, disabled: opt.disabled, onkeydown: e => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); if (add(inp.value)) inp.value = ''; } else if (e.key === 'Backspace' && !inp.value && arr.length) { arr.pop(); draw(); L.touch(); } }, onblur: () => { if (inp.value && add(inp.value)) inp.value = ''; } });
    draw(); box.append(chips, opt.disabled ? null : inp); return h('div', {}, box, msg);
  }
};

/* ---------- save bar ---------- */
L.renderSaveBar = () => {
  const bar = L.$('.savebar'); if (!bar) return;
  const dirty = L.isDirty(); bar.classList.toggle('show', dirty);
  if (!dirty) return;
  const errs = L.validate(L.S.draft);
  bar.querySelector('.msg').replaceChildren(h('b', {}, 'Unsaved changes. '), errs.length ? `${errs.length} problem${errs.length > 1 ? 's' : ''} to fix before applying.` : 'Nothing is live until you apply.');
  bar.querySelector('[data-act=apply]').disabled = errs.length > 0;
};
L.applyDraft = async () => {
  const errs = L.validate(L.S.draft); if (errs.length) return L.reviewDraft();
  const ok = await L.confirm({ title: 'Apply configuration', text: 'Lumen checks the new settings, restarts its listeners, closes active connections and clears DNS caches. If anything fails to start, the previous settings are restored. You may be signed out of the console for a moment.', label: 'Apply and reload' });
  if (!ok) return;
  const btn = L.$('[data-act=apply]'); if (btn) btn.disabled = true;
  try {
    const r = await L.api('PUT', '/api/config', L.toServer(L.S.draft));
    L.toast(`Applying revision ${r.revision}…`);
    const result = await L.waitForConfig(r.revision);
    if (result.ok) { L.S.draft = null; await L.loadConfig(); L.renderSaveBar(); L.rerender(); L.toast(`Revision ${r.revision} is live.`); }
    else { L.toast(result.error || 'The daemon rejected the new settings. The previous settings are still active.', 'bad'); if (btn) btn.disabled = false; }
  } catch (e) { L.toast(e.message, 'bad'); if (btn) btn.disabled = false; }
};
L.reviewDraft = async () => {
  const errs = L.validate(L.D()); let toml = '', serverError = '';
  try { toml = (await L.api('POST', '/api/config/preview', L.toServer(L.D()))).toml; } catch (e) { serverError = e.message; }
  const problems = [...errs.map(e => [e.path, e.msg]), ...(serverError ? [['config', serverError]] : [])];
  L.modal({ title: 'Review configuration', wide: true, body: [
    problems.length ? h('div', { class: 'note bad' }, L.ic('alert'), h('div', {}, h('b', {}, `${problems.length} problem${problems.length > 1 ? 's' : ''}`), h('ul', { style: 'margin:6px 0 0;padding-left:18px' }, problems.map(([p, m]) => h('li', {}, h('code', {}, p), ' — ', m))))) : h('div', { class: 'note' }, L.ic('check'), h('p', {}, 'Lumen accepts this configuration. Ports, certificates and list downloads are checked again when you apply.')),
    toml ? h('pre', { class: 'code' }, toml) : null],
    actions: [toml ? { label: 'Download TOML', onClick: () => { const a = h('a', { href: URL.createObjectURL(new Blob([toml], { type: 'application/toml' })), download: 'lumen.toml' }); a.click(); return false; } } : { label: 'Close' }, toml ? { label: 'Close' } : null].filter(Boolean) });
};

/* ---------- router ---------- */
L.route = () => { const p = location.hash.replace(/^#\//, '').split('/'); return { page: p[0] || 'overview', sub: p[1] || '' }; };
L.go = (page, sub = '') => { location.hash = '#/' + page + (sub ? '/' + sub : ''); };
L.rerender = () => { const y = scrollY; L.render(); scrollTo(0, y); };
L.lockPage = () => h('div', { class: 'card' }, h('div', { class: 'empty' }, L.ic('lock', 28), h('h3', {}, 'Administrators only'), h('p', {}, `Your account (${L.session.name}) has the ${L.ROLE_LABEL[L.session.role].toLowerCase()} role. Ask an administrator if you need access.`)));
L.tabs = (items, current, onPick) => h('div', { class: 'tabs', role: 'tablist' }, items.map(([id, label]) => h('button', { role: 'tab', 'aria-selected': String(id === current), onclick: () => onPick(id) }, label)));
L.pageHead = (title, desc, actions) => h('div', { class: 'top' }, h('div', {}, h('h1', {}, title), desc ? h('p', {}, desc) : null), actions ? h('div', { class: 'actions' }, actions) : null);
L.empty = (title, text, action) => h('div', { class: 'empty' }, h('h3', {}, title), h('p', {}, text), action || null);


/* ---------- config validation ---------- */
L.validate = cfg => {
  const e = []; const bad = (path, msg) => e.push({ path, msg });
  for (const [p, [min, max]] of Object.entries(L.bounds)) { const v = L.get(cfg, p); if (v === undefined) continue; if (!(Number.isInteger(v) && v >= min && v <= max)) bad(p, `must be ${min}–${max}`); }
  const li = cfg.listen, r = cfg.resolver;
  const nL = ['udp', 'tcp', 'dot', 'doh', 'doq'].reduce((n, k) => n + li[k].length, 0); if (nL < 1 || nL > 16) bad('listen', 'enable 1–16 DNS listeners in total');
  ['udp', 'tcp', 'dot', 'doh', 'doq'].forEach(k => li[k].forEach(a => { if (!L.v.socket(a)) bad('listen.' + k, `${a} is not a valid address:port`); }));
  if (!li.allow_clients.length || li.allow_clients.length > 128) bad('listen.allow_clients', '1–128 CIDRs required');
  if ((li.dot.length || li.doh.length || li.doq.length) && !(li.certificate && li.private_key)) bad('listen.certificate', 'encrypted listeners need certificate and private_key');
  if (cfg.web.https.length && !(cfg.web.certificate && cfg.web.private_key)) bad('web.certificate', 'HTTPS needs certificate and private_key');
  if (r.mode === 'forward') { if (!r.upstreams.length && !r.providers.length) bad('resolver.upstreams', 'forward mode needs 1–8 upstreams or a provider'); if (r.upstreams.length && r.providers.length) bad('resolver.providers', 'cannot mix providers with custom upstreams'); if (r.upstreams.length > 8) bad('resolver.upstreams', 'at most 8'); }
  else { if (r.upstreams.length) bad('resolver.upstreams', 'rejected in recursive mode'); if (r.providers.length) bad('resolver.providers', 'rejected in recursive mode'); }
  r.upstreams.forEach((u, i) => { if (!L.v.socket(u.address)) bad(`resolver.upstreams[${i}]`, 'address must be an explicit IP:port'); if (['tls', 'https', 'quic'].includes(u.protocol) && !u.server_name) bad(`resolver.upstreams[${i}]`, 'encrypted protocols need server_name'); });
  const f = r.fallback; if (f.enabled) { if (r.mode !== 'recursive') bad('resolver.fallback', 'recursive mode only'); if (!f.upstreams.length || f.upstreams.length > 8) bad('resolver.fallback.upstreams', 'enabled fallback needs 1–8 upstreams'); if (f.recursive_timeout_ms + f.timeout_ms > cfg.limits.query_timeout_ms) bad('resolver.fallback', 'recursive_timeout_ms + timeout_ms must not exceed limits.query_timeout_ms'); }
  if (!(r.hedge_ms === 0 || (r.hedge_ms >= 100 && r.hedge_ms <= 5000))) bad('resolver.hedge_ms', 'must be 0 or 100–5000'); if (r.hedge_ms && r.mode !== 'recursive') bad('resolver.hedge_ms', 'recursive mode only');
  if (r.warm.zones.length > 64) bad('resolver.warm.zones', 'at most 64 zones');
  if (cfg.metrics && !/^(127\.|\[::1\])/.test(cfg.metrics)) bad('metrics', 'must be loopback');
  const F = cfg.filtering, ids = n => new Set(F[n].map(x => x.id));
  if (F.default_profile && !ids('profiles').has(F.default_profile)) bad('filtering.default_profile', 'unknown profile');
  F.groups.forEach(g => { if (!ids('profiles').has(g.profile)) bad('filtering.groups.' + g.id, 'unknown profile ' + g.profile); }); F.subnets.forEach(s => { if (!L.v.cidr(s.network)) bad('filtering.subnets', s.network + ' invalid CIDR'); else if (!ids('profiles').has(s.profile)) bad('filtering.subnets', 'unknown profile ' + s.profile); });
  F.profiles.forEach(p => { p.lists.forEach(x => { if (!ids('lists').has(x)) bad('filtering.profiles.' + p.id, 'unknown list ' + x); }); if (p.schedules.length > 32) bad('filtering.profiles.' + p.id, 'at most 32 schedule windows'); p.schedules.forEach(s => { if (s.start_minute === s.end_minute) bad('filtering.profiles.' + p.id, 'schedule start and end must differ'); }); });
  if (F.lists.length > 64) bad('filtering.lists', 'at most 64 lists'); if (F.rules.allow.length > 4096 || F.rules.block.length > 4096) bad('filtering.rules', 'at most 4096 manual rules per tier');
  const seen = new Set(); F.lists.forEach(l => { if (seen.has(l.id)) bad('filtering.lists', 'duplicate id ' + l.id); seen.add(l.id); if (l.url && !/^https:\/\/[^@#\s]+$/.test(l.url)) bad('filtering.lists.' + l.id, 'URL must be HTTPS without credentials'); if (l.refresh_secs !== 0 && !(l.refresh_secs >= 60 && l.refresh_secs <= 604800)) bad('filtering.lists.' + l.id, 'refresh_secs must be 0 or 60–604800'); });
  return e;
};


/* ---------- passwords ---------- */
L.v.username = s => /^[a-z][a-z0-9._-]{2,31}$/.test(s);
L.pw = {
  generate: () => { const a = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; const r = crypto.getRandomValues(new Uint8Array(16)); return [...r].map((x, i) => (i && i % 4 === 0 ? '-' : '') + a[x % a.length]).join(''); },
  check: pw => {
    const tips = []; if (pw.length < 10) tips.push('at least 10 characters'); if (/^(password|12345678|qwertyuiop|letmein|iloveyou)/i.test(pw)) tips.push('not a common password');
    let score = 0; if (pw.length >= 10) score++; if (pw.length >= 14) score++; if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++; if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++; if (new Set(pw).size < 5) score = Math.min(score, 1);
    if (tips.length) score = Math.min(score, 1); return { ok: !tips.length, score, label: ['Too weak', 'Weak', 'Okay', 'Good', 'Strong'][pw ? score : 0] || 'Too weak', tips };
  }
};
/* password input with show/hide and strength meter */
L.pwField = (o, k, { label = 'Password', meter = true, autocomplete = 'new-password', id } = {}) => {
  const bar = h('div', { class: 'meter' }, h('i'), h('i'), h('i'), h('i')); const txt = h('div', { class: 'hint' });
  const inp = h('input', { class: 'input', type: 'password', autocomplete, spellcheck: false, id, value: o[k] || '', oninput: e => { o[k] = e.target.value; if (meter) paint(); } });
  const paint = () => { const r = L.pw.check(o[k] || ''); [...bar.children].forEach((b, i) => { b.className = o[k] && i < r.score ? 's' + r.score : ''; }); txt.textContent = o[k] ? (r.ok ? r.label : `${r.label}. Use ${r.tips.join(' and ')}.`) : 'At least 10 characters. A passphrase works well.'; };
  if (meter) paint();
  return h('div', { class: 'field' }, h('label', { for: id }, label), h('div', { class: 'eye' }, inp, h('button', { type: 'button', class: 'btn icon flat', 'aria-label': 'Show password', onclick: () => { inp.type = inp.type === 'password' ? 'text' : 'password'; } }, L.ic('eye'))), meter ? [bar, txt] : null);
};
})();
