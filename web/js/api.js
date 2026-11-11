/* Console API client and data loaders. Every request goes to the same origin. */
(() => {
'use strict';
const L = window.L;

class ApiError extends Error { constructor(message, status) { super(message); this.status = status; } }
L.ApiError = ApiError;

L.api = async (method, path, body) => {
  const init = { method, credentials: 'same-origin', headers: {} };
  if (method !== 'GET') { init.headers['content-type'] = 'application/json'; init.headers['x-lumen-csrf'] = L.csrf; }
  if (body !== undefined) init.body = JSON.stringify(body);
  let res;
  /* A reload restarts the listeners for a moment. Reads wait it out; writes are never repeated. */
  for (let attempt = 0; ; attempt++) {
    try { res = await fetch(path, init); break; }
    catch { if (method !== 'GET' || attempt >= 12) throw new ApiError(L.t('Cannot reach Lumen. Check that the service is running.'), 0); await new Promise(r => setTimeout(r, 500)); }
  }
  let data = null; try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && L.session) { L.session = null; L.S.draft = null; if (L.onSignedOut) L.onSignedOut(); }
  if (!res.ok) throw new ApiError(data && data.error ? L.t(data.error) : L.t('Request failed ({status})', { status: res.status }), res.status);
  return data;
};

L.loadConfig = async () => {
  const r = await L.api('GET', '/api/config');
  L.S.revision = r.revision; L.S.pending = r.pending_revision; L.S.cfg = L.normalizeConfig(r.config);
};
L.loadStatus = async () => { L.S.status = await L.api('GET', '/api/status'); };
L.loadSeries = async () => { L.S.series = (await L.api('GET', '/api/series')).points; };
L.loadDevices = async () => { L.S.devices = await L.api('GET', '/api/devices'); };
L.loadUsers = async () => { L.S.users = await L.api('GET', '/api/users'); };
L.loadAudit = async () => { L.S.audit = await L.api('GET', '/api/audit?limit=300'); };
/* `q` = { search, filter }. `more` appends the next page of saved lookups instead of replacing the list. */
L.loadHistory = async (q = {}, more = false) => {
  const p = new URLSearchParams({ limit: '100' });
  if (q.search) p.set('search', q.search);
  if (q.filter && q.filter !== 'all') p.set('filter', q.filter);
  if (more && L.S.history.next_before) p.set('before', String(L.S.history.next_before));
  const r = await L.api('GET', '/api/history?' + p);
  if (more) r.items = [...L.S.history.items, ...r.items];
  L.S.history = r;
};
L.loadSettings = async () => { L.S.settings = await L.api('GET', '/api/settings'); };
L.loadProviders = async () => { if (!L.S.providers.length) L.S.providers = await L.api('GET', '/api/providers'); };
L.loadRevisions = async () => { L.S.revisions = await L.api('GET', '/api/config/history'); };

/* What each page needs before it can draw. The draft config is only (re)loaded when it is clean. */
const NEEDS = {
  overview: () => [L.loadStatus(), L.loadSeries(), L.loadSettings(), L.can('admin') ? L.loadConfig() : null],
  activity: () => [L.loadStatus(), L.loadHistory()],
  filtering: () => [L.loadStatus(), L.loadDevices(), L.S.draft ? null : L.loadConfig()],
  devices: () => [L.loadDevices(), L.can('admin') ? (L.S.draft ? null : L.loadConfig()) : null],
  dns: () => [L.loadProviders(), L.S.draft ? null : L.loadConfig()],
  users: () => [L.loadSettings(), L.can('admin') ? L.loadUsers() : null, L.can('admin') ? L.loadAudit() : null, L.can('admin') && !L.S.draft ? L.loadConfig() : null],
  system: () => [L.loadStatus(), L.loadRevisions(), L.loadSettings(), L.S.draft ? null : L.loadConfig()],
  /* The map's code is only fetched, and its data only loaded, while the module is on and its page is open. */
  trafficmap: () => [L.moduleOn('traffic-map') ? L.lazy('/assets/js/view-trafficmap.js').then(() => L.loadTraffic()) : null]
};
/* Load a script once, on demand. */
const scripts = new Map();
L.lazy = src => {
  if (!scripts.has(src)) scripts.set(src, new Promise((ok, no) => {
    const s = document.createElement('script'); s.src = src; s.onload = ok;
    s.onerror = () => { scripts.delete(src); no(new Error('Could not load this part of the console.')); };
    document.head.append(s);
  }));
  return scripts.get(src);
};
/* Modules load first: a module page decides from them whether it has anything to fetch. They change rarely, so a
   recent answer is reused instead of asking on every page change. */
L.loadPage = async page => { if (!L.S.modules || page === 'modules' || Date.now() - (L.S.modulesAt || 0) > 60000) await L.loadModules(); await Promise.all((NEEDS[page] ? NEEDS[page]() : []).filter(Boolean)); };

/* Change the lists right away, with no draft and no Apply bar. `mutate(filtering)` edits a filtering
   section and returns a function that undoes the edit. It runs on the saved settings, so unsaved edits elsewhere
   are never applied by accident. Lumen downloads in the background and DNS keeps answering; the progress panel
   shows it and can cancel it. Returns whether the change was handed to Lumen. */
L.changeLists = async mutate => {
  try {
    const status = await L.api('GET', '/api/status');
    if (status.pending_revision != null || ['checking', 'downloading', 'starting'].includes(status.activity.phase)) {
      L.toast('Another change is still being applied. Wait for it to finish, or cancel it in the progress panel.', 'bad'); return false;
    }
    const saved = await L.api('GET', '/api/config'); const next = L.normalizeConfig(saved.config); mutate(next.filtering);
    const sent = await L.api('PUT', '/api/config', L.toServer(next));
    const undo = mutate(L.S.cfg.filtering); if (L.S.draft) mutate(L.S.draft.filtering);
    L.rerender(); L.activity.poke();
    L.waitForConfig(sent.revision).then(async result => {
      if (!result.ok) { undo(L.S.cfg.filtering); if (L.S.draft) undo(L.S.draft.filtering); }
      try { await L.loadStatus(); } catch { /* shown on the next refresh */ }
      L.rerender();
    });
    return true;
  } catch (e) { L.toast(e.message, 'bad'); return false; }
};

/* After a config change the daemon restarts listeners; this console may be unreachable for a moment. */
L.waitForConfig = async revision => {
  const started = Date.now(), until = started + 300000; let lastError = null, told = false;
  while (Date.now() < until) {
    await new Promise(r => setTimeout(r, 800));
    if (!told && Date.now() - started > 15000) { told = true; L.toast('Still applying. Lumen is downloading and checking your filter lists; DNS keeps working meanwhile. Large lists can take a minute or two.'); }
    try {
      const s = await L.api('GET', '/api/status'); lastError = s.last_error;
      if (s.revision >= revision) return { ok: true };
      if (s.pending_revision == null && s.revision < revision) return { ok: false, error: s.last_error ? L.t('Lumen refused the new settings: {error}', { error: s.last_error }) : null };
    } catch (e) { if (e.status === 401) return { ok: false, error: L.t('You were signed out. Sign in again to check the result.') }; }
  }
  return { ok: false, error: lastError || L.t('The change is still pending after 5 minutes. Check the System page and the daemon log.') };
};
})();
