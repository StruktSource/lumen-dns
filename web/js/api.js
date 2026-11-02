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
    catch { if (method !== 'GET' || attempt >= 12) throw new ApiError('Cannot reach Lumen. Check that the service is running.', 0); await new Promise(r => setTimeout(r, 500)); }
  }
  let data = null; try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && L.session) { L.session = null; L.S.draft = null; if (L.onSignedOut) L.onSignedOut(); }
  if (!res.ok) throw new ApiError((data && data.error) || `Request failed (${res.status})`, res.status);
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
L.loadHistory = async () => { L.S.history = await L.api('GET', '/api/history?limit=500'); };
L.loadSettings = async () => { L.S.settings = await L.api('GET', '/api/settings'); };
L.loadProviders = async () => { if (!L.S.providers.length) L.S.providers = await L.api('GET', '/api/providers'); };
L.loadRevisions = async () => { L.S.revisions = await L.api('GET', '/api/config/history'); };

/* What each page needs before it can draw. The draft config is only (re)loaded when it is clean. */
const NEEDS = {
  overview: () => [L.loadStatus(), L.loadSeries(), L.can('admin') ? L.loadConfig() : null],
  activity: () => [L.loadStatus(), L.loadHistory()],
  filtering: () => [L.loadStatus(), L.loadDevices(), L.S.draft ? null : L.loadConfig()],
  devices: () => [L.loadDevices(), L.can('admin') ? (L.S.draft ? null : L.loadConfig()) : null],
  dns: () => [L.loadProviders(), L.S.draft ? null : L.loadConfig()],
  access: () => [L.loadUsers(), L.loadSettings(), L.loadAudit(), L.S.draft ? null : L.loadConfig()],
  system: () => [L.loadStatus(), L.loadRevisions(), L.S.draft ? null : L.loadConfig()],
  account: () => [L.loadSettings()]
};
L.loadPage = async page => { await Promise.all((NEEDS[page] ? NEEDS[page]() : []).filter(Boolean)); };

/* After a config change the daemon restarts listeners; this console may be unreachable for a moment. */
L.waitForConfig = async revision => {
  const started = Date.now(), until = started + 300000; let lastError = null, told = false;
  while (Date.now() < until) {
    await new Promise(r => setTimeout(r, 800));
    if (!told && Date.now() - started > 15000) { told = true; L.toast('Still applying. Lumen is downloading and checking your filter lists; DNS keeps working meanwhile. Large lists can take a minute or two.'); }
    try {
      const s = await L.api('GET', '/api/status'); lastError = s.last_error;
      if (s.revision >= revision) return { ok: true };
      if (s.pending_revision == null && s.revision < revision) return { ok: false, error: s.last_error ? `Lumen refused the new settings: ${s.last_error}` : null };
    } catch (e) { if (e.status === 401) return { ok: false, error: 'You were signed out. Sign in again to check the result.' }; }
  }
  return { ok: false, error: lastError || 'The change is still pending after 5 minutes. Check the System page and the daemon log.' };
};
})();
