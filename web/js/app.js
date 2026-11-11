/* App shell: boot, navigation, role gating, live refresh. */
(() => {
'use strict';
const L = window.L, h = L.h;
const PAGES = [['overview', 'Overview', 'overview', 'user'], ['activity', 'Activity', 'activity', 'user'], ['filtering', 'Filtering', 'filter', 'admin'], ['devices', 'Devices', 'devices', 'user'],
  ['dns', 'DNS settings', 'server', 'admin'], ['users', 'Users', 'user', 'user'], ['system', 'System', 'settings', 'admin'],
  /* Pages that belong to a module (6th entry) show in the sidebar only while it is on. */
  ['modules', 'Modules', 'modules', 'user'], ['trafficmap', 'Traffic map', 'map', 'user', false, 'traffic-map']];
const root = () => L.$('#root');
L.sideHidden = () => { try { return localStorage.getItem('lumen-side-hidden') === '1'; } catch { return false; } };
L.toggleSide = () => {
  const app = L.$('.app'); if (!app) return;
  const hide = !app.classList.contains('side-hidden');
  app.classList.toggle('side-hidden', hide); L.setSideHidden(hide);
  L.$('.side-handle')?.setAttribute('tabindex', hide ? '0' : '-1');
  (hide ? L.$('.side-handle') : L.$('.side-collapse'))?.focus({ preventScroll: true });
  /* Let drawings such as the traffic map fit the new width once the slide has finished. */
  setTimeout(() => dispatchEvent(new Event('resize')), 340);
};
addEventListener('keydown', e => { if (e.key === '[' && !e.ctrlKey && !e.metaKey && !e.altKey && L.session && !e.target.closest?.('input,textarea,select,[contenteditable]') && !L.$('dialog[open]')) { e.preventDefault(); L.toggleSide(); } });
L.setSideHidden = hide => { try { localStorage.setItem('lumen-side-hidden', hide ? '1' : '0'); } catch { /* storage blocked */ } };
let gen = 0;

/* ---------- session ---------- */
L.signedIn = data => {
  L.session = data.user; L.csrf = data.csrf;
  location.hash = data.user.must_change ? '#/users/me' : '#/overview'; L.render();
};
L.logout = async () => { let r = null; try { r = await L.api('POST', '/api/logout'); } catch { /* already gone */ } L.session = null; L.csrf = ''; L.S.draft = null; L.meta = await L.api('GET', '/api/state').catch(() => L.meta); /* Signed in through the provider: end its session too. */ if (r?.redirect) { location.href = r.redirect; return; } location.hash = '#/login'; L.render(); };
L.onSignedOut = () => { L.toast('Your session ended. Sign in again.', 'bad'); location.hash = '#/login'; L.render(); };

/* ---------- shell ---------- */
function shell(content, page) {
  const side = h('aside', { class: 'side', id: 'side' },
    h('div', { class: 'brand' }, h('b', {}, '✦'), 'LUMEN', h('small', {}, 'v' + (L.meta?.version || ''))),
    h('nav', { class: 'nav', 'aria-label': 'Main' }, PAGES.filter(p => !p[4] && L.can(p[3]) && (!p[5] || L.moduleOn(p[5]))).map(([id, label, icon]) => h('a', { href: '#/' + id, 'aria-current': id === page ? 'page' : null, onclick: () => side.classList.remove('open') }, L.ic(icon), label))),
    h('div', { class: 'side-foot' },
      h('div', { class: 'side-tools' },
        h('div', { class: 'side-lang' }, L.ic('globe', 16), L.langSelect()),
        h('button', { class: 'btn sp', title: 'Toggle theme', onclick: () => { const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; document.documentElement.dataset.theme = t; localStorage.setItem('lumen-theme', t); L.render(); } }, L.ic(document.documentElement.dataset.theme === 'dark' ? 'sun' : 'moon'), document.documentElement.dataset.theme === 'dark' ? 'Light' : 'Dark'),
        h('button', { class: 'btn sp', onclick: L.logout }, L.ic('logout'), 'Sign out'))));
  const mob = h('div', { class: 'mobbar' }, h('div', { class: 'brand', style: 'padding:0' }, h('b', {}, '✦'), 'LUMEN'), h('button', { class: 'btn', 'aria-label': 'Menu', onclick: () => side.classList.toggle('open') }, L.ic('menu')));
  const bar = h('div', { class: 'savebar', role: 'region', 'aria-label': 'Unsaved changes' }, h('div', { class: 'msg' }),
    h('button', { class: 'btn', onclick: () => { L.S.draft = null; L.renderSaveBar(); L.rerender(); L.toast('Changes discarded'); } }, 'Discard'),
    h('button', { class: 'btn', onclick: L.reviewDraft }, 'Review TOML'),
    h('button', { class: 'btn primary', 'data-act': 'apply', onclick: L.applyDraft }, L.ic('check'), 'Apply config'));
  /* Hide the sidebar for more room (the traffic map, wide tables). A small tab on the left edge brings it back. */
  const app = h('div', { class: 'app' + (L.sideHidden() ? ' side-hidden' : '') }, side, h('div', {}, mob, h('main', { class: 'main', id: 'view' }, content), bar),
    h('button', { class: 'side-handle', 'aria-controls': 'side', 'aria-label': 'Show sidebar', title: L.t('Show sidebar') + ' ([)', tabindex: L.sideHidden() ? null : '-1', onclick: () => L.toggleSide() }, L.ic('chevr')));
  side.querySelector('.brand').append(h('button', { class: 'side-collapse', 'aria-controls': 'side', 'aria-label': 'Hide sidebar', title: L.t('Hide sidebar') + ' ([)', onclick: () => L.toggleSide() }, L.ic('chevl')));
  return app;
}

/* Earlier versions had separate pages; old links and bookmarks land on the new ones. */
const MOVED = { account: ['users', 'me'], access: ['users', 'people'] };
const current = () => { const { page, sub } = L.route(); const def = PAGES.find(p => p[0] === page) || PAGES[0]; return { def, sub }; };
const draw = () => {
  const moved = MOVED[L.route().page];
  if (moved) { const sub = L.route().sub; L.go(...(moved[0] === 'users' && sub === 'audit' ? ['users', 'audit'] : moved[1] === 'people' && sub === 'console' ? ['system', 'console'] : moved)); return; }
  const { def, sub } = current();
  if (L.session.must_change && !(def[0] === 'users' && sub === 'me')) { location.hash = '#/users/me'; return; }
  const view = !L.can(def[3]) ? [L.pageHead(def[1]), L.lockPage()]
    : def[5] && !L.moduleOn(def[5]) ? [L.pageHead(def[1]), L.empty('This module is off', 'Turn it on under Modules to use it.', h('button', { class: 'btn primary', onclick: () => L.go('modules') }, 'Open Modules'))]
    : L.views[def[0]](sub);
  root().replaceChildren(shell(view, def[0])); L.renderSaveBar(); document.title = `${L.t(def[1])} · Lumen`;
};
const failure = (message, retry) => h('div', { class: 'main' }, L.pageHead('Something went wrong'), h('div', { class: 'card' }, L.empty('Lumen could not load this page', message, h('button', { class: 'btn primary', onclick: retry }, 'Try again'))));

/* Fetch what the page needs, then draw it. Stale responses from earlier navigation are dropped. */
L.render = async () => {
  const mine = ++gen;
  if (!L.meta) return root().replaceChildren(L.views.unavailable(L.metaError));
  if (!L.session) return root().replaceChildren(L.views.login());
  const { def } = current();
  if (L.can(def[3])) {
    try { await L.loadPage(def[0]); } catch (e) { if (mine === gen && L.session) root().replaceChildren(failure(e.message, () => L.render())); return; }
  }
  if (mine === gen && L.session) draw();
};
/* Redraw with data already in memory (form toggles, tab-local changes). */
L.redraw = () => L.render();
L.rerender = () => { if (!L.session) return; const y = scrollY; draw(); scrollTo(0, y); };
/* Reload this page's data from the server, then redraw (after a successful change). */
L.refreshPage = async () => { const { def } = current(); try { await L.loadPage(def[0]); } catch (e) { L.toast(e.message, 'bad'); } L.rerender(); };
L.paintMain = () => { const m = L.$('#view'); if (!m || !L.session) return; const { def, sub } = current(); const y = scrollY; m.replaceChildren(...[].concat(L.views[def[0]](sub)).flat(9).filter(c => c != null && c !== false)); scrollTo(0, y); };

addEventListener('hashchange', () => { L.render(); scrollTo(0, 0); });

/* ---------- boot ---------- */
(async () => {
  document.documentElement.dataset.theme = localStorage.getItem('lumen-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  try { L.meta = await L.api('GET', '/api/state'); } catch (e) { L.meta = null; L.metaError = e.message; }
  L.initLang();
  if (L.meta?.user) { L.session = L.meta.user.user; L.csrf = L.meta.user.csrf; }
  await L.render();
})();

/* Keep the overview live. How often it reloads is a per-browser choice (default 10 s, or off), set with the slider on the Overview. */
L.RELOAD_STEPS = [1, 2, 5, 10, 30, 60, 0];
/* Saved on the server (System > Console), so it is the same for every user and browser. */
L.reloadSecs = () => { const v = L.S.settings?.overview_reload_secs; return L.RELOAD_STEPS.includes(v) ? v : 10; };
L.setReloadSecs = async secs => { L.S.settings = await L.api('PUT', '/api/settings', { overview_reload_secs: secs }); scheduleReload(); };
let reloadTimer = 0;
function scheduleReload() {
  clearTimeout(reloadTimer);
  const secs = L.reloadSecs();
  /* Off: look again now and then, in case an administrator turns it back on. */
  if (!secs) { reloadTimer = setTimeout(scheduleReload, 5000); return; }
  reloadTimer = setTimeout(async () => {
    const slider = L.$('.reload-range');
    if (!document.hidden && L.session && L.route().page === 'overview' && !L.$('dialog[open]') && document.activeElement !== slider) {
      try { await Promise.all([L.loadStatus(), L.loadSeries()]); L.paintMain(); } catch { /* next tick */ }
    }
    scheduleReload();
  }, secs * 1000);
}
scheduleReload();
})();
