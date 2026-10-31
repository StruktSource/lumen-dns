/* App shell: boot, navigation, role gating, live refresh. */
(() => {
'use strict';
const L = window.L, h = L.h;
const PAGES = [['overview', 'Overview', 'overview', 'user'], ['activity', 'Activity', 'activity', 'user'], ['filtering', 'Filtering', 'filter', 'admin'], ['devices', 'Devices', 'devices', 'user'],
  ['dns', 'DNS settings', 'server', 'admin'], ['access', 'Users & access', 'key', 'admin'], ['system', 'System', 'settings', 'admin'], ['account', 'My account', 'user', 'user', true]];
const root = () => L.$('#root');
let gen = 0;

/* ---------- session ---------- */
L.signedIn = data => {
  L.session = data.user; L.csrf = data.csrf;
  location.hash = data.user.must_change ? '#/account' : '#/overview'; L.render();
};
L.logout = async () => { try { await L.api('POST', '/api/logout'); } catch { /* already gone */ } L.session = null; L.csrf = ''; L.S.draft = null; L.meta = await L.api('GET', '/api/state').catch(() => L.meta); location.hash = '#/login'; L.render(); };
L.onSignedOut = () => { L.toast('Your session ended. Sign in again.', 'bad'); location.hash = '#/login'; L.render(); };

/* ---------- shell ---------- */
function shell(content, page) {
  const side = h('aside', { class: 'side', id: 'side' },
    h('div', { class: 'brand' }, h('b', {}, '✦'), 'LUMEN', h('small', {}, 'v' + (L.meta?.version || ''))),
    h('nav', { class: 'nav', 'aria-label': 'Main' }, PAGES.filter(p => !p[4] && L.can(p[3])).map(([id, label, icon]) => h('a', { href: '#/' + id, 'aria-current': id === page ? 'page' : null, onclick: () => side.classList.remove('open') }, L.ic(icon), label))),
    h('div', { class: 'side-foot' },
      h('a', { class: 'who', href: '#/account', title: 'My account', onclick: () => side.classList.remove('open') }, h('div', { class: 'av' }, L.session.name[0].toUpperCase()), h('div', {}, h('strong', {}, L.session.name), h('span', {}, L.ROLE_LABEL[L.session.role]))),
      h('div', { class: 'side-tools' },
        h('button', { class: 'btn sp', title: 'Toggle theme', onclick: () => { const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; document.documentElement.dataset.theme = t; localStorage.setItem('lumen-theme', t); L.render(); } }, L.ic(document.documentElement.dataset.theme === 'dark' ? 'sun' : 'moon'), document.documentElement.dataset.theme === 'dark' ? 'Light' : 'Dark'),
        h('button', { class: 'btn sp', onclick: L.logout }, L.ic('logout'), 'Sign out'))));
  const mob = h('div', { class: 'mobbar' }, h('div', { class: 'brand', style: 'padding:0' }, h('b', {}, '✦'), 'LUMEN'), h('button', { class: 'btn', 'aria-label': 'Menu', onclick: () => side.classList.toggle('open') }, L.ic('menu')));
  const bar = h('div', { class: 'savebar', role: 'region', 'aria-label': 'Unsaved changes' }, h('div', { class: 'msg' }),
    h('button', { class: 'btn', onclick: () => { L.S.draft = null; L.renderSaveBar(); L.rerender(); L.toast('Changes discarded'); } }, 'Discard'),
    h('button', { class: 'btn', onclick: L.reviewDraft }, 'Review TOML'),
    h('button', { class: 'btn primary', 'data-act': 'apply', onclick: L.applyDraft }, L.ic('check'), 'Apply config'));
  return h('div', { class: 'app' }, side, h('div', {}, mob, h('main', { class: 'main', id: 'view' }, content), bar));
}

const current = () => { const { page, sub } = L.route(); const def = PAGES.find(p => p[0] === page) || PAGES[0]; return { def, sub }; };
const draw = () => {
  const { def, sub } = current();
  if (L.session.must_change && def[0] !== 'account') { location.hash = '#/account'; return; }
  const view = !L.can(def[3]) ? [L.pageHead(def[1]), L.lockPage()] : L.views[def[0]](sub);
  root().replaceChildren(shell(view, def[0])); L.renderSaveBar(); document.title = `${def[1]} · Lumen`;
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
L.rerender = () => { if (!L.session) return; const y = scrollY; draw(); scrollTo(0, y); };
/* Reload this page's data from the server, then redraw (after a successful change). */
L.refreshPage = async () => { const { def } = current(); try { await L.loadPage(def[0]); } catch (e) { L.toast(e.message, 'bad'); } L.rerender(); };
L.paintMain = () => { const m = L.$('#view'); if (!m || !L.session) return; const { def, sub } = current(); const y = scrollY; m.replaceChildren(...[].concat(L.views[def[0]](sub))); scrollTo(0, y); };

addEventListener('hashchange', () => { L.render(); scrollTo(0, 0); });

/* ---------- boot ---------- */
(async () => {
  document.documentElement.dataset.theme = localStorage.getItem('lumen-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  try { L.meta = await L.api('GET', '/api/state'); } catch (e) { L.meta = null; L.metaError = e.message; }
  if (L.meta?.user) { L.session = L.meta.user.user; L.csrf = L.meta.user.csrf; }
  await L.render();
})();

/* Keep the overview live. */
setInterval(async () => {
  if (document.hidden || !L.session || L.route().page !== 'overview' || L.$('dialog[open]')) return;
  try { await Promise.all([L.loadStatus(), L.loadSeries()]); L.paintMain(); } catch { /* next tick */ }
}, 5000);
})();
