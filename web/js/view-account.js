/* My account: password, appearance, sign out. Available to every signed-in user. */
(() => {
'use strict';
const L = window.L, h = L.h;
L.views.account = () => {
  const me = L.session; const f = { cur: '', pw: '', pw2: '' }; const err = h('div', { class: 'err', role: 'alert' });
  const save = async () => {
    err.textContent = ''; const c = L.pw.check(f.pw);
    if (!f.cur) return (err.textContent = 'Enter your current password.'); if (!c.ok) return (err.textContent = `New password needs ${c.tips.join(' and ')}.`);
    if (f.pw !== f.pw2) return (err.textContent = 'The new passwords do not match.'); if (f.pw === f.cur) return (err.textContent = 'Choose a password you have not used just now.');
    const btn = L.$('#view form button[type=submit]'); if (btn) btn.disabled = true;
    try { const r = await L.api('POST', '/api/me/password', { current: f.cur, password: f.pw }); L.session = r.user; L.csrf = r.csrf; L.toast('Password changed. Other sessions were signed out.'); location.hash = '#/overview'; L.render(); }
    catch (e) { err.textContent = e.message; if (btn) btn.disabled = false; }
  };
  const theme = { v: document.documentElement.dataset.theme };
  return [L.pageHead('My account', `Signed in as ${me.name}.`),
    me.must_change ? h('div', { class: 'note warn', style: 'margin-bottom:16px' }, L.ic('alert'), h('p', {}, h('b', {}, 'Choose your own password. '), 'An administrator gave you a temporary one.')) : null,
    h('div', { class: 'grid g2' },
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Change password')), h('form', { class: 'card-b stack', onsubmit: e => { e.preventDefault(); save(); } },
        L.pwField(f, 'cur', { label: 'Current password', meter: false, autocomplete: 'current-password', id: 'cur' }), L.pwField(f, 'pw', { label: 'New password', id: 'new' }), L.pwField(f, 'pw2', { label: 'Repeat new password', meter: false, id: 'new2' }), err,
        h('div', {}, h('button', { class: 'btn primary', type: 'submit' }, 'Change password')))),
      h('div', { class: 'stack' },
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Account')), h('div', { class: 'card-b' }, h('dl', { class: 'kv' }, h('dt', {}, 'Username'), h('dd', {}, me.name), h('dt', {}, 'Role'), h('dd', {}, L.ROLE_LABEL[me.role]), h('dt', {}, 'Auto sign-out'), h('dd', {}, `after ${L.S.settings.session_idle_minutes} min idle`)))),
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Appearance')), h('div', { class: 'card-b' }, L.f.seg(theme, 'v', [['light', 'Light'], ['dark', 'Dark']], { onChange: () => { document.documentElement.dataset.theme = theme.v; localStorage.setItem('lumen-theme', theme.v); L.rerender(); } }))),
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'This session')), h('div', { class: 'card-b row' }, h('div', { class: 'sp' }, h('strong', {}, 'This browser'), h('div', { class: 'hint' }, 'Ends only this session.')), h('button', { class: 'btn', onclick: L.logout }, L.ic('logout'), 'Sign out')))))];
};
})();
