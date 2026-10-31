/* Users & access (admin): accounts, console listeners, audit log. */
(() => {
'use strict';
const L = window.L, h = L.h, f = L.f, F = L.fmt;
const card = (title, right, ...body) => h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, title), right || null), h('div', { class: 'card-b stack' }, ...body));
const copy = async t => { try { await navigator.clipboard.writeText(t); L.toast('Copied'); } catch { L.toast('Copy failed. Select the text manually.', 'bad'); } };
const roleHint = { admin: 'Can change every setting, manage users and see the audit log.', user: 'Can see the overview, activity and devices. Cannot change anything.' };
const isMe = u => u.name === L.session.name;
const ago = secs => F.ago(secs * 1000);

/* ---------- users ---------- */
function tempPassword(u, title, isNew) {
  const st = { pw: L.pw.generate() }; const out = h('input', { class: 'input mono-in', readOnly: true, value: st.pw, onfocus: e => e.target.select() });
  L.modal({ title, body: [h('p', { style: 'margin:0' }, isNew ? 'Give this temporary password to the person.' : `Give this temporary password to ${u.name}.`, ' They will be asked to choose their own the first time they sign in. It is shown only now.'),
    h('div', { class: 'row' }, out, h('button', { class: 'btn', onclick: () => copy(out.value) }, L.ic('copy'), 'Copy'), h('button', { class: 'btn', onclick: () => { st.pw = L.pw.generate(); out.value = st.pw; } }, L.ic('refresh'), 'New'))],
    actions: [{ label: 'Cancel' }, { label: isNew ? 'Create account' : 'Reset password', kind: 'primary', onClick: async () => {
      try { if (isNew) await L.api('POST', '/api/users', { name: u.name, role: u.role, password: st.pw }); else await L.api('POST', `/api/users/${encodeURIComponent(u.name)}/password`, { password: st.pw }); }
      catch (e) { L.toast(e.message, 'bad'); return false; }
      L.toast(isNew ? `${u.name} created.` : `Password reset for ${u.name}. Their sessions ended.`); await L.refreshPage(); } }] });
}
function addUser() {
  const d = { name: '', role: 'user' }; const err = h('div', { class: 'err' }); const hint = h('div', { class: 'hint' }, roleHint.user);
  L.modal({ title: 'Add user', body: [h('div', { class: 'fgrid' }, f.field('Username', f.text(d, 'name', { mono: true, placeholder: 'anna', validate: L.v.username }), 'Lowercase, 3–32 characters.'), f.field('Role', f.sel(d, 'role', [['user', 'User'], ['admin', 'Administrator']], { onChange: () => { hint.textContent = roleHint[d.role]; } }))), hint, err],
    actions: [{ label: 'Cancel' }, { label: 'Next', kind: 'primary', onClick: () => { const n = d.name.trim().toLowerCase(); if (!L.v.username(n)) { err.textContent = 'Enter a valid username.'; return false; } if (L.S.users.some(u => u.name === n)) { err.textContent = 'That username is taken.'; return false; } setTimeout(() => tempPassword({ name: n, role: d.role }, 'Temporary password', true), 30); } }] });
}
function editUser(u) {
  const d = { role: u.role }; const err = h('div', { class: 'err' });
  L.modal({ title: 'Edit ' + u.name, body: [f.field('Role', f.sel(d, 'role', [['user', 'User'], ['admin', 'Administrator']]), roleHint[u.role]), err],
    actions: [{ label: 'Cancel' }, { label: 'Save', kind: 'primary', onClick: async () => {
      try { await L.api('PATCH', `/api/users/${encodeURIComponent(u.name)}`, { role: d.role }); } catch (e) { err.textContent = e.message; return false; }
      if (isMe(u)) L.session.role = d.role; L.toast('Saved'); await L.refreshPage(); } }] });
}
function usersTab() {
  return h('div', { class: 'stack' }, h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Accounts'), h('button', { class: 'btn primary sm', onclick: addUser }, L.ic('plus'), 'Add user')),
    h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['User', 'Role', 'Created', 'Last sign-in', ''].map(x => h('th', {}, x)))), h('tbody', {}, L.S.users.map(u => h('tr', {}, h('td', {}, h('strong', {}, u.name), isMe(u) ? h('span', { class: 'pill plain', style: 'margin-left:8px' }, 'You') : null, u.must_change ? h('span', { class: 'pill warn plain', style: 'margin-left:8px' }, 'Must change password') : null),
      h('td', {}, h('span', { class: 'chip' }, L.ROLE_LABEL[u.role])), h('td', {}, ago(u.created_at)), h('td', {}, u.last_login ? ago(u.last_login) : h('span', { class: 'muted' }, 'never')),
      h('td', { class: 'act' }, h('button', { class: 'btn sm flat', 'aria-label': 'Edit ' + u.name, onclick: () => editUser(u) }, L.ic('pencil')), h('button', { class: 'btn sm flat', title: 'Reset password', 'aria-label': 'Reset password for ' + u.name, onclick: () => tempPassword(u, 'Reset password for ' + u.name, false) }, L.ic('key')),
        h('button', { class: 'btn sm flat danger', 'aria-label': 'Delete ' + u.name, onclick: async () => { if (isMe(u)) return L.toast('You cannot delete your own account.', 'bad'); if (await L.confirm({ title: 'Delete ' + u.name, text: 'They can no longer sign in. Their past actions stay in the audit log.', label: 'Delete', danger: true })) { try { await L.api('DELETE', `/api/users/${encodeURIComponent(u.name)}`); L.toast('User deleted.'); await L.refreshPage(); } catch (e) { L.toast(e.message, 'bad'); } } } }, L.ic('trash'))))))))),
    h('div', { class: 'note' }, L.ic('shield'), h('p', {}, 'Passwords are stored as salted hashes, never in plain text. After five wrong attempts a username is locked for 30 seconds, then longer. A password reset signs that person out everywhere.')));
}

/* ---------- console ---------- */
function consoleTab() {
  const c = L.D(); const w = c.web;
  return h('div', { class: 'stack' },
    card('Where the console is served', h('span', { class: 'pill ' + (w.http.length || w.https.length ? 'ok' : 'off') }, w.http.length || w.https.length ? 'Online' : 'Off'),
      h('div', { class: 'grid g2' }, h('div', { class: 'field' }, h('label', {}, 'HTTP'), f.tags(w.http, { validate: L.v.socket, placeholder: '127.0.0.1:8080' })), h('div', { class: 'field' }, h('label', {}, 'HTTPS'), f.tags(w.https, { validate: L.v.socket, placeholder: '0.0.0.0:8443' }))),
      w.https.length ? h('div', { class: 'fgrid' }, f.field('Certificate', f.text(w, 'certificate', { mono: true, placeholder: 'tls/web-cert.pem' })), f.field('Private key', f.text(w, 'private_key', { mono: true, placeholder: 'tls/web-key.pem' }))) : null,
      h('div', { class: 'fgrid' }, f.field('Max connections', f.num(w, 'max_connections', 'web.max_connections'))),
      h('div', { class: 'note warn' }, L.ic('alert'), h('p', {}, 'Careful: if you remove the address you are using right now, you lose access to this console. Sign-in over plain HTTP is only safe on this machine. For other devices, use HTTPS or a reverse proxy.'))),
    sessionCard(),
    card('Monitoring', null, h('div', { class: 'fgrid' }, f.field('Prometheus & health endpoint', f.text(c, 'metrics', { mono: true, placeholder: '127.0.0.1:9153 (empty = off)' }), 'Loopback only. Counts by transport; never domains or devices.'))));
}
const sessionCard = () => { const st = { v: String(L.S.settings.session_idle_minutes) }; const opts = [[15, '15 minutes'], [30, '30 minutes'], [60, '1 hour'], [240, '4 hours']]; if (!opts.some(o => String(o[0]) === st.v)) opts.push([+st.v, `${st.v} minutes`]);
  return card('Sessions', null, h('div', { class: 'fgrid' }, f.field('Sign out after inactivity', f.sel(st, 'v', opts.map(([v, t]) => [String(v), t]), { onChange: async () => { try { L.S.settings = await L.api('PUT', '/api/settings', { session_idle_minutes: +st.v }); L.toast('Saved'); } catch (e) { L.toast(e.message, 'bad'); } } }), 'Applies to everyone. Saved immediately.'))); };

/* ---------- audit ---------- */
let af = { q: '', outcome: 'all' };
const ACTIONS = { 'setup.complete': 'Finished setup', 'session.start': 'Signed in', 'session.end': 'Signed out', 'user.add': 'Added user', 'user.remove': 'Removed user', 'user.role': 'Changed role', 'user.password': 'Changed own password', 'user.reset-password': 'Reset password', 'config.apply': 'Applied configuration', 'config.restore': 'Restored configuration', 'device.set': 'Saved device', 'device.remove': 'Removed device', 'filter.refresh': 'Refreshed filter lists', 'filter.rollback': 'Rolled back filter lists', reload: 'Reloaded', shutdown: 'Shut down', 'history.enable': 'Turned recent queries on', 'history.disable': 'Turned recent queries off', 'settings.update': 'Changed settings' };
function auditTab() {
  const rows = L.S.audit.filter(a => (af.outcome === 'all' || a.outcome === af.outcome) && (!af.q || Object.values(a).join(' ').toLowerCase().includes(af.q.toLowerCase())));
  const body = h('tbody', {}, rows.length ? rows.slice(0, 200).map(a => h('tr', {}, h('td', { class: 'mono-c' }, F.time(a.t * 1000)), h('td', {}, a.actor), h('td', {}, ACTIONS[a.action] || a.action), h('td', { class: 'mono-c' }, a.target), h('td', {}, h('span', { class: 'pill ' + (a.outcome === 'accepted' ? 'ok' : 'bad') }, a.outcome === 'accepted' ? 'Done' : 'Refused')), h('td', { class: 'mono-c' }, a.peer))) : h('tr', {}, h('td', { colspan: 6, class: 'muted' }, 'Nothing here yet.')));
  return h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('div', { class: 'row' }, h('input', { class: 'input', style: 'width:240px', placeholder: 'Search', value: af.q, 'aria-label': 'Search audit log', oninput: e => { af.q = e.target.value; L.rerender(); const i = L.$('input[aria-label="Search audit log"]'); i.focus(); i.setSelectionRange(af.q.length, af.q.length); } }),
    h('div', { class: 'seg' }, ['all', 'accepted', 'rejected'].map(k => h('button', { 'aria-pressed': String(af.outcome === k), onclick: () => { af.outcome = k; L.rerender(); } }, { all: 'All', accepted: 'Done', rejected: 'Refused' }[k])))), h('span', { class: 'mono muted' }, `newest ${Math.min(rows.length, 200)} of ${L.S.audit.length}`)),
    h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Time (UTC)', 'Who', 'Action', 'Target', 'Result', 'From'].map(x => h('th', {}, x)))), body)));
}

L.views.access = sub => {
  const tab = sub || 'users';
  const body = tab === 'console' ? consoleTab() : tab === 'audit' ? auditTab() : usersTab();
  return [L.pageHead('Users & access', 'Who can sign in, and how the console is reached.'), L.tabs([['users', 'Users'], ['console', 'Console'], ['audit', 'Audit log']], tab, id => L.go('access', id)), body];
};
})();
