/* Users: one place for your own account and, for administrators, everyone else.
   Tabs: My account (everyone) | People, Sign-in (single sign-on, sessions) and Audit log (administrators). */
(() => {
'use strict';
const L = window.L, h = L.h, f = L.f, F = L.fmt;
const card = (title, right, ...body) => h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, title), right || null), h('div', { class: 'card-b stack' }, ...body));
const copy = async t => { try { await navigator.clipboard.writeText(t); L.toast('Copied'); } catch { L.toast('Copy failed. Select the text manually.', 'bad'); } };
const group = secret => secret.match(/.{1,4}/g).join(' ');

function showRecovery(codes) {
  const text = codes.join('\n');
  L.modal({ title: 'Save your recovery codes', wide: true, body: [h('div', { class: 'note warn' }, L.ic('alert'), h('p', {}, 'Each code works once if you lose your phone. They are shown only now. Store them somewhere safe, like a password manager.')),
    h('pre', { class: 'code', style: 'columns:2;column-gap:32px' }, text), h('div', { class: 'row' }, h('button', { class: 'btn', onclick: () => copy(text) }, L.ic('copy'), 'Copy'),
      h('button', { class: 'btn', onclick: () => { const link = h('a', { href: URL.createObjectURL(new Blob([`Lumen recovery codes for ${L.session.name}\n\n${text}\n`], { type: 'text/plain' })), download: 'lumen-recovery-codes.txt' }); link.click(); } }, L.ic('download'), 'Download'))],
    actions: [{ label: 'I saved them', kind: 'primary' }] });
}
function enable2fa() {
  const st = { pw: '', code: '' }; const err = h('div', { class: 'err', role: 'alert' }); const body = h('div', { class: 'stack' }); let secret = '';
  const stepOne = () => body.replaceChildren(h('p', { style: 'margin:0' }, 'Two-step verification asks for a code from an authenticator app (Google Authenticator, Authy, 1Password, Aegis…) every time you sign in. First, confirm your password.'), L.pwField(st, 'pw', { label: 'Your password', meter: false, autocomplete: 'current-password', id: 'tfa-pw' }), err);
  const stepTwo = r => { secret = r.secret; body.replaceChildren(h('p', { style: 'margin:0' }, 'Add Lumen to your authenticator app, then enter the 6-digit code it shows.'),
    h('div', { class: 'field' }, h('label', {}, 'Setup key'), h('div', { class: 'row' }, h('input', { class: 'input mono-in sp', readOnly: true, value: group(r.secret), onfocus: e => e.target.select() }), h('button', { class: 'btn', type: 'button', onclick: () => copy(r.secret) }, L.ic('copy'), 'Copy')),
      h('div', { class: 'hint' }, 'Choose “enter a setup key” in the app: account ', h('b', {}, L.session.name), ', type time-based. On a phone you can also ', h('a', { href: r.uri, style: 'text-decoration:underline' }, 'open it directly'), '.')),
    L.f.field('Code from the app', h('input', { class: 'input mono-in', id: 'tfa-code', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 6, placeholder: '123456', oninput: e => { st.code = e.target.value; } })), err); setTimeout(() => L.$('#tfa-code')?.focus(), 30); };
  stepOne();
  L.modal({ title: 'Turn on two-step verification', wide: true, body: [body], actions: [{ label: 'Cancel' }, { label: 'Continue', kind: 'primary', onClick: async () => {
    err.textContent = '';
    try {
      if (!secret) { stepTwo(await L.api('POST', '/api/me/2fa/setup', { password: st.pw })); return false; }
      const r = await L.api('POST', '/api/me/2fa/enable', { code: st.code }); L.session.totp_enabled = true; L.toast('Two-step verification is on.'); L.rerender(); setTimeout(() => showRecovery(r.recovery_codes), 50);
    } catch (e) { err.textContent = e.message; return false; } } }] });
}
function disable2fa() {
  const st = { pw: '', code: '' }; const err = h('div', { class: 'err', role: 'alert' });
  L.modal({ title: 'Turn off two-step verification', body: [h('p', { style: 'margin:0' }, 'Your account will be protected by your password alone.'), L.pwField(st, 'pw', { label: 'Your password', meter: false, autocomplete: 'current-password', id: 'dis-pw' }),
    L.f.field('Code from the app (or a recovery code)', h('input', { class: 'input mono-in', autocomplete: 'one-time-code', placeholder: '123456', oninput: e => { st.code = e.target.value; } })), err],
    actions: [{ label: 'Cancel' }, { label: 'Turn off', kind: 'danger', onClick: async () => { try { await L.api('POST', '/api/me/2fa/disable', { password: st.pw, code: st.code }); L.session.totp_enabled = false; L.toast('Two-step verification is off.'); L.rerender(); } catch (e) { err.textContent = e.message; return false; } } }] });
}

/* Single sign-on: link or unlink this account. Only shown when an administrator turned external login on. */
function unlinkSso(then) {
  const st = { pw: '' }; const err = h('div', { class: 'err', role: 'alert' });
  L.modal({ title: 'Unlink single sign-on', body: [h('p', { style: 'margin:0' }, 'You will sign in with your username and password only.'), L.pwField(st, 'pw', { label: 'Your password', meter: false, autocomplete: 'current-password', id: 'unlink-pw' }), err],
    actions: [{ label: 'Cancel' }, { label: 'Unlink', kind: 'danger', onClick: async () => { try { await L.api('DELETE', '/api/me/oidc', { password: st.pw }); L.toast('Single sign-on is unlinked.'); then(); } catch (e) { err.textContent = e.message; return false; } } }] });
}
function ssoCard() {
  const card = h('div', { class: 'card', style: 'display:none' });
  const paint = s => {
    const name = s.label || ''; card.style.display = '';
    card.replaceChildren(h('div', { class: 'card-h' }, h('h3', {}, 'Single sign-on'), h('span', { class: 'pill ' + (s.linked ? 'ok' : 'off') }, s.linked ? 'Linked' : 'Not linked')),
      h('div', { class: 'card-b stack' }, h('p', { class: 'hint', style: 'margin:0' }, s.linked ? L.t('You can sign in with {name} or with your password.', { name }) : L.t('Link this account to {name} to sign in with one click. Your username, role and settings stay the same.', { name })),
        h('div', {}, s.linked ? h('button', { class: 'btn danger', onclick: () => unlinkSso(load) }, 'Unlink')
          : h('button', { class: 'btn primary', onclick: async e => { e.target.disabled = true; try { location.href = (await L.api('POST', '/api/me/oidc/link')).url; } catch (x) { e.target.disabled = false; L.toast(x.message, 'bad'); } } }, L.t('Link {name}', { name })))));
  };
  const load = () => L.api('GET', '/api/me/oidc').then(s => { if (s.available) paint(s); else card.style.display = 'none'; }).catch(() => {});
  if (L.meta?.oidc) load();
  return card;
}
/* The provider sends people back here after linking. Show one notice and tidy the address. */
function ssoNotice() {
  const r = new URLSearchParams(location.search).get('sso');
  if (r !== 'linked' && r !== 'link-failed') return;
  history.replaceState(null, '', location.pathname + location.hash);
  setTimeout(() => (r === 'linked' ? L.toast('Your account is now linked.') : L.toast('Linking did not work. That identity may already be used by another account.', 'bad')), 0);
}

const roleHint = { admin: 'Can change every setting, manage users and see the audit log.', user: 'Can see the overview, activity and devices. Cannot change anything.' };
const isMe = u => u.name === L.session.name;
const ago = secs => F.ago(secs * 1000);

/* ---------- users ---------- */
function tempPassword(u, title, isNew) {
  const st = { pw: L.pw.generate() }; const out = h('input', { class: 'input mono-in', readOnly: true, value: st.pw, onfocus: e => e.target.select() });
  L.modal({ title, body: [h('p', { style: 'margin:0' }, isNew ? 'Give this temporary password to the person.' : L.t('Give this temporary password to {name}.', { name: u.name }), ' They will be asked to choose their own the first time they sign in. It is shown only now.'),
    h('div', { class: 'row' }, out, h('button', { class: 'btn', onclick: () => copy(out.value) }, L.ic('copy'), 'Copy'), h('button', { class: 'btn', onclick: () => { st.pw = L.pw.generate(); out.value = st.pw; } }, L.ic('refresh'), 'New'))],
    actions: [{ label: 'Cancel' }, { label: isNew ? 'Create account' : 'Reset password', kind: 'primary', onClick: async () => {
      try { if (isNew) await L.api('POST', '/api/users', { name: u.name, role: u.role, password: st.pw }); else await L.api('POST', `/api/users/${encodeURIComponent(u.name)}/password`, { password: st.pw }); }
      catch (e) { L.toast(e.message, 'bad'); return false; }
      L.toast(isNew ? L.t('{name} created.', { name: u.name }) : L.t('Password reset for {name}. Their sessions ended.', { name: u.name })); await L.refreshPage(); } }] });
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
    h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['User', 'Role', 'Created', 'Last sign-in', ''].map(x => h('th', {}, x)))), h('tbody', {}, L.S.users.map(u => h('tr', {}, h('td', {}, h('strong', {}, u.name), isMe(u) ? h('span', { class: 'pill plain', style: 'margin-left:8px' }, 'You') : null, u.totp_enabled ? h('span', { class: 'pill ok plain', style: 'margin-left:8px' }, '2FA') : null, u.must_change ? h('span', { class: 'pill warn plain', style: 'margin-left:8px' }, 'Must change password') : null),
      h('td', {}, h('span', { class: 'chip' }, L.ROLE_LABEL[u.role]), u.sso ? h('span', { class: 'chip', style: 'margin-left:6px', title: L.t('Linked to a single sign-on identity') }, 'SSO') : null), h('td', {}, ago(u.created_at)), h('td', {}, u.last_login ? ago(u.last_login) : h('span', { class: 'muted' }, 'never')),
      h('td', { class: 'act' }, h('button', { class: 'btn sm flat', 'aria-label': 'Edit ' + u.name, onclick: () => editUser(u) }, L.ic('pencil')), h('button', { class: 'btn sm flat', title: 'Reset password', 'aria-label': 'Reset password for ' + u.name, onclick: () => tempPassword(u, 'Reset password for ' + u.name, false) }, L.ic('key')),
        u.totp_enabled ? h('button', { class: 'btn sm flat', title: 'Remove two-step verification (lost phone)', 'aria-label': L.t('Reset two-step verification for {name}', { name: u.name }), onclick: async () => { if (await L.confirm({ title: L.t('Remove two-step verification for {name}', { name: u.name }), text: 'Use this when they lost their phone and recovery codes. They are signed out everywhere and can turn it on again after signing in with their password.', label: 'Remove', danger: true })) { try { await L.api('POST', `/api/users/${encodeURIComponent(u.name)}/2fa/reset`); L.toast('Two-step verification removed.'); await L.refreshPage(); } catch (e) { L.toast(e.message, 'bad'); } } } }, L.ic('shield')) : null,
        h('button', { class: 'btn sm flat danger', 'aria-label': L.t('Delete {name}', { name: u.name }), onclick: async () => { if (isMe(u)) return L.toast('You cannot delete your own account.', 'bad'); if (await L.confirm({ title: L.t('Delete {name}', { name: u.name }), text: 'They can no longer sign in. Their past actions stay in the audit log.', label: 'Delete', danger: true })) { try { await L.api('DELETE', `/api/users/${encodeURIComponent(u.name)}`); L.toast('User deleted.'); await L.refreshPage(); } catch (e) { L.toast(e.message, 'bad'); } } } }, L.ic('trash'))))))))),
    h('div', { class: 'note' }, L.ic('shield'), h('p', {}, 'Passwords are stored as salted hashes, never in plain text. After five wrong attempts a username is locked for 30 seconds, then longer. A password reset signs that person out everywhere.')));
}

/* ---------- console ---------- */
const sessionCard = () => { const st = { v: String(L.S.settings.session_idle_minutes) }; const opts = [[15, '15 minutes'], [30, '30 minutes'], [60, '1 hour'], [240, '4 hours']]; if (!opts.some(o => String(o[0]) === st.v)) opts.push([+st.v, L.t('{n} minutes', { n: st.v })]);
  return card('Sessions', null, h('div', { class: 'fgrid' }, f.field('Sign out after inactivity', f.sel(st, 'v', opts.map(([v, t]) => [String(v), t]), { onChange: async () => { try { L.S.settings = await L.api('PUT', '/api/settings', { session_idle_minutes: +st.v }); L.toast('Saved'); } catch (e) { L.toast(e.message, 'bad'); } } }), 'Applies to everyone. Saved immediately.'))); };

/* How often the Overview reloads its numbers. One choice for everyone, saved on the server. */
let af = { q: '', outcome: 'all' };
const ACTIONS = { 'history.update': 'Changed query history', 'history.clear': 'Deleted saved query history', 'setup.complete': 'Finished setup', 'session.start': 'Signed in', 'session.end': 'Signed out', 'user.add': 'Added user', 'user.remove': 'Removed user', 'user.role': 'Changed role', 'user.password': 'Changed own password', 'user.reset-password': 'Reset password', 'user.2fa-enable': 'Turned on two-step verification', 'user.2fa-disable': 'Turned off two-step verification', 'user.2fa-reset': 'Removed two-step verification', 'config.apply': 'Applied configuration', 'config.restore': 'Restored configuration', 'device.set': 'Saved device', 'device.remove': 'Removed device', 'filter.refresh': 'Refreshed filter lists', 'filter.rollback': 'Rolled back filter lists', reload: 'Reloaded', shutdown: 'Shut down', 'history.enable': 'Turned recent queries on', 'history.disable': 'Turned recent queries off', 'settings.update': 'Changed settings' };
function auditTab() {
  const rows = L.S.audit.filter(a => (af.outcome === 'all' || a.outcome === af.outcome) && (!af.q || Object.values(a).join(' ').toLowerCase().includes(af.q.toLowerCase())));
  const body = h('tbody', {}, rows.length ? rows.slice(0, 200).map(a => h('tr', {}, h('td', { class: 'mono-c' }, F.time(a.t * 1000)), h('td', {}, a.actor), h('td', {}, ACTIONS[a.action] || a.action), h('td', { class: 'mono-c' }, a.target), h('td', {}, h('span', { class: 'pill ' + (a.outcome === 'accepted' ? 'ok' : 'bad') }, a.outcome === 'accepted' ? 'Done' : 'Refused')), h('td', { class: 'mono-c' }, a.peer))) : h('tr', {}, h('td', { colspan: 6, class: 'muted' }, 'Nothing here yet.')));
  return h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('div', { class: 'row' }, h('input', { class: 'input', style: 'width:240px', placeholder: 'Search', value: af.q, 'aria-label': 'Search audit log', oninput: e => { af.q = e.target.value; L.rerender(); const i = L.$('input[aria-label="Search audit log"]'); i.focus(); i.setSelectionRange(af.q.length, af.q.length); } }),
    h('div', { class: 'seg' }, ['all', 'accepted', 'rejected'].map(k => h('button', { 'aria-pressed': String(af.outcome === k), onclick: () => { af.outcome = k; L.rerender(); } }, { all: 'All', accepted: 'Done', rejected: 'Refused' }[k])))), h('span', { class: 'mono muted' }, L.t('newest {a} of {b}', { a: Math.min(rows.length, 200), b: L.S.audit.length }))),
    h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Time (UTC)', 'Who', 'Action', 'Target', 'Result', 'From'].map(x => h('th', {}, x)))), body)));
}

function meTab() {
  const me = L.session; const f = { cur: '', pw: '', pw2: '' }; const err = h('div', { class: 'err', role: 'alert' });
  const save = async () => {
    err.textContent = ''; const c = L.pw.check(f.pw);
    if (!f.cur) return (err.textContent = 'Enter your current password.'); if (!c.ok) return (err.textContent = L.t('New password needs {tips}.', { tips: c.tips.map(x => L.t(x)).join(L.t(' and ')) }));
    if (f.pw !== f.pw2) return (err.textContent = 'The new passwords do not match.'); if (f.pw === f.cur) return (err.textContent = 'Choose a password you have not used just now.');
    const btn = L.$('#view form button[type=submit]'); if (btn) btn.disabled = true;
    try { const r = await L.api('POST', '/api/me/password', { current: f.cur, password: f.pw }); L.session = r.user; L.csrf = r.csrf; L.toast('Password changed. Other sessions were signed out.'); location.hash = '#/overview'; L.render(); }
    catch (e) { err.textContent = e.message; if (btn) btn.disabled = false; }
  };
  const theme = { v: document.documentElement.dataset.theme }; ssoNotice();
  return [    me.must_change ? h('div', { class: 'note warn', style: 'margin-bottom:16px' }, L.ic('alert'), h('p', {}, h('b', {}, 'Choose your own password. '), 'An administrator gave you a temporary one.')) : null,
    h('div', { class: 'grid g2' },
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Change password')), h('form', { class: 'card-b stack', onsubmit: e => { e.preventDefault(); save(); } },
        L.pwField(f, 'cur', { label: 'Current password', meter: false, autocomplete: 'current-password', id: 'cur' }), L.pwField(f, 'pw', { label: 'New password', id: 'new' }), L.pwField(f, 'pw2', { label: 'Repeat new password', meter: false, id: 'new2' }), err,
        h('div', {}, h('button', { class: 'btn primary', type: 'submit' }, 'Change password')))),
      h('div', { class: 'stack' },
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Two-step verification'), h('span', { class: 'pill ' + (me.totp_enabled ? 'ok' : 'off') }, me.totp_enabled ? 'On' : 'Off')), h('div', { class: 'card-b stack' }, h('p', { class: 'hint', style: 'margin:0' }, me.totp_enabled ? 'Signing in needs a code from your authenticator app. You also have single-use recovery codes.' : 'Add a second step so a stolen password is not enough to sign in.'), h('div', {}, me.totp_enabled ? h('button', { class: 'btn danger', onclick: disable2fa }, 'Turn off') : h('button', { class: 'btn primary', onclick: enable2fa }, L.ic('shield'), 'Turn on')))),
        ssoCard(),
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Account')), h('div', { class: 'card-b' }, h('dl', { class: 'kv' }, h('dt', {}, 'Username'), h('dd', {}, me.name), h('dt', {}, 'Role'), h('dd', {}, L.ROLE_LABEL[me.role]), h('dt', {}, 'Auto sign-out'), h('dd', {}, L.t('after {n} min idle', { n: L.S.settings.session_idle_minutes }))))),
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Appearance')), h('div', { class: 'card-b' }, L.f.seg(theme, 'v', [['light', 'Light'], ['dark', 'Dark']], { onChange: () => { document.documentElement.dataset.theme = theme.v; localStorage.setItem('lumen-theme', theme.v); L.rerender(); } }))),
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Language')), h('div', { class: 'card-b stack' },
          L.langSelect({ value: L.savedLang(), extra: ['', L.meta?.language ? L.t('Console default ({name})', { name: (L.LANGS.find(l => l[0] === L.meta.language) || [])[1] || L.meta.language }) : L.t('Automatic (browser language)')] }),
          h('div', { class: 'hint' }, 'Applies to this browser only. Choose the first entry to follow the console default.'))),
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'This session')), h('div', { class: 'card-b row' }, h('div', { class: 'sp' }, h('strong', {}, 'This browser'), h('div', { class: 'hint' }, 'Ends only this session.')), h('button', { class: 'btn', onclick: L.logout }, L.ic('logout'), 'Sign out')))))];
}

/* ---------- sign-in (admin): single sign-on and sessions ---------- */
/* The console's standard switch, with the hint underneath. No re-render: that would rebuild the form from the saved settings and drop the change. */
const ssoSwitch = (st, key, text, hint) => h('div', {}, f.sw(st, key, text), hint ? h('div', { class: 'hint', style: 'margin-top:6px' }, hint) : null);
function ssoSettings() {
  const c = L.S.cfg?.web?.oidc || {};
  const st = { enabled: !!c.enabled, label: c.label || 'Single sign-on', issuer: c.issuer || '', client_id: c.client_id || '', client_secret_file: c.client_secret_file || '',
    redirect_url: c.redirect_url || '', ca_file: c.ca_file || '', username_claim: c.username_claim || 'preferred_username',
    groups_claim: c.groups_claim || 'groups', admin_group: c.admin_group || '', sync_role: !!c.sync_role, single_logout: !!c.single_logout };
  const callback = location.origin + '/api/login/oidc/callback';
  const result = h('div', { class: 'hint', role: 'status' });
  const test = async e => {
    e.target.disabled = true; result.className = 'hint'; result.textContent = L.t('Checking…');
    try { const r = await L.api('POST', '/api/oidc/test', st);
      if (r.ok) { result.className = 'hint ok'; result.textContent = L.t('The provider answered. Issuer: {issuer}.', { issuer: r.issuer }) + ' ' + (r.logout ? L.t('It offers a logout page, so single logout can work.') : L.t('It offers no logout page, so single logout has no effect.')); }
      else { result.className = 'err'; result.textContent = r.error; } }
    catch (x) { result.className = 'err'; result.textContent = x.message; } finally { e.target.disabled = false; }
  };
  const save = async e => {
    if (L.isDirty()) return L.toast('You have DNS settings that are not applied yet. Apply or discard them first, then save single sign-on.', 'bad');
    e.target.disabled = true;
    try {
      const status = await L.api('GET', '/api/status');
      if (status.pending_revision != null) { L.toast('Another change is still being applied. Wait for it to finish.', 'bad'); return; }
      if (!(await L.confirm({ title: 'Apply single sign-on', text: 'Lumen checks the settings and restarts its listeners for a moment. Signing in with a username and password keeps working.', label: 'Apply' }))) return;
      const r = await L.api('PUT', '/api/oidc', st);
      L.toast(L.t('Applying revision {n}…', { n: r.revision }));
      const done = await L.waitForConfig(r.revision);
      if (!done.ok) { L.toast(done.error || 'The daemon rejected the new settings. The previous settings are still active.', 'bad'); return; }
      if (!L.isDirty()) L.S.draft = null; await L.loadConfig(); L.meta = await L.api('GET', '/api/state').catch(() => L.meta); L.rerender(); L.toast(L.t('Revision {n} is live.', { n: r.revision }));
    } catch (x) { L.toast(x.message, 'bad'); } finally { e.target.disabled = false; }
  };
  return card('Single sign-on', h('span', { class: 'pill ' + (c.enabled ? 'ok' : 'off') }, c.enabled ? 'On' : 'Off'),
    h('p', { class: 'hint', style: 'margin:0' }, 'Let people sign in with Authentik, Authelia, Pocket ID, Octelium, or another OpenID Connect provider. The username and password login always stays available.'),
    ssoSwitch(st, 'enabled', 'Turn on single sign-on'),
    h('div', { class: 'fgrid' }, f.field('Button text', f.text(st, 'label', { placeholder: 'Single sign-on' })),
      f.field('Issuer URL', f.text(st, 'issuer', { mono: true, placeholder: 'https://auth.example.com/application/o/lumen/' }), 'The provider’s address. https only, except on this machine.')),
    h('div', { class: 'fgrid' }, f.field('Client ID', f.text(st, 'client_id', { mono: true })),
      f.field('Client secret file (optional)', f.text(st, 'client_secret_file', { mono: true, placeholder: '/run/secrets/oidc' }), 'A file on the Lumen host that holds the secret. Leave empty for a public client.')),
    f.field('Redirect URL for your provider', h('div', { class: 'row' }, h('input', { class: 'input mono-in', readOnly: true, value: callback, 'aria-label': 'Redirect URL for your provider', onfocus: e => e.target.select() }), h('button', { class: 'btn', type: 'button', onclick: () => copy(callback) }, L.ic('copy'), 'Copy')),
      c.redirect_url ? 'An override under Advanced is set, so Lumen uses that address instead.' : 'Register this address with the provider. Lumen builds it from the address you use to open the console, so it fits a name, an IP address, http or https. If people open the console in different ways, register each address.'),
    h('div', { class: 'fgrid' }, f.field('Administrator group (optional)', f.text(st, 'admin_group', { mono: true, placeholder: 'lumen-admins' }), 'Members of this group start as administrators.')),
    ssoSwitch(st, 'sync_role', 'Keep roles in step with the group on every sign-in', 'The last administrator is never demoted. Needs an administrator group.'),
    ssoSwitch(st, 'single_logout', 'Also sign out of the provider when signing out here', 'Only for people who signed in through the provider.'),
    h('details', {}, h('summary', { style: 'cursor:pointer' }, 'Advanced'),
      h('div', { class: 'stack', style: 'margin-top:12px' }, f.field('Redirect URL override (optional)', f.text(st, 'redirect_url', { mono: true, placeholder: 'https://dns.example/api/login/oidc/callback' }), 'Leave empty. Set it only if a reverse proxy hides the address people use. It must end in /api/login/oidc/callback.'),
        f.field('Certificate authority file (optional)', f.text(st, 'ca_file', { mono: true, placeholder: '/etc/lumen/provider-ca.pem' }), 'Only for a provider with a private certificate authority.'),
        h('div', { class: 'fgrid' }, f.field('Username claim', f.text(st, 'username_claim', { mono: true })), f.field('Groups claim', f.text(st, 'groups_claim', { mono: true }))))),
    result,
    h('div', { class: 'row' }, h('button', { class: 'btn', type: 'button', onclick: test }, L.ic('refresh'), 'Check provider'), h('span', { class: 'sp' }), h('button', { class: 'btn primary', type: 'button', onclick: save }, 'Save and apply')));
}
function signInTab() {
  const users = L.S.users, withTwoStep = users.filter(u => u.totp_enabled).length;
  return h('div', { class: 'stack' }, ssoSettings(), sessionCard(),
    card('Two-step verification', null, h('p', { class: 'hint', style: 'margin:0' }, L.t('{n} of {total} accounts use two-step verification.', { n: withTwoStep, total: users.length })),
      h('div', { class: 'hint' }, 'Everyone turns it on for their own account under My account. If someone loses their phone, reset it for them under People.')));
}

const TABS = [['me', 'My account'], ['people', 'People'], ['signin', 'Sign-in'], ['audit', 'Audit log']];
L.views.users = sub => {
  const admin = L.can('admin'); const tab = admin ? (TABS.some(t => t[0] === sub) ? sub : 'people') : 'me';
  const body = tab === 'me' ? h('div', {}, ...meTab()) : tab === 'signin' ? signInTab() : tab === 'audit' ? auditTab() : usersTab();
  return [L.pageHead('Users', admin ? 'Your account, the people who use this console, and how they sign in.' : L.t('Signed in as {name}.', { name: L.session.name })), admin ? L.tabs(TABS, tab, id => L.go('users', id)) : null, body];
};

})();
