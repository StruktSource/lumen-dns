/* My account: password, appearance, sign out. Available to every signed-in user. */
(() => {
'use strict';
const L = window.L, h = L.h;
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
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Two-step verification'), h('span', { class: 'pill ' + (me.totp_enabled ? 'ok' : 'off') }, me.totp_enabled ? 'On' : 'Off')), h('div', { class: 'card-b stack' }, h('p', { class: 'hint', style: 'margin:0' }, me.totp_enabled ? 'Signing in needs a code from your authenticator app. You also have single-use recovery codes.' : 'Add a second step so a stolen password is not enough to sign in.'), h('div', {}, me.totp_enabled ? h('button', { class: 'btn danger', onclick: disable2fa }, 'Turn off') : h('button', { class: 'btn primary', onclick: enable2fa }, L.ic('shield'), 'Turn on')))),
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Account')), h('div', { class: 'card-b' }, h('dl', { class: 'kv' }, h('dt', {}, 'Username'), h('dd', {}, me.name), h('dt', {}, 'Role'), h('dd', {}, L.ROLE_LABEL[me.role]), h('dt', {}, 'Auto sign-out'), h('dd', {}, `after ${L.S.settings.session_idle_minutes} min idle`)))),
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'Appearance')), h('div', { class: 'card-b' }, L.f.seg(theme, 'v', [['light', 'Light'], ['dark', 'Dark']], { onChange: () => { document.documentElement.dataset.theme = theme.v; localStorage.setItem('lumen-theme', theme.v); L.rerender(); } }))),
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, 'This session')), h('div', { class: 'card-b row' }, h('div', { class: 'sp' }, h('strong', {}, 'This browser'), h('div', { class: 'hint' }, 'Ends only this session.')), h('button', { class: 'btn', onclick: L.logout }, L.ic('logout'), 'Sign out')))))];
};
})();
