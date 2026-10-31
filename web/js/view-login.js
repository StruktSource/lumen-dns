/* Sign-in, first-run setup and the "console unavailable" screen. */
(() => {
'use strict';
const L = window.L, h = L.h;
const art = (kicker, line1, line2) => h('section', { class: 'login-art' }, h('div', { class: 'mono k' }, kicker),
  h('div', {}, h('div', { style: 'font-size:clamp(40px,5vw,72px);color:var(--acid);margin-bottom:12px' }, '✦'), h('h1', {}, 'LUMEN.'), h('p', {}, line1, h('br'), h('span', {}, line2))),
  h('div', { class: 'meta mono' }, h('span', {}, 'SELF-HOSTED'), h('span', {}, 'NO TELEMETRY'), h('span', {}, 'YOUR NETWORK'), h('span', { class: 'sp' }), h('span', { class: 'ver' }, 'v' + (L.meta?.version || ''))));

L.views.unavailable = message => h('div', { class: 'login' }, art('STRUKT / LUMEN', 'The console', 'is not reachable.'),
  h('div', { class: 'login-form' }, h('h2', {}, 'Console unavailable'), h('p', { class: 'muted', style: 'margin:0' }, message || 'Lumen did not answer.'),
    h('p', { class: 'hint', style: 'margin:0' }, 'The console needs Lumen to run in managed mode: ', h('code', {}, 'lumen --config FILE --state FILE'), '.'), h('button', { class: 'btn primary', onclick: () => location.reload() }, 'Try again')));

/* ---------- sign in ---------- */
let pending = null; // { challenge } once the password was accepted and a code is owed
function codeStep() {
  const f = { code: '' }; let recovery = false; const err = h('div', { class: 'err', role: 'alert' }); const btn = h('button', { class: 'btn primary', type: 'submit', style: 'padding:13px' }, 'Verify');
  const input = h('input', { class: 'input mono-in', id: 'code', autocomplete: 'one-time-code', inputmode: 'numeric', spellcheck: false, maxlength: 12, placeholder: '123456', oninput: e => { f.code = e.target.value; } });
  const label = h('label', { for: 'code' }, 'Authenticator code'); const hint = h('div', { class: 'hint' }, 'Open your authenticator app and enter the 6-digit code for Lumen.');
  const toggle = h('button', { type: 'button', class: 'linkish', onclick: () => { recovery = !recovery; label.textContent = recovery ? 'Recovery code' : 'Authenticator code'; hint.textContent = recovery ? 'Enter one of the recovery codes you saved. Each works once.' : 'Open your authenticator app and enter the 6-digit code for Lumen.'; input.placeholder = recovery ? 'xxxxx-xxxxx' : '123456'; input.inputMode = recovery ? 'text' : 'numeric'; toggle.textContent = recovery ? 'Use my authenticator app' : 'Use a recovery code instead'; input.value = ''; f.code = ''; input.focus(); } }, 'Use a recovery code instead');
  const submit = async e => {
    e.preventDefault(); err.textContent = ''; btn.disabled = true;
    try { const r = await L.api('POST', '/api/login/2fa', { challenge: pending.challenge, code: f.code }); pending = null; L.signedIn(r); }
    catch (x) { err.textContent = x.message; btn.disabled = false; if (/expired|Too many wrong/.test(x.message)) { pending = null; setTimeout(() => L.$('#root').replaceChildren(L.views.login()), 1200); } else { input.select(); } }
  };
  return h('div', { class: 'login' }, art('STRUKT / LUMEN', 'One more step.', 'Prove it’s you.'),
    h('form', { class: 'login-form', onsubmit: submit }, h('h2', {}, 'Two-step verification'), h('div', { class: 'field' }, label, input, hint), err, btn,
      h('div', { class: 'row' }, toggle, h('span', { class: 'sp' }), h('button', { type: 'button', class: 'linkish', onclick: () => { pending = null; L.$('#root').replaceChildren(L.views.login()); } }, 'Back to sign in'))));
}
function signIn() {
  if (pending) return codeStep();
  const f = { name: '', pw: '' }; const err = h('div', { class: 'err', role: 'alert' }); const btn = h('button', { class: 'btn primary', type: 'submit', style: 'padding:13px' }, 'Sign in');
  const submit = async e => {
    e.preventDefault(); err.textContent = ''; btn.disabled = true;
    try { const r = await L.api('POST', '/api/login', { username: f.name.trim(), password: f.pw }); if (r.needs_2fa) { pending = { challenge: r.challenge }; L.$('#root').replaceChildren(L.views.login()); return; } L.signedIn(r); }
    catch (x) { err.textContent = x.message; btn.disabled = false; L.$('#p')?.select(); }
  };
  return h('div', { class: 'login' }, art('STRUKT / LUMEN', 'Welcome back.', 'Your DNS, your rules.'),
    h('form', { class: 'login-form', onsubmit: submit },
      h('h2', {}, 'Sign in'),
      L.f.field('Username', h('input', { class: 'input', autocomplete: 'username', spellcheck: false, autocapitalize: 'none', id: 'u', oninput: e => { f.name = e.target.value; } })),
      L.pwField(f, 'pw', { label: 'Password', meter: false, autocomplete: 'current-password', id: 'p' }), err, btn,
      h('details', { class: 'hint' }, h('summary', { style: 'cursor:pointer' }, 'Forgot your password?'), h('p', { style: 'margin:8px 0 0' }, 'Ask an administrator to reset it under ', h('b', {}, 'Users & access'), '. If you are the only administrator, run ', h('code', {}, 'lumenctl user reset-password --state FILE --name NAME --password generate'), ' on the server.'))));
}

/* ---------- first-run setup ---------- */
let step = 1; const sf = { name: 'admin', pw: '', pw2: '', mode: 'recursive', code: '' }; let nets = [];
function setup() {
  const needCode = !!L.meta.setup_code_required;
  const err = h('div', { class: 'err', role: 'alert' }); const dots = h('div', { class: 'steps', 'aria-label': `Step ${step} of 3` }, [1, 2, 3].map(i => h('i', { class: i < step ? 'on' : i === step ? 'now' : '' })));
  const back = step > 1 && step < 3 ? h('button', { type: 'button', class: 'btn', onclick: () => { step--; draw(); } }, 'Back') : null;
  let body, next;
  if (step === 1) {
    body = [h('h2', {}, 'Create your account'), h('p', { class: 'muted', style: 'margin:0' }, 'This is the first time Lumen runs here. The account you create now is the administrator. You can add other people later.'),
      needCode ? L.f.field('Setup code', L.f.text(sf, 'code', { mono: true, placeholder: 'XXXX-XXXX' }), 'You are not on the machine that runs Lumen. The code is printed in its log when Lumen starts (for Docker: docker logs).') : null,
      L.f.field('Username', L.f.text(sf, 'name', { mono: true, placeholder: 'admin', validate: L.v.username }), 'Lowercase letters, digits, dot, dash, underscore. 3–32 characters, starting with a letter.'), L.pwField(sf, 'pw', { label: 'Password', id: 'pw1' }), L.pwField(sf, 'pw2', { label: 'Repeat password', meter: false, id: 'pw2' }), err];
    next = () => { const n = sf.name.trim().toLowerCase(); if (needCode && !sf.code.trim()) return (err.textContent = 'Enter the setup code.'); if (!L.v.username(n)) return (err.textContent = 'Choose a valid username.'); const c = L.pw.check(sf.pw); if (!c.ok) return (err.textContent = `Password needs ${c.tips.join(' and ')}.`); if (sf.pw !== sf.pw2) return (err.textContent = 'The passwords do not match.'); sf.name = n; step = 2; draw(); };
  } else if (step === 2) {
    body = [h('h2', {}, 'How should Lumen work?'), h('p', { class: 'muted', style: 'margin:0' }, 'You can change all of this later under DNS settings.'),
      h('div', { class: 'field' }, h('label', {}, 'Resolution'), h('div', { class: 'choice' }, [['recursive', 'Resolve privately', 'Lumen asks the internet’s root servers itself. No third party sees your lookups. Recommended.'], ['forward', 'Use another resolver', 'Forward to a provider (Quad9 to start). Often a little faster, but that provider sees your lookups.']].map(([v, t, d]) => h('label', {}, h('input', { type: 'radio', name: 'mode', checked: sf.mode === v, onchange: () => { sf.mode = v; } }), h('div', {}, h('b', {}, t), h('span', {}, d)))))),
      L.f.field('Which networks may use this DNS server?', L.f.tags(nets, { validate: L.v.cidr, placeholder: '192.168.1.0/24', what: 'as a network (CIDR)', max: 128 }), 'Optional. This machine is always allowed. Leave empty to keep Lumen reachable only from this machine.'), err];
    next = () => { step = 3; draw(); };
  } else {
    body = [h('h2', {}, 'All set'), h('p', { class: 'muted', style: 'margin:0' }, 'Lumen creates your account and applies these choices. DNS restarts for a moment.'),
      h('dl', { class: 'kv' }, h('dt', {}, 'Administrator'), h('dd', {}, sf.name), h('dt', {}, 'Resolution'), h('dd', {}, sf.mode === 'recursive' ? 'private (recursive)' : 'forwarding'), h('dt', {}, 'Allowed networks'), h('dd', {}, nets.length ? nets.join(', ') : 'this machine only')), err];
    next = async () => {
      try { L.signedIn(await L.api('POST', '/api/setup', { code: sf.code, username: sf.name, password: sf.pw, mode: sf.mode, allow_clients: nets })); sf.pw = sf.pw2 = ''; }
      catch (x) { err.textContent = x.message; if (x.status === 403) { step = 1; draw(); } }
    };
  }
  return h('div', { class: 'login' }, art('STRUKT / LUMEN / SETUP', 'Let’s get', 'you set up.'),
    h('form', { class: 'login-form', onsubmit: async e => { e.preventDefault(); const b = L.$('.login-form button[type=submit]'); b.disabled = true; await next(); b.disabled = false; } }, dots, body, h('div', { class: 'row' }, back, h('span', { class: 'sp' }), h('button', { class: 'btn primary', type: 'submit', style: 'padding:12px 22px' }, step === 3 ? 'Create account' : 'Continue'))));
}
const draw = () => L.$('#root').replaceChildren(L.views.login());

L.views.login = () => { const v = L.meta.setup_needed ? setup() : signIn(); setTimeout(() => { if (document.activeElement === document.body || !document.activeElement) (L.$('#code') || L.$('#u') || L.$('form input'))?.focus({ preventScroll: true }); }, 50); return v; };
})();
