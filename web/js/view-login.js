/* Sign-in, first-run setup and the "console unavailable" screen. */
(() => {
'use strict';
const L = window.L, h = L.h;
const art = (kicker, line1, line2) => h('section', { class: 'login-art' }, h('div', { class: 'mono k' }, kicker),
  h('div', {}, h('div', { style: 'font-size:clamp(40px,5vw,72px);color:var(--acid);margin-bottom:12px' }, '✦'), h('h1', {}, 'LUMEN.'), h('p', {}, line1, h('br'), h('span', {}, line2))),
  h('div', { class: 'meta mono' }, h('span', {}, 'SELF-HOSTED'), h('span', {}, 'NO TELEMETRY'), h('span', {}, 'YOUR NETWORK'), h('span', { class: 'sp' }), h('span', { class: 'ver' }, 'v' + (L.meta?.version || ''))));

/* A small language switcher in the corner of every sign-in and setup screen. */
const langCorner = () => h('div', { class: 'lang-corner' }, L.ic('globe', 16), L.langSelect());
/* Big language buttons for the first setup step. */
const langButtons = () => h('div', { class: 'seg', role: 'group', 'aria-label': 'Language' }, L.LANGS.map(([code, name]) => h('button', { type: 'button', 'aria-pressed': String(code === L.lang), onclick: () => L.setLang(code) }, name)));

L.views.unavailable = message => h('div', { class: 'login' }, art('STRUKT / LUMEN', 'The console', 'is not reachable.'),
  h('div', { class: 'login-form' }, langCorner(), h('h2', {}, 'Console unavailable'), h('p', { class: 'muted', style: 'margin:0' }, message || 'Lumen did not answer.'),
    h('p', { class: 'hint', style: 'margin:0' }, 'The console needs Lumen to run in managed mode: ', h('code', {}, 'lumen --config FILE --state FILE'), '.'), h('button', { class: 'btn primary', onclick: () => location.reload() }, 'Try again')));

/* ---------- sign in ---------- */
let pending = null; // { challenge } once the password was accepted and a code is owed
function codeStep() {
  const f = { code: '' }; let recovery = false; const err = h('div', { class: 'err', role: 'alert' }); const btn = h('button', { class: 'btn primary', type: 'submit', style: 'padding:13px' }, 'Verify');
  const input = h('input', { class: 'input mono-in', id: 'code', autocomplete: 'one-time-code', inputmode: 'numeric', spellcheck: false, maxlength: 12, placeholder: '123456', oninput: e => { f.code = e.target.value; } });
  const label = h('label', { for: 'code' }, 'Authenticator code'); const hint = h('div', { class: 'hint' }, 'Open your authenticator app and enter the 6-digit code for Lumen.');
  const toggle = h('button', { type: 'button', class: 'linkish', onclick: () => { recovery = !recovery; label.textContent = L.t(recovery ? 'Recovery code' : 'Authenticator code'); hint.textContent = L.t(recovery ? 'Enter one of the recovery codes you saved. Each works once.' : 'Open your authenticator app and enter the 6-digit code for Lumen.'); input.placeholder = recovery ? 'xxxxx-xxxxx' : '123456'; input.inputMode = recovery ? 'text' : 'numeric'; toggle.textContent = L.t(recovery ? 'Use my authenticator app' : 'Use a recovery code instead'); input.value = ''; f.code = ''; input.focus(); } }, 'Use a recovery code instead');
  const submit = async e => {
    e.preventDefault(); err.textContent = ''; btn.disabled = true;
    try { const r = await L.api('POST', '/api/login/2fa', { challenge: pending.challenge, code: f.code }); pending = null; L.signedIn(r); }
    catch (x) { err.textContent = x.message; btn.disabled = false; if (/expired|Too many wrong/.test(x.message)) { pending = null; setTimeout(() => L.$('#root').replaceChildren(L.views.login()), 1200); } else { input.select(); } }
  };
  return h('div', { class: 'login' }, art('STRUKT / LUMEN', 'One more step.', 'Prove it’s you.'),
    h('form', { class: 'login-form', onsubmit: submit }, langCorner(), h('h2', {}, 'Two-step verification'), h('div', { class: 'field' }, label, input, hint), err, btn,
      h('div', { class: 'row' }, toggle, h('span', { class: 'sp' }), h('button', { type: 'button', class: 'linkish', onclick: () => { pending = null; L.$('#root').replaceChildren(L.views.login()); } }, 'Back to sign in'))));
}
function signIn() {
  if (pending) return codeStep();
  const f = { name: '', pw: '' }; const err = h('div', { class: 'err', role: 'alert' }); const btn = h('button', { class: 'btn primary', type: 'submit', style: 'padding:13px' }, 'Sign in');
  /* A failed external sign-in lands here as ?sso=failed. Show one generic notice and tidy the address. */
  if (new URLSearchParams(location.search).get('sso') === 'failed') { err.textContent = L.t('Single sign-on did not work. Try again, or use your username and password.'); history.replaceState(null, '', location.pathname + location.hash); }
  const submit = async e => {
    e.preventDefault(); err.textContent = ''; btn.disabled = true;
    try { const r = await L.api('POST', '/api/login', { username: f.name.trim(), password: f.pw }); if (r.needs_2fa) { pending = { challenge: r.challenge }; L.$('#root').replaceChildren(L.views.login()); return; } L.signedIn(r); }
    catch (x) { err.textContent = x.message; btn.disabled = false; L.$('#p')?.select(); }
  };
  return h('div', { class: 'login' }, art('STRUKT / LUMEN', 'Welcome back.', 'Your DNS, your rules.'),
    h('form', { class: 'login-form', onsubmit: submit },
      langCorner(),
      h('h2', {}, 'Sign in'),
      L.f.field('Username', h('input', { class: 'input', autocomplete: 'username', spellcheck: false, autocapitalize: 'none', id: 'u', oninput: e => { f.name = e.target.value; } })),
      L.pwField(f, 'pw', { label: 'Password', meter: false, autocomplete: 'current-password', id: 'p' }), err, btn,
      L.meta.oidc ? h('a', { class: 'btn', href: '/api/login/oidc', style: 'padding:13px;text-align:center;text-decoration:none' }, L.t('Sign in with {name}', { name: L.meta.oidc.label })) : null,
      h('details', { class: 'hint' }, h('summary', { style: 'cursor:pointer' }, 'Forgot your password?'), h('p', { style: 'margin:8px 0 0' }, 'Ask an administrator to reset it under ', h('b', {}, 'Users'), '. If you are the only administrator, run ', h('code', {}, 'lumenctl user reset-password --state FILE --name NAME --password generate'), ' on the server.'))));
}

/* ---------- first-run setup ---------- */
/* A guided wizard: welcome, setup code (only off the host machine), account, privacy, networks, protection, review. */
const sf = { sso: false, ssoLabel: '', ssoIssuer: '', ssoClient: '', ssoSecret: '', ssoGroup: '', ssoSync: false, ssoLogout: false, name: 'admin', pw: '', pw2: '', mode: 'recursive', code: '', protect: 'recommended' }; let nets = []; let at = 0; let verified = false;
const PROTECT = [
  ['recommended', 'Recommended', 'Hagezi Pro plus the Threat Intelligence feed. Blocks ads, trackers, malware and phishing with very few broken sites.', '≈ 1.4 M rules · 40 MB'],
  ['light', 'Light', 'Hagezi Light and a trimmed threat feed. Gentle and small, a good fit for a Raspberry Pi.', '≈ 270 k rules · 10 MB'],
  ['strict', 'Strict', 'Hagezi Ultimate, Threat Intelligence and OISD Big. Maximum protection; expect to allow a few domains yourself.', '≈ 2.4 M rules · 70 MB'],
  ['none', 'No blocking yet', 'Start as a plain DNS server. You can install lists any time under Filtering.', 'nothing to download']];
const NETS = [['192.168.0.0/16', 'Home network', '192.168.x.x, most routers'], ['10.0.0.0/8', 'Private 10.x', 'larger or VPN networks'], ['172.16.0.0/12', 'Private 172.16–31', 'Docker and some offices']];
const journey = needCode => [['welcome', 'Welcome'], ...(needCode ? [['code', 'Setup code']] : []), ['account', 'Your account'], ['sso', 'Single sign-on'], ['privacy', 'Privacy'], ['network', 'Networks'], ['protect', 'Protection'], ['review', 'Finish']];
const STORY = {
  welcome: ['Hello.', 'Private DNS in a few minutes.'], code: ['Prove you', 'own this box.'], account: ['Make it', 'yours.'], sso: ['Already have', 'an identity provider?'], privacy: ['Who gets', 'to see?'],
  network: ['Who may', 'ask?'], protect: ['Keep the', 'junk out.'], review: ['Ready', 'when you are.']
};
function wizardArt(steps, i) {
  const [id] = steps[i]; const [l1, l2] = STORY[id];
  return h('section', { class: 'login-art wiz-art' }, h('div', { class: 'mono k' }, L.t('STRUKT / LUMEN / SETUP · {i} OF {n}', { i: i + 1, n: steps.length })),
    h('div', {}, h('div', { style: 'font-size:clamp(34px,4vw,56px);color:var(--acid);margin-bottom:10px' }, '✦'), h('h1', { class: 'wiz-h1' }, 'LUMEN.'), h('p', {}, l1, h('br'), h('span', {}, l2))),
    h('ol', { class: 'journey', 'aria-label': 'Setup progress' }, steps.map(([sid, name], k) => h('li', { class: k < i ? 'done' : k === i ? 'now' : '', 'aria-current': k === i ? 'step' : null }, h('i', {}, k < i ? '✓' : String(k + 1)), h('span', {}, name)))),
    h('div', { class: 'meta mono' }, h('span', {}, 'SELF-HOSTED'), h('span', {}, 'NO TELEMETRY'), h('span', { class: 'sp' }), h('span', { class: 'ver' }, 'v' + (L.meta?.version || ''))));
}
function codeBoxes() {
  const cells = []; const wrap = h('div', { class: 'codebox', role: 'group', 'aria-label': 'Setup code' });
  const read = () => cells.map(c => c.value).join(''); const sync = () => { const v = read(); sf.code = v.length > 4 ? v.slice(0, 4) + '-' + v.slice(4) : v; };
  for (let i = 0; i < 8; i++) {
    const c = h('input', { class: 'input mono-in', maxlength: 1, inputmode: 'text', autocomplete: 'off', spellcheck: false, autocapitalize: 'characters', 'aria-label': `Character ${i + 1}`,
      oninput: e => { e.target.value = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 1); sync(); if (e.target.value && cells[i + 1]) cells[i + 1].focus(); },
      onkeydown: e => { if (e.key === 'Backspace' && !e.target.value && cells[i - 1]) { cells[i - 1].focus(); cells[i - 1].value = ''; sync(); } else if (e.key === 'ArrowLeft' && cells[i - 1]) cells[i - 1].focus(); else if (e.key === 'ArrowRight' && cells[i + 1]) cells[i + 1].focus(); },
      onpaste: e => { const t = (e.clipboardData.getData('text') || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8); if (!t) return; e.preventDefault(); [...t].forEach((ch, k) => { if (cells[k]) cells[k].value = ch; }); sync(); cells[Math.min(t.length, 7)].focus(); } });
    cells.push(c); if (i === 4) wrap.append(h('b', { class: 'dash', 'aria-hidden': 'true' }, '–')); wrap.append(c);
  }
  [...sf.code.replace(/[^A-Z0-9]/gi, '').toUpperCase()].forEach((ch, k) => { if (cells[k]) cells[k].value = ch; });
  return wrap;
}
function setup() {
  const needCode = !!L.meta.setup_code_required; const steps = journey(needCode); if (at >= steps.length) at = 0; const id = steps[at][0];
  const err = h('div', { class: 'err', role: 'alert' }); const go = n => { at = n; draw(); };
  let body = []; let next = () => go(at + 1); let nextLabel = 'Continue';
  const back = at > 0 ? h('button', { type: 'button', class: 'btn', onclick: () => go(at - 1) }, 'Back') : null;
  if (id === 'welcome') {
    nextLabel = 'Get started';
    body = [h('h2', {}, 'Welcome to Lumen'), h('p', { class: 'muted', style: 'margin:0' }, 'This is the first run, so there is no account yet. A few quick choices and your private DNS server is ready. Everything can be changed later.'),
      h('div', { class: 'feat' }, [['lock', 'Private by design', 'Resolve on your own machine. No third party has to see your lookups.'], ['shield', 'Blocks the junk', 'Ads, trackers, malware and phishing, with lists you control.'], ['devices', 'Built for a household', 'Devices, profiles, schedules and an audit log, no cloud account.']].map(([ic, t, d]) => h('div', {}, L.ic(ic), h('b', {}, t), h('span', {}, d)))),
      h('div', { class: 'field' }, h('label', {}, 'Language'), langButtons(), h('div', { class: 'hint' }, 'You can change the language later in the settings.')),
      h('p', { class: 'hint', style: 'margin:0' }, L.t(needCode ? 'About three minutes. Lumen v{v}.' : 'About two minutes. Lumen v{v}.', { v: L.meta?.version || '' }))];
  } else if (id === 'code') {
    nextLabel = 'Verify code';
    const tabs = { docker: ['Docker', 'docker logs lumen 2>&1 | grep -i "setup code"'], system: ['Linux service', 'journalctl -u lumen | grep -i "setup code"'], kube: ['Kubernetes', 'kubectl logs deploy/lumen | grep -i "setup code"'], term: ['Terminal', 'Look just above the “listening on” lines where you started lumen.'] };
    const out = h('code', { class: 'cmd' }); let cur = 'docker'; const tabRow = h('div', { class: 'seg', role: 'group' }); const paint = () => { out.textContent = tabs[cur][1]; tabRow.replaceChildren(...Object.entries(tabs).map(([k, [t]]) => h('button', { type: 'button', 'aria-pressed': String(k === cur), onclick: () => { cur = k; paint(); } }, t))); }; paint();
    body = [h('h2', {}, 'Enter your setup code'), h('p', { class: 'muted', style: 'margin:0' }, 'You are not on the machine that runs Lumen, so Lumen needs proof that you control it. The code was printed when Lumen started.'),
      h('div', { class: 'field' }, h('label', {}, 'Setup code'), codeBoxes()), err,
      h('div', { class: 'field' }, h('label', {}, 'Where do I find it?'), tabRow, out, h('div', { class: 'hint' }, 'The code stays valid until the account exists. Opening the console from the host machine skips this step.'))];
    next = async () => {
      const raw = sf.code.replace(/[^A-Z0-9]/gi, ''); if (raw.length < 8) { err.textContent = L.t('The code has 8 characters.'); return; }
      try { await L.api('POST', '/api/setup/code', { code: sf.code }); verified = true; go(at + 1); } catch (x) { err.textContent = x.message; const box = L.$('.codebox'); box?.classList.remove('shake'); void box?.offsetWidth; box?.classList.add('shake'); }
    };
  } else if (id === 'account') {
    body = [h('h2', {}, 'Create your account'), h('p', { class: 'muted', style: 'margin:0' }, 'You become the administrator. Other people get their own accounts later.'),
      L.f.field('Username', L.f.text(sf, 'name', { mono: true, placeholder: 'admin', validate: L.v.username }), 'Lowercase letters, digits, dot, dash, underscore. 3–32 characters, starting with a letter.'), L.pwField(sf, 'pw', { label: 'Password', id: 'pw1' }), L.pwField(sf, 'pw2', { label: 'Repeat password', meter: false, id: 'pw2' }), err,
      h('p', { class: 'hint', style: 'margin:0' }, 'Use a passphrase of at least 10 characters. You can add two-step verification in your account settings afterwards.')];
    next = () => { const n = sf.name.trim().toLowerCase(); if (!L.v.username(n)) return (err.textContent = L.t('Choose a valid username.')); const c = L.pw.check(sf.pw); if (!c.ok) return (err.textContent = L.t('Password needs {tips}.', { tips: c.tips.map(x => L.t(x)).join(L.t(' and ')) })); if (sf.pw !== sf.pw2) return (err.textContent = L.t('The two passwords differ.')); sf.name = n; go(at + 1); };
  } else if (id === 'sso') {
    nextLabel = sf.sso ? 'Continue' : 'Skip for now';
    const callback = location.origin + '/api/login/oidc/callback';
    const check = (key, text) => h('div', {}, L.f.sw(sf, key, text, { onChange: key === 'sso' ? draw : null }));
    body = [h('h2', {}, 'Sign in with your identity provider'), h('p', { class: 'muted', style: 'margin:0' }, 'Optional. Let people sign in with Authentik, Authelia, Pocket ID, Octelium, or another OpenID Connect provider. The username and password login always stays available. You can also set this up later.'),
      check('sso', 'Use an identity provider'),
      ...(sf.sso ? [L.f.field('Button text', L.f.text(sf, 'ssoLabel', { placeholder: 'Single sign-on' })),
        L.f.field('Issuer URL', L.f.text(sf, 'ssoIssuer', { mono: true, placeholder: 'https://auth.example.com/application/o/lumen/' })),
        L.f.field('Client ID', L.f.text(sf, 'ssoClient', { mono: true })),
        L.f.field('Client secret file (optional)', L.f.text(sf, 'ssoSecret', { mono: true, placeholder: '/run/secrets/oidc' }), 'A file on the Lumen host that holds the secret. Leave empty for a public client.'),
        L.f.field('Redirect URL for your provider', h('div', { class: 'row' }, h('input', { class: 'input mono-in', readOnly: true, value: callback, 'aria-label': 'Redirect URL for your provider', onfocus: e => e.target.select() }), h('button', { class: 'btn', type: 'button', onclick: async () => { try { await navigator.clipboard.writeText(callback); L.toast('Copied'); } catch { L.toast('Copy failed. Select the text manually.', 'bad'); } } }, L.ic('copy'), 'Copy')), 'Register this address with the provider. Lumen builds it from the address you use to open the console, so it fits a name, an IP address, http or https.'),
        L.f.field('Administrator group (optional)', L.f.text(sf, 'ssoGroup', { mono: true, placeholder: 'lumen-admins' }), 'Members of this group start as administrators.'),
        check('ssoSync', 'Keep roles in step with the group on every sign-in'), check('ssoLogout', 'Also sign out of the provider when signing out here')] : []), err];
    next = () => { if (sf.sso && (!sf.ssoIssuer.trim() || !sf.ssoClient.trim())) return (err.textContent = L.t('Enter the issuer URL and client ID.')); go(at + 1); };
  } else if (id === 'privacy') {
    const card = (v, t, d, tag) => h('label', { class: 'pick' }, h('input', { type: 'radio', name: 'mode', checked: sf.mode === v, onchange: () => { sf.mode = v; } }), h('div', {}, h('b', {}, t, tag ? h('span', { class: 'chip', style: 'margin-left:8px' }, tag) : null), h('span', {}, d)));
    body = [h('h2', {}, 'How should Lumen find answers?'), h('p', { class: 'muted', style: 'margin:0' }, 'This decides who can see which sites your devices look up.'),
      h('div', { class: 'picks' }, card('recursive', 'Resolve privately', 'Lumen asks the internet’s root servers itself and validates the answers. No single company sees your lookups. A little slower the first time a name is used.', 'recommended'), card('forward', 'Use another resolver', 'Forward to an encrypted provider, Quad9 to start. Often a bit faster, but that provider sees your lookups. Change or add providers later.')), err];
  } else if (id === 'network') {
    nextLabel = nets.length ? 'Continue' : 'Only this machine';
    const chips = h('div', { class: 'quick' }, NETS.map(([cidr, t, d]) => h('button', { type: 'button', class: 'quickbtn', 'aria-pressed': String(nets.includes(cidr)), onclick: e => { const i = nets.indexOf(cidr); if (i >= 0) nets.splice(i, 1); else nets.push(cidr); draw(); } }, h('b', {}, t), h('span', { class: 'mono' }, cidr), h('em', {}, d))));
    body = [h('h2', {}, 'Which devices may use it?'), h('p', { class: 'muted', style: 'margin:0' }, 'Lumen only answers networks you name. This machine is always allowed. Tap the ones your devices live on, or add your own.'), chips,
      L.f.field('Other networks', L.f.tags(nets, { validate: L.v.cidr, placeholder: '192.168.1.0/24', what: 'as a network (CIDR)', max: 128 }), 'Leave empty to keep Lumen reachable only from this machine. Never allow the whole internet.'), err];
  } else if (id === 'protect') {
    body = [h('h2', {}, 'Block ads, trackers and threats'), h('p', { class: 'muted', style: 'margin:0' }, 'Pick a starting set of block lists. Lumen downloads them right after you sign in, shows you the progress, and refreshes them daily. You can change them anytime.'),
      h('div', { class: 'picks' }, PROTECT.map(([v, t, d, size]) => h('label', { class: 'pick' }, h('input', { type: 'radio', name: 'protect', checked: sf.protect === v, onchange: () => { sf.protect = v; } }), h('div', {}, h('b', {}, t, v === 'recommended' ? h('span', { class: 'chip', style: 'margin-left:8px' }, 'recommended') : null), h('span', {}, d), h('em', { class: 'mono' }, size))))), err];
  } else {
    nextLabel = 'Create account and start';
    const label = { recursive: 'Private (recursive)', forward: 'Forwarding to Quad9' }[sf.mode]; const prot = PROTECT.find(x => x[0] === sf.protect)[1];
    body = [h('h2', {}, 'Ready to start'), h('p', { class: 'muted', style: 'margin:0' }, 'Lumen creates your account and applies these choices. DNS restarts for a moment, then you land on the overview.'),
      h('dl', { class: 'kv review' }, h('dt', {}, 'Administrator'), h('dd', {}, sf.name), h('dt', {}, 'Resolution'), h('dd', {}, label), h('dt', {}, 'Single sign-on'), h('dd', {}, sf.sso ? (sf.ssoLabel.trim() || 'Single sign-on') : 'Off'), h('dt', {}, 'Allowed networks'), h('dd', {}, nets.length ? nets.join(', ') : 'this machine only'), h('dt', {}, 'Block lists'), h('dd', {}, sf.protect === 'none' ? 'none yet' : L.t('{name} (downloads after setup)', { name: L.t(prot) }))), err];
    next = async () => {
      try { L.signedIn(await L.api('POST', '/api/setup', { code: sf.code, username: sf.name, password: sf.pw, mode: sf.mode, allow_clients: nets, oidc: sf.sso ? { label: sf.ssoLabel.trim(), issuer: sf.ssoIssuer.trim(), client_id: sf.ssoClient.trim(), client_secret_file: sf.ssoSecret.trim(), admin_group: sf.ssoGroup.trim(), sync_role: sf.ssoSync && !!sf.ssoGroup.trim(), single_logout: sf.ssoLogout } : undefined, language: L.lang })); if (sf.protect !== 'none') localStorage.setItem('lumen.pendingBundle', sf.protect); L.activity.poke(); sf.pw = sf.pw2 = ''; at = 0; }
      catch (x) { err.textContent = x.message; if (x.status === 403) { at = needCode ? 1 : 0; draw(); } }
    };
  }
  const form = h('form', { class: 'login-form wiz', onsubmit: async e => { e.preventDefault(); const b = L.$('.login-form button[type=submit]'); b.disabled = true; try { await next(); } finally { b.disabled = false; } } },
    id === 'welcome' ? null : langCorner(), h('div', { class: 'steps', 'aria-hidden': 'true' }, steps.map((_, k) => h('i', { class: k < at ? 'on' : k === at ? 'now' : '' }))), h('div', { class: 'wiz-body' }, body),
    h('div', { class: 'row' }, back, h('span', { class: 'sp' }), h('button', { class: 'btn primary', type: 'submit', style: 'padding:13px 22px' }, nextLabel, id === 'review' ? null : L.ic('arrow'))));
  return h('div', { class: 'login' }, wizardArt(steps, at), form);
}
const draw = () => L.$('#root').replaceChildren(L.views.login());

L.views.login = () => { const v = L.meta.setup_needed ? setup() : signIn(); setTimeout(() => { if (document.activeElement === document.body || !document.activeElement) (L.$('.codebox input') || L.$('#u') || L.$('form input'))?.focus({ preventScroll: true }); }, 50); return v; };
})();
