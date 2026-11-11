/* Console settings (System > Console): where the console is served, default language, auto reload, monitoring. */
(() => {
'use strict';
const L = window.L, h = L.h, f = L.f;
const card = (title, right, ...body) => h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', {}, title), right || null), h('div', { class: 'card-b stack' }, ...body));
L.consoleTab = () => {
  const c = L.D(); const w = c.web;
  return h('div', { class: 'stack' },
    card('Where the console is served', h('span', { class: 'pill ' + (w.http.length || w.https.length ? 'ok' : 'off') }, w.http.length || w.https.length ? 'Online' : 'Off'),
      h('div', { class: 'grid g2' }, h('div', { class: 'field' }, h('label', {}, 'HTTP'), f.tags(w.http, { validate: L.v.socket, placeholder: '127.0.0.1:8080' })), h('div', { class: 'field' }, h('label', {}, 'HTTPS'), f.tags(w.https, { validate: L.v.socket, placeholder: '0.0.0.0:8443' }))),
      w.https.length ? h('div', { class: 'fgrid' }, f.field('Certificate', f.text(w, 'certificate', { mono: true, placeholder: 'tls/web-cert.pem' })), f.field('Private key', f.text(w, 'private_key', { mono: true, placeholder: 'tls/web-key.pem' }))) : null,
      h('div', { class: 'fgrid' }, f.field('Max connections', f.num(w, 'max_connections', 'web.max_connections'))),
      h('div', { class: 'note warn' }, L.ic('alert'), h('p', {}, 'Careful: if you remove the address you are using right now, you lose access to this console. Sign-in over plain HTTP is only safe on this machine. For other devices, use HTTPS or a reverse proxy.'))),
    reloadCard(),
    languageCard(),
    card('Monitoring', null, h('div', { class: 'fgrid' }, f.field('Prometheus & health endpoint', f.text(c, 'metrics', { mono: true, placeholder: '127.0.0.1:9153 (empty = off)' }), 'Loopback only. Counts by transport; never domains or devices.'))));
};
/* The language everyone sees until they pick their own in My account. */
const languageCard = () => card('Language', null, f.field('Default language for the console', L.langSelect({ value: L.S.settings.language || '', extra: ['', L.t('Automatic (browser language)')],
  onPick: async v => { try { L.S.settings = await L.api('PUT', '/api/settings', { language: v || null }); L.meta.language = L.S.settings.language; L.toast('Saved'); if (L.savedLang()) L.rerender(); else L.setLang(''); } catch (e) { L.toast(e.message, 'bad'); L.rerender(); } } }),
  'Used on the sign-in page and by everyone who has not chosen a language of their own. Each person can change theirs under My account.'));
const reloadCard = () => {
  const steps = L.RELOAD_STEPS, label = secs => secs ? L.t('{n} s', { n: secs }) : L.t('Off');
  const out = h('output', { class: 'mono' }, label(L.reloadSecs()));
  return card('Overview', null, f.field('Auto reload', h('div', { class: 'reload-pick' },
    h('input', { class: 'reload-range', type: 'range', min: 0, max: steps.length - 1, step: 1, value: steps.indexOf(L.reloadSecs()), 'aria-label': 'Auto reload',
      oninput: e => { out.textContent = label(steps[e.target.value]); },
      onchange: async e => { try { await L.setReloadSecs(steps[e.target.value]); L.toast('Saved'); } catch (err) { L.toast(err.message, 'bad'); L.rerender(); } } }), out),
    'How often the Overview reloads its numbers. Applies to everyone. Saved immediately.'));
};

})();
