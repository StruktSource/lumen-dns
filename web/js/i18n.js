/* Console localization. Catalogs are keyed by the English text, so an untranslated string simply stays English.
   `L.h` translates text and the title / placeholder / aria-label attributes by itself; use `L.t(text, vars)` where a
   sentence is built from parts. To add a language, see docs/guides/translations.md. */
(() => {
'use strict';
const L = window.L;

/* [code, name in that language]. The first entry is the fallback. Add a language here and in
   `LANGUAGES` in crates/lumen-web/src/console.rs, then add web/js/lang-<code>.js and list it in index.html. */
L.LANGS = [['en', 'English'], ['de', 'Deutsch'], ['it', 'Italiano'], ['es', 'Español'], ['nl', 'Nederlands']];
L.lang = 'en';
L.i18n = { catalogs: {}, add(code, entries) { this.catalogs[code] = entries; } };

const known = code => L.LANGS.some(l => l[0] === code);

/* Translate `key` into the current language. `{name}` placeholders are filled from `vars`. */
L.t = (key, vars) => {
  const catalog = L.i18n.catalogs[L.lang];
  let out = catalog && Object.prototype.hasOwnProperty.call(catalog, key) ? catalog[key] : key;
  if (vars) out = out.replace(/\{(\w+)\}/g, (whole, name) => (name in vars ? String(vars[name]) : whole));
  return out;
};

/* Your own choice in this browser wins, then the language an administrator picked for the console,
   then the browser's language, then English. */
L.detectLang = () => {
  let saved = null;
  try { saved = localStorage.getItem('lumen-lang'); } catch { /* storage blocked */ }
  if (known(saved)) return saved;
  if (known(L.meta?.language)) return L.meta.language;
  for (const tag of navigator.languages || [navigator.language]) {
    const code = String(tag || '').slice(0, 2).toLowerCase();
    if (known(code)) return code;
  }
  return 'en';
};

/* The language chosen in this browser, or '' when the console default is used. */
L.savedLang = () => { try { const v = localStorage.getItem('lumen-lang'); return known(v) ? v : ''; } catch { return ''; } };

/* Switch language. `remember` keeps the choice in this browser; '' forgets it and follows the console default. */
L.setLang = (code, remember = true) => {
  try {
    if (remember && known(code)) localStorage.setItem('lumen-lang', code);
    else if (code === '') localStorage.removeItem('lumen-lang');
  } catch { /* storage blocked */ }
  L.lang = known(code) ? code : L.detectLang();
  document.documentElement.lang = L.lang;
  if (L.redraw) L.redraw();
};

/* Apply the detected language without saving it. Call once the console state is known. */
L.initLang = () => { L.lang = L.detectLang(); document.documentElement.lang = L.lang; };

/* A language drop-down. Names are shown in their own language so anyone can find theirs. */
L.langSelect = ({ extra = null, value = L.lang, onPick = null } = {}) => {
  const options = [...(extra ? [extra] : []), ...L.LANGS];
  return L.h('select', { class: 'select lang-select', 'aria-label': 'Language', onchange: e => (onPick || (v => L.setLang(v)))(e.target.value) },
    options.map(([code, name]) => L.h('option', { value: code, selected: code === value }, name)));
};

/* Numbers and dates follow the language. */
L.locale = () => L.lang;
})();
