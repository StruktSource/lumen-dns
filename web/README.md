# Console UI

Plain HTML, CSS and JavaScript with no build step and no dependencies. The files are
embedded into the `lumen` binary by `crates/lumen-web` (`include_bytes!`), so after
editing anything here run `cargo build -p lumen`.

- `index.html` loads the scripts in order; `app.css` holds the design tokens.
- `js/core.js` DOM helper, form controls, validation, config model.
- `js/api.js` same-origin API client and per-page data loading.
- `js/app.js` boot, shell, routing, role gating. `js/view-*.js` one file per page.
- A new file must also be listed in `ASSETS` in `crates/lumen-web/src/lib.rs`
  (a test fails if `index.html` references anything that is not embedded).

Translations: write text in English in the views. `L.h` translates text, `title`, `placeholder`, and `aria-label` through `L.t()`, keyed by the English string; call `L.t('{n} items', { n })` where a sentence is built from parts. Catalogs are `js/lang-*.js`, and `cargo test -p lumen-web` checks them. See `docs/guides/translations.md`.

Rules: no inline `<script>`/`style=` markup (the CSP forbids them), set styles through
the `style` prop of `L.h` (CSSOM), never insert server data with `innerHTML`, and keep
every request same-origin.
