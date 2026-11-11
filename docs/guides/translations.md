# Languages and translations

The web console speaks **English, German (Deutsch), Italian (Italiano), Spanish (Español), and Dutch (Nederlands)**. This page explains how to change the language and how to add or improve a translation.

## Choose a language

There are three places, from the most personal to the most general:

| Where | Who | What it does |
| :--- | :--- | :--- |
| **The language menu** on the sign-in page, in the setup wizard, and in the sidebar | Anyone | Switches this browser right away and remembers the choice |
| **My account → Language** | Each signed-in user | Same, with an extra entry that follows the console default |
| **System → Console → Default language** | Administrators | Sets the language for the sign-in page and for everyone who has not picked their own |

The console picks the language in this order:

1. The language you chose in **this browser**.
2. The **console default** an administrator set.
3. Your **browser's language**, if the console has it.
4. English.

On first run, the setup wizard starts with a language picker. The language you choose there also becomes the console default.

> [!NOTE]
> The language applies to the console only. Messages written to the process log, the command-line tools, and the documentation stay in English.

## What is translated

The whole console is translated: navigation, sign-in and two-step verification, the setup wizard, every page, editors, dialogs, confirmations, help text, and common error messages.

Names such as list titles, protocol names, and file paths are not translated. Text supplied at runtime, such as a list publisher's download error, can also stay in English because it is not part of a locale catalog.

Anything without a translation falls back to English, so a missing entry never breaks a page.

## How it works

The console is plain JavaScript with no build step. Translations are plain data:

- `web/js/i18n.js` holds the language list, the language detection, and `L.t()`.
- `web/js/lang-de.js`, `lang-it.js`, `lang-es.js`, and `lang-nl.js` each hold one catalog.
- A catalog is a list of `"English text": "translation"` pairs, one per line. The **English text is the key**, so there is no separate English file and no ID to look up.
- The helper that builds every page element translates text, and the `title`, `placeholder`, and `aria-label` attributes, automatically. Code only calls `L.t()` where a sentence is built from parts.
- A sentence with a variable uses a named placeholder, such as `"{n} lookups saved"`. Keep the same `{names}` in the translation.

## Improve a translation

1. Open the catalog for the language, for example `web/js/lang-de.js`.
2. Find the English text on the left and change the text on the right.
3. Keep every `{placeholder}` exactly as written, and keep the same punctuation at the start and end of the text.
4. Run `cargo test -p lumen-web`. A test checks that the catalog is valid, has the same entries as the others, uses the same placeholders, and still matches text that really exists in the console.
5. Open a pull request.

**Tone.** The English text is friendly and direct, and the translations use the informal form of address (*du*, *tu*, *tú*, *je*). Keep technical terms people will search for, such as DNS, DNSSEC, DoH, DoT, DoQ, TOML, and CIDR.

## Add a language

1. Pick a two-letter language code, for example `fr`.
2. Add it to the list in `web/js/i18n.js`: `L.LANGS = [['en', 'English'], …, ['fr', 'Français']]`. Use the language's own name.
3. Add the same code to `LANGUAGES` in `crates/lumen-web/src/console.rs`.
4. Create `web/js/lang-fr.js`, copying the layout of an existing catalog, and translate the entries.
5. List the file in `web/index.html` (after `lang-nl.js`) and in `ASSETS` in `crates/lumen-web/src/lib.rs`.
6. Run `cargo test -p lumen-web`. The tests fail until the new catalog has the same entries as the others, which is how a half-finished language is caught.
7. Describe the new language in `CHANGELOG.md` and open a pull request.

A native speaker's review is welcome on every translation pull request.

## Add or change English text

When you add text to the console, write it in English in the view, as usual. To make it translatable, add the same English text to every catalog. The test fails if a catalog still contains text that no longer exists in the console, so removed or reworded text has to be updated there too.

## Related

- [Web console](web-console.md)
- [Contributing](../../CONTRIBUTING.md)
- [`web/README.md`](../../web/README.md): working on the console UI
