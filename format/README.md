# Book format modules

Add one directory under `format/` whose name is a stable lowercase format ID.
A release module has a `manifest.json` and a `module.php`; optional adjacent PHP
helpers are packaged automatically. Tests and sample books belong under
`tests/fixtures/`, not in the deployed application. Do not load modules from
library storage or allow users to install module code via an upload.

- Manifest: lowercase `extensions` without dots (unique across modules), one
  download `mime`, short `label`, integer `metadata_version`, nullable
  `reader` (`bytes` or `chapters`), and `requires` (PHP extension names).
  Optional `zh` maps module error messages for use via `formatMessage(id,key)`.
- The entry point returns a `BookFormat`. It receives the path selected by the
  host. Dispatch uses the submitted filename, never the temporary path or
  the browser's Content-Type. Confirm the format from content; reject malformed
  or unsupported variants. Use bounded reads and do not fetch remote resources,
  modify the book, emit HTTP output, or perform authorization in a module.
- `metadata()` can return title, author and language, with filename defaults.
  Check the supplied budget at bounded steps. Increment `metadata_version`
  if cached metadata should be rebuilt; this does not affect reading progress.
- Optionally implement `ByteBookReader` or `ChapterBookReader`. The latter gives
  the host a chapter DOM with internal reference resolvers; the host owns
  markup sanitization, asset MIME/size limits, URL generation, and authorization.
  Preserve position semantics when modernizing existing adapters.
- An absent dependency, or listing the ID in the private site configuration
  (`'disabled_formats' => ['id']`), disables uploads and preview, not the
  listing, authorized original download, or management of existing books.
  Leave the manifest in place to keep those files recognized.

The HTTPS Agent verification response advertises `accepted_formats`. A missing
field denotes a legacy server; an empty list is authoritative. An existing
credential works with the format-aware Skill without reissuing the token.
A device that can browse an OPDS feed may not support every advertised format.

Run `php tools/build.php` to regenerate the single-file installer. To verify
the extension boundary, run `OPDS_TEST_EXTRA_FORMAT=1 node tests/integration.mjs`:
it adds a download-only fixture in a temporary build and installs the result.
