# MOBI browser parser sources

- `foliate-mobi.js` is adapted from
  [Foliate-js](https://github.com/johnfactotum/foliate-js/blob/78914aef4466eb960965702401634c2cb348e9b1/mobi.js)
  at commit `78914aef4466eb960965702401634c2cb348e9b1`, under the MIT license.
  Personal OPDS exposes chapter markup, enforces decoding limits, and runs the
  parser and DOM conversion in a worker without a browsing context.
- `linkedom-worker.js` is the standalone worker build from
  [`linkedom@0.18.12`](https://www.npmjs.com/package/linkedom/v/0.18.12).
  It ships under ISC; bundled package notices are included separately.
  Trailing whitespace is normalized.
- The PHP structural checks follow the public
  [Calibre MOBI format notes](https://github.com/kovidgoyal/calibre/blob/master/format_docs/pdb/mobi.txt).

The web renderer shares the application's reflowable chapter UI. Embedded
raster images and internal navigation are supported. Original stylesheets,
scripts, remote media, embedded fonts, and fixed-layout fidelity are not
served by the reader. No input is decrypted or converted on disk.
