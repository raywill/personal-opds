# personal-opds

A small, self-hosted OPDS 1.2 library with a browser uploader, an agent-friendly HTTPS upload API, and a single-file installer. Built with PHP, without a database or a framework.

## Why I built this

After buying an **XTEINK**, I realized that OPDS could connect the entire **AI + reading** workflow: ask an agent to generate reading material, turn it into an EPUB, upload it to my own library, and make it available on my XTEINK whenever I want to read.

```text
AI / agent → EPUB or TXT → HTTPS upload → personal OPDS library → XTEINK
```

Your OPDS reader fetches the catalog and downloads books. Agents only need HTTPS access to the upload endpoint; they do not need SSH access to your server.

## Features

- OPDS navigation, category feeds, all-books view, OpenSearch discovery, title/author search, and paginated acquisition feeds.
- EPUB and TXT downloads through the catalog endpoint, with persistent metadata caching.
- Multiple top-level categories, including Unicode names. Traversal is depth-aware, with a server-side guard currently enforcing exactly one category level.
- Browser uploads with per-file and overall progress, validation results, and a stop-after-current-file button.
- A **CLI / API** button in the upper-right corner. The default page stays focused on browser uploads; the dialog contains token copy/reset and complete agent-ready curl commands with the actual token and installation URL.
- English and Simplified Chinese interfaces, selected automatically from the browser's `Accept-Language` preferences. English is the fallback. Book titles, authors, filenames, and category names are preserved.
- A standalone `install.php` that contains the application payload and generates the remaining files locally. No runtime source-code downloads.

## Requirements

- A Linux/Unix-like host with 64-bit PHP 8.1+; use a **currently supported, patched PHP version** in production.
- PHP extensions: session, ZIP, DOM, SimpleXML/libxml, filter, zlib, and OpenSSL.
- HTTPS with a valid certificate. Behind a trusted TLS terminator, configure the server-side `HTTPS` value correctly; client forwarding headers are not used to bypass transport checks.
- `allow_url_fopen=1` and working HTTPS access from the server to its own public installation URL for setup verification.
- At least two available PHP workers during installation: the installer makes HTTP self-check requests.
- A filesystem that supports POSIX permissions and hard links. Do not run PHP as root.

Set these values in the site's PHP configuration and reload PHP-FPM:

```ini
file_uploads = On
upload_max_filesize = 100M
post_max_size = 205M
max_file_uploads = 21
max_input_time = 1800
max_execution_time = 120
memory_limit = 128M
display_errors = Off
log_errors = On
session.upload_progress.enabled = 0
```

The application accepts **20** files. The parser needs **at least 21 slots** so the server can detect and reject excess files instead of silently saving a truncated batch.

## Install

1. Download [`install.php`](https://github.com/raywill/personal-opds/releases/latest/download/install.php). If no release is available, use the repository's [`install.php`](https://github.com/raywill/personal-opds/blob/main/install.php).
2. **Before uploading it**, edit the `INSTALL_KEY` constant near the top. Set a private, randomly generated installation code of at least 24 characters. Keep this customized file out of public repositories. For example, generate a code locally with `php -r 'echo bin2hex(random_bytes(24)), PHP_EOL;'`.
3. Upload only `install.php` to an empty website directory, such as `/opds/`. PHP needs write permission to that directory during setup.
4. Protect the `conf` URL path as described below. Open `https://your-host/opds/install.php`.
5. Enter the installation code, library name, upload password, and initial categories, one per line. The suggested base URL is the directory containing the installer; review it before submitting.
6. Complete installation and **delete `install.php`**. Setup also creates an installation lock to prevent reinitialization.

The default generated layout is:

```text
opds/
├── index.php
├── up.php
├── bootstrap.php
├── security.php
├── i18n.php
├── books-data/
│   ├── books/
│   └── another-category/
└── conf/
    ├── config.php
    ├── pass.conf
    ├── cache/
    └── installed.lock
```

The installer creates `books-data` and `conf` next to itself. It generates a salted password hash and a random 256-bit API token. It verifies payload checksums, refuses different existing application files/configuration, serializes concurrent setup attempts, and removes files created by a failed attempt. Existing books are not deleted.

The library root is made non-writable by PHP after setup; its category directories remain writable for uploads. Configuration and cache remain private and writable. For later maintenance, add categories with your file manager and grant PHP write access to those categories while keeping the library root protected. Changing filesystem permissions or updating application files is an administrator operation; rerunning the installer is not an upgrade mechanism.

### Protect configuration

For an installation at `/opds/`, add these rules to the **Nginx server configuration** and reload Nginx:

```nginx
location = /opds/conf { return 404; }
location ^~ /opds/conf/ { deny all; }
```

For Apache, the installer writes `conf/.htaccess` with `Require all denied`; the host must allow that directive to take effect. A file existing on disk is not proof of protection. Setup places harmless temporary probes, checks the exact `conf/pass.conf` path and an additional file under `conf`, and only writes credentials after those paths return 403/404. It first verifies a separate random probe in the installation directory to make sure `BASE_URL` points to the correct site. Requests do not follow redirects or disable certificate verification.

**Direct HTTP access to books is allowed by default.** Generated UI/catalog links use `index.php` and do not advertise the physical storage-directory name. This is presentation, not access control: anyone who guesses a direct file URL may access it. Configure book-directory access restrictions separately if you want them. Credentials, unlike books, must not be directly accessible.

Check the actual PHP upload location as well:

```nginx
client_max_body_size 205m;
client_body_timeout 120s;
fastcgi_read_timeout 150s;
fastcgi_param HTTP_AUTHORIZATION $http_authorization;
fastcgi_param HTTPS $https if_not_empty;
```

Merge these into the existing site configuration; this is not a complete virtual-host example. With upstream TLS termination, set HTTPS only through your trusted server configuration. Check CDN/proxy body-size and timeout limits too.

## Read and upload

Add `https://your-host/opds/index.php` to your OPDS reader. The catalog and book downloads are public by default. Open `https://your-host/opds/up.php` and sign in to upload or manage the token.

Upload limits are enforced on the server:

| Limit | Value |
| --- | --- |
| Formats | EPUB, TXT |
| Per file | 1 byte–100 MiB |
| Per request | 20 files, 200 MiB total |
| Request body including multipart overhead | 201 MiB |
| Concurrent processing | 2 requests |
| Existing names | Never overwritten |

The browser sends files sequentially. A 100% progress bar means the browser sent the request body; it still waits for the server's validation/save result. Stopping the queue lets the active file finish before skipping subsequent files.

## Agent / curl upload API

For a ready-to-run command, sign in and open **CLI / API**. Copy the complete command: it already contains your current token, selected category, and actual HTTPS endpoint.

The API uses `POST up.php`, a Bearer token, and multipart form data:

```bash
export OPDS_TOKEN='YOUR_API_TOKEN'

curl --fail-with-body --show-error --progress-bar \
  -H "Authorization: Bearer $OPDS_TOKEN" \
  --form-string 'directory=books' \
  -F 'files[]=@./article.epub' \
  -- 'https://your-host/opds/up.php'
```

The placeholders above are documentation only. The dialog substitutes real values. Requires curl 7.76+ and a POSIX shell such as Bash or zsh. Repeat `-F 'files[]=@./another.epub'` for multiple files. `--form-string` keeps category names literal, including names beginning with `@`. Standard local-file uploads provide the required Content-Length; unbounded streaming uploads without it are not supported.

Tokens are accepted only in `Authorization`; they cannot be supplied by URL, form field, or Cookie. Requests carrying Authorization never fall back to a browser login. The API grants upload access only, not token rotation or configuration access. Browser uploads and token resets use session authentication and CSRF checks.

Example response:

```json
{
  "success": true,
  "message": "Saved: article.epub",
  "results": [
    {"name": "article.epub", "success": true, "message": "Saved: article.epub", "status": 200}
  ]
}
```

Messages follow `Accept-Language`; `success`, `results`, and numeric status values are stable. Agents should inspect those fields instead of matching prose.

| HTTP status | Meaning |
| --- | --- |
| 200 | Every file was saved |
| 400 / 401 | Invalid parameters / missing or invalid authentication |
| 403 / 405 | Operation not allowed / wrong method |
| 409 | All failures were duplicate-name conflicts |
| 413 / 415 | Too large / unsupported request type |
| 422 | Content validation or mixed/partial failure |
| 429 | Rate or concurrency limit; see Retry-After |
| 5xx | Internal processing/storage failure |

Partial success is preserved, but **any failure returns non-2xx**, so `curl --fail-with-body` exits nonzero while retaining the JSON. If a connection drops, check the library before retrying: the server may already have saved a file.

Resetting the token invalidates it for subsequent requests, updates `conf/pass.conf` atomically under a fixed lock, and leaves the password/browser login unchanged. Requests authorized before reset may finish. A stale dialog cannot overwrite a newer token. Password changes invalidate existing browser sessions. Sessions expire after 30 idle minutes or 12 hours total.

## Configuration

`conf/config.php` stores `base_url`, `title`, and `max_category_depth`. The last value is currently required to be **1**, even though the traversal implementation is depth-aware. Nested categories are excluded from feeds and rejected by upload/download endpoints.

`conf/pass.conf` uses this format:

```ini
password=PASSWORD_HASH
api_token=64_LOWERCASE_HEX_CHARACTERS
```

The installer writes a password hash; legacy plaintext password values remain supported. Tokens remain recoverable because the authenticated UI must display/copy them. Files are private (`0600`) and the directory is `0700`. Keep them out of public backups, logs, and Git. When manually maintaining credentials, acquire the fixed `.config.lock` and replace the file atomically; do not edit concurrently with UI resets or remove active lock files.

## Security boundaries

- File types, sizes, multipart array shapes, destination paths, actual uploaded-file provenance, and duplicate names are checked by the server. Symbolic links and path traversal are rejected.
- EPUB metadata has bounded reads, entry/expansion/compression limits, DTD/entity rejection, and rootfile checks. TXT is scanned throughout for NUL bytes. The catalog shares validation code with the uploader.
- Metadata indexing processes at most 20 changed books per request and caches failed metadata until the file changes. Large initial libraries may need multiple feed refreshes before all entries appear. The current cap is 5,000 books and 1,000 categories, with 100 entries per acquisition page.
- Shared file-based counters limit login attempts, invalid tokens, authenticated uploads, and token resets. Default windows are 15 minutes: per-IP/global limits are 10/100, 30/300, 120/600, and 10/30 respectively. Proxies must restore the real source address through trusted server configuration. Global throttling can temporarily affect availability.
- CSP nonces, escaped HTML/text nodes, secure cookies, constant-time credential comparisons, and CSRF checks protect the management UI. Configuration protection must stay enabled after installation, including across aliases and other download interfaces.
- PHP receives multipart data before application authentication. Entry-level access controls, request limits, temporary-storage quotas, cumulative library quotas, and rate/concurrency limits remain important. A free-space check does not replace disk quotas.
- EPUB validation is not a complete EPUBCheck, antivirus, or HTML sanitizer. Read files with a maintained reader; do not render embedded book HTML in the management site's origin. Disable script execution/configuration overrides for book storage at the web-server level. Direct book access has the explicit limitations described above.
- The installer assumes trusted filesystem ancestors and no hostile application sharing the PHP account. Keep ownership separated. Remove abandoned staging files carefully without disrupting active uploads.

## Development

The repository contains readable sources plus the generated standalone installer. Rebuild it after changing application files or translations:

```sh
php tools/build.php
```

The build is deterministic and embeds source hashes. `INSTALL_KEY` stays empty in the published artifact; each deployer sets their own private value locally.

Run the installation-to-reading integration tests with Node 20+, native PHP, and the OpenSSL CLI:

```sh
php tools/build.php
PHP_BINARY=php node tests/integration.mjs
```

Tests run an isolated HTTPS endpoint and multiple native PHP workers, using temporary fake credentials. They cover installation failures/locking, credential protection, generated payload identity, categories, metadata/search, downloads, symlinks, depth restrictions, localization, and Bearer uploads. An optional Playwright pass is enabled with `PLAYWRIGHT_MODULE` (an importable module specifier or file URL), `CHROME_BIN`, and optionally `SCREENSHOT_DIR`. Never deploy the test router as part of the application.

## License

[Apache License 2.0](LICENSE).
