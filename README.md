# Personal OPDS · Multiuser

A self-hosted PHP OPDS 1.2 library for moving AI-generated EPUB and TXT files to e-readers. No database or framework is required. Each account has a private library, its own browser session and API token, and the option to share one folder as a read-only OPDS subscription.

## Install

1. Use a supported 64-bit PHP release (PHP 8.1+), with session, ZIP, DOM, SimpleXML/libxml, filter, zlib, and OpenSSL. Enable `allow_url_fopen`, provide at least two PHP workers for installer self-checks, and use a valid HTTPS certificate. Run PHP as a dedicated, non-root account.
2. Build `install.php` with `php tools/build.php` or take the generated installer from this branch. Place it in a new web application directory. Restrict installer access to the operator during setup, while letting the service reach its own temporary HTTPS verification file. Do not expose an unconfigured installer indefinitely.
3. Open the installer over HTTPS and complete its four server-validated steps: **Environment → Library location → First account → Review and install**. In step 2, choose a site-wide display name. The site URL is inferred from the HTTPS host and path used to open `install.php`; open it via the public address readers should use, not a temporary host alias. The private data root must be separate from the website root and must not be exposed through an alias or another virtual host. The wizard shows which PHP account needs access and what to change if a permission check fails. For a dedicated application subdirectory that PHP does not own, it shows non-recursive chown and chmod commands. The installer does not require ACL utilities. If a shared parent is not traversable, choose another path or ask the server administrator for traverse-only access using the host’s permission policy. Do not transfer ownership of a shared directory or the website root. Use an existing parent for the private data directory. If that parent is traversable but not writable by PHP, follow the wizard’s non-recursive commands to create and assign **only** the new private directory. Do not make the parent writable. If the private directory already exists, PHP needs read, write and traverse on it, but only traverse on its ancestors. Data is organized as `conf/` and `books/<username>/` under that root. Existing account paths (including case variants, files and symlinks) are never claimed by a new account. For a legacy flat library, choose a fresh data root and migrate separately. The HTTPS self-check creates and removes only a small temporary probe before installation.
4. Copy or open the first activation link. The account owner sets their own password (12–72 bytes). The link expires in 24 hours, works once, and is not recoverable from installer output after setup is locked. If the first link was lost or expired before activation, run `php admin.php invite USERNAME` from the installed application directory as the same operating-system account that runs PHP. That reissues for the pending account and immediately invalidates the previous link. Remove the installer when done.
5. Open `up.php` for the web library. Add `index.php` to the OPDS reader with the same username and password. Anonymous reads are disabled except via an explicit share link.

For Nginx/PHP-FPM, pass the trusted HTTPS state and the Authorization header. Configure the web server to route only approved Host names to the installer. Do not trust a client-supplied forwarding header. Typical upload configuration:

```ini
file_uploads=On
upload_max_filesize=100M
post_max_size=205M
max_file_uploads=21
max_input_time=1800
max_execution_time=120
memory_limit=128M
display_errors=Off
log_errors=On
session.upload_progress.enabled=0
```

Set equivalent HTTP body limits and timeouts at the proxy. Omit query strings from application access log formats (for example use `$uri`, not `$request_uri`, in Nginx) and redact them in CDN/monitoring logs: activation and share links contain credentials. Never log the Authorization header. Do not cache private feeds, management pages or subscriptions at the reverse proxy.

## Manage accounts

Run the CLI as the same account as PHP, from the installed web application directory:

```sh
php admin.php invite alice
php admin.php reset alice
php admin.php quota alice 5368709120 5000
php admin.php disable alice
```

Send the activation/reset URL privately. Reissuing a link invalidates the previous one; the reset itself invalidates old browser sessions when the password is changed. Disabling an account revokes its access and leaves its files on disk. Usernames are immutable lowercase ASCII letters/digits with optional underscore/hyphen, up to 32 characters. Users cannot register themselves. The default per-account quota is 5 GiB and 5,000 books; enforce external disk and temporary upload quotas as well.

Private storage layout:

```text
opds-data/
  books/
    alice/
      Personal.epub
      Reading notes/
    bob/
  conf/
    config.php
    users.json
    shares.json
    cache/
```

Back up the private data directory and protect the backup. The JSON config files are versioned and written atomically through the app/CLI; avoid editing them concurrently. Passwords are hashed, and raw activation and API credentials are not stored. The sharing key in `config.php` must be backed up and treated as sensitive.

## Books and subscriptions

Use the folder sidebar to select the library root, an existing folder, or create a folder. Folders are only one level deep and can have spaces and Unicode names. Upload EPUB or TXT, and download, move, or delete individual files. Web uploads report each file's progress and allow retrying failed files. Moves and deletions affect what subscribers can next see. Already downloaded copies cannot be recalled.

Use the folder's **Subscription share** panel to preview, create, copy, replace, or revoke its subscription. The folder sidebar shows its share status. There is only one active link per folder. Links take the form `index.php?s=72835164-K7M2`: eight random nonzero digits, a separator, and a case-insensitive mixed letter/digit code. Paste the full URL into the reader with no username or password. Anyone holding it can read or forward it. The shared catalog and all its download links are scoped to that one folder; new books appear on refresh. The link expires 120 days after issuance and is not extended by use. Replacement or revocation stops future requests with the old link; a download that started earlier may finish. Treat this short, rate-limited link as a convenience for personal sharing, not as a strong substitute for authenticated private access.

## AI uploads

In **CLI / API & upload Skill**, generate a private per-account token and save it securely. A new token immediately replaces the old one for future requests. Download the generated `SKILL.md` and set the token in the agent's protected environment as `OPDS_TOKEN`. The token is never embedded in the skill. The API token does not authenticate reads or the web UI.

```sh
curl --fail-with-body --show-error -H "Authorization: Bearer $OPDS_TOKEN" \
  --form-string 'directory=Reading notes' \
  -F 'files[]=@./article.epub' -- 'https://your-host/opds/api.php'
```

Omit `directory` for the account's root. A valid missing directory is created. Invalid paths or creation failures never fall back to the root. Limits: 20 files per request, 100 MiB per file, 200 MiB combined, plus account quotas. Same directory/name/content is a successful retry (`already_exists: true`); a different file with the same name is not overwritten. Read each item in `results` even when HTTP reports partial failure, then retry only failed or unknown items. A full quota returns 507 for a single rejected file.

## Migrate from the single-user release

Keep the old deployment intact until the new application is verified. Install in a distinct application directory and data root, activate the destination account, and pause writes to the old library before copying.

```sh
php admin.php migrate alice /absolute/path/to/old/books
php admin.php migrate alice /absolute/path/to/old/books --apply
```

The first command previews safe root and first-level EPUB/TXT files and conflicts. The second copies into one account without deleting or overwriting source files. It rejects destination name conflicts before copying. If a storage or validation error occurs midway, already copied files remain and original files are not removed. Review the report before retrying. Unsupported types, symlinks and nested folders are not migrated. Reset clients to the new username/password; the old upload token is not reused. Never copy the old credential file into the new data directory.

## Development

```sh
php tools/build.php
PHP_BINARY=php node tests/integration.mjs
```

The Node 20+ integration test uses OpenSSL CLI, a temporary private data directory, and a trusted local HTTPS proxy. Environment variables `PLAYWRIGHT_MODULE` and `CHROME_BIN` additionally enable desktop/mobile browser tests. Optionally set `SCREENSHOT_DIR` to a writable directory for UI screenshots. Test with a physical e-reader before rolling the new URL out to other people. Never deploy the test router.

Apache License 2.0.
