# Personal OPDS · Multiuser

A self-hosted PHP OPDS 1.2 library for moving AI-generated EPUB and TXT files to e-readers. No database or framework is required. Each account owns one personal library and can join other users’ libraries. Web browsing, web uploads, private OPDS reads, and Agent uploads have separate permissions. A folder can still be shared as a read-only anonymous OPDS subscription.

## Install

1. Use a supported 64-bit PHP release (PHP 8.1+), with session, ZIP, DOM, SimpleXML/libxml, filter, zlib, and OpenSSL. Enable `allow_url_fopen`, provide at least two PHP workers for installer self-checks, and use a valid HTTPS certificate. Run PHP as a dedicated, non-root account.
2. Build `install.php` with `php tools/build.php` or take the generated installer from this branch. Place it in a new web application directory. Restrict installer access to the operator during setup, while letting the service reach its own temporary HTTPS verification file. Do not expose an unconfigured installer indefinitely.
3. Open the installer over HTTPS and complete its four server-validated steps: **Environment → Library location → First account → Review and install**. In step 2, choose a site-wide display name. The site URL is inferred from the HTTPS host and path used to open `install.php`; open it via the public address readers should use, not a temporary host alias. The private data root must be separate from the website root and must not be exposed through an alias or another virtual host. The wizard shows which PHP account needs access and what to change if a permission check fails. For a dedicated application subdirectory that PHP does not own, it shows non-recursive chown and chmod commands. The installer does not require ACL utilities. If a shared parent is not traversable, choose another path or ask the server administrator for traverse-only access using the host’s permission policy. Do not transfer ownership of a shared directory or the website root. Use an existing parent for the private data directory. If that parent is traversable but not writable by PHP, follow the wizard’s non-recursive commands to create and assign **only** the new private directory. Do not make the parent writable. If the private directory already exists, PHP needs read, write and traverse on it, but only traverse on its ancestors. Data is organized as `conf/` and `books/` under that root. Each account has exactly one personal library in `books/<username>/`. Existing account paths (including case variants, files and symlinks) are never claimed by a new account. For a legacy flat library, choose a fresh data root and migrate separately. The HTTPS self-check creates and removes only a small temporary probe before installation.
4. Copy or open the first activation link. The account owner sets their own nonempty password. The link expires in 24 hours, works once, and is not recoverable from installer output after setup is locked. If the first link was lost or expired before activation, run `php admin.php invite USERNAME` from the installed application directory as the same operating-system account that runs PHP. That reissues for the pending account and immediately invalidates the previous link. Remove the installer when done.
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

The first account on a fresh installation is a site administrator. In the avatar menu choose **Site accounts → Create account and get link**. Send the one-time link privately; it expires in 24 hours. The recipient sets a password and gets their own personal library, shown as “USERNAME’s library” by default. Existing custom names are preserved. Use **Replace pending activation link** if an unused link has expired or been lost; replacing it invalidates the prior link. To grant access to another library after activation, use that library’s **Library members** panel. Being a library administrator or owner alone does not grant the site-wide right to create accounts.

For an existing installation, grant the site administrator permission from the server using `php admin.php grant-site-admin USERNAME`. Revoke it with `php admin.php revoke-site-admin USERNAME`. Neither command grants reading access to other users’ libraries.


Run the CLI as the same account as PHP, from the installed web application directory:

```sh
php admin.php invite alice
php admin.php reset alice
php admin.php quota alice 5368709120 5000
php admin.php disable alice
```

Web sign-ins last 30 days from login, even if the browser is closed, unless the user signs out, resets their password, or is disabled. OPDS reader credentials and anonymous subscription links are unchanged. Upgrading from the older short-lived sessions requires signing in once; new sessions use a private `conf/web-sessions` directory created by PHP.

Send the activation/reset URL privately. Passwords cannot be empty but have no length or composition rules; use a long, unique password for an internet-facing library. Reissuing a link invalidates the previous one; the reset itself invalidates old browser sessions when the password is changed. In **Site accounts**, choose **Disable account** to stop their sign-ins and uploads, block access to their personal library, and revoke its subscription links. Files and member roles are retained. **Restore account** issues a one-time link so they can set a new password; old upload tokens and subscriptions stay revoked. Only the server operator can change another site administrator. CLI equivalents are `php admin.php disable USERNAME` and `php admin.php restore USERNAME`. To revoke access only to one library, choose **Library members → … → Remove from library**; the account and its own library are unaffected. Usernames are immutable lowercase ASCII letters/digits with optional underscore/hyphen, up to 32 characters. Users cannot register themselves. The default per-library quota is 5 GiB and 5,000 books; enforce external disk and temporary upload quotas as well.

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
    libraries.json
    cache/
```

Back up the private data directory and protect the backup. The JSON config files are versioned and written atomically through the app/CLI; avoid editing them concurrently. Passwords are hashed, and raw activation and API credentials are not stored. The sharing key in `config.php` must be backed up and treated as sensitive.

## Libraries, invitations and roles

A single web-accessible library opens directly after sign-in. With two or more, choose a library first, then use the switcher at the top left. The page shows folders and books from the selected library only. Reader-only OPDS libraries are listed in the account menu’s **Connect e-reader** panel, not in the web picker. Use the copied library-specific OPDS URL with your account credentials. Existing clients with the old URL without a library parameter still reach their original personal library, subject to current access.

1. Open the target library. As its owner or admin, open the top-right account menu and choose **Library members**.
2. Enter the recipient’s existing active username, choose one role, and send the invitation. If they do not yet have an account, a site administrator can issue an activation link under **Site accounts**. The recipient chooses their own password.
3. The recipient signs in with that account and opens **Review library invitations**. They can see the roles and accept or decline. Invitations are single-use, valid for seven days, and visible only in the application. The app does not send email. The sender can cancel a pending invitation from the members panel.
4. After acceptance, edit or revoke roles in the same panel. The change affects only that library; it does not revoke anonymous subscription URLs. Only the owner can appoint or modify library admins.

| Scenario | Role | Access granted |
| --- | --- | --- |
| Read | Reader | Browse and download on the web or through OPDS |
| Read | OPDS-only reader | Read and download through OPDS, without a web catalog |
| Contribute | Web contributor | Upload on the web to existing folders, without browsing books |
| Contribute | Agent contributor | Set up a scoped Agent upload token, without web uploads or reading |
| Manage | Library editor | Read, upload on the web, create folders, rename and move; no delete or public sharing |
| Manage | Library admin | Manage books, uploads, anonymous shares, ordinary members and upload tokens; no owner controls |

A member has one role per library and may hold different roles in different libraries. In **Library members**, copy the invitation link after sending or from **Invitation history** while it is pending. Only the intended account can sign in and accept; opening or forwarding the link alone grants nothing. Invitations expire after seven days. Use the refresh icon in **Invitation history** to check the latest status without leaving the panel, and the **Members** tab to change a role or revoke access. Rename and archive are under the separate **Library settings** menu, visible to the owner. Administrators can revoke member Agent connections under **Connect Agent → Manage Agent connections**. The site operator does not gain in-app access to books by managing accounts or quotas. The library owner can rename, archive or restore the personal library. Ownership is fixed to the account. The account menu shows the current library and your role there. Archiving stops anonymous subscriptions and Agent tokens, which stay invalid after restore. Files and member roles are retained. Site operators can set per-library quotas with `php admin.php library-quota LIBRARY_ID BYTES MAX_FILES`, inspect recent administration events with `php admin.php rbac-audit`.

### Advanced settings: optional short links

Sign in as the **site administrator**, open the top-right account menu, and choose **Advanced settings → Network and links → Link format**. Choose original links (the default), short reader links, or short reader and anonymous share links. For example, on a site installed at `/opds/`, the personal library `p-alice` becomes `/opds/alice`, and the anonymous share entry can become `/opds/s/12345678-AB12`.

Copy the generated rules into the site's HTTPS Nginx `server { ... }` block, outside any `location` and before a catch-all server-level rewrite. If you already use the same reader rule, keep just one copy. Keep the existing PHP handler and its standard FastCGI `REQUEST_URI $request_uri` setting. Run `nginx -t` and reload Nginx, then click **Test rewrite** and **Save link format**. The browser tests the selected routes on this site without using a real account password or share link. The app never edits Nginx.

This changes the addresses shown in **Connect e-reader** and **Copy URL**. Authentication, permissions, share codes, expiry and revocation are unchanged. Existing original links and all feed, search and download links continue to use the PHP endpoint. To stop issuing short links, select original links again. Keep the Nginx rules until previously distributed short links are no longer needed. If you move the app to a different site address or mount path, it issues original links until you verify the new rewrite.

### Private books and folders

In a library you own, choose **⋯ → Make private** on any book or folder. The lock is visible only to you. A private folder protects its contents; an individually private book stays private if you later unlock its folder. Renaming or moving a private book in the app does not expose it. If you move a book out of a private folder, it stays private. To restore the library’s normal access rules, choose **Restore normal visibility** and confirm. Privileged library members and site administrators are not treated as the owner. The owner can still browse, read, download and manage private books in the web app and read them through their authenticated OPDS feed.

Private content is omitted from other members' feeds, listings, counts, downloads, and searches. Agent tokens, including the owner's, do not see private folders and cannot upload to them or replace a private book. Making a folder private permanently revokes its existing anonymous subscriptions; the old link returns HTTP 403 with a permission message. Direct requests for private content are also denied with HTTP 403. A guessed name can therefore distinguish an access denial from an unused name, without exposing the contents. Making an individual book private leaves its folder subscription active and removes only the book. Previous downloads cannot be recalled.

Visibility is application access control, not disk encryption. Back up the entire private data directory, including `conf/privacy-*.json` and `conf/shares.json`, together with the books. Use the app to rename or move private books; if you reorganize files directly on disk, keep their path-based privacy rules in sync. Do not revert to a build that does not enforce these rules while serving a library with private content.

## Books and subscriptions

Use the folder sidebar to select the library root, an existing folder, or create a folder. Folders are only one level deep and can have spaces and Unicode names. Upload EPUB or TXT, and download, move, or delete individual files. Web uploads show each file's progress separately from its save confirmation. Confirmed temporary failures can be retried; if saving is unconfirmed, check the destination before uploading again. Moves and deletions affect what subscribers can next see. Already downloaded copies cannot be recalled.

Use the folder's **Subscription share** panel to preview, create, copy, replace, or revoke its subscription. The folder sidebar shows its share status. There is only one active link per folder. Links take the form `index.php?s=72835164-K7M2`: eight random nonzero digits, a separator, and a case-insensitive mixed letter/digit code. Paste the full URL into the reader with no username or password. Anyone holding it can read or forward it. The shared catalog and all its download links are scoped to that one folder; new books appear on refresh. The link expires 120 days after issuance and is not extended by use. Replacement or revocation stops future requests with the old link; a download that started earlier may finish. Treat this short, rate-limited link as a convenience for personal sharing, not as a strong substitute for authenticated private access.

In the web dashboard, the library root shows folders first, then books, in one continuous list. Use the folder sidebar (the **Choose folder** button on a phone) to move between directories. Click a book title to read it online or **Download** to save it, and **…** to rename, move, or delete. Renaming changes the filename, not the file format or embedded EPUB metadata. It preserves the directory subscription URL but changes the book’s download URL. **Upload books** shows the current destination. On desktop, dropping EPUB or TXT files onto the current folder list or into the upload dialog starts an upload there immediately. To upload elsewhere, first open that folder; create new folders from the folder list. For a shared folder, click its status next to the book count to copy or revoke the subscription link.

## AI uploads

In the target library, open **Connect Agent**, click **Copy complete Agent setup**, and paste it into your agent. The text includes the Skill, API endpoint, upload-only token, and current folder names. The agent chooses a suitable folder and the server creates it if missing. No settings are required.

New connections are tied to a single library, last 90 days, and can be revoked separately. They can list folder names for upload routing, but cannot read books, change settings, or access another library. Existing tokens retain their original scope and expiry. If a token expires or is rejected, copy the complete setup again from the same library and paste it into your agent to replace that connection.

The Skill uses `GET ?action=verify` to verify the token and refresh the folder names, and multipart POST to upload. If it omits `directory`, the file goes to the library root. Invalid paths are rejected. The Skill may send a confirmed book detail URL via `douban_url[0]`, `douban_url[1]`, etc., matching the zero-based order of `files[]`. Omit unknown links. Only HTTPS `book.douban.com/subject/<id>/` links are accepted; an invalid URL rejects that file without rejecting other valid files. The web shelf shows a small link beside the file size, with no remote lookup or preview. The metadata follows in-app renames and moves; replacing books outside the app can detach its metadata.

Limits: 20 files per request, 100 MiB per file, 200 MiB combined, and the target library quota. **An existing filename in the same folder is an error even when bytes are identical.** The original is never overwritten. Single-file conflicts return HTTP 409. For a batch with partial failures, inspect every item in `results` (an individual conflict has status 409); successful files remain in place. On an interrupted connection, check whether a file landed before retrying; a retry can now return a conflict.

## Upgrade an existing multiuser installation

1. Schedule a short maintenance window and pause uploads and other writes. Back up the entire private `opds-data/` tree and current application files, including local `paths.php`. Keep the original HTTPS URL and directory. Do not run `install.php` again.
2. If the deployed app is a Git checkout, fetch `multiuser` and fast-forward it; preserve untracked `paths.php` and local settings. If the app was copied from the standalone installer, update the PHP application files from the branch (including `libraries.php`, `library-controls.php`, `privacy.php` and `agent-skill.php`); preserve `paths.php` and the existing private data. Never replace the live config with example data.
3. In the updated app directory, run `php admin.php rbac-check` as the PHP service account. This read-only preflight reports the library/owner mapping, book counts and bytes, quotas, and active shares, without printing credentials. Exit code 2 means unresolved storage or link identity issues. Investigate them before allowing writes; unknown folders are not automatically adopted.
4. Test the old OPDS and upload URLs and at least one previously issued anonymous subscription, including a download without credentials. Only then reopen writes. Existing libraries retain their physical folders, share key, expiry, revocation and hidden folder identities. There is no book copy or account reset; the private RBAC JSON is initialized on first management write on an old site. No new PHP extension or database service is needed.

After collaborative writes begin, do not blindly roll back to the earlier code or restore only old share records. The old program does not enforce the new access model. Preserve new files and revocations and reconcile them before any rollback.

## Migrate from the single-user release

Keep the old deployment intact until the new application is verified. Install in a distinct application directory and data root, activate the destination account, and pause writes to the old library before copying.

```sh
php admin.php migrate alice /absolute/path/to/old/books
php admin.php migrate alice /absolute/path/to/old/books --apply
```

The first command previews safe root and first-level EPUB/TXT files and conflicts. The second copies into one account without deleting or overwriting source files. It rejects destination name conflicts before copying. If a storage or validation error occurs midway, already copied files remain and original files are not removed. Review the report before retrying. Unsupported types, symlinks and nested folders are not migrated. Reset clients to the new username/password; the old upload token is not reused. Never copy the old credential file into the new data directory.

## Diagnose account storage

Run the read-only check as the same OS user that runs PHP-FPM, not as root:

```sh
sudo -u www-data php admin.php doctor USERNAME
```

Use your actual PHP service user in place of `www-data`. This checks the private config directory, the account file and format, the relevant write locks and optionally the named account’s personal book directory. It does not generate links, change file permissions or print secrets. An exit code of 2 indicates a problem. Do not remove live lock files or apply recursive permissions: if an affected regular, single-link file is wrongly owned, correct only that file. When PHP provides the POSIX extension, CLI write commands reject a user that does not match the private configuration directory owner.

## Move the application to another URL path

You can move the application to another directory on the same HTTPS host without rerunning the installer or changing the private data path. Web login, OPDS links and new Agent and activation links use the current public PHP entry-point path; the HTTPS origin still comes from the private configuration, not from request headers. After moving, open the new web URL and sign in again. Update the URLs in existing readers and upload clients; old URLs will only work if the web server still serves or redirects the old path. Do not rely on redirects for authenticated uploads.

For CLI commands that generate links, there is no web request to supply the new path. Set it for the command, for example:

```sh
OPDS_BASE_URL=https://example.com/opds/ php admin.php invite USERNAME
```

The web server should pass the public PHP path in `SCRIPT_NAME` (for example, `/opds/up.php`). Do not configure it using client request headers.

## Development

```sh
php tools/build.php
PHP_BINARY=php node tests/integration.mjs
```

The Node 20+ integration test uses OpenSSL CLI, a temporary private data directory, and a trusted local HTTPS proxy. Environment variables `PLAYWRIGHT_MODULE` and `CHROME_BIN` additionally enable desktop/mobile browser tests. Set `OPDS_TEST_WEBKIT=1` with Playwright WebKit installed to also test the chapter drawer with an iPhone-sized touch profile. Set `NGINX_BIN` to run the emitted rewrite rules in a temporary Nginx instance. Optionally set `SCREENSHOT_DIR`, `RBAC_SCREENSHOT_DIR`, or `ADVANCED_SCREENSHOT_DIR` to a writable directory for UI screenshots. Set `OPDS_LEGACY_SOURCE` to an unpacked copy of the previous release to test creating a share on the actual old code, then upgrading and using the exact same URL. Test with a physical e-reader before rolling the new URL out to other people. Never deploy the test router.

Apache License 2.0.

### Read EPUB and TXT in the browser

Click the book title in the web library to open `preview.php`. The reader opens the current EPUB chapter or a bounded TXT segment rather than downloading the full book. In EPUB, the floating **Contents** button opens a chapter drawer on the left, centered on your current chapter or subsection. Click the backdrop to close it and keep scrolling. The header hides when you scroll down; tap the reading area or scroll back to the top to show it again. EPUB contents are available on demand; book scripts, CSS and remote resources are not loaded. TXT scrolls continuously: nearby text loads in the background, and the floating **Go to position** button lets you jump by percentage or return to the beginning. TXT supports UTF‑8 and GB18030/GBK (choose the encoding in Reading settings if automatic detection is incorrect).

Font size, line spacing, theme, reading mode and per-book position are kept in the current browser, separated by account. They do not sync across devices. The web view permission is required to read; downloading uses the existing separate permission. Anonymous OPDS links are unchanged.
