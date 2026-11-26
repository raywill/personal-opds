<?php
declare(strict_types=1);
final class RequestError extends RuntimeException {}
function reject(string $message, int $status = 400): never { throw new RequestError($message, $status); }
function privateDirectory(): string
{
    clearstatcache(true);
    $root = realpath(CONFIG_DIR);
    $mode = fileperms(CONFIG_DIR);
    if (is_link(CONFIG_DIR) || $root === false || !is_dir($root)
        || $mode === false || ($mode & 0077) !== 0) {
        throw new RuntimeException('CONFIG_DIR must be a private directory with mode 0700.');
    }
    return $root;
}

const WEB_SESSION_NAME = 'OPDS_LIBRARY';

function webSessionCookie(): array
{
    return ['path'=>COOKIE_PATH,'secure'=>true,'httponly'=>true,'samesite'=>'Strict'];
}
function startWebSession(): void
{
    // Isolate these sessions from the host's short-lived PHP default directory
    // and from the installation wizard. PHP's own GC handles this private path.
    $path=privateDirectory().'/web-sessions';
    if (!is_dir($path)&&!is_link($path)) @mkdir($path,0700);
    clearstatcache(true,$path);
    $mode=@fileperms($path);
    if (is_link($path)||realpath($path)!==$path||!is_dir($path)||$mode===false||
        ($mode&0777)!==0700||!is_readable($path)||!is_writable($path)||!is_executable($path))
        throw new RuntimeException('The private web session directory must be accessible to PHP with mode 0700.');
    session_name(WEB_SESSION_NAME);
    session_set_cookie_params(webSessionCookie()+['lifetime'=>0,'domain'=>'']);
    if (!session_start([
        'save_handler'=>'files','save_path'=>$path,'serialize_handler'=>'php',
        'use_strict_mode'=>1,'use_cookies'=>1,'use_only_cookies'=>1,'use_trans_sid'=>0,
        'gc_maxlifetime'=>WEB_SESSION_TTL,'gc_probability'=>1,'gc_divisor'=>1000,
    ])) throw new RuntimeException('Cannot open the private web session.');
}
function webSessionAccount(): ?array
{
    $viewer=$_SESSION['account']??null;
    $hash=$_SESSION['password']??null;
    $issued=$_SESSION['issued']??null;
    $now=time();
    if (is_string($viewer)&&is_string($hash)&&is_int($issued)&&$issued<=$now&&
        $issued>$now-WEB_SESSION_TTL&&($account=activeAccount($viewer))&&hash_equals($account['password'],$hash)) {
        setAccountScope($viewer);
        return $account;
    }
    unset($_SESSION['account'],$_SESSION['password'],$_SESSION['issued']);
    return null;
}
function signInWebSession(string $user,string $hash): void
{
    if (!session_regenerate_id(true)) throw new RuntimeException('Cannot rotate the web session ID.');
    $now=time();
    $_SESSION=['csrf'=>bin2hex(random_bytes(32)),'account'=>$user,'password'=>$hash,'issued'=>$now];
    if (!setcookie(WEB_SESSION_NAME,session_id(),webSessionCookie()+['expires'=>$now+WEB_SESSION_TTL]))
        throw new RuntimeException('Cannot set the web session cookie.');
}
function signOutWebSession(): void
{
    // Revoke the old ID on disk, not just in this browser.
    $_SESSION=[];
    if (!session_destroy()) throw new RuntimeException('Cannot revoke the web session.');
    setcookie(WEB_SESSION_NAME,'',webSessionCookie()+['expires'=>1]);
}

function openPrivateState(string $path)
{
    $root = privateDirectory();
    if (dirname($path) !== CONFIG_DIR || is_link($path)) {
        throw new RuntimeException('Invalid private state path.');
    }
    $handle = fopen($path, 'c+b');
    if ($handle === false) {
        throw new RuntimeException('Cannot open private state file.');
    }
    $stat = fstat($handle);
    if ($stat === false || ($stat['mode'] & 0170000) !== 0100000
        || ($stat['mode'] & 0077) !== 0 || $stat['nlink'] !== 1
        || realpath(dirname($path)) !== $root) {
        fclose($handle);
        throw new RuntimeException('Private state must be a regular, non-shared 0600 file.');
    }
    return $handle;
}

// Caller holds CONFIG_LOCK_FILE, which is never replaced or deleted.
function readCredentialsUnlocked(): array
{
    clearstatcache(true, PASSWORD_FILE);
    if (is_link(PASSWORD_FILE) || !is_file(PASSWORD_FILE)) {
        throw new RuntimeException('pass.conf is unavailable.');
    }
    $handle = fopen(PASSWORD_FILE, 'rb');
    if ($handle === false) {
        throw new RuntimeException('Cannot read pass.conf.');
    }
    try {
        $stat = fstat($handle);
        if ($stat === false || ($stat['mode'] & 0170000) !== 0100000
            || ($stat['mode'] & 0077) !== 0 || $stat['nlink'] !== 1) {
            throw new RuntimeException('pass.conf must be a private regular file with mode 0600.');
        }
        $raw = stream_get_contents($handle, 16385);
    } finally {
        fclose($handle);
    }
    if ($raw === false || strlen($raw) > 16384 || str_contains($raw, "\0")) {
        throw new RuntimeException('Invalid pass.conf size or encoding.');
    }
    $config = [];
    foreach (preg_split('/\r\n|\n|\r/', $raw) ?: [] as $line) {
        $line = ltrim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        $parts = explode('=', $line, 2);
        if (count($parts) !== 2 || !in_array($parts[0], ['password', 'api_token', 'opds_user', 'opds_pwd'], true)
            || isset($config[$parts[0]])) {
            throw new RuntimeException('pass.conf contains an unknown or duplicate key.');
        }
        $config[$parts[0]] = in_array($parts[0], ['opds_user', 'opds_pwd'], true) ? $parts[1] : rtrim($parts[1]);
    }
    if (!isset($config['password'], $config['api_token']) || $config['password'] === ''
        || strlen($config['password']) > 1024 || preg_match('/[\x00-\x1F\x7F]/', $config['password'])
        || preg_match('/\A[a-f0-9]{64}\z/D', $config['api_token']) !== 1) {
        throw new RuntimeException('pass.conf requires password and a 64-character lowercase hex api_token.');
    }
    if (isset($config['opds_user']) || isset($config['opds_pwd'])) {
        $user = $config['opds_user'] ?? '';
        $password = $config['opds_pwd'] ?? '';
        if ($user === '' || $password === '' || str_contains($user, ':')
            || preg_match('/[\x00-\x1f\x7f]/', $user . $password)) {
            throw new RuntimeException('pass.conf requires a valid pair of OPDS reading credentials.');
        }
    }
    return $config;
}

function readCredentials(): array
{
    $lock = openPrivateState(CONFIG_LOCK_FILE);
    try {
        if (!flock($lock, LOCK_SH)) {
            throw new RuntimeException('Cannot lock credentials.');
        }
        return readCredentialsUnlocked();
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function getLibraryRoot(): string
{
    return directoryUnder(accountBooks(),libraryStorageKey());
}

function validDirectoryName(string $name): bool
{
    return $name !== '' && $name[0] !== '.' && strlen($name) <= 240
        && preg_match('//u', $name) === 1
        && !preg_match('~[/\\\\\x00-\x1F\x7F]~', $name);
}

// Traversal supports bounded depth; bootstrap currently enforces depth === 1.
function libraryDirectories(bool $writableOnly = false, bool $includePrivate = false): array
{
    $root = getLibraryRoot();
    $result = [];
    $walk = function (string $parent, string $prefix, int $depth) use (&$walk, &$result, $writableOnly, $includePrivate): void {
        if ($depth >= MAX_CATEGORY_DEPTH) return;
        foreach (scandir($parent) ?: [] as $name) {
            $path = $parent . '/' . $name;
            if (!validDirectoryName($name) || is_link($path) || !is_dir($path)
                || dirname((string) realpath($path)) !== $parent) continue;
            $relative = $prefix === '' ? $name : $prefix . '/' . $name;
            if (!$includePrivate && !canSeePrivateBooks() && folderPrivate($relative)) continue;
            if (!$writableOnly || is_writable($path)) $result[$relative] = $path;
            if (count($result) > 1000) reject(tr('Too many categories.'), 503);
            $walk($path, $relative, $depth + 1);
        }
    };
    $walk($root, '', 0);
    return $result;
}
function resolveDestinationDirectory(string $name): string
{
    if ($name === '') return getLibraryRoot();
    requireVisibleFolder($name);
    $parts = explode('/', $name);
    if (count($parts) > MAX_CATEGORY_DEPTH) reject(tr('Only one category level is currently supported.'));
    $parent = getLibraryRoot();
    foreach ($parts as $part) {
        if (!validDirectoryName($part)) reject(tr('Invalid destination category.'));
        $candidate = $parent . '/' . $part;
        if (is_link($candidate) || !is_dir($candidate)) reject(tr('Destination category does not exist.'));
        if (privacyRules() && !exactLibraryName($parent,$part)) reject('Directory not found.',404);
        $real = realpath($candidate);
        if ($real === false || dirname($real) !== $parent || basename($real) !== $part) reject(tr('Category is outside the allowed location.'));
        $parent = $real;
    }
    return $parent;
}
function getDirectories(): array { return array_map('strval', array_keys(libraryDirectories(true))); }

function safeFilename(string $name): string
{
    if ($name === '' || strlen($name) > 240 || preg_match('//u', $name) !== 1
        || $name[0] === '.' || trim($name) !== $name || str_ends_with($name, '.')
        || str_contains($name, '..') || preg_match('~[/\\\\:\x00-\x1F\x7F]~', $name)) {
        reject(tr('Invalid filename.'));
    }
    if (!in_array(strtolower(pathinfo($name, PATHINFO_EXTENSION)), ['epub', 'txt'], true)) {
        reject(tr('Only EPUB and TXT files are accepted.'), 422);
    }
    // Defense in depth for servers with unsafe multiple-extension handlers.
    if (preg_match('/(?:^|\.)(?:php\d*|phtml|pht|phar|cgi|pl|shtml|htaccess)(?:\.|$)/i', $name)) {
        reject(tr('The filename contains a disallowed extension.'), 422);
    }
    return $name;
}

function validArchivePath(string $name): bool
{
    if ($name === '' || strlen($name) > 1024 || preg_match('//u', $name) !== 1
        || preg_match('~[\\\\:\x00-\x1F\x7F]~', $name) || $name[0] === '/') {
        return false;
    }
    foreach (explode('/', rtrim($name, '/')) as $part) {
        if ($part === '' || $part === '.' || $part === '..') {
            return false;
        }
    }
    return true;
}

function readZipEntry(ZipArchive $zip, string $name, int $limit): string
{
    $stream = $zip->getStream($name);
    if ($stream === false) {
        reject(tr('Cannot read EPUB metadata.'), 422);
    }
    try {
        $value = stream_get_contents($stream, $limit + 1);
        if ($value === false || strlen($value) > $limit || !feof($stream)) {
            reject(tr('EPUB metadata is too large or unreadable.'), 422);
        }
        return $value;
    } finally {
        fclose($stream);
    }
}

function validateEpub(string $path): void
{
    if (!class_exists(ZipArchive::class) || !function_exists('simplexml_load_string')) {
        throw new RuntimeException('ZIP and SimpleXML extensions are required.');
    }
    $zip = new ZipArchive();
    if ($zip->open($path, ZipArchive::RDONLY | ZipArchive::CHECKCONS) !== true) {
        reject(tr('The EPUB is not a valid ZIP archive.'), 422);
    }
    try {
        if ($zip->numFiles < 3 || $zip->numFiles > 10000) {
            reject(tr('Invalid EPUB entry count.'), 422);
        }
        // Inspect ALL size metadata before decompressing any entry.
        $total = 0;
        $entries = [];
        for ($i = 0; $i < $zip->numFiles; ++$i) {
            $stat = $zip->statIndex($i);
            if ($stat === false || !isset($stat['name'], $stat['size'], $stat['comp_size'])
                || !is_int($stat['size']) || !is_int($stat['comp_size'])
                || $stat['size'] < 0 || $stat['comp_size'] < 0
                || !validArchivePath($stat['name']) || isset($entries[$stat['name']])) {
                reject(tr('The EPUB contains invalid or duplicate entries.'), 422);
            }
            if ($stat['size'] > MAX_TOTAL_UNCOMPRESSED - $total
                || $stat['size'] / max(1, $stat['comp_size']) > 200) {
                reject(tr('The EPUB expansion size or compression ratio is excessive.'), 422);
            }
            if (($stat['encryption_method'] ?? 0) !== 0) {
                reject(tr('ZIP-encrypted EPUB files are not accepted.'), 422);
            }
            $opsys = $attributes = 0;
            if ($zip->getExternalAttributesIndex($i, $opsys, $attributes)
                && $opsys === ZipArchive::OPSYS_UNIX
                && (($attributes >> 16) & 0170000) === 0120000) {
                reject(tr('EPUB symbolic-link entries are not allowed.'), 422);
            }
            $total += $stat['size'];
            $entries[$stat['name']] = $stat;
            if ($i === 0 && ($stat['name'] !== 'mimetype' || $stat['size'] !== 20
                || ($stat['comp_method'] ?? -1) !== ZipArchive::CM_STORE)) {
                reject(tr('The first EPUB mimetype entry is invalid.'), 422);
            }
        }
        if (readZipEntry($zip, 'mimetype', 20) !== 'application/epub+zip') {
            reject(tr('Incorrect EPUB mimetype.'), 422);
        }
        $containerStat = $entries['META-INF/container.xml'] ?? null;
        if ($containerStat === null || $containerStat['size'] < 1
            || $containerStat['size'] > MAX_CONTAINER_SIZE) {
            reject(tr('EPUB container.xml is missing or has an invalid size.'), 422);
        }
        $container = readZipEntry($zip, 'META-INF/container.xml', MAX_CONTAINER_SIZE);
        // Only UTF-8/ASCII metadata is accepted, so NUL/UTF-16 cannot bypass
        // the DTD check. Never enable NOENT, DTDLOAD, DTDVALID or PARSEHUGE.
        if (preg_match('//u', $container) !== 1 || str_contains($container, "\0")
            || preg_match('/<!\s*(?:DOCTYPE|ENTITY)\b/i', $container)
            || (preg_match('/<\?xml\b[^?]*\bencoding\s*=\s*([\'"])([^\'"]+)\1/i', $container, $m)
                && !in_array(strtoupper($m[2]), ['UTF-8', 'UTF8', 'US-ASCII', 'ASCII'], true))) {
            reject(tr('EPUB container.xml has an invalid encoding or DTD/entity declaration.'), 422);
        }
        $previous = libxml_use_internal_errors(true);
        $loader = function_exists('libxml_get_external_entity_loader')
            ? libxml_get_external_entity_loader() : null;
        libxml_set_external_entity_loader(static fn () => null);
        try {
            $xml = simplexml_load_string($container, SimpleXMLElement::class, LIBXML_NONET);
            if ($xml === false) {
                reject(tr('Malformed EPUB container.xml.'), 422);
            }
            $xml->registerXPathNamespace('c', 'urn:oasis:names:tc:opendocument:xmlns:container');
            $rootfiles = $xml->xpath('/c:container/c:rootfiles/c:rootfile');
            if (!$rootfiles) {
                reject(tr('The EPUB has no rootfile declaration.'), 422);
            }
            foreach ($rootfiles as $rootfile) {
                $fullPath = (string) $rootfile['full-path'];
                if (!validArchivePath($fullPath) || str_ends_with($fullPath, '/')
                    || !isset($entries[$fullPath]) || $entries[$fullPath]['size'] < 1
                    || (string) $rootfile['media-type'] !== 'application/oebps-package+xml') {
                    reject(tr('Invalid EPUB rootfile path, media type, or entry.'), 422);
                }
            }
        } finally {
            libxml_set_external_entity_loader($loader);
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
    } finally {
        $zip->close();
    }
}

function validateTxt(string $path): void
{
    $handle = fopen($path, 'rb');
    if ($handle === false) {
        throw new RuntimeException('Cannot read TXT file.');
    }
    try {
        while (!feof($handle)) {
            $chunk = fread($handle, 65536);
            if ($chunk === false || ($chunk === '' && !feof($handle))) {
                throw new RuntimeException('Cannot read TXT file.');
            }
            if (str_contains($chunk, "\0")) {
                reject(tr('The TXT contains binary NUL bytes. Use a text encoding such as UTF-8 or GBK.'), 422);
            }
        }
    } finally {
        fclose($handle);
    }
}
