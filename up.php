<?php
declare(strict_types=1);

/* PHP 8.1 syntax; deploy on a currently supported, patched PHP release.
 * Required extensions: session, zip, SimpleXML, libxml.
 * See README.md for the required private configuration directory and PHP limits.
 */
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/security.php';

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.use_trans_sid', '0');
umask(0077);

$nonce = base64_encode(random_bytes(24));
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');
header("Content-Security-Policy: default-src 'none'; script-src 'nonce-$nonce'; style-src 'nonce-$nonce'; connect-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'");
header('Content-Type: text/html; charset=UTF-8');


function startBrowserSession(): void
{
    session_name('OPDS_UPLOAD_SESSION');
    session_set_cookie_params([
        'lifetime' => 0, 'path' => COOKIE_PATH, 'secure' => true,
        'httponly' => true, 'samesite' => 'Strict',
    ]);
    if (!session_start()) {
        throw new RuntimeException('Session service unavailable.');
    }
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function publicError(Throwable $error): string
{
    if ($error instanceof RequestError) {
        return $error->getMessage();
    }
    // Details (including filesystem paths) stay in the server log.
    // Do not log a stack trace: its arguments could contain credentials.
    error_log('EPUB uploader: ' . get_class($error) . ': ' . $error->getMessage()
        . ' at ' . $error->getFile() . ':' . $error->getLine());
    return tr('Server processing failed. Check the server log.');
}

function jsonResponse(array $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
    exit;
}

function redirectSelf(): never
{
    header('Location: up.php', true, 303);
    exit;
}

function csrfToken(): string
{
    if (!isset($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function verifyCsrf(): void
{
    $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? $_POST['csrf'] ?? '';
    if (!is_string($token) || !isset($_SESSION['csrf'])
        || !is_string($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $token)) {
        reject(tr('Invalid request token. Refresh the page.'), 403);
    }
}

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
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        $parts = explode('=', $line, 2);
        if (count($parts) !== 2 || !in_array($parts[0], ['password', 'api_token'], true)
            || isset($config[$parts[0]])) {
            throw new RuntimeException('pass.conf contains an unknown or duplicate key.');
        }
        $config[$parts[0]] = $parts[1];
    }
    if (!isset($config['password'], $config['api_token']) || $config['password'] === ''
        || strlen($config['password']) > 1024 || preg_match('/[\x00-\x1F\x7F]/', $config['password'])
        || preg_match('/\A[a-f0-9]{64}\z/D', $config['api_token']) !== 1) {
        throw new RuntimeException('pass.conf requires password and a 64-character lowercase hex api_token.');
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

function verifyPassword(string $password, string $configured): bool
{
    if (strlen($password) > 1024 || str_contains($password, "\0")) {
        return false;
    }
    $info = password_get_info($configured);
    if (($info['algoName'] ?? 'unknown') !== 'unknown') {
        return ($info['algoName'] !== 'bcrypt' || strlen($password) <= 72)
            && password_verify($password, $configured);
    }
    // Compatibility with the supplied password=plaintext configuration.
    return hash_equals(hash('sha256', $configured), hash('sha256', $password));
}

function writeAll($handle, string $data): void
{
    $offset = 0;
    while ($offset < strlen($data)) {
        $written = fwrite($handle, substr($data, $offset));
        if ($written === false || $written === 0) {
            throw new RuntimeException('Cannot write private state.');
        }
        $offset += $written;
    }
}

function resetApiToken(string $expectedTokenVersion, string $sessionCredential): void
{
    $lock = openPrivateState(CONFIG_LOCK_FILE);
    $temp = null;
    try {
        if (!flock($lock, LOCK_EX)) {
            throw new RuntimeException('Cannot lock credentials for update.');
        }
        $config = readCredentialsUnlocked();
        if (!hash_equals(hash('sha256', $config['password']), $sessionCredential)) {
            reject(tr('The password changed. Sign in again.'), 401);
        }
        if (!hash_equals(hash('sha256', $config['api_token']), $expectedTokenVersion)) {
            reject(tr('Another request updated the token. Refresh the page.'), 409);
        }
        $config['api_token'] = bin2hex(random_bytes(32));
        $encoded = 'password=' . $config['password'] . "\napi_token=" . $config['api_token'] . "\n";
        $temp = CONFIG_DIR . '/.pass-' . bin2hex(random_bytes(16)) . '.tmp';
        $handle = fopen($temp, 'x+b');
        if ($handle === false) {
            throw new RuntimeException('Cannot create replacement credentials.');
        }
        try {
            if (!chmod($temp, 0600)) {
                throw new RuntimeException('Cannot protect replacement credentials.');
            }
            writeAll($handle, $encoded);
            if (!fflush($handle) || !fsync($handle)) {
                throw new RuntimeException('Cannot sync replacement credentials.');
            }
        } finally {
            fclose($handle);
        }
        if (!rename($temp, PASSWORD_FILE)) {
            throw new RuntimeException('Cannot atomically replace pass.conf.');
        }
        $temp = null;
        clearstatcache(true, PASSWORD_FILE);
    } finally {
        if ($temp !== null) {
            @unlink($temp);
        }
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

/* Shared, bounded counters survive new cookies and concurrent workers.
 * The server's REMOTE_ADDR is used; never trust arbitrary forwarding headers.
 */
function reserveRateAttempt(string $bucket, int $ipLimit, int $globalLimit): void
{
    $handle = openPrivateState(RATE_STATE_FILE);
    try {
        if (!flock($handle, LOCK_EX)) {
            throw new RuntimeException('Cannot lock rate limiter.');
        }
        $raw = stream_get_contents($handle, 262145);
        if ($raw === false || strlen($raw) > 262144) {
            throw new RuntimeException('Invalid rate limiter state.');
        }
        $state = trim($raw) === '' ? [] : json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($state)) {
            throw new RuntimeException('Invalid rate limiter state.');
        }
        $now = time();
        foreach ($state as $key => $entry) {
            if (!is_array($entry) || !isset($entry['until'], $entry['count'])
                || !is_int($entry['until']) || !is_int($entry['count'])) {
                throw new RuntimeException('Invalid rate limiter entry.');
            }
            if ($entry['until'] <= $now) {
                unset($state[$key]);
            }
        }
        $ip = $bucket . ':' . hash('sha256', (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        $global = $bucket . ':global';
        $retry = 0;
        foreach ([$ip => $ipLimit, $global => $globalLimit] as $key => $limit) {
            if (($state[$key]['count'] ?? 0) >= $limit) {
                $retry = max($retry, $state[$key]['until'] - $now);
            }
        }
        if ($retry > 0) {
            header('Retry-After: ' . $retry);
            reject(tr('Too many requests. Try again later.'), 429);
        }
        foreach ([$ip, $global] as $key) {
            $state[$key] ??= ['until' => $now + LOGIN_WINDOW, 'count' => 0];
            ++$state[$key]['count'];
        }
        $encoded = json_encode($state, JSON_THROW_ON_ERROR);
        if (strlen($encoded) > 262144) {
            reject(tr('The service is busy. Try again later.'), 429);
        }
        rewind($handle);
        writeAll($handle, $encoded);
        if (!ftruncate($handle, strlen($encoded)) || !fflush($handle)) {
            throw new RuntimeException('Cannot persist rate limiter.');
        }
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

function acquireUploadSlot()
{
    for ($i = 0; $i < MAX_CONCURRENT_UPLOADS; ++$i) {
        $handle = openPrivateState(CONFIG_DIR . '/.upload-slot-' . $i . '.lock');
        if (flock($handle, LOCK_EX | LOCK_NB)) {
            return $handle;
        }
        fclose($handle);
    }
    header('Retry-After: 5');
    reject(tr('All upload processing slots are busy. Try again later.'), 429);
}

function publicUploadUrl(): string
{
    if (PUBLIC_UPLOAD_URL === '') {
        return '';
    }
    $parts = parse_url(PUBLIC_UPLOAD_URL);
    if ($parts === false || !filter_var(PUBLIC_UPLOAD_URL, FILTER_VALIDATE_URL)
        || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])
        || isset($parts['user']) || isset($parts['pass'])
        || isset($parts['query']) || isset($parts['fragment'])
        || preg_match('/[\x00-\x20\x7F]/', PUBLIC_UPLOAD_URL)) {
        throw new RuntimeException('PUBLIC_UPLOAD_URL must be an HTTPS URL without credentials, query or fragment.');
    }
    return PUBLIC_UPLOAD_URL;
}

function shellQuote(string $value): string
{
    return "'" . str_replace("'", "'\"'\"'", $value) . "'";
}

function curlCommand(string $apiToken, string $directory, string $url): string
{
    return 'export OPDS_TOKEN=' . shellQuote($apiToken) . "\n\n"
        . "curl --fail-with-body --show-error --progress-bar \\\n"
        . '  -H "Authorization: Bearer $OPDS_TOKEN" ' . "\\\n"
        . '  --form-string ' . shellQuote('directory=' . $directory) . " \\\n"
        . "  -F 'files[]=@./article.epub' \\\n"
        . '  -- ' . shellQuote($url);
}

function saveUpload(string $tmpPath, string $filename, string $directoryName): void
{
    $filename = safeFilename($filename);
    if (!is_uploaded_file($tmpPath)) {
        reject(tr('Invalid upload source.'));
    }
    $size = filesize($tmpPath);
    if ($size === false || $size < 1 || $size > MAX_FILE_SIZE) {
        reject(tr('Each file must be between 1 byte and 100 MiB.'), 413);
    }
    if (strtolower(pathinfo($filename, PATHINFO_EXTENSION)) === 'epub') {
        validateEpub($tmpPath);
    } else {
        validateTxt($tmpPath);
    }
    $destination = resolveDestinationDirectory($directoryName);
    $target = $destination . DIRECTORY_SEPARATOR . $filename;
    if (file_exists($target) || is_link($target)) {
        reject(tr('File already exists; not overwritten: ') . $filename, 409);
    }
    // Reserve the random staging name exclusively; do not overwrite a link.
    $temp = $destination . '/.upload-' . bin2hex(random_bytes(24)) . '.tmp';
    $reservation = fopen($temp, 'x+b');
    if ($reservation === false) {
        throw new RuntimeException('Cannot create upload staging file.');
    }
    fclose($reservation);
    try {
        if (!move_uploaded_file($tmpPath, $temp) || !chmod($temp, 0640)) {
            throw new RuntimeException('Cannot stage uploaded file with safe permissions.');
        }
        if (resolveDestinationDirectory($directoryName) !== $destination) {
            throw new RuntimeException('Destination changed during upload.');
        }
        // Same-directory hard link: atomic creation, never overwrites target.
        if (!@link($temp, $target)) {
            if (file_exists($target) || is_link($target)) {
                reject(tr('File already exists; not overwritten: ') . $filename, 409);
            }
            throw new RuntimeException('Cannot create final hard link.');
        }
    } finally {
        if (!@unlink($temp)) {
            error_log('EPUB uploader: unable to remove staging file.');
        }
    }
}

function receiveUploads(string $directory, bool $singleFile): array
{
    $destination = resolveDestinationDirectory($directory);
    // PHP silently truncates excess uploads BEFORE user code runs. One extra
    // parser slot lets the application reject more than MAX_FILES safely.
    if ((int) ini_get('max_file_uploads') < MAX_FILES + 1) {
        throw new RuntimeException('Set max_file_uploads to at least 21 to detect excess files.');
    }
    if (count($_FILES) !== 1 || !isset($_FILES['files']) || !is_array($_FILES['files'])) {
        reject(tr('No files received; the request may exceed the server limit.'), 413);
    }
    $files = $_FILES['files'];
    $count = isset($files['name']) && is_array($files['name']) ? count($files['name']) : 0;
    if ($count < 1 || $count > ($singleFile ? 1 : MAX_FILES)) {
        reject($singleFile ? tr('Each progress request accepts only one file.') : tr('Select between 1 and 20 files.'));
    }
    $expected = range(0, $count - 1);
    foreach (['name', 'tmp_name', 'error', 'size'] as $key) {
        if (!isset($files[$key]) || !is_array($files[$key]) || array_keys($files[$key]) !== $expected) {
            reject(tr('Invalid upload data structure.'));
        }
    }
    $total = 0;
    for ($i = 0; $i < $count; ++$i) {
        if (!is_string($files['name'][$i]) || !is_string($files['tmp_name'][$i])
            || !is_int($files['error'][$i]) || !is_int($files['size'][$i]) || $files['size'][$i] < 0) {
            reject(tr('Invalid upload field types.'));
        }
        if ($files['error'][$i] === UPLOAD_ERR_OK) {
            if (!is_uploaded_file($files['tmp_name'][$i])) {
                reject(tr('Invalid upload source.'));
            }
            $actual = filesize($files['tmp_name'][$i]);
            if ($actual === false || $actual !== $files['size'][$i]) {
                reject(tr('Upload size mismatch.'));
            }
            if ($actual > MAX_BATCH_SIZE - $total) {
                reject(tr('Files in one request must not exceed 200 MiB in total.'), 413);
            }
            $total += $actual;
        }
    }
    $free = disk_free_space($destination);
    if ($free === false || $free - $total < MIN_FREE_SPACE) {
        reject(tr('Insufficient library disk space.'), 507);
    }
    $messages = [];
    for ($i = 0; $i < $count; ++$i) {
        try {
            if ($files['error'][$i] !== UPLOAD_ERR_OK) {
                $code = $files['error'][$i];
                reject(match ($code) {
                    UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => tr('The file exceeds the server upload limit.'),
                    UPLOAD_ERR_PARTIAL => tr('The file was only partially uploaded. Try again.'),
                    UPLOAD_ERR_NO_FILE => tr('No file selected.'),
                    default => tr('The server could not receive the file. Check temporary storage and free space.'),
                }, match ($code) {
                    UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 413,
                    UPLOAD_ERR_NO_TMP_DIR, UPLOAD_ERR_CANT_WRITE, UPLOAD_ERR_EXTENSION => 503,
                    default => 400,
                });
            }
            saveUpload($files['tmp_name'][$i], $files['name'][$i], $directory);
            $messages[] = ['name' => $files['name'][$i], 'success' => true,
                'text' => tr('Saved: ') . $files['name'][$i], 'status' => 200];
        } catch (Throwable $e) {
            $messages[] = ['name' => $files['name'][$i], 'success' => false, 'text' => publicError($e),
                'status' => $e instanceof RequestError ? $e->getCode() : 500];
        }
    }
    return $messages;
}

function requireMultipart(): void
{
    $type = $_SERVER['CONTENT_TYPE'] ?? '';
    if (!is_string($type) || !preg_match('~\Amultipart/form-data\s*;~i', $type)) {
        reject(tr('Use multipart/form-data to upload files.'), 415);
    }
    $length = $_SERVER['CONTENT_LENGTH'] ?? '';
    if (!is_string($length) || preg_match('/\A[0-9]+\z/D', $length) !== 1
        || strlen($length) > 12 || (int) $length > MAX_BATCH_SIZE + 1024 * 1024) {
        reject(tr('The request is too large or has no valid Content-Length.'), 413);
    }
    if (empty($_POST) && empty($_FILES)) {
        reject(tr('The request is empty or exceeds the server post_max_size limit.'), 413);
    }
}

function processUpload(bool $singleFile, bool $bearer): array
{
    requireMultipart();
    foreach (array_keys($_POST) as $field) {
        if (!in_array($field, $bearer ? ['directory'] : ['directory', 'csrf', 'action'], true)) {
            reject(tr('The upload contains unsupported form fields.'));
        }
    }
    $directory = $_POST['directory'] ?? '';
    if (!is_string($directory)) {
        reject(tr('Invalid destination directory.'));
    }
    reserveRateAttempt('upload', 120, 600);
    $slot = acquireUploadSlot();
    try {
        return receiveUploads($directory, $singleFile);
    } finally {
        flock($slot, LOCK_UN);
        fclose($slot);
    }
}

function uploadJsonResponse(array $messages): never
{
    $successes = count(array_filter($messages, static fn (array $m): bool => $m['success']));
    $success = $successes === count($messages);
    $status = 200;
    if (!$success) {
        $errors = array_values(array_filter($messages, static fn (array $m): bool => !$m['success']));
        $codes = array_unique(array_column($errors, 'status'));
        // Partial success MUST NOT return 2xx: curl --fail-with-body must fail.
        $status = count($codes) === 1 && $successes === 0 ? $errors[0]['status'] : 422;
        if (max($codes) >= 500) {
            $status = 500;
        }
    }
    $message = count($messages) === 1 ? $messages[0]['text']
        : tr('Saved ') . $successes . '/' . count($messages) . tr(' files; saved files are not rolled back.');
    jsonResponse([
        'success' => $success, 'message' => $message,
        'results' => array_map(static fn (array $m): array => [
            'name' => $m['name'], 'success' => $m['success'], 'message' => $m['text'], 'status' => $m['status'],
        ], $messages),
    ], $status);
}

function bearerUpload(): never
{
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (isset($_SERVER['HTTP_AUTHORIZATION'], $_SERVER['REDIRECT_HTTP_AUTHORIZATION'])
        && $_SERVER['HTTP_AUTHORIZATION'] !== $_SERVER['REDIRECT_HTTP_AUTHORIZATION']) {
        reject(tr('Ambiguous Authorization headers.'), 401);
    }
    $config = readCredentials();
    if (!is_string($header) || strlen($header) > 128
        || preg_match('/\ABearer ([a-f0-9]{64})\z/iD', $header, $match) !== 1
        || !hash_equals($config['api_token'], $match[1])) {
        reserveRateAttempt('invalid-token', 30, 300);
        header('WWW-Authenticate: Bearer realm="opds-upload"');
        reject(tr('Missing or invalid API token. Use the Authorization: Bearer header.'), 401);
    }
    // A Bearer token can upload only. It cannot access the UI or rotate itself.
    if (array_diff(array_keys($_GET), ['action'])) {
        reject(tr('URL parameters are not accepted. Send credentials only in the Authorization header.'));
    }
    if (isset($_GET['action']) && $_GET['action'] !== 'upload') {
        reject(tr('This API only supports file uploads.'), 403);
    }
    uploadJsonResponse(processUpload(false, true));
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$hasAuthorization = array_key_exists('HTTP_AUTHORIZATION', $_SERVER)
    || array_key_exists('REDIRECT_HTTP_AUTHORIZATION', $_SERVER);
$browserUpload = !$hasAuthorization && ($_GET['action'] ?? null) === 'upload';
$jsonRequest = $hasAuthorization || $browserUpload
    || str_contains(strtolower((string) ($_SERVER['HTTP_ACCEPT'] ?? '')), 'application/json')
    || ($method === 'POST' && !isset($_POST['action']));
$error = '';
$messages = [];
$directories = [];
$authenticated = false;
$token = '';
$apiToken = '';
$uploadUrl = '';
$notice = '';
try {
    // Do not let client-controlled forwarding headers bypass HTTPS enforcement.
    if (!in_array(strtolower((string) ($_SERVER['HTTPS'] ?? '')), ['on', '1'], true)) {
        reject(tr('HTTPS is required. Check the TLS endpoint and FastCGI HTTPS configuration.'));
    }
    if (!in_array($method, ['GET', 'POST'], true)) {
        header('Allow: GET, POST');
        reject(tr('Unsupported request method.'), 405);
    }
    if ($jsonRequest && $method !== 'POST') {
        header('Allow: POST');
        reject(tr('The upload endpoint only accepts POST.'), 405);
    }
    if ($jsonRequest && !$browserUpload) {
        bearerUpload(); // No session is started, and cookies are ignored.
    }
    startBrowserSession();
    $token = csrfToken();
    if ($method === 'POST' && empty($_POST) && empty($_FILES)) {
        reject(tr('The request is empty or exceeds post_max_size / client_max_body_size.'), 413);
    }
    $action = $browserUpload ? 'upload' : ($_POST['action'] ?? '');
    if (!is_string($action)) {
        reject(tr('Invalid request action.'));
    }
    if ($method === 'POST' && $action === 'logout') {
        verifyCsrf();
        $_SESSION = [];
        setcookie(session_name(), '', [
            'expires' => time() - 42000, 'path' => COOKIE_PATH,
            'secure' => true, 'httponly' => true, 'samesite' => 'Strict',
        ]);
        session_destroy();
        redirectSelf();
    }
    if ($method === 'POST' && $action === 'login') {
        verifyCsrf();
        reserveRateAttempt('login', LOGIN_IP_LIMIT, LOGIN_GLOBAL_LIMIT);
        $config = readCredentials();
        $password = $_POST['password'] ?? '';
        if (!is_string($password) || !verifyPassword($password, $config['password'])) {
            reject(tr('Incorrect password.'), 401);
        }
        if (!session_regenerate_id(true)) {
            throw new RuntimeException('Cannot regenerate session ID.');
        }
        $_SESSION = [
            'authenticated' => true, 'issued_at' => time(), 'last_seen' => time(),
            'credential' => hash('sha256', $config['password']), 'csrf' => bin2hex(random_bytes(32)),
        ];
        redirectSelf();
    }
    if (($_SESSION['authenticated'] ?? false) === true) {
        $now = time();
        $issued = $_SESSION['issued_at'] ?? 0;
        $seen = $_SESSION['last_seen'] ?? 0;
        $credential = $_SESSION['credential'] ?? '';
        $authenticated = is_int($issued) && is_int($seen) && is_string($credential)
            && $now - $issued < SESSION_ABSOLUTE_TTL && $now - $seen < SESSION_IDLE_TTL
            && hash_equals(hash('sha256', readCredentials()['password']), $credential);
        if ($authenticated) {
            $_SESSION['last_seen'] = $now;
        } else {
            $_SESSION = [];
            $token = csrfToken();
        }
    }
    if ($method === 'POST' && $action === 'reset_token') {
        if (!$authenticated) {
            reject(tr('Sign in again before resetting the token.'), 401);
        }
        verifyCsrf();
        $version = $_POST['token_version'] ?? '';
        if (!is_string($version) || preg_match('/\A[a-f0-9]{64}\z/D', $version) !== 1) {
            reject(tr('Invalid token version. Refresh the page.'));
        }
        reserveRateAttempt('reset-token', 10, 30);
        resetApiToken($version, $_SESSION['credential']);
        $_SESSION['notice'] = tr('API token reset. The old token is invalid. Copy the updated command.');
        redirectSelf();
    } elseif ($method === 'POST' && $action === 'upload') {
        if (!$authenticated) {
            reject(tr('Your login expired. Refresh the page and sign in again.'), 401);
        }
        verifyCsrf();
        session_write_close(); // no session lock during validation and disk I/O
        $messages = processUpload($browserUpload, false);
        if ($browserUpload) {
            uploadJsonResponse($messages);
        }
    } elseif ($method === 'POST') {
        reject(tr('Unknown action.'));
    }
    if ($authenticated) {
        $directories = getDirectories();
        $apiToken = readCredentials()['api_token'];
        $uploadUrl = publicUploadUrl();
        $notice = is_string($_SESSION['notice'] ?? null) ? $_SESSION['notice'] : '';
        unset($_SESSION['notice']);
    }
} catch (Throwable $e) {
    $status = $e instanceof RequestError ? $e->getCode() : 500;
    $error = publicError($e);
    if ($jsonRequest) {
        jsonResponse(['success' => false, 'message' => $error, 'results' => []], $status);
    }
    http_response_code($status);
}
if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}
?>
<!DOCTYPE html>
<html lang="<?=uiLanguage() === 'zh' ? 'zh-CN' : 'en'?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?=tr_html('Book uploader')?></title>
<style nonce="<?= h($nonce) ?>">
* { box-sizing: border-box; }
[hidden] { display: none !important; }
body { margin: 0; padding: 40px 16px; background: #f5f6f8; color: #222; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
.container { max-width: 660px; margin: auto; background: #fff; padding: 30px; border-radius: 14px; box-shadow: 0 4px 20px #0000000f; }
h2 { margin-top: 0; font-size: 23px; }
input, select, button { width: 100%; padding: 13px; margin: 10px 0; font-size: 16px; border: 1px solid #ddd; border-radius: 8px; }
button { background: #222; color: #fff; border: 0; cursor: pointer; }
button:hover { background: #444; }
button:disabled { opacity: .5; cursor: default; }
label { display: block; margin-top: 20px; font-weight: 600; }
.dropzone { margin: 20px 0; padding: 30px 20px; text-align: center; border: 2px dashed #bbb; border-radius: 12px; background: #fafafa; cursor: pointer; }
.dropzone.dragover { border-color: #333; background: #eee; }
.dropzone[aria-disabled="true"] { opacity: .6; cursor: default; }
.note { color: #666; font-size: 13px; line-height: 1.7; }
.error, .messages { padding: 12px; margin: 12px 0; border-radius: 8px; overflow-wrap: anywhere; }
.error { background: #ffecec; color: #a00; }
.messages { background: #f5f7f5; line-height: 1.8; }
.success { color: #16803c; }
.failure { color: #c22; }
.toolbar { display: flex; align-items: center; justify-content: flex-end; gap: 8px; margin-bottom: 24px; }
.toolbar form { margin: 0; }
.toolbar button { width: auto; padding: 7px 12px; margin: 0; background: transparent; color: #555; border: 1px solid #ddd; font-size: 13px; }
.toolbar button:hover { background: #f5f6f8; }
.file-row { padding: 12px 0; border-bottom: 1px solid #eee; overflow-wrap: anywhere; font-size: 14px; }
.file-state { display: block; margin: 5px 0; font-size: 13px; }
progress { display: block; width: 100%; height: 14px; accent-color: #16803c; }
#overall { margin: 20px 0; }
#stopButton { background: #eee; color: #333; }
.api-panel { margin: 0; }
.api-panel h3 { margin: 0 0 12px; }
.api-panel pre { padding: 16px; background: #f5f6f8; border-radius: 8px; white-space: pre-wrap; overflow-wrap: anywhere; font-size: 13px; line-height: 1.6; }
.api-panel code, #apiToken { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
.api-panel .secondary { background: #eee; color: #333; }
.api-panel .danger { background: #a52828; }
.api-panel summary { cursor: pointer; padding: 12px 0; font-weight: 600; }
#apiToken { font-size: 13px; }
#apiDialog { width: min(760px, calc(100% - 32px)); max-height: calc(100% - 32px); overflow: auto; padding: 24px; border: 0; border-radius: 14px; color: #222; box-shadow: 0 12px 60px #0003; }
#apiDialog::backdrop { background: #14181e80; }
.dialog-heading { position: sticky; top: -24px; display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 12px 0; background: #fff; z-index: 1; }
.dialog-heading h3 { margin: 0; font-size: 18px; }
.dialog-heading button { width: auto; padding: 7px 12px; margin: 0; background: #eee; color: #333; font-size: 13px; flex-shrink: 0; }
</style>
</head>
<body>
<main class="container">
<?php if (!$authenticated): ?>
    <h2>EPUB Library</h2>
    <p><?=tr_html('Enter your upload password.')?></p>
    <?php if ($error !== ''): ?><div class="error" role="alert"><?= h($error) ?></div><?php endif; ?>
    <form method="post" action="up.php">
        <input type="hidden" name="action" value="login">
        <input type="hidden" name="csrf" value="<?= h($token) ?>">
        <input type="password" name="password" aria-label="<?=tr_html('Upload password')?>" placeholder="Password" required autofocus autocomplete="current-password">
        <button type="submit"><?=tr_html('Sign in')?></button>
    </form>
<?php else: ?>
    <div class="toolbar">
        <?php if ($apiToken !== ''): ?>
            <button type="button" id="apiSettingsButton" aria-haspopup="dialog" aria-controls="apiDialog"><?=tr_html('CLI / API')?></button>
        <?php endif; ?>
        <form method="post" action="up.php" id="logoutForm">
            <input type="hidden" name="action" value="logout">
            <input type="hidden" name="csrf" value="<?= h($token) ?>">
            <button type="submit" id="logoutButton"><?=tr_html('Sign out')?></button>
        </form>
    </div>
    <h2><?=tr_html('Upload books')?></h2>
    <?php if ($error !== ''): ?><div class="error" role="alert"><?= h($error) ?></div><?php endif; ?>
    <?php if ($messages): ?>
        <div class="messages">
        <?php foreach ($messages as $message): ?>
            <div class="<?= $message['success'] ? 'success' : 'failure' ?>"><?= h($message['text']) ?></div>
        <?php endforeach; ?>
        </div>
    <?php endif; ?>
    <?php if (!$directories): ?>
        <div class="error"><?=tr_html('No writable categories found. Check directory permissions.')?></div>
    <?php else: ?>
    <form method="post" action="up.php" enctype="multipart/form-data" id="uploadForm">
        <input type="hidden" name="action" value="upload">
        <input type="hidden" name="csrf" value="<?= h($token) ?>">
        <label for="directory"><?=tr_html('Destination category')?></label>
        <select name="directory" id="directory" required>
        <?php foreach ($directories as $name): ?>
            <option value="<?= h($name) ?>"<?= $name === 'books' ? ' selected' : '' ?>><?= h($name) ?></option>
        <?php endforeach; ?>
        </select>
        <div class="dropzone" id="dropzone" role="button" tabindex="0" aria-controls="fileInput" hidden>
            <strong><?=tr_html('Drop files here')?></strong>
            <p><?=tr_html('or click to choose files')?></p>
        </div>
        <p class="note"><?=tr_html('EPUB and TXT only. Up to 100 MiB per file, 20 files and 200 MiB per batch.')?></p>
        <input type="file" id="fileInput" name="files[]" aria-label="<?=tr_html('Choose books')?>" accept=".epub,.txt" multiple required>
        <div id="clientError" class="error" role="alert" hidden></div>
        <div id="fileList"></div>
        <div id="overall" hidden>
            <label for="totalProgress"><?=tr_html('Overall transfer progress')?></label>
            <progress id="totalProgress" max="100" value="0"></progress>
            <p id="transferStatus" class="note"></p>
            <p id="batchStatus" role="status" aria-live="polite"></p>
        </div>
        <button type="submit" id="uploadButton"><?=tr_html('Start upload')?></button>
        <button type="button" id="stopButton" hidden><?=tr_html('Stop after this file')?></button>
        <noscript><p class="note"><?=tr_html('Using a standard form. Enable JavaScript for live progress.')?></p></noscript>
    </form>
    <?php endif; ?>
    <?php if ($apiToken !== ''): ?>
    <dialog id="apiDialog" aria-labelledby="apiHeading">
        <div class="dialog-heading">
            <h3 id="apiHeading"><?=tr_html('Command-line upload / Agent')?></h3>
            <button type="button" id="closeApiDialog" autofocus><?=tr_html('Close')?></button>
        </div>
    <section class="api-panel" aria-labelledby="apiHeading">
        <?php if ($notice !== ''): ?><div class="messages success" role="status"><?= h($notice) ?></div><?php endif; ?>
        <p class="note"><?=tr_html('Your agent uploads over HTTPS from its own environment. No SSH, browser login, or cookies are needed. This command contains your current token. Update the local file path before running it.')?></p>
        <label for="apiToken"><?=tr_html('Current API token')?></label>
        <input type="text" id="apiToken" value="<?= h($apiToken) ?>" readonly autocomplete="off" spellcheck="false">
        <button type="button" id="copyToken" class="secondary"><?=tr_html('Copy token')?></button>
        <form method="post" action="up.php" id="resetTokenForm">
            <input type="hidden" name="action" value="reset_token">
            <input type="hidden" name="csrf" value="<?= h($token) ?>">
            <input type="hidden" name="token_version" value="<?= h(hash('sha256', $apiToken)) ?>">
            <details>
                <summary><?=tr_html('Reset token')?></summary>
                <p class="note"><?=tr_html('The old token will become invalid. Update existing scripts. Your password and browser login remain unchanged. Already-authorized uploads may finish.')?></p>
                <button type="submit" id="resetTokenButton" class="danger"><?=tr_html('Confirm token reset')?></button>
            </details>
        </form>
        <?php if ($uploadUrl === ''): ?>
            <div class="error"><?=tr_html('Configure the actual HTTPS base URL in conf/config.php to generate a usable command.')?></div>
        <?php elseif ($directories): ?>
            <label for="apiDirectory"><?=tr_html('Command destination category')?></label>
            <select id="apiDirectory">
            <?php foreach ($directories as $name): ?>
                <option value="<?= h($name) ?>"<?= $name === 'books' ? ' selected' : '' ?>><?= h($name) ?></option>
            <?php endforeach; ?>
            </select>
            <pre><code id="curlCommand" data-upload-url="<?= h($uploadUrl) ?>"><?= h(curlCommand($apiToken, in_array('books', $directories, true) ? 'books' : $directories[0], $uploadUrl)) ?></code></pre>
            <button type="button" id="copyCommand"><?=tr_html('Copy complete command for your agent')?></button>
        <?php endif; ?>
        <p id="copyStatus" class="note" role="status" aria-live="polite"></p>
        <details>
            <summary><?=tr_html('HTTP parameters, batch uploads, and responses')?></summary>
            <p class="note"><?=tr_html('POST to this installation\'s up.php with Authorization: Bearer TOKEN. The multipart form requires directory (a category name) and files[] (files). Tokens are accepted only in the header, never in URLs or form fields.')?></p>
            <p class="note"><?=tr_html('Requires curl 7.76+. For multiple files, repeat')?> <code>-F 'files[]=@./second.epub'</code><?=tr_html('. Each file is limited to 100 MiB; a request accepts up to 20 files and 200 MiB total. Existing files are never overwritten.')?></p>
            <p class="note"><?=tr_html('directory uses --form-string so category names are treated as literal text. The server validates filenames and destinations independently of the selection list.')?></p>
            <pre><code><?=tr_html('{"success":true,"message":"Saved: article.epub","results":[{"name":"article.epub","success":true,"message":"Saved: article.epub","status":200}]}')?></code></pre>
            <p class="note"><?=tr_html('All saved: HTTP 200. Invalid parameters: 400; invalid token: 401; duplicate: 409; too large: 413; unsupported request type: 415; validation or partial failure: 422; rate/concurrency limit: 429. Internal errors return 5xx. See results for individual files. Partial success is preserved and curl exits with a nonzero status.')?></p>
            <p class="note"><?=tr_html('After 100% transfer, wait for server validation and saving. Check the library before retrying an interrupted request. This command contains credentials: share it only with agents that need upload access, and keep it out of public logs and repositories.')?></p>
        </details>
    </section>
    </dialog>
    <?php endif; ?>
<?php endif; ?>
</main>
<script nonce="<?= h($nonce) ?>">
(() => {
    'use strict';
    const dictionary = <?=json_encode(uiLanguage() === 'zh' ? UI_TRANSLATIONS : [], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)?>;
    const tr = text => dictionary[text] ?? text;
    const tokenInput = document.getElementById('apiToken');
    const command = document.getElementById('curlCommand');
    const apiDirectory = document.getElementById('apiDirectory');
    const copyStatus = document.getElementById('copyStatus');
    const resetForm = document.getElementById('resetTokenForm');
    const apiDialog = document.getElementById('apiDialog');
    document.getElementById('apiSettingsButton')?.addEventListener('click', () => apiDialog.showModal());
    document.getElementById('closeApiDialog')?.addEventListener('click', () => apiDialog.close());
    apiDialog?.addEventListener('click', event => {
        if (event.target !== apiDialog) return;
        const rect = apiDialog.getBoundingClientRect();
        if (event.clientX < rect.left || event.clientX > rect.right
            || event.clientY < rect.top || event.clientY > rect.bottom) apiDialog.close();
    });
    if (apiDialog && <?= json_encode($notice !== '') ?>) apiDialog.showModal();
    const quote = value => "'" + value.replaceAll("'", "'\"'\"'") + "'";
    function updateCommand() {
        if (!command || !apiDirectory || !tokenInput) return;
        command.textContent = 'export OPDS_TOKEN=' + quote(tokenInput.value) + '\n\n'
            + 'curl --fail-with-body --show-error --progress-bar \\\n'
            + '  -H "Authorization: Bearer $OPDS_TOKEN" \\\n'
            + '  --form-string ' + quote('directory=' + apiDirectory.value) + ' \\\n'
            + "  -F 'files[]=@./article.epub' \\\n"
            + '  -- ' + quote(command.dataset.uploadUrl);
    }
    async function copyText(text, element) {
        try {
            await navigator.clipboard.writeText(text);
            copyStatus.textContent = tr("Copied.");
        } catch {
            if (element instanceof HTMLInputElement) {
                element.focus(); element.select();
            } else {
                const range = document.createRange();
                range.selectNodeContents(element);
                const selection = window.getSelection();
                selection.removeAllRanges(); selection.addRange(range);
            }
            copyStatus.textContent = tr("Automatic copying was blocked. The content is selected; copy it manually.");
        }
    }
    document.getElementById('copyToken')?.addEventListener('click', () => copyText(tokenInput.value, tokenInput));
    document.getElementById('copyCommand')?.addEventListener('click', () => copyText(command.textContent, command));
    apiDirectory?.addEventListener('change', updateCommand);
    resetForm?.addEventListener('submit', event => {
        if (!window.confirm(tr("Reset the API token? The old token will become invalid and existing scripts will need updating."))) event.preventDefault();
    });
    const form = document.getElementById('uploadForm');
    if (!form || !window.XMLHttpRequest || !window.FormData) return;
    const input = document.getElementById('fileInput');
    const dropzone = document.getElementById('dropzone');
    const list = document.getElementById('fileList');
    const directory = document.getElementById('directory');
    const uploadButton = document.getElementById('uploadButton');
    const logoutButton = document.getElementById('logoutButton');
    const resetTokenButton = document.getElementById('resetTokenButton');
    const stopButton = document.getElementById('stopButton');
    const errorBox = document.getElementById('clientError');
    const overall = document.getElementById('overall');
    const totalProgress = document.getElementById('totalProgress');
    const transferStatus = document.getElementById('transferStatus');
    const batchStatus = document.getElementById('batchStatus');
    const maxFileSize = <?= MAX_FILE_SIZE ?>;
    const maxFiles = <?= MAX_FILES ?>;
    const maxBatchSize = <?= MAX_BATCH_SIZE ?>;
    let busy = false;
    let stopRequested = false;
    let rows = [];
    const mib = bytes => (bytes / 1024 / 1024).toFixed(2) + ' MiB';
    directory.addEventListener('change', () => {
        if (apiDirectory) { apiDirectory.value = directory.value; updateCommand(); }
    });
    dropzone.hidden = false;
    // Use the localized, keyboard-accessible picker with JavaScript. Native
    // file controls follow the OS language; keep them for the no-JS fallback.
    input.hidden = true;
    input.required = false;

    function showError(message) {
        errorBox.textContent = message;
        errorBox.hidden = !message;
    }

    function selectionError(files) {
        if (!files.length || files.length > maxFiles) return tr("Select between 1 and 20 files.");
        let total = 0;
        for (const file of files) {
            if (!/\.(epub|txt)$/i.test(file.name)) return tr("Only EPUB and TXT files are accepted: ") + file.name;
            if (file.size < 1 || file.size > maxFileSize) return tr("The file is empty or exceeds 100 MiB: ") + file.name;
            total += file.size;
        }
        return total > maxBatchSize ? tr("This batch exceeds 200 MiB.") : '';
    }

    function showFiles() {
        list.replaceChildren();
        rows = Array.from(input.files, file => {
            const row = document.createElement('div');
            row.className = 'file-row';
            const title = document.createElement('div');
            title.textContent = file.name + ' (' + mib(file.size) + ')';
            const state = document.createElement('span');
            state.className = 'file-state';
            state.textContent = tr("Waiting");
            const progress = document.createElement('progress');
            progress.max = 100;
            progress.value = 0;
            progress.setAttribute('aria-label', file.name + tr(" transfer progress"));
            row.append(title, state, progress);
            list.appendChild(row);
            return { state, progress };
        });
        showError(input.files.length ? selectionError(Array.from(input.files)) : '');
        overall.hidden = true;
        uploadButton.disabled = false;
    }

    dropzone.addEventListener('click', () => { if (!busy) input.click(); });
    dropzone.addEventListener('keydown', event => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            if (!busy) input.click();
        }
    });
    dropzone.addEventListener('dragover', event => {
        event.preventDefault();
        if (!busy) dropzone.classList.add('dragover');
    });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone.addEventListener('drop', event => {
        event.preventDefault();
        dropzone.classList.remove('dragover');
        if (busy) return;
        try {
            input.files = event.dataTransfer.files;
            showFiles();
        } catch {
            showError(tr("Drag-and-drop selection is unavailable. Use the file picker."));
        }
    });
    input.addEventListener('change', showFiles);
    stopButton.addEventListener('click', () => {
        stopRequested = true;
        stopButton.disabled = true;
        stopButton.textContent = tr("Waiting for this file to finish...");
    });
    window.addEventListener('beforeunload', event => {
        if (busy) { event.preventDefault(); event.returnValue = ''; }
    });

    function sendFile(file, row, onProgress) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            // A named input called "action" shadows HTMLFormElement.action.
            const url = new URL(form.getAttribute('action'), window.location.href);
            url.searchParams.set('action', 'upload');
            const data = new FormData();
            data.append('csrf', form.elements.csrf.value);
            data.append('directory', directory.value);
            data.append('files[]', file, file.name);
            xhr.upload.addEventListener('progress', event => {
                if (event.lengthComputable) {
                    const ratio = Math.min(1, event.loaded / event.total);
                    row.progress.value = ratio * 100;
                    row.state.textContent = ratio < 1
                        ? tr("Uploading ") + (ratio * 100).toFixed(1) + '%'
                        : tr("Transfer complete. The server is validating and saving...");
                    onProgress(file.size * ratio);
                } else {
                    row.progress.removeAttribute('value');
                    row.state.textContent = tr("Uploading; progress is not available yet...");
                }
            });
            xhr.upload.addEventListener('load', () => {
                row.progress.value = 100;
                row.state.textContent = tr("Transfer complete. The server is validating and saving...");
                onProgress(file.size);
            });
            xhr.open('POST', url);
            xhr.responseType = 'json';
            xhr.timeout = 30 * 60 * 1000;
            xhr.setRequestHeader('Accept', 'application/json');
            xhr.setRequestHeader('X-CSRF-Token', form.elements.csrf.value);
            xhr.addEventListener('load', () => {
                const result = xhr.response;
                if (result && typeof result.success === 'boolean' && typeof result.message === 'string') {
                    resolve({ success: xhr.status === 200 && result.success, message: result.message, status: xhr.status });
                } else {
                    const message = xhr.status === 413 ? tr("The server rejected an oversized request. Check upload limits.")
                        : tr("Invalid server response (HTTP ") + xhr.status + tr("). Save status is unknown. Check the library.");
                    reject(new Error(message));
                }
            });
            for (const type of ['error', 'timeout', 'abort']) {
                xhr.addEventListener(type, () => reject(new Error(
                    type === 'timeout' ? tr("Request timed out. Save status is unknown; check the library before retrying.")
                        : tr("Connection interrupted. Save status is unknown; check the library before retrying.")
                )));
            }
            xhr.send(data); // Browser supplies the multipart boundary.
        });
    }

    form.addEventListener('submit', async event => {
        event.preventDefault();
        if (busy) return;
        const files = Array.from(input.files);
        const error = selectionError(files);
        showError(error);
        if (error) return;
        showFiles();
        busy = true;
        stopRequested = false;
        input.disabled = directory.disabled = uploadButton.disabled = logoutButton.disabled = true;
        if (resetTokenButton) resetTokenButton.disabled = true;
        dropzone.setAttribute('aria-disabled', 'true');
        stopButton.disabled = false;
        stopButton.textContent = tr("Stop after this file");
        stopButton.hidden = false;
        overall.hidden = false;
        totalProgress.value = 0;
        const total = files.reduce((sum, file) => sum + file.size, 0);
        let sent = 0, processed = 0, successes = 0, failures = 0;
        const started = performance.now();
        function updateProgress(current) {
            const bytes = Math.min(total, sent + current);
            const elapsed = Math.max(.1, (performance.now() - started) / 1000);
            totalProgress.value = bytes / total * 100;
            transferStatus.textContent = totalProgress.value.toFixed(1) + '% · '
                + mib(bytes) + ' / ' + mib(total) + tr(" · average ") + mib(bytes / elapsed) + '/s';
        }
        function updateSummary(prefix) {
            batchStatus.textContent = prefix + tr(" · processed ") + processed + '/' + files.length
                + tr(" · saved ") + successes + tr(" · failed ") + failures;
        }
        try {
            updateProgress(0);
            for (let i = 0; i < files.length; ++i) {
                const row = rows[i];
                row.state.textContent = tr("Starting upload...");
                updateSummary(tr("Processing file ") + (i + 1) + tr(" of this batch"));
                let currentSent = 0;
                try {
                    const result = await sendFile(files[i], row, bytes => {
                        currentSent = Math.max(currentSent, bytes);
                        updateProgress(currentSent);
                    });
                    row.state.textContent = result.message;
                    row.state.classList.add(result.success ? 'success' : 'failure');
                    if (result.success) ++successes; else ++failures;
                    // Stop on authentication, infrastructure or unexpected failures.
                    if (!result.success && ![400, 409, 413, 422].includes(result.status)) {
                        stopRequested = true;
                        showError(result.message);
                    }
                } catch (e) {
                    ++failures;
                    row.state.textContent = e.message;
                    row.state.classList.add('failure');
                    showError(e.message);
                    stopRequested = true;
                }
                sent += currentSent;
                ++processed;
                updateProgress(0);
                if (stopRequested) break;
            }
            for (let i = processed; i < rows.length; ++i) rows[i].state.textContent = tr("Not uploaded");
            updateSummary(processed < files.length ? tr("Queue stopped") : tr("Batch finished"));
        } finally {
            busy = false;
            input.disabled = directory.disabled = logoutButton.disabled = false;
            if (resetTokenButton) resetTokenButton.disabled = false;
            dropzone.setAttribute('aria-disabled', 'false');
            stopButton.hidden = true;
            input.value = '';
            uploadButton.disabled = true; // Select files again; do not resubmit saved files.
        }
    });
})();
</script>
</body>
</html>
