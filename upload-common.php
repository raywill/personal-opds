<?php
declare(strict_types=1);

// Shared upload processing for the browser and API entry points.

function requireUploadHttps(): void
{
    // The server sets HTTPS. A client forwarding header cannot override it.
    if (!in_array(strtolower((string) ($_SERVER['HTTPS'] ?? '')), ['on', '1'], true)) {
        reject(tr('HTTPS is required. Check the TLS endpoint and FastCGI HTTPS configuration.'));
    }
}

function publicError(Throwable $error): string
{
    if ($error instanceof RequestError) {
        return tr($error->getMessage());
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

function saveUpload(string $tmpPath, string $filename, string $directoryName,?array &$quota): bool
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
        if (!is_link($target) && is_file($target) && filesize($target)===$size) {
            $existing=hash_file('sha256',$target); $incoming=hash_file('sha256',$tmpPath);
            if (is_string($existing) && is_string($incoming) && hash_equals($existing,$incoming)) return false;
        }
        reject(tr('File already exists; not overwritten: ') . $filename, 409);
    }
    enforceAccountQuota($size,$quota);
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
    $quota['bytes']+=$size; $quota['files']++;
    return true;
}

function receiveUploads(string $directory, bool $singleFile,bool $create): array
{
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
    $destination = $create && $directory!=='' ? createCategory($directory) : resolveDestinationDirectory($directory);
    $free = disk_free_space($destination);
    if ($free === false || $free - $total < MIN_FREE_SPACE) {
        reject(tr('Insufficient library disk space.'), 507);
    }
    $messages = []; $quota=null;
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
            $saved=saveUpload($files['tmp_name'][$i], $files['name'][$i], $directory,$quota);
            $messages[] = ['name' => $files['name'][$i], 'success' => true,
                'text' => ($saved?tr('Saved: '):tr('Already exists: ')) . $files['name'][$i], 'status' => 200, 'already_exists'=>!$saved];
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
    return withLock('books-'.accountScope(),function () use ($directory,$singleFile,$bearer) {
        $slot=acquireUploadSlot();
        try { return receiveUploads($directory,$singleFile,$bearer); }
        finally { fclose($slot); }
    });
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
        if (in_array(500,$codes,true)) {
            $status = 500;
        }
    }
    $message = count($messages) === 1 ? $messages[0]['text']
        : tr('Saved ') . $successes . '/' . count($messages) . tr(' files; saved files are not rolled back.');
    jsonResponse([
        'success' => $success, 'message' => $message,
        'results' => array_map(static fn (array $m): array => [
            'name' => $m['name'], 'success' => $m['success'], 'message' => $m['text'], 'status' => $m['status'], 'already_exists'=>$m['already_exists']??false,
        ], $messages),
    ], $status);
}
