<?php
declare(strict_types=1);

define('OPDS_JSON_BOOTSTRAP', true);
header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/security.php';
require __DIR__ . '/upload-common.php';

function verifyUploadToken(): void
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
}

try {
    requireUploadHttps();
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        header('Allow: POST');
        reject(tr('The upload endpoint only accepts POST.'), 405);
    }
    verifyUploadToken();
    uploadJsonResponse(processUpload(singleFile: false, bearer: true));
} catch (Throwable $error) {
    jsonResponse([
        'success' => false,
        'message' => publicError($error),
        'results' => [],
    ], $error instanceof RequestError ? $error->getCode() : 500);
}
