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
require __DIR__ . '/accounts.php';

function verifyUploadToken(): array
{
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (isset($_SERVER['HTTP_AUTHORIZATION'], $_SERVER['REDIRECT_HTTP_AUTHORIZATION'])
        && $_SERVER['HTTP_AUTHORIZATION'] !== $_SERVER['REDIRECT_HTTP_AUTHORIZATION']) {
        reject(tr('Ambiguous Authorization headers.'), 401);
    }
    if (!is_string($header) || strlen($header) > 128
        || preg_match('/\ABearer ([a-z0-9.]+)\z/iD', $header, $match) !== 1
        || ($scope=agentScope($match[1]))===null) {
        reserveRateAttempt('invalid-token', 30, 300);
        header('WWW-Authenticate: Bearer realm="opds-upload"');
        reject(tr('Missing or invalid API token. Use the Authorization: Bearer header.'), 401);
    }
    setAccountScope($scope['user']);
    setLibraryScope($scope['library']);
    $GLOBALS['opdsUploadGuard']=static function () use ($match,$scope) {
        $check=agentScope($match[1]);
        if (!$check || $check['library']['id']!==$scope['library']['id']) reject('Upload authorization changed.',403);
    };
    // A Bearer token can upload only. It cannot access the UI or rotate itself.
    if (array_diff(array_keys($_GET), ['action'])) {
        reject(tr('URL parameters are not accepted. Send credentials only in the Authorization header.'));
    }
    if (isset($_GET['action']) && !in_array($_GET['action'],['upload','verify'],true)) {
        reject(tr('This API only supports file uploads.'), 403);
    }
    return $scope;
}

try {
    requireUploadHttps();
    $method=$_SERVER['REQUEST_METHOD']??'GET';
    $verify=($_GET['action']??'')==='verify';
    if ($method!==($verify?'GET':'POST')) {
        header('Allow: '.($verify?'GET':'POST'));
        reject($verify?'Verification only accepts GET.':tr('The upload endpoint only accepts POST.'),405);
    }
    $scope=verifyUploadToken();
    if ($verify) {
        lockBookRead();
        if ($scope['fixed']) requireVisibleFolder($scope['dir']);
        $profile=['success'=>true,'library_id'=>$scope['library']['id'],
            'directory'=>$scope['fixed']?$scope['dir']:null,'can_create_directory'=>$scope['mkdir'],'expires_at'=>$scope['expires']?gmdate(DATE_ATOM,$scope['expires']):null];
        if (!empty($scope['folder_names'])) $profile['folders']=agentFolderNames();
        jsonResponse($profile);
    }
    uploadJsonResponse(processUpload(singleFile:false,bearer:true,scope:$scope));
} catch (Throwable $error) {
    jsonResponse([
        'success' => false,
        'message' => publicError($error),
        'results' => [],
    ], $error instanceof RequestError ? $error->getCode() : 500);
}
