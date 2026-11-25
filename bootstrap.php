<?php
declare(strict_types=1);
require_once __DIR__ . '/i18n.php';
sendUiLanguageHeaders();
ini_set('display_errors', '0');
ini_set('log_errors', '1');
umask(0077);

function bootstrapFailure(string $message): never
{
    http_response_code(503);
    if (defined('OPDS_JSON_BOOTSTRAP')) {
        echo json_encode(['success' => false, 'message' => $message, 'results' => []], JSON_UNESCAPED_UNICODE);
    } else {
        if (PHP_SAPI!=='cli') header('Content-Type: text/plain; charset=UTF-8');
        echo $message;
    }
    exit;
}

// The configured address supplies a trusted HTTPS origin, not a binding to
// the installation folder. HTTP_HOST and forwarding headers are not trusted.
function publicAppBase(string $configured): string
{
    $cli=PHP_SAPI==='cli';
    $override=$cli?getenv('OPDS_BASE_URL'):false;
    $address=$override!==false&&$override!==''?$override:$configured;
    $base=parse_url($address);
    if (!$base || ($base['scheme']??'')!=='https' ||
        !preg_match('/\A(?:[a-z0-9.-]+|\[[0-9a-f:]+\])\z/iD',$base['host']??'') ||
        isset($base['user']) || isset($base['pass']) || isset($base['query']) || isset($base['fragment']) ||
        !filter_var($address,FILTER_VALIDATE_URL)) bootstrapFailure(tr('Invalid public site address.'));
    $origin='https://'.$base['host'].(isset($base['port'])?':'.$base['port']:'');
    if ($cli) {
        $path=rtrim($base['path']??'','/').'/';
    } else {
        // SCRIPT_NAME is the web server's public path to the PHP entry point,
        // not PATH_INFO, the underlying filesystem path, or a proxy header.
        $script=$_SERVER['SCRIPT_NAME']??'';
        if (!is_string($script)||!preg_match('~\A((?:/[a-zA-Z0-9._-]+)*/)(?:up|api|index)\.php\z~D',$script,$parts))
            bootstrapFailure(tr('Cannot determine the public application path.'));
        $path=$parts[1];
    }
    if (!preg_match('~\A(?:/[a-zA-Z0-9._-]+)*/\z~D',$path)||preg_match('~/(?:\.|\.\.)/~',$path))
        bootstrapFailure(tr('Invalid public site address.'));
    return $origin.$path;
}

$locations=['books_dir'=>__DIR__.'/books-data', 'config_dir'=>__DIR__.'/conf'];
if (file_exists(__DIR__.'/paths.php') || is_link(__DIR__.'/paths.php')) {
    if (is_link(__DIR__.'/paths.php') || !is_file(__DIR__.'/paths.php') || !is_readable(__DIR__.'/paths.php')) {
        bootstrapFailure(tr('Invalid storage configuration.'));
    }
    $loaded=require __DIR__.'/paths.php';
    if (!is_array($loaded) || !is_string($loaded['books_dir']??null) || !is_string($loaded['config_dir']??null)
        || !str_starts_with($loaded['books_dir'],'/') || !str_starts_with($loaded['config_dir'],'/')) {
        bootstrapFailure(tr('Invalid storage configuration.'));
    }
    $locations=$loaded;
}
if (!is_file($locations['config_dir'].'/installed.lock') || is_link($locations['config_dir'])
    || is_link($locations['config_dir'].'/config.php')) {
    bootstrapFailure(tr('Not installed. Run install.php first.'));
}
$settings = require $locations['config_dir'].'/config.php';
if (!is_array($settings) || ($settings['max_category_depth'] ?? 0) !== 1) {
    bootstrapFailure(tr('Only one category level is enabled in this release.'));
}
if (($settings['multiuser']??false)!==true || !is_string($settings['share_key']??null)) {
    bootstrapFailure(tr('This release requires a new private multiuser installation.'));
}
if (PHP_SAPI!=='cli') {
    $doc=realpath((string)($_SERVER['DOCUMENT_ROOT']??''));
    foreach ($locations as $location) {
        $real=realpath($location);
        if ($doc===false || $real===false || $real===$doc || str_starts_with($real,rtrim($doc,'/').'/'))
            bootstrapFailure(tr('Library data must be outside the web root.'));
    }
}
define('SHARE_KEY', $settings['share_key']);
define('BASE_URL', publicAppBase(is_string($settings['base_url']??null)?$settings['base_url']:''));
define('LIBRARY_TITLE', $settings['title']);
define('MAX_CATEGORY_DEPTH', $settings['max_category_depth']);
define('DATA_DIR', $locations['books_dir']);
define('CONFIG_DIR', $locations['config_dir']);
define('PASSWORD_FILE', CONFIG_DIR . '/pass.conf');
define('CONFIG_LOCK_FILE', CONFIG_DIR . '/.config.lock');
define('RATE_STATE_FILE', CONFIG_DIR . '/.rate.json');
define('PUBLIC_UPLOAD_URL', BASE_URL . 'api.php');
define('COOKIE_PATH', parse_url(BASE_URL, PHP_URL_PATH) ?: '/');
const MAX_FILE_SIZE = 100 * 1024 * 1024;
const MAX_FILES = 20;
const MAX_BATCH_SIZE = 200 * 1024 * 1024;
const MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024;
const MAX_CONTAINER_SIZE = 1024 * 1024;
const LOGIN_WINDOW = 900;
const LOGIN_IP_LIMIT = 10;
const LOGIN_GLOBAL_LIMIT = 100;
const SESSION_IDLE_TTL = 1800;
const SESSION_ABSOLUTE_TTL = 43200;
const MAX_CONCURRENT_UPLOADS = 2;
const MIN_FREE_SPACE = 64 * 1024 * 1024;
