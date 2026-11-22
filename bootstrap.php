<?php
declare(strict_types=1);
require_once __DIR__ . '/i18n.php';
ini_set('display_errors', '0');
ini_set('log_errors', '1');
umask(0077);
if (!is_file(__DIR__ . '/conf/installed.lock') || is_link(__DIR__ . '/conf')
    || is_link(__DIR__ . '/conf/config.php')) {
    http_response_code(503);
    exit(tr('Not installed. Run install.php first.'));
}
$settings = require __DIR__ . '/conf/config.php';
if (!is_array($settings) || ($settings['max_category_depth'] ?? 0) !== 1) {
    http_response_code(503);
    exit(tr('Only one category level is enabled in this release.'));
}
define('BASE_URL', $settings['base_url']);
define('LIBRARY_TITLE', $settings['title']);
define('MAX_CATEGORY_DEPTH', $settings['max_category_depth']);
define('DATA_DIR', __DIR__ . '/books-data');
define('CONFIG_DIR', __DIR__ . '/conf');
define('PASSWORD_FILE', CONFIG_DIR . '/pass.conf');
define('CONFIG_LOCK_FILE', CONFIG_DIR . '/.config.lock');
define('RATE_STATE_FILE', CONFIG_DIR . '/.rate.json');
define('PUBLIC_UPLOAD_URL', BASE_URL . 'up.php');
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
