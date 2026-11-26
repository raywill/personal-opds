<?php
declare(strict_types=1);
if (!defined('BASE_URL')) { http_response_code(404); exit; }

const OPDS_LINK_MODES = ['original','reader','reader-share'];
const OPDS_REWRITE_PROBES = [
    'reader'=>['opds-link-test','library','p-opds-link-test'],
    'share'=>['s/12345678-AB12','s','12345678-AB12'],
];
const OPDS_REWRITE_TEST_QUERY = '?opds_rewrite_check=1';

function linkModeForSite(): string
{
    $file=CONFIG_DIR.'/site-links.json';
    if (!file_exists($file)&&!is_link($file)) return 'original';
    $state=stateRead('site-links');
    if (($state['base']??null)!==BASE_URL) return 'original';
    return in_array($state['mode']??null,OPDS_LINK_MODES,true)?$state['mode']:'original';
}

function activeSiteLinkMode(): string
{
    static $mode=null;
    if ($mode!==null) return $mode;
    try { return $mode=linkModeForSite(); }
    catch (Throwable $e) { error_log('OPDS: link settings unavailable.'); return $mode='original'; }
}

function readerSetupUrl(string $libraryId): string
{
    $owner=substr($libraryId,2);
    if (activeSiteLinkMode()!=='original'&&str_starts_with($libraryId,'p-')&&accountName($owner))
        return BASE_URL.$owner;
    return BASE_URL.'index.php?'.http_build_query(['library'=>$libraryId],'','&',PHP_QUERY_RFC3986);
}

function shareSetupUrl(string $key): string
{
    return activeSiteLinkMode()==='reader-share'&&preg_match('/\A[1-9]{8}-[A-Z0-9]{4}\z/D',$key)
        ? BASE_URL.'s/'.$key : BASE_URL.'index.php?s='.rawurlencode($key);
}

function nginxLinkRules(): array
{
    $prefix=parse_url(BASE_URL,PHP_URL_PATH);
    // Dot is literal in a mounted path, and brace quantifiers need quoting.
    $pattern=str_replace('.','\\.',$prefix);
    $reader='rewrite "^'.$pattern.'([a-z0-9][a-z0-9_-]{0,31})$" '.$prefix.'index.php?library=p-$1? last;';
    $share='rewrite "^'.$pattern.'s/([1-9]{8}-[A-Za-z0-9]{4})$" '.$prefix.'index.php?s=$1? last;';
    return ['reader'=>$reader,'reader-share'=>$reader."\n".$share];
}

function requireSiteLinkAdmin(): void
{
    requireUploadHttps();
    startWebSession();
    if ((webSessionAccount()['site_admin']??null)!==true) reject('Site administrator access required.',403);
}

function requireSiteLinkCsrf(mixed $token): void
{
    if (!is_string($token)||!isset($_SESSION['csrf'])||!hash_equals($_SESSION['csrf'],$token))
        reject('Session changed; reload the page.',403);
}

function requiredRewriteChecks(string $mode): array
{
    return match($mode){ 'reader'=>['reader'],'reader-share'=>['reader','share'],default=>[] };
}

function siteRewriteVerified(string $mode): bool
{
    foreach (requiredRewriteChecks($mode) as $kind) {
        $checked=$_SESSION['site_link_checks'][$kind]??[];
        if (($checked['base']??null)!==BASE_URL||($checked['at']??0)<time()-600) return false;
    }
    return true;
}

// A probe uses a synthetic route, not an existing book, user or subscription.
// It records success only when the original clean request arrived through that
// route and the internal rewrite produced the exact expected query.
function handleSiteLinkProbe(): never
{
    requireSiteLinkAdmin();
    requireSiteLinkCsrf($_SERVER['HTTP_X_OPDS_REWRITE_CSRF']??null);
    $kind=$_SERVER['HTTP_X_OPDS_REWRITE_TEST']??'';
    if (!isset(OPDS_REWRITE_PROBES[$kind])) reject('Invalid parameter.');
    [$suffix,$key,$value]=OPDS_REWRITE_PROBES[$kind];
    $expected=parse_url(BASE_URL,PHP_URL_PATH).$suffix.OPDS_REWRITE_TEST_QUERY;
    if (($_SERVER['REQUEST_URI']??'')!==$expected||$_GET!==[$key=>$value])
        reject('The request did not reach the expected rewrite.',422);
    $_SESSION['site_link_checks'][$kind]=['base'=>BASE_URL,'at'=>time()];
    session_write_close();
    header('X-OPDS-Rewrite-Verified: '.$kind);
    http_response_code(204);
    exit;
}
