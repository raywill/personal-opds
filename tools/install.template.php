<?php
declare(strict_types=1);
// Set a fresh, private installation code BEFORE uploading this file.
// At least 24 characters; never publish your configured installation code.
const INSTALL_KEY = '';
const PAYLOAD = '__OPDS_PAYLOAD__';
/*__OPDS_I18N__*/
ini_set('display_errors','0'); ini_set('log_errors','1'); umask(0077);
header('Content-Type: text/html; charset=UTF-8'); header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff'); header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
$nonce=base64_encode(random_bytes(24));
header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$nonce'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
function esc(string $s): string { return htmlspecialchars($s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
function stopInstall(string $message): never { throw new RuntimeException($message); }
function input(string $key): string {
    $v=$_POST[$key]??''; if (!is_string($v) || strlen($v)>8192) stopInstall(tr('Invalid form parameter.')); return $v;
}
function categoryName(string $name): bool {
    return $name!=='' && $name[0]!=='.' && strlen($name)<=240 && trim($name)===$name
        && preg_match('//u',$name)===1 && !preg_match('~[/\\\\\x00-\x1F\x7F]~',$name);
}
function baseUrl(string $url): string {
    $p=parse_url($url);
    if (!$p || !filter_var($url,FILTER_VALIDATE_URL) || ($p['scheme']??'')!=='https'
        || empty($p['host']) || isset($p['user']) || isset($p['pass']) || isset($p['query']) || isset($p['fragment'])
        || preg_match('/[\x00-\x20\x7f]/',$url) || str_contains($url,'\\')) stopInstall(tr('BASE_URL must be the HTTPS URL of this installation directory, without a query string.'));
    return rtrim($url,'/').'/';
}
function probe(string $url): array {
    $context=stream_context_create(['http'=>['timeout'=>8,'follow_location'=>0,'max_redirects'=>0,
        'ignore_errors'=>true,'header'=>"Cache-Control: no-cache\r\nConnection: close\r\n"],
        'ssl'=>['verify_peer'=>true,'verify_peer_name'=>true,'allow_self_signed'=>false]]);
    $http_response_header=[];
    $body=@file_get_contents($url,false,$context,0,4096);
    $status=0;
    foreach ($http_response_header as $line) if (preg_match('~^HTTP/\S+\s+(\d{3})~',$line,$m)) $status=(int)$m[1];
    return [$status,$body];
}
function writeNew(string $path,string $value,array &$created,int $mode=0600): void {
    if (file_exists($path) || is_link($path)) stopInstall(tr('The installation target already exists; nothing was overwritten.'));
    $h=@fopen($path,'x+b'); if (!$h) stopInstall(tr('Cannot create a file. Check installation directory permissions.'));
    $created[]=$path;
    try {
        if (!chmod($path,$mode)) stopInstall(tr('Cannot set file permissions.'));
        $offset=0;
        while ($offset<strlen($value)) { $n=fwrite($h,substr($value,$offset)); if (!$n) stopInstall(tr('Cannot write file.')); $offset+=$n; }
        if (!fflush($h) || !fsync($h)) stopInstall(tr('Cannot synchronize file.'));
    } finally { fclose($h); }
}
function environmentErrors(): array {
    $errors=[];
    if (PHP_VERSION_ID<80100 || PHP_INT_SIZE<8) $errors[]=tr('64-bit PHP 8.1+ is required. Use a supported, patched release in production.');
    foreach (['ZipArchive','DOMDocument','SimpleXMLElement'] as $class) if (!class_exists($class)) $errors[]=tr('Missing extension: ').$class;
    foreach (['session_start','gzdecode','filter_var','fsync'] as $f) if (!function_exists($f)) $errors[]=tr('Missing PHP function: ').$f;
    if (!ini_get('allow_url_fopen') || !in_array('https',stream_get_wrappers(),true)) $errors[]=tr('Installation checks require allow_url_fopen and HTTPS streams (OpenSSL).');
    if ((int)ini_get('max_file_uploads')<21) $errors[]=tr('Set max_file_uploads=21; the application limit is still 20 files.');
    if ((bool)ini_get('session.upload_progress.enabled')) $errors[]=tr('Set session.upload_progress.enabled=0 in PHP configuration.');
    if (!is_writable(__DIR__)) $errors[]=tr('PHP needs write access to the installation directory during setup.');
    return $errors;
}
$error=''; $done=false; $url=''; $sessionReady=false;
$root=__DIR__; $conf=$root.'/conf';
// tools/install.template.php is only a build input. The generated install.php
// runs in the deployment root; the payload has no external download dependency.
if (is_file($conf.'/installed.lock')) { http_response_code(403); exit(tr('Already installed. Setup is locked. Delete install.php.')); }
try {
    if (!in_array(strtolower((string)($_SERVER['HTTPS']??'')),['on','1'],true)) stopInstall(tr('HTTPS is required for setup. Configure the server HTTPS state at your trusted proxy.'));
    if (!in_array($_SERVER['REQUEST_METHOD']??'GET',['GET','POST'],true)) { header('Allow: GET, POST'); stopInstall(tr('Method not allowed.')); }
    if (strlen(INSTALL_KEY)<24 || strlen(INSTALL_KEY)>128) stopInstall(tr('Set a private INSTALL_KEY of at least 24 characters at the top of install.php first.'));
    ini_set('session.use_strict_mode','1'); ini_set('session.use_only_cookies','1');
    session_name('OPDS_INSTALL_SESSION');
    session_set_cookie_params(['secure'=>true,'httponly'=>true,'samesite'=>'Strict','path'=>'/']);
    if (!session_start()) stopInstall(tr('Cannot start the installation session.'));
    $sessionReady=true; $_SESSION['install_csrf']??=bin2hex(random_bytes(32));
    if (($_SERVER['REQUEST_METHOD']??'GET')==='POST') {
        if (!hash_equals($_SESSION['install_csrf'],input('csrf'))) stopInstall(tr('Invalid request token. Refresh.'));
        if (!hash_equals(hash('sha256',INSTALL_KEY),hash('sha256',input('install_key')))) stopInstall(tr('Incorrect installation code.'));
        $problems=environmentErrors(); if ($problems) stopInstall(implode('；',$problems));
        $url=baseUrl(input('base_url')); $title=trim(input('title'));
        if ($title==='' || strlen($title)>200 || preg_match('//u',$title)!==1 || preg_match('/[\x00-\x1f\x7f]/',$title)) stopInstall(tr('Invalid library name.'));
        $password=input('password');
        if (strlen($password)<12 || strlen($password)>72 || str_contains($password,"\0") || $password!==input('password_confirm')) stopInstall(tr('Use a 12-72 byte password and enter it identically twice.'));
        $categories=array_values(array_unique(array_filter(array_map('trim',preg_split('/\r\n|\n|\r/',input('categories'))?:[]),static fn($s)=>$s!=='')));
        if (!$categories || count($categories)>20) stopInstall(tr('Enter 1-20 top-level categories, one per line.'));
        foreach ($categories as $category) if (!categoryName($category)) stopInstall(tr('Invalid category name. Only one category level is currently allowed.'));
        $lockPath=$root.'/.opds-install.lock';
        if (is_link($lockPath)) stopInstall(tr('Invalid installation lock path.'));
        $lock=fopen($lockPath,'c+b'); if (!$lock || !flock($lock,LOCK_EX|LOCK_NB)) stopInstall(tr('Another installation is running.'));
        $created=[]; $dirs=[]; $probeFiles=[]; $oldRootMode=null;
        try {
            clearstatcache(true);
            if (is_file($conf.'/installed.lock')) stopInstall(tr('Already installed; reinitialization is not allowed.'));
            if (is_link($conf) || (file_exists($conf) && !is_dir($conf))) stopInstall(tr('Invalid configuration directory.'));
            if (!is_dir($conf)) { if (!mkdir($conf,0700)) stopInstall(tr('Cannot create configuration directory.')); $dirs[]=$conf; }
            if (!chmod($conf,0700)) stopInstall(tr('Cannot protect configuration directory.'));
            foreach (['pass.conf','config.php','installed.lock'] as $name) if (file_exists($conf.'/'.$name) || is_link($conf.'/'.$name)) stopInstall(tr('Existing configuration was not overwritten.'));
            $deny="Require all denied\n";
            if (!file_exists($conf.'/.htaccess')) writeNew($conf.'/.htaccess',$deny,$created);
            elseif (is_link($conf.'/.htaccess') || file_get_contents($conf.'/.htaccess')!==$deny) stopInstall(tr('Existing directory protection differs and was not overwritten.'));
            $id=bin2hex(random_bytes(24));
            foreach ([$root.'/install-check-'.$id.'.txt',$conf.'/pass.conf',$conf.'/access-check-'.$id.'.txt'] as $path) {
                writeNew($path,$id,$probeFiles);
            }
            [$status,$body]=probe($url.'install-check-'.$id.'.txt');
            if ($status!==200 || $body!==$id) stopInstall(tr('BASE_URL does not point to this installation, or HTTPS self-access with a valid certificate failed.'));
            foreach (['pass.conf','access-check-'.$id.'.txt'] as $name) {
                [$status]=probe($url.'conf/'.$name);
                if (!in_array($status,[403,404],true)) stopInstall(tr('HTTP access to conf is not blocked. Apply the protection rules below. No credentials were stored.'));
            }
            foreach ($probeFiles as $path) unlink($path); $probeFiles=[];
            $decoded=gzdecode(base64_decode(PAYLOAD,true) ?: '');
            $payload=$decoded===false ? null : json_decode($decoded,true,16,JSON_THROW_ON_ERROR);
            if (!is_array($payload) || array_keys($payload)!==['i18n.php','bootstrap.php','security.php','index.php','up.php','LICENSE','NOTICE']) stopInstall(tr('The installation payload is damaged.'));
            foreach ($payload as $name=>$entry) {
                $content=base64_decode($entry['content'],true);
                if (!is_string($content) || !hash_equals($entry['sha256'],hash('sha256',$content))) stopInstall(tr('Installation payload checksum mismatch.'));
                $path=$root.'/'.$name;
                if (is_link($path)) stopInstall(tr('Installation files must not be symbolic links.'));
                if (file_exists($path)) { if (!is_file($path) || !hash_equals(hash_file('sha256',$path),$entry['sha256'])) stopInstall(tr('Different application files already exist. Nothing was overwritten. Use an empty directory.')); }
                else writeNew($path,$content,$created,0640);
            }
            $data=$root.'/books-data';
            if (is_link($data) || (file_exists($data) && !is_dir($data))) stopInstall(tr('Invalid library directory.'));
            if (!is_dir($data)) { if (!mkdir($data,0750)) stopInstall(tr('Cannot create library directory.')); $dirs[]=$data; }
            $oldRootMode=fileperms($data)&0777;
            foreach ($categories as $category) {
                $dir=$data.'/'.$category;
                if (is_link($dir) || (file_exists($dir) && !is_dir($dir))) stopInstall(tr('Invalid existing category path.'));
                if (!is_dir($dir)) { if (!mkdir($dir,0750)) stopInstall(tr('Cannot create category.')); $dirs[]=$dir; }
                if (!is_writable($dir)) stopInstall(tr('Category is not writable.'));
            }
            if (is_link($conf.'/cache') || (file_exists($conf.'/cache') && !is_dir($conf.'/cache'))) stopInstall(tr('Invalid cache path.'));
            if (!is_dir($conf.'/cache')) { if (!mkdir($conf.'/cache',0700)) stopInstall(tr('Cannot create cache directory.')); $dirs[]=$conf.'/cache'; }
            $config=['base_url'=>$url,'title'=>$title,'max_category_depth'=>1];
            writeNew($conf.'/config.php',"<?php\nreturn ".var_export($config,true).";\n",$created);
            writeNew($conf.'/pass.conf','password='.password_hash($password,PASSWORD_DEFAULT)."\napi_token=".bin2hex(random_bytes(32))."\n",$created);
            if (!chmod($data,0550)) stopInstall(tr('Cannot protect library root.'));
            clearstatcache(true,$data); if (is_writable($data)) stopInstall(tr('Do not run PHP as root. The filesystem must enforce directory permissions.'));
            writeNew($conf.'/installed.lock',"installed\n",$created);
            $done=true; $_SESSION=[]; session_destroy();
        } catch (Throwable $e) {
            foreach (array_reverse($created) as $path) @unlink($path);
            if ($oldRootMode!==null) @chmod($root.'/books-data',$oldRootMode);
            foreach (array_reverse($dirs) as $dir) { @chmod($dir,0700); @rmdir($dir); }
            throw $e;
        } finally {
            foreach ($probeFiles as $path) @unlink($path);
            flock($lock,LOCK_UN); fclose($lock);
        }
    }
} catch (Throwable $e) {
    http_response_code(400);
    $error=$e instanceof JsonException ? tr('Invalid installation payload format.') : $e->getMessage();
}
$host=(string)($_SERVER['HTTP_HOST']??'localhost');
$script=(string)($_SERVER['SCRIPT_NAME']??'/install.php');
$guess='https://'.$host.rtrim(str_replace('\\','/',dirname($script)),'/.').'/';
?>
<!doctype html><html lang="<?=uiLanguage() === 'zh' ? 'zh-CN' : 'en'?>"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title><?=tr_html('Install your OPDS library')?></title>
<style nonce="<?=esc($nonce)?>">*{box-sizing:border-box}body{margin:0;padding:32px 16px;background:#f5f6f8;color:#222;font:16px/1.6 system-ui}main{max-width:680px;margin:auto;padding:28px;background:white;border-radius:14px}h1{font-size:24px}label{display:block;margin-top:16px}input,textarea,button{width:100%;padding:12px;border:1px solid #ddd;border-radius:8px;font:inherit}button{margin-top:24px;background:#222;color:white}.error{padding:12px;background:#ffecec;color:#900;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f6f8;padding:12px}small{color:#666}a{color:#146c43}</style>
<main><h1><?= $done ? tr('Installation complete') : tr('Install your OPDS library') ?></h1>
<?php if ($done): ?>
<p><?=tr_html('Directories, configuration, and application files are ready. Setup is locked. Delete install.php.')?></p><p><a href="<?=esc($url.'index.php')?>"><?=tr_html('Open OPDS catalog')?></a> · <a href="<?=esc($url.'up.php')?>"><?=tr_html('Open uploader')?></a></p><p><?=tr_html('Sign in with the password you just set. Use CLI / API in the upper-right corner to copy your token and agent command.')?></p>
<?php else: ?>
<?php if ($error!==''): ?><p class="error" role="alert"><?=esc($error)?></p><?php endif; ?>
<p><?=tr_html('Set your library name, upload password, and categories. Application files, configuration, cache, and the installation lock are generated automatically. Different existing files are never overwritten.')?></p>
<?php foreach (environmentErrors() as $problem): ?><p class="error"><?=esc($problem)?></p><?php endforeach; ?>
<?php if ($sessionReady): ?><form method="post">
<input type="hidden" name="csrf" value="<?=esc($_SESSION['install_csrf'])?>">
<label><?=tr_html('One-time installation code')?><input type="password" name="install_key" required autocomplete="off"></label>
<label><?=tr_html('Library name')?><input name="title" value="<?=esc(isset($_POST['title'])&&is_string($_POST['title'])?$_POST['title']:tr('My Library'))?>" required maxlength="100"></label>
<label>BASE_URL<input type="url" name="base_url" value="<?=esc(isset($_POST['base_url'])&&is_string($_POST['base_url'])?$_POST['base_url']:$guess)?>" required></label><small><?=tr_html('Check that this URL points to the installation directory. Use HTTPS and a trailing /.')?></small>
<label><?=tr_html('Upload password')?><input type="password" name="password" required autocomplete="new-password"></label>
<label><?=tr_html('Confirm password')?><input type="password" name="password_confirm" required autocomplete="new-password"></label><small><?=tr_html('12-72 bytes. The password is stored as a hash; an API token is generated randomly.')?></small>
<label><?=tr_html('Initial categories (one per line)')?><textarea name="categories" rows="4" required><?=esc(isset($_POST['categories'])&&is_string($_POST['categories'])?$_POST['categories']:'books')?></textarea></label>
<button type="submit"><?=tr_html('Check and install')?></button></form><?php endif; ?>
<details><summary><?=tr_html('Server configuration and directory protection')?></summary>
<p><?=tr_html('The installer writes conf/.htaccess for Apache, which must allow it to take effect. With Nginx, deny HTTP access to this installation\'s conf directory. Example for /opds/:')?></p>
<pre>location = /opds/conf { return 404; }
location ^~ /opds/conf/ { deny all; }</pre>
<p><?=tr_html('Only configuration requires protection here; direct book downloads remain allowed. HTTPS probes verify the base URL and configuration protection before storing credentials. The server needs HTTPS self-access with a trusted certificate.')?></p>
<pre>upload_max_filesize = 100M
post_max_size = 205M
max_file_uploads = 21
session.upload_progress.enabled = 0</pre>
<p><?=tr_html('PHP needs ZIP, DOM, SimpleXML, session, filter, and zlib. HTTPS probes need OpenSSL and allow_url_fopen. The upload location must pass HTTP_AUTHORIZATION and HTTPS, with client_max_body_size 205m. Setup needs at least two PHP workers so self-check requests can complete.')?></p>
</details><?php endif; ?></main></html>
