<?php
declare(strict_types=1);
const PAYLOAD = '__OPDS_PAYLOAD__';
/*__OPDS_I18N__*/
ini_set('display_errors','0'); ini_set('log_errors','1'); umask(0077);
header('Content-Type: text/html; charset=UTF-8'); header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff'); header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
$nonce=base64_encode(random_bytes(24));
header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$nonce'; script-src 'nonce-$nonce'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
function esc(string $s): string { return htmlspecialchars($s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
function stopInstall(string $message): never { throw new RuntimeException($message); }
function input(string $key): string {
    $v=$_POST[$key]??''; if (!is_string($v) || strlen($v)>8192) stopInstall(tr('Invalid form parameter.')); return $v;
}
function baseUrl(string $url): string {
    $p=parse_url($url);
    if (!$p || !filter_var($url,FILTER_VALIDATE_URL) || ($p['scheme']??'')!=='https'
        || empty($p['host']) || isset($p['user']) || isset($p['pass']) || isset($p['query']) || isset($p['fragment'])
        || preg_match('/[\x00-\x20\x7f]/',$url) || str_contains($url,'\\')) stopInstall(tr('BASE_URL must be the HTTPS URL of the web application directory, without a query string.'));
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
    return $errors;
}
final class InstallProblem extends RuntimeException {
    public function __construct(string $message, public array $commands = []) { parent::__construct($message); }
}
function shellArg(string $s): string { return "'".str_replace("'", "'\"'\"'", $s)."'"; }
function phpProcessIds(bool $installing = false): ?array {
    if (function_exists('posix_geteuid') && function_exists('posix_getegid')) {
        return ['uid'=>posix_geteuid(), 'gid'=>posix_getegid()];
    }
    if (PHP_OS_FAMILY==='Linux' && ($status=@file_get_contents('/proc/self/status'))!==false
        && preg_match('/^Uid:\s+\d+\s+(\d+)/m',$status,$uid)
        && preg_match('/^Gid:\s+\d+\s+(\d+)/m',$status,$gid)) {
        return ['uid'=>(int)$uid[1], 'gid'=>(int)$gid[1]];
    }
    if (!$installing) return null;
    $tmp=@tmpfile(); if (!$tmp) return null;
    $stat=fstat($tmp); fclose($tmp);
    return $stat && isset($stat['uid'],$stat['gid']) ? ['uid'=>$stat['uid'],'gid'=>$stat['gid']] : null;
}
function directoryAdvice(string $path): array {
    $owner='PHP_USER:PHP_GROUP';
    $ids=phpProcessIds(); if ($ids) $owner=$ids['uid'].':'.$ids['gid'];
    $commands=[];
    if (!is_dir($path)) $commands[]='sudo mkdir -p -- '.shellArg($path);
    $commands[]='sudo chown -- '.shellArg($owner).' '.shellArg($path);
    $commands[]='sudo chmod u+rwx -- '.shellArg($path);
    return $commands;
}
function targetPath(string $path): string {
    $path=rtrim(trim($path),'/');
    if ($path==='' || $path[0]!=='/' || strlen($path)>4096 || preg_match('/[\\\\\x00-\x1f\x7f]/',$path)) stopInstall(tr('Use an absolute data directory path.'));
    $cursor='';
    foreach (explode('/',substr($path,1)) as $part) {
        if ($part==='' || $part==='.' || $part==='..') stopInstall(tr('The data directory path contains an invalid component.'));
        $cursor.='/'.$part;
        if (is_link($cursor) || (file_exists($cursor) && !is_dir($cursor))) stopInstall(tr('The data directory path must not contain symbolic links or files.'));
    }
    return $path;
}
function makeDirectory(string $path,int $mode,array &$createdDirs): void {
    if (is_dir($path)) return;
    $parent=dirname($path);
    if (!is_dir($parent)) makeDirectory($parent,0755,$createdDirs);
    if (!is_writable($parent) || !@mkdir($path,$mode)) throw new InstallProblem(tr('Create this directory and allow PHP to write to it: ').$path,directoryAdvice($path));
    $createdDirs[]=$path;
}
function writableDirectory(string $path): void {
    clearstatcache(true,$path);
    if (!is_writable($path)) throw new InstallProblem(tr('Allow PHP to write to this directory: ').$path,directoryAdvice($path));
}
function setupLocked(string $root): bool {
    clearstatcache(true);
    foreach ([__DIR__.'/install.lock',__DIR__.'/conf/installed.lock',$root.'/install.lock',$root.'/conf/installed.lock',$root.'/paths.php'] as $path) {
        if (file_exists($path) || is_link($path)) return true;
    }
    return false;
}
function insideDirectory(string $path,string $parent): bool {
    return $path===$parent || str_starts_with($path,rtrim($parent,'/').'/');
}
function storageLayout(string $webRoot): array {
    $mode=input('storage_mode') ?: 'external';
    if ($mode!=='external') stopInstall(tr('Invalid storage mode.'));
    $dataRoot=targetPath(input('data_dir'));
    $documentRoot=(string)($_SERVER['DOCUMENT_ROOT']??'');
    $documentRoot=$documentRoot!==''?realpath($documentRoot):false;
    if ($documentRoot===false || !is_dir($documentRoot)) stopInstall(tr('Cannot verify the document root. Configure DOCUMENT_ROOT correctly.'));
    if (insideDirectory($dataRoot,$documentRoot) || insideDirectory($dataRoot,$webRoot)) stopInstall(tr('Choose a separate data directory outside the document root and web application directory: ').$documentRoot);
    foreach ([$webRoot,__DIR__] as $site) {
        if (insideDirectory($site,$dataRoot.'/books') || insideDirectory($site,$dataRoot.'/conf')) stopInstall(tr('Book and configuration directories must not contain web application files.'));
    }
    return ['mode'=>'external','root'=>$dataRoot,'books'=>$dataRoot.'/books','conf'=>$dataRoot.'/conf'];
}
function payloadFiles(string $root): array {
    $decoded=gzdecode(base64_decode(PAYLOAD,true) ?: '');
    $payload=$decoded===false ? null : json_decode($decoded,true,16,JSON_THROW_ON_ERROR);
    if (!is_array($payload) || array_keys($payload)!==['i18n.php','bootstrap.php','security.php','index.php','up.php','api.php','upload-common.php','accounts.php','catalogue.php','admin.php','LICENSE','NOTICE']) stopInstall(tr('The installation payload is damaged.'));
    $files=[];
    foreach ($payload as $name=>$entry) {
        $content=base64_decode($entry['content'],true);
        if (!is_string($content) || !hash_equals($entry['sha256'],hash('sha256',$content))) stopInstall(tr('Installation payload checksum mismatch.'));
        $path=$root.'/'.$name;
        if (is_link($path)) stopInstall(tr('Installation files must not be symbolic links.'));
        if (file_exists($path) && (!is_file($path) || !is_readable($path) || !hash_equals(hash_file('sha256',$path),$entry['sha256']))) stopInstall(tr('Different application files already exist. Nothing was overwritten. Use an empty directory.'));
        $files[$name]=$content;
    }
    return $files;
}
function inspectDirectoryTarget(string $path, string $invalidMessage): void {
    if (is_link($path) || (file_exists($path) && !is_dir($path))) stopInstall(tr($invalidMessage));
    $existing=$path;
    while (!is_dir($existing) && dirname($existing)!==$existing) $existing=dirname($existing);
    writableDirectory($existing);
}
function inspectConfiguration(string $conf): void {
    foreach (['pass.conf','config.php','users.json','shares.json','installed.lock'] as $name) {
        if (file_exists($conf.'/'.$name) || is_link($conf.'/'.$name)) stopInstall(tr('Existing configuration was not overwritten.'));
    }

}
function inspectSetup(string $root,array $layout,string $url,array &$results): void {
    writableDirectory($root);
    $results[]=['label'=>tr('Web application directory'),'ok'=>true,'detail'=>$root];
    if ($layout['mode']==='external') {
        inspectDirectoryTarget($layout['root'],'Invalid storage configuration.');
        $results[]=['label'=>tr('Separate data directory'),'ok'=>true,'detail'=>$layout['root']];
    }
    payloadFiles($root);
    $results[]=['label'=>tr('Application files'),'ok'=>true];
    $books=$layout['books']; $conf=$layout['conf'];
    if (is_link($books)) stopInstall(tr('Invalid library directory.'));
    if (is_dir($books)) { writableDirectory($books); if (count(scandir($books)?:[])!==2) stopInstall('Use an empty books directory, then migrate existing files separately.'); }
    else inspectDirectoryTarget($books,'Invalid library directory.');
    $results[]=['label'=>tr('Book directory permissions'),'ok'=>true,'detail'=>$books];
    inspectDirectoryTarget($conf,'Invalid configuration directory.');
    inspectConfiguration($conf);
    $results[]=['label'=>tr('Public URL format'),'ok'=>true,'detail'=>$url];
}
function setupCsrfToken(): string {
    // A host-only, SameSite cookie keeps the read-only steps free of server sessions.
    $key='__Host-OPDS_INSTALL_CSRF';
    $token=$_COOKIE[$key]??'';
    if (is_string($token) && preg_match('/\A[a-f0-9]{64}\z/D',$token)) return $token;
    $token=bin2hex(random_bytes(32));
    setcookie($key,$token,['path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Strict']);
    return $token;
}
$activationUrl=''; $error=''; $commands=[]; $done=false; $checked=false; $results=[]; $url=''; $csrf=''; $failureStep=1;
$root=__DIR__; $conf=$root.'/conf'; $books=$root.'/books-data'; $storageMode='external';
$jsonRequest=str_contains(strtolower((string)($_SERVER['HTTP_ACCEPT']??'')),'application/json');
if (setupLocked(__DIR__)) {
    http_response_code(403);
    if ($jsonRequest) { header('Content-Type: application/json'); echo json_encode(['success'=>false,'message'=>tr('Already installed. Setup is locked. Delete install.php.')]); }
    else echo esc(tr('Already installed. Setup is locked. Delete install.php.'));
    exit;
}
try {
    if (!in_array(strtolower((string)($_SERVER['HTTPS']??'')),['on','1'],true)) stopInstall(tr('HTTPS is required for setup. Configure the server HTTPS state at your trusted proxy.'));
    if (!in_array($_SERVER['REQUEST_METHOD']??'GET',['GET','POST'],true)) { header('Allow: GET, POST'); stopInstall(tr('Method not allowed.')); }
    $csrf=setupCsrfToken();
    if (($_SERVER['REQUEST_METHOD']??'GET')==='POST') {
        if (!hash_equals($csrf,input('csrf'))) stopInstall(tr('Invalid request token. Refresh.'));
        $action=input('action');
        if (!in_array($action,['check','install','back'],true)) stopInstall(tr('Invalid request action.'));
        if ($action!=='back') {
            // Application files always belong beside this installer. Client input
            // can choose private storage, never the PHP program destination.
            $root=__DIR__;
            $layout=storageLayout($root); $storageMode=$layout['mode']; $conf=$layout['conf']; $books=$layout['books'];
            if (setupLocked($root)) stopInstall(tr('Already installed; reinitialization is not allowed.'));
            $problems=environmentErrors(); if ($problems) stopInstall(implode('; ',$problems));
            $results[]=['label'=>tr('PHP requirements'),'ok'=>true];
            $url=baseUrl(input('base_url'));
            if ($action==='check') {
                inspectSetup($root,$layout,$url,$results);
                $checked=true;
            } else {
                writableDirectory(__DIR__);
                $failureStep=2;
                $username=trim(input('username'));
                if (!preg_match('/\A[a-z0-9][a-z0-9_-]{0,31}\z/D',$username)) stopInstall('Use a lowercase username with letters, numbers, underscores or hyphens.');
                $title=trim(input('title'));
                if ($title==='' || strlen($title)>200 || preg_match('//u',$title)!==1 || preg_match('/[\x00-\x1f\x7f]/',$title)) stopInstall(tr('Invalid library name.'));
                $failureStep=1;
                $lockPath=__DIR__.'/.opds-install.lock';
                if (is_link($lockPath)) stopInstall(tr('Invalid installation lock path.'));
                $lock=fopen($lockPath,'c+b'); if (!$lock || !flock($lock,LOCK_EX|LOCK_NB)) stopInstall(tr('Another installation is running.'));
                $storageLock=null; $created=[]; $dirs=[]; $probeFiles=[];
                try {
                    if (setupLocked($root)) stopInstall(tr('Already installed; reinitialization is not allowed.'));
                    makeDirectory($root,0755,$dirs); writableDirectory($root);
                    $results[]=['label'=>tr('Web application directory'),'ok'=>true,'detail'=>$root];
                    if (setupLocked($root)) stopInstall(tr('Already installed; reinitialization is not allowed.'));
                    if ($storageMode==='external') {
                        makeDirectory($layout['root'],0700,$dirs); writableDirectory($layout['root']);
                        if (is_link($layout['root'].'/.opds-install.lock')) stopInstall(tr('Invalid installation lock path.'));
                        $storageLock=fopen($layout['root'].'/.opds-install.lock','c+b');
                        if (!$storageLock || !flock($storageLock,LOCK_EX|LOCK_NB)) stopInstall(tr('Another installation is running.'));
                        $results[]=['label'=>tr('Separate data directory'),'ok'=>true,'detail'=>$layout['root']];
                    }
                    $files=payloadFiles($root);
                    $results[]=['label'=>tr('Application files'),'ok'=>true];
                    if (is_link($books) || (file_exists($books) && !is_dir($books))) stopInstall(tr('Invalid library directory.'));
                    makeDirectory($books,0750,$dirs);
                    $failureStep=2;
                    writableDirectory($books);
                    if (count(scandir($books)?:[])!==2) stopInstall('Use an empty books directory, then migrate existing files separately.');
                    $results[]=['label'=>tr('Book directory permissions'),'ok'=>true,'detail'=>$books];
                    makeDirectory($conf,0700,$dirs);
                    inspectConfiguration($conf);
                    if (!chmod($conf,0700)) stopInstall(tr('Cannot protect configuration directory.'));
                    $id=bin2hex(random_bytes(24));
                    writeNew($root.'/install-check-'.$id.'.txt',$id,$probeFiles,0644);
                    [$status,$body]=probe($url.'install-check-'.$id.'.txt');
                    if ($status!==200 || $body!==$id) stopInstall(tr('BASE_URL must point to the web application directory, not the separate data directory. HTTPS self-access with a valid certificate is also required.'));
                    $results[]=['label'=>tr('Public URL'),'ok'=>true,'detail'=>$url];
                    foreach ($probeFiles as $path) unlink($path); $probeFiles=[];
                    $failureStep=4;
                    foreach ($files as $name=>$content) {
                        if (!file_exists($root.'/'.$name)) writeNew($root.'/'.$name,$content,$created,0640);
                    }
                    if (!mkdir($books.'/'.$username,0750)) stopInstall('Cannot create the initial account library.');
                    $dirs[]=$books.'/'.$username;
                    if (is_link($conf.'/cache') || (file_exists($conf.'/cache') && !is_dir($conf.'/cache'))) stopInstall(tr('Invalid cache path.'));
                    if (!is_dir($conf.'/cache')) { if (!mkdir($conf.'/cache',0700)) stopInstall(tr('Cannot create cache directory.')); $dirs[]=$conf.'/cache'; }
                    $config=['base_url'=>$url,'title'=>$title,'max_category_depth'=>1,'multiuser'=>true,'share_key'=>bin2hex(random_bytes(32))];
                    $locations=['books_dir'=>$books,'config_dir'=>$conf];
                    writeNew($root.'/paths.php',"<?php\nreturn ".var_export($locations,true).";\n",$created);
                    writeNew($conf.'/config.php',"<?php\nreturn ".var_export($config,true).";\n",$created);
                    $secret=bin2hex(random_bytes(32));
                    $record=['state'=>'pending','activation'=>['digest'=>hash('sha256',$secret),'expires'=>time()+86400]];
                    writeNew($conf.'/users.json',json_encode(['version'=>1,'records'=>(object)[$username=>$record]],JSON_THROW_ON_ERROR),$created);
                    writeNew($conf.'/shares.json','{"version":1,"records":{}}',$created);
                    $activationUrl=$url.'up.php?'.http_build_query(['account'=>$username,'activate'=>$secret]);
                    writeNew($conf.'/installed.lock',"installed\n",$created);
                    writeNew(__DIR__.'/install.lock',"installed\n",$created);

                    $done=true;
                } finally {
                    foreach ($probeFiles as $path) @unlink($path);
                    if (!$done) {
                        foreach (array_reverse($created) as $path) @unlink($path);
                        foreach (array_reverse($dirs) as $dir) @rmdir($dir);
                    }
                    if (is_resource($storageLock)) { flock($storageLock,LOCK_UN); fclose($storageLock); }
                    flock($lock,LOCK_UN); fclose($lock);
                }
            }
        }
    }
} catch (Throwable $e) {
    http_response_code(400);
    $error=$e instanceof JsonException ? tr('Invalid installation payload format.') : $e->getMessage();
    if ($e instanceof InstallProblem) $commands=$e->commands;
    $results[]=['label'=>$error,'ok'=>false];
}
if ($jsonRequest) {
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode(['success'=>$done||$checked,'installed'=>$done,'message'=>$done?tr('Installation complete'):($checked?tr('Initial checks passed.'):$error),
        'step'=>$done?4:($checked?2:$failureStep),
        'results'=>$results,'commands'=>$commands,'activation_url'=>$done?$activationUrl:null,
        'catalog_url'=>$done?$url.'index.php':null,'upload_url'=>$done?$url.'up.php':null],JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
$host=(string)($_SERVER['HTTP_HOST']??'localhost');
$script=(string)($_SERVER['SCRIPT_NAME']??'/install.php');
$pageStep=$checked?2:($error!==''?$failureStep:1);
$documentRoot=(string)($_SERVER['DOCUMENT_ROOT']??'');
$resolvedDocumentRoot=$documentRoot!==''?realpath($documentRoot):false;
$defaultDataRoot=dirname($resolvedDocumentRoot ?: __DIR__).'/opds-data';
$guess='https://'.$host.rtrim(str_replace('\\','/',dirname($script)),'/.').'/';
?>
<!doctype html><html lang="<?=uiLanguage()==='zh'?'zh-CN':'en'?>"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?=tr_html('Set up Personal OPDS')?></title>
<style nonce="<?=esc($nonce)?>">*{box-sizing:border-box}body{margin:0;background:#f0f7f6;color:#173438;font:16px/1.55 system-ui;padding:40px 16px}main{max-width:660px;margin:auto;background:#fff;border:1px solid #dbe7e7;border-radius:20px;padding:clamp(16px,5vw,40px)}h1{margin-top:0;letter-spacing:-.04em}label{display:block;font-weight:650;margin:16px 0}input{width:100%;padding:10px;font:inherit;border-radius:8px;border:1px solid #aec5c6}button,a.action{display:inline-block;background:#076e64;color:#fff;font:inherit;padding:9px 14px;border:0;border-radius:9px;text-decoration:none;cursor:pointer}.secondary{background:#edf5f4;color:#173438}small{display:block;color:#4d666b;font-weight:400}.error{color:#9d263a}pre{white-space:pre-wrap;overflow-wrap:anywhere}a{color:#076e64}</style>
<main>
<?php if ($done): ?>
<h1><?=tr_html('Your library is installed')?></h1><p><?=tr_html('Open the one-time activation link to set your password. It expires in 24 hours.')?></p>
<a class="action" href="<?=esc($activationUrl)?>"><?=tr_html('Activate first account')?></a><p><label><?=tr_html('Activation URL')?><input readonly value="<?=esc($activationUrl)?>"></label></p>
<p>Setup is locked. Remove install.php after setup. If the link is lost, issue another from the server with <code>php admin.php invite USERNAME</code>.</p>
<?php else: ?>
<h1><?=tr_html('Set up your private OPDS library')?></h1><p><?=tr_html('Choose private storage, check the server, then install. The first user sets their own password after installation.')?></p>
<?php if ($error!==''): ?><p class="error" role="alert"><?=esc($error)?></p><?php endif;?>
<?php foreach ($results as $result): ?><p><?=esc(($result['ok']?'✓ ':'').$result['label'])?> <?=esc($result['detail']??'')?></p><?php endforeach;?>
<?php if ($commands): ?><pre><?=esc(implode("\n",$commands))?></pre><?php endif;?>
<?php if ($csrf!==''): ?><form method="post">
<input type="hidden" name="csrf" value="<?=esc($csrf)?>">
<label><?=tr_html('HTTPS application URL')?><input type="url" name="base_url" required value="<?=esc(input('base_url')?:$guess)?>"></label>
<label><?=tr_html('Private data directory')?><input name="data_dir" required value="<?=esc(input('data_dir')?:$defaultDataRoot)?>"><small><?=tr_html('Outside the web root. Use an empty books directory for new installs.')?></small></label>
<label><?=tr_html('Library name')?><input name="title" maxlength="200" value="<?=esc(input('title')?:'Personal OPDS')?>"></label>
<label><?=tr_html('First username')?><input name="username" maxlength="32" pattern="[a-z0-9][a-z0-9_-]{0,31}" value="<?=esc(input('username'))?>"><small><?=tr_html('Lowercase letters and digits; hyphen or underscore allowed.')?></small></label>
<button class="secondary" name="action" value="check"><?=tr_html('Check configuration')?></button> <button name="action" value="install"><?=tr_html('Install')?></button>
</form><?php endif;?>
<?php endif;?>
</main></html>
