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
function categoryName(string $name): bool {
    return $name!=='' && $name[0]!=='.' && strlen($name)<=240 && trim($name)===$name
        && preg_match('//u',$name)===1 && !preg_match('~[/\\\\\x00-\x1F\x7F]~',$name);
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
function directoryAdvice(string $path): array {
    $owner='PHP_USER:PHP_GROUP';
    $tmp=@tmpfile();
    if ($tmp) { $stat=fstat($tmp); fclose($tmp); if ($stat && isset($stat['uid'],$stat['gid'])) $owner=$stat['uid'].':'.$stat['gid']; }
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
    $mode=input('storage_mode') ?: 'local';
    if ($mode==='local') return ['mode'=>'local','root'=>$webRoot,'books'=>$webRoot.'/books-data','conf'=>$webRoot.'/conf'];
    if ($mode!=='external') stopInstall(tr('Invalid storage mode.'));
    $dataRoot=targetPath(input('data_dir'));
    $documentRoot=(string)($_SERVER['DOCUMENT_ROOT']??'');
    $documentRoot=$documentRoot!==''?realpath($documentRoot):false;
    if ($documentRoot===false || !is_dir($documentRoot)) stopInstall(tr('Cannot verify the document root. Use site storage or configure DOCUMENT_ROOT correctly.'));
    if (insideDirectory($dataRoot,$documentRoot) || insideDirectory($dataRoot,$webRoot)) stopInstall(tr('Choose a separate data directory outside the document root and web application directory: ').$documentRoot);
    foreach ([$webRoot,__DIR__] as $site) {
        if (insideDirectory($site,$dataRoot.'/books') || insideDirectory($site,$dataRoot.'/conf')) stopInstall(tr('Book and configuration directories must not contain web application files.'));
    }
    return ['mode'=>'external','root'=>$dataRoot,'books'=>$dataRoot.'/books','conf'=>$dataRoot.'/conf'];
}
function passwordDraft(): ?string {
    if (time()-(int)($_SESSION['password_draft_time']??0)>1800) {
        unset($_SESSION['password_draft_hash'],$_SESSION['password_draft_time']);
    }
    return is_string($_SESSION['password_draft_hash']??null)?$_SESSION['password_draft_hash']:null;
}
function retainPassword(bool $required): ?string {
    $password=input('password'); $confirm=input('password_confirm');
    if ($password!=='' || $confirm!=='') {
        if (strlen($password)<12 || strlen($password)>72 || str_contains($password,"\0") || $password!==$confirm) {
            if ($required) stopInstall(tr('Use a 12-72 byte password and enter it identically twice.'));
            return passwordDraft();
        }
        $_SESSION['password_draft_hash']=password_hash($password,PASSWORD_DEFAULT);
        $_SESSION['password_draft_time']=time();
    }
    $hash=passwordDraft();
    if ($required && $hash===null) stopInstall(tr('Use a 12-72 byte password and enter it identically twice.'));
    return $hash;
}
function payloadFiles(string $root): array {
    $decoded=gzdecode(base64_decode(PAYLOAD,true) ?: '');
    $payload=$decoded===false ? null : json_decode($decoded,true,16,JSON_THROW_ON_ERROR);
    if (!is_array($payload) || array_keys($payload)!==['i18n.php','bootstrap.php','security.php','index.php','up.php','LICENSE','NOTICE']) stopInstall(tr('The installation payload is damaged.'));
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
$error=''; $commands=[]; $done=false; $checked=false; $results=[]; $url=''; $sessionReady=false;
$root=__DIR__; $conf=$root.'/conf'; $books=$root.'/books-data'; $storageMode='local';
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
    ini_set('session.use_strict_mode','1'); ini_set('session.use_only_cookies','1');
    session_name('OPDS_INSTALL_SESSION');
    session_set_cookie_params(['secure'=>true,'httponly'=>true,'samesite'=>'Strict','path'=>'/']);
    if (!session_start()) stopInstall(tr('Cannot start the installation session.'));
    $sessionReady=true; $_SESSION['install_csrf']??=bin2hex(random_bytes(32));
    if (($_SERVER['REQUEST_METHOD']??'GET')==='POST') {
        if (!hash_equals($_SESSION['install_csrf'],input('csrf'))) stopInstall(tr('Invalid request token. Refresh.'));
        $action=input('action') ?: 'install';
        if (!in_array($action,['check','install'],true)) stopInstall(tr('Invalid request action.'));
        $passwordHash=retainPassword($action==='install');
        // Application files always belong beside this installer. Client input
        // can choose private storage, never the PHP program destination.
        $root=__DIR__;
        $layout=storageLayout($root); $storageMode=$layout['mode']; $conf=$layout['conf']; $books=$layout['books'];
        if (setupLocked($root)) stopInstall(tr('Already installed; reinitialization is not allowed.'));
        $problems=environmentErrors(); if ($problems) stopInstall(implode('; ',$problems));
        $results[]=['label'=>tr('PHP requirements'),'ok'=>true];
        writableDirectory(__DIR__);
        $url=baseUrl(input('base_url'));
        $title=trim(input('title'));
        if ($action==='install' && ($title==='' || strlen($title)>200 || preg_match('//u',$title)!==1 || preg_match('/[\x00-\x1f\x7f]/',$title))) stopInstall(tr('Invalid library name.'));
        $categories=array_values(array_unique(array_filter(array_map('trim',preg_split('/\r\n|\n|\r/',input('categories'))?:[]),static fn($s)=>$s!=='')));
        if ($action==='install') {
            if (!$categories || count($categories)>20) stopInstall(tr('Enter 1-20 top-level categories, one per line.'));
            foreach ($categories as $category) if (!categoryName($category)) stopInstall(tr('Invalid category name. Only one category level is currently allowed.'));
        }
        $lockPath=__DIR__.'/.opds-install.lock';
        if (is_link($lockPath)) stopInstall(tr('Invalid installation lock path.'));
        $lock=fopen($lockPath,'c+b'); if (!$lock || !flock($lock,LOCK_EX|LOCK_NB)) stopInstall(tr('Another installation is running.'));
        $storageLock=null; $created=[]; $dirs=[]; $probeFiles=[]; $oldRootMode=null;
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
            if (is_link($conf) || (file_exists($conf) && !is_dir($conf))) stopInstall(tr('Invalid configuration directory.'));
            makeDirectory($conf,0700,$dirs);
            if (!chmod($conf,0700)) stopInstall(tr('Cannot protect configuration directory.'));
            foreach (['pass.conf','config.php','installed.lock'] as $name) if (file_exists($conf.'/'.$name) || is_link($conf.'/'.$name)) stopInstall(tr('Existing configuration was not overwritten.'));
            if ($storageMode==='local') {
                $deny="Require all denied\n";
                if (!file_exists($conf.'/.htaccess')) writeNew($conf.'/.htaccess',$deny,$created);
                elseif (is_link($conf.'/.htaccess') || file_get_contents($conf.'/.htaccess')!==$deny) stopInstall(tr('Existing directory protection differs and was not overwritten.'));
            }
            $id=bin2hex(random_bytes(24));
            writeNew($root.'/install-check-'.$id.'.txt',$id,$probeFiles,0644);
            if ($storageMode==='local') foreach ([$conf.'/pass.conf',$conf.'/access-check-'.$id.'.txt'] as $path) writeNew($path,$id,$probeFiles);
            [$status,$body]=probe($url.'install-check-'.$id.'.txt');
            if ($status!==200 || $body!==$id) stopInstall(tr('BASE_URL must point to the web application directory, not the separate data directory. HTTPS self-access with a valid certificate is also required.'));
            $results[]=['label'=>tr('Public URL'),'ok'=>true,'detail'=>$url];
            if ($storageMode==='local') foreach (['pass.conf','access-check-'.$id.'.txt'] as $name) {
                [$status]=probe($url.'conf/'.$name);
                if (!in_array($status,[403,404],true)) stopInstall(tr('HTTP access to conf is not blocked. Apply the protection rules below. No credentials were stored.'));
            }
            $results[]=['label'=>tr('Configuration protection'),'ok'=>true,'detail'=>$storageMode==='external'?tr('Outside the document root; no conf URL rule is required.'):''];
            foreach ($probeFiles as $path) unlink($path); $probeFiles=[];
            if ($action==='install') {
                foreach ($files as $name=>$content) {
                    if (!file_exists($root.'/'.$name)) writeNew($root.'/'.$name,$content,$created,0640);
                }
                $data=$books;
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
                $locations=['books_dir'=>$books,'config_dir'=>$conf];
                writeNew($root.'/paths.php',"<?php\nreturn ".var_export($locations,true).";\n",$created);
                writeNew($conf.'/config.php',"<?php\nreturn ".var_export($config,true).";\n",$created);
                writeNew($conf.'/pass.conf','password='.$passwordHash."\napi_token=".bin2hex(random_bytes(32))."\n",$created);
                if (!chmod($data,0550)) stopInstall(tr('Cannot protect library root.'));
                clearstatcache(true,$data); if (is_writable($data)) stopInstall(tr('Do not run PHP as root. The filesystem must enforce directory permissions.'));
                writeNew($conf.'/installed.lock',"installed\n",$created);
                writeNew(__DIR__.'/install.lock',"installed\n",$created);

                $done=true; $_SESSION=[]; session_destroy();
            } else $checked=true;
        } finally {
            foreach ($probeFiles as $path) @unlink($path);
            if (!$done) {
                foreach (array_reverse($created) as $path) @unlink($path);
                if ($oldRootMode!==null) @chmod($books,$oldRootMode);
                foreach (array_reverse($dirs) as $dir) @rmdir($dir);
            }
            if (is_resource($storageLock)) { flock($storageLock,LOCK_UN); fclose($storageLock); }
            flock($lock,LOCK_UN); fclose($lock);
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
    echo json_encode(['success'=>$done||$checked,'installed'=>$done,'message'=>$done?tr('Installation complete'):($checked?tr('Checks passed. You can install now.'):$error),
        'results'=>$results,'commands'=>$commands,'password_saved'=>!$done&&$sessionReady&&passwordDraft()!==null,
        'catalog_url'=>$done?$url.'index.php':null,'upload_url'=>$done?$url.'up.php':null],JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
$host=(string)($_SERVER['HTTP_HOST']??'localhost');
$script=(string)($_SERVER['SCRIPT_NAME']??'/install.php');
$documentRoot=(string)($_SERVER['DOCUMENT_ROOT']??'');
$resolvedDocumentRoot=$documentRoot!==''?realpath($documentRoot):false;
$defaultDataRoot=dirname($resolvedDocumentRoot ?: __DIR__).'/opds-data';
$guess='https://'.$host.rtrim(str_replace('\\','/',dirname($script)),'/.').'/';
?>
<!doctype html><html lang="<?=uiLanguage() === 'zh' ? 'zh-CN' : 'en'?>"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title><?=tr_html('Install your OPDS library')?></title>
<style nonce="<?=esc($nonce)?>">*{box-sizing:border-box}[hidden]{display:none!important}body{margin:0;padding:32px 16px;background:#f5f6f8;color:#222;font:16px/1.6 system-ui}main{max-width:680px;margin:auto;padding:28px;background:white;border-radius:14px}h1{font-size:24px}label{display:block;margin-top:16px}input,textarea,select,button{width:100%;padding:12px;border:1px solid #ddd;border-radius:8px;font:inherit}button{margin-top:16px;background:#222;color:white;cursor:pointer}button:disabled{opacity:.5;cursor:wait}.actions{display:flex;gap:12px}.actions button{flex:1}.secondary{background:#eee;color:#222}.error{padding:12px;background:#ffecec;color:#900;overflow-wrap:anywhere}.success{padding:12px;background:#edf8ef;color:#146c43}.result{overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f6f8;padding:12px}small{color:#666}a{color:#146c43}</style>
<main><h1><?= $done ? tr('Installation complete') : tr('Install your OPDS library') ?></h1>
<?php if ($done): ?>
<p><?=tr_html('Directories, configuration, and application files are ready. Setup is locked. Delete install.php.')?></p><p><a href="<?=esc($url.'index.php')?>"><?=tr_html('Open OPDS catalog')?></a> · <a href="<?=esc($url.'up.php')?>"><?=tr_html('Open uploader')?></a></p><p><?=tr_html('Sign in with the password you just set. Use CLI / API in the upper-right corner to copy your token and agent command.')?></p>
<?php else: ?>
<?php if ($error!==''): ?><p class="error" role="alert"><?=esc($error)?></p><?php endif; ?>
<?php if ($commands): ?><p><?=tr_html('Run these commands on the server, then click Check again. They affect only the named directory.')?></p><pre><?=esc(implode("\n",$commands))?></pre><?php endif; ?>
<?php if ($checked): ?><p class="success" role="status"><?=tr_html('Checks passed. You can install now.')?></p><?php endif; ?>
<p><?=tr_html('Set your library name, upload password, and categories. Application files, configuration, cache, and the installation lock are generated automatically. Different existing files are never overwritten.')?></p>
<?php foreach (environmentErrors() as $problem): ?><p class="error"><?=esc($problem)?></p><?php endforeach; ?>
<div id="checkResults" role="status" aria-live="polite"></div>
<?php if ($sessionReady): ?><form method="post" id="setupForm">
<input type="hidden" name="csrf" value="<?=esc($_SESSION['install_csrf'])?>">
<p><strong><?=tr_html('Web application directory (automatic)')?></strong><br><code id="detectedWebDir"><?=esc(__DIR__)?></code></p><small><?=tr_html('Detected from install.php. index.php and up.php are generated here; only the data location needs to be chosen.')?></small>
<label><?=tr_html('Storage mode')?><select name="storage_mode" id="storageMode">
<option value="local"<?=($_POST['storage_mode']??'local')==='local'?' selected':''?>><?=tr_html('Inside the web application directory')?></option>
<option value="external"<?=($_POST['storage_mode']??'local')==='external'?' selected':''?>><?=tr_html('Separate data directory (recommended)')?></option>
</select></label>
<div id="externalStorage"><label><?=tr_html('Separate data directory')?><input name="data_dir" id="dataDir" value="<?=esc(isset($_POST['data_dir'])&&is_string($_POST['data_dir'])?$_POST['data_dir']:$defaultDataRoot)?>"></label><small><?=tr_html('Creates books/ and conf/ here. Choose a path outside the site document root; no Nginx conf-blocking rule is needed for this mode. Do not expose this path through an alias.')?></small></div>
<pre id="layoutPreview"></pre>
<label><?=tr_html('Library name')?><input name="title" value="<?=esc(isset($_POST['title'])&&is_string($_POST['title'])?$_POST['title']:tr('My Library'))?>" required maxlength="100"></label>
<label>BASE_URL<input type="url" name="base_url" value="<?=esc(isset($_POST['base_url'])&&is_string($_POST['base_url'])?$_POST['base_url']:$guess)?>" required></label><small><?=tr_html('The HTTPS URL for index.php and up.php, ending with /. Private books and configuration do not need a public URL.')?></small>
<label><?=tr_html('Upload password')?><input type="password" name="password" autocomplete="new-password"></label>
<label><?=tr_html('Confirm password')?><input type="password" name="password_confirm" autocomplete="new-password"></label><small id="passwordHint"><?=tr_html(passwordDraft()!==null?'Password saved for this setup session. Leave both fields blank to keep it.':'12-72 bytes. The password is stored as a hash; an API token is generated randomly.')?></small>
<label><?=tr_html('Initial categories (one per line)')?><textarea name="categories" rows="4" required><?=esc(isset($_POST['categories'])&&is_string($_POST['categories'])?$_POST['categories']:'books')?></textarea></label>
<div class="actions"><button type="submit" name="action" value="check" id="checkButton" class="secondary" formnovalidate><?=tr_html('Check')?></button><button type="submit" name="action" value="install" id="installButton"><?=tr_html('Install')?></button></div></form><?php endif; ?>
<details><summary><?=tr_html('Server configuration and directory protection')?></summary>
<p><?=tr_html('Separate storage outside the document root does not need the conf URL rules below. These rules apply only to storage inside the web application directory.')?></p>
<p><?=tr_html('The installer writes conf/.htaccess for Apache, which must allow it to take effect. With Nginx, deny HTTP access to this installation\'s conf directory. Example for /opds/:')?></p>
<pre>location = /opds/conf { return 404; }
location ^~ /opds/conf/ { deny all; }</pre>
<p><?=tr_html('Checks verify the public web directory over HTTPS. Site storage also requires an HTTP protection check for conf; separate storage instead checks that data paths are outside the document root.')?></p>
<pre>upload_max_filesize = 100M
post_max_size = 205M
max_file_uploads = 21
session.upload_progress.enabled = 0</pre>
<p><?=tr_html('PHP needs ZIP, DOM, SimpleXML, session, filter, and zlib. HTTPS probes need OpenSSL and allow_url_fopen. The upload location must pass HTTP_AUTHORIZATION and HTTPS, with client_max_body_size 205m. Setup needs at least two PHP workers so self-check requests can complete.')?></p>
</details><?php endif; ?></main>
<script nonce="<?=esc($nonce)?>">
(() => {
    const form=document.getElementById('setupForm');
    if (!form || !window.fetch || !window.FormData) return;
    const dictionary=<?=json_encode(uiLanguage()==='zh'?UI_TRANSLATIONS:[],JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?>;
    const tr=text=>dictionary[text]??text;
    const output=document.getElementById('checkResults');
    const mode=document.getElementById('storageMode');
    const webDirectory=<?=json_encode(__DIR__,JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?>;
    const dataDirectory=document.getElementById('dataDir');
    function updateLayout() {
        const external=mode.value==='external';
        document.getElementById('externalStorage').hidden=!external;
        const web=webDirectory.replace(/\/+$/,'');
        const data=dataDirectory.value.replace(/\/+$/,'');
        document.getElementById('layoutPreview').textContent=tr('Web files: ')+web+'\n'
            +tr('Books: ')+(external?data+'/books':web+'/books-data')+'\n'
            +tr('Configuration: ')+(external?data+'/conf':web+'/conf');
    }
    mode.addEventListener('change',updateLayout);
    dataDirectory.addEventListener('input',updateLayout);
    updateLayout();
    const buttons=Array.from(form.querySelectorAll('button'));
    let busy=false;
    function message(text,className='result') {
        const line=document.createElement('p'); line.textContent=text; line.className=className; output.appendChild(line);
    }
    form.addEventListener('submit',async event=>{
        event.preventDefault(); if (busy) return;
        const action=event.submitter?.value??'install';
        const data=new FormData(form); data.set('action',action);
        // Checks do not need to transmit the password; fields stay in the DOM.
        if (action==='check') { data.delete('password'); data.delete('password_confirm'); }
        busy=true; buttons.forEach(button=>button.disabled=true); output.replaceChildren();
        message(tr(action==='check'?'Checking...':'Installing...'));
        try {
            const response=await fetch(window.location.href,{method:'POST',headers:{Accept:'application/json'},body:data});
            const result=await response.json(); output.replaceChildren();
            for (const check of result.results??[]) {
                if (!check.ok && check.label===result.message) continue;
                message((check.ok?'✓ ':'✗ ')+check.label+(check.detail?' · '+check.detail:''));
            }
            message(result.message,result.success?'success':'error');
            if (result.commands?.length) {
                message(tr('Run these commands on the server, then click Check again. They affect only the named directory.'));
                const pre=document.createElement('pre'); pre.textContent=result.commands.join('\n'); output.appendChild(pre);
            }
            if (result.password_saved) document.getElementById('passwordHint').textContent=tr('Password saved for this setup session. Leave both fields blank to keep it.');
            if (result.installed) {
                form.hidden=true; document.querySelector('h1').textContent=tr('Installation complete');
                for (const [text,url] of [['Open OPDS catalog',result.catalog_url],['Open uploader',result.upload_url]]) {
                    const link=document.createElement('a'); link.textContent=tr(text); link.href=url; const p=document.createElement('p');p.appendChild(link); output.appendChild(p);
                }
            }
        } catch {
            output.replaceChildren(); message(tr('Could not complete the request. Your form is unchanged. Check the connection and try again.'),'error');
        } finally { busy=false; buttons.forEach(button=>button.disabled=false); }
    });
})();
</script></html>
