<?php
declare(strict_types=1);
const PAYLOAD = '__OPDS_PAYLOAD__';
/*__OPDS_I18N__*/
/*__OPDS_ACCOUNT_RULES__*/
ini_set('display_errors','0'); ini_set('log_errors','1'); umask(0077);
header('Content-Type: text/html; charset=UTF-8'); header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff'); header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
$nonce=base64_encode(random_bytes(24));
header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$nonce'; script-src 'nonce-$nonce'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
function esc(string $s): string { return htmlspecialchars($s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
function stopInstall(string $message): never { throw new InstallProblem($message); }
function input(string $key): string {
    $v=$_POST[$key]??''; if (!is_string($v) || strlen($v)>8192) stopInstall(tr('Invalid form parameter.')); return $v;
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
    $h=@fopen($path,'x+b'); if (!$h) { writableDirectory(dirname($path)); stopInstall(tr('Cannot create file. Check free space and filesystem policy: ').$path); }
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
    if (!ini_get('file_uploads')) $errors[]=tr('Enable file_uploads in the web PHP configuration.');
    if ((phpProcessIds()['uid']??null)===0) $errors[]=tr('Run web PHP as a dedicated non-root service account.');
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
function permissionCommands(string $path,int $uid,int|false $owner,bool $traverseOnly,bool $dedicatedAppDirectory): array {
    $quoted=shellArg($path);
    if ($owner===$uid) return ['sudo chmod u+'.($traverseOnly?'x':'rwx').' -- '.$quoted];
    if ($owner!==false && !$traverseOnly && $dedicatedAppDirectory)
        return ['sudo chown -- '.shellArg((string)$uid).' '.$quoted,'sudo chmod u+rwx -- '.$quoted];
    return [];
}
function directoryAdvice(string $path,bool $traverseOnly=false): array {
    $ids=phpProcessIds();
    if (!$ids || $ids['uid']===0) return [];
    $documentRoot=empty($_SERVER['DOCUMENT_ROOT']) ? false : realpath((string)$_SERVER['DOCUMENT_ROOT']);
    // Never suggest taking ownership of a parent directory or a website's document root.
    $dedicatedAppDirectory=$documentRoot!==false && $path===__DIR__ && $path!==$documentRoot && insideDirectory($path,$documentRoot);
    $owner=@fileowner($path);
    if (!$traverseOnly && !$dedicatedAppDirectory && ($path===__DIR__ || $owner!==$ids['uid'])) return [];
    return permissionCommands($path,(int)$ids['uid'],$owner,$traverseOnly,$dedicatedAppDirectory);
}
function permissionProblem(string $path,bool $traverseOnly=false): never {
    $ids=phpProcessIds();
    $who=$ids && $ids['uid']!==0 ? 'UID '.(int)$ids['uid'] : tr('the PHP service account');
    $need=$traverseOnly ? tr('traverse (x)') : tr('read, write and traverse (rwx)');
    $commands=directoryAdvice($path,$traverseOnly);
    $message=sprintf(tr('%s needs %s on %s.'),$who,$need,$path);
    if (!$commands) {
        if ($traverseOnly)
            $message.=' '.tr('Choose a location whose parent directories PHP can already enter, or ask the administrator to grant traverse access only. Do not make a shared parent writable.');
        elseif ($path===__DIR__)
            $message.=' '.tr('Use a dedicated application directory. Do not grant PHP write access to the website root or a shared directory.');
    }
    throw new InstallProblem($message,$commands);
}
function targetPath(string $path): string {
    $path=rtrim(trim($path),'/');
    if ($path==='' || $path[0]!=='/' || strlen($path)>4096 || preg_match('/[\\\\\x00-\x1f\x7f]/',$path)) stopInstall(tr('Use an absolute data directory path.'));
    foreach (explode('/',substr($path,1)) as $part)
        if ($part==='' || $part==='.' || $part==='..') stopInstall(tr('The data directory path contains an invalid component.'));
    return $path;
}
function checkStoragePath(string $path): void {
    $cursor='';
    foreach (explode('/',substr($path,1)) as $part) {
        if (is_dir($cursor ?: '/') && !is_executable($cursor ?: '/')) permissionProblem($cursor ?: '/',true);
        $cursor.='/'.$part;
        if (is_link($cursor) || (file_exists($cursor) && !is_dir($cursor))) stopInstall(tr('The data directory path must not contain symbolic links or files.'));
    }
}
function makeDirectory(string $path,int $mode,array &$createdDirs): void {
    clearstatcache(true);
    if (is_link($path)) stopInstall(tr('The data directory path must not contain symbolic links or files.'));
    if (is_dir($path)) return;
    $parent=dirname($path);
    clearstatcache(true,$parent);
    if (!is_dir($parent) || !is_writable($parent) || !is_executable($parent))
        stopInstall(tr('Cannot create directory under this parent. Check the directory and filesystem policy: ').$parent);
    if (!@mkdir($path,$mode)) {
        if (is_dir($path) && !is_link($path)) return;
        stopInstall(tr('Cannot create directory. Check free space and filesystem policy: ').$path);
    }
    $createdDirs[]=$path;
}
function writableDirectory(string $path): void {
    clearstatcache(true,$path);
    if (!is_readable($path) || !is_writable($path) || !is_executable($path)) permissionProblem($path);
}
function setupLocked(string $root): bool {
    clearstatcache(true);
    foreach ([$root.'/install.lock',$root.'/conf/installed.lock',$root.'/paths.php'] as $path) {
        if (file_exists($path) || is_link($path)) return true;
    }
    return false;
}
function insideDirectory(string $path,string $parent): bool {
    return $path===$parent || str_starts_with($path,rtrim($parent,'/').'/');
}
function storageLayout(string $webRoot,string $dataDir): array {
    $dataRoot=targetPath($dataDir);
    $documentRoot=(string)($_SERVER['DOCUMENT_ROOT']??'');
    $documentRoot=$documentRoot!==''?realpath($documentRoot):false;
    if ($documentRoot===false || !is_dir($documentRoot)) stopInstall(tr('Cannot verify the document root. Configure DOCUMENT_ROOT correctly.'));
    if (insideDirectory($dataRoot,$documentRoot) || insideDirectory($dataRoot,$webRoot) || insideDirectory($documentRoot,$dataRoot) || insideDirectory($webRoot,$dataRoot)) stopInstall(tr('Choose a separate data directory outside the document root and web application directory: ').$documentRoot);
    // Reject disallowed paths before reporting permissions or suggesting shell commands.
    clearstatcache(true);
    checkStoragePath($dataRoot);
    return ['root'=>$dataRoot,'books'=>$dataRoot.'/books','conf'=>$dataRoot.'/conf'];
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
function preparePrivateRootCommand(string $path,int $uid): string {
    $quoted=shellArg($path);
    // Deliberately no -p: never change an existing directory or any parent.
    return 'sudo mkdir -m 0700 -- '.$quoted.' && sudo chown -- '.shellArg((string)$uid).' '.$quoted;
}
function inspectPrivateRoot(string $path): bool {
    if (is_dir($path)) return true;
    $parent=dirname($path);
    if (!@is_dir($parent)) stopInstall(sprintf(tr('The parent directory %s does not exist or PHP cannot see it. Choose an existing accessible parent outside the website, or ask the administrator to prepare the private data directory.'),$parent));
    if (!@is_executable($parent)) permissionProblem($parent,true);
    if (!@is_writable($parent)) {
        $ids=phpProcessIds();
        $commands=$ids && $ids['uid']!==0 ? [preparePrivateRootCommand($path,(int)$ids['uid'])] : [];
        throw new InstallProblem(sprintf(tr('The private data directory %s does not exist and PHP cannot create it under %s. Ask the administrator to create only the private directory, or choose another location. Do not grant PHP write access to the parent.'),$path,$parent),$commands);
    }
    return false;
}
function inspectPrivateDirectory(string $path,string $invalidMessage,bool $privateConfig=false): void {
    if (is_link($path) || (file_exists($path) && !is_dir($path))) stopInstall(tr($invalidMessage));
    if (!is_dir($path)) return;
    $ids=phpProcessIds();
    $phpOwns=$ids && $ids['uid']!==0 && @fileowner($path)===$ids['uid'];
    if ($privateConfig && ((int)fileperms($path)&077)!==0) {
        $commands=$phpOwns ? ['sudo chmod 700 -- '.shellArg($path)] : [];
        throw new InstallProblem(tr('The configuration directory must be private (0700).').' '.$path,$commands);
    }
    if (is_readable($path) && is_writable($path) && is_executable($path)) return;
    if ($phpOwns) permissionProblem($path);
    throw new InstallProblem(sprintf(tr('PHP cannot read, write or enter the private directory %s. Ask the administrator to grant the PHP service account access to this dedicated directory only, or choose a new private data directory.'),$path));
}
function inspectConfiguration(string $conf): void {
    foreach (['pass.conf','config.php','users.json','shares.json','installed.lock'] as $name) {
        if (file_exists($conf.'/'.$name) || is_link($conf.'/'.$name)) stopInstall(tr('Existing configuration was not overwritten.'));
    }

}
function inspectStorage(array $layout): void {
    $books=$layout['books']; $conf=$layout['conf'];
    if (!inspectPrivateRoot($layout['root'])) return;
    inspectPrivateDirectory($layout['root'],'Invalid storage configuration.');
    inspectPrivateDirectory($books,'Invalid library directory.');
    inspectPrivateDirectory($conf,'Invalid configuration directory.',true);
    inspectConfiguration($conf);
    inspectPrivateDirectory($conf.'/cache','Invalid cache path.');
    if (!is_dir($books)) return;
    $entries=@scandir($books);
    if ($entries===false) stopInstall(tr('Cannot list the private books directory.').' '.$books);
    foreach ($entries as $entry) {
        if ($entry==='.' || $entry==='..') continue;
        $path=$books.'/'.$entry;
        // Leave existing account-like paths untouched; reject a legacy flat shelf.
        // A same-name file/link is handled explicitly by the username check.
        if (!accountName(strtolower($entry)))
            stopInstall(tr('This books directory contains legacy items. Choose a new data root, then migrate separately.'));
    }
}
function inspectUsername(array $layout,string $name): void {
    if (!accountName($name)) stopInstall(tr('Use 1–32 lowercase letters, digits, hyphens or underscores; start with a letter or digit.'));
    if (accountNameReserved($name)) stopInstall(tr('This username is reserved.'));
    // An existing account database is never opened or reused by fresh setup.
    inspectConfiguration($layout['conf']);
    if (accountDirectoryOccupied($layout['books'],$name))
        stopInstall(tr('This library path already exists. Choose another username; no existing files will be touched.').' '.$layout['books'].'/'.$name);
}
function currentInstallUrl(): string {
    $host=(string)($_SERVER['HTTP_HOST']??'');
    $script=explode('?',(string)($_SERVER['REQUEST_URI']??$_SERVER['SCRIPT_NAME']??''),2)[0];
    if (!preg_match('/\A(?:[a-z0-9.-]+|\[[0-9a-f:]+\])(?::[0-9]{1,5})?\z/iD',$host)
        || !preg_match('~\A/(?:[a-zA-Z0-9._-]+/)*install\.php\z~D',$script)
        || preg_match('~/(?:\.|\.\.)/~',$script)) return '';
    $url='https://'.strtolower($host).substr($script,0,-strlen('install.php'));
    return filter_var($url,FILTER_VALIDATE_URL) ? $url : '';
}
function validateLibrary(array $fields): array {
    $title=trim($fields['title']);
    if ($title==='' || strlen($title)>200 || preg_match('//u',$title)!==1 || preg_match('/[\x00-\x1f\x7f]/',$title))
        stopInstall(tr('Invalid site name.'));
    $layout=storageLayout(__DIR__,$fields['data_dir']);
    inspectStorage($layout);
    return [$title,$layout];
}
function verifyPublicUrl(string $url): void {
    $id=bin2hex(random_bytes(24)); $files=[];
    try {
        writeNew(__DIR__.'/install-check-'.$id.'.txt',$id,$files,0644);
        [$status,$body]=probe($url.'install-check-'.$id.'.txt');
        if ($status!==200 || $body!==$id)
            stopInstall(tr('HTTPS self-check failed. Check the certificate, local DNS and access to the application directory.').' (HTTP '.$status.')');
    } finally { foreach ($files as $path) @unlink($path); }
}
function checkEnvironment(): void {
    $problems=environmentErrors();
    if ($problems) stopInstall(implode("\n",$problems));
    writableDirectory(__DIR__);
    payloadFiles(__DIR__);
}
function iniBytes(string $value): int {
    if (function_exists('ini_parse_quantity')) return @ini_parse_quantity($value);
    $value=trim($value);
    if (!preg_match('/\A(-?\d+)\s*([KMG]?)\z/iD',$value,$m)) return 0;
    return (int)((int)$m[1]*match(strtoupper($m[2])){'K'=>1024,'M'=>1048576,'G'=>1073741824,default=>1});
}
function uploadWarnings(): array {
    $warnings=[];
    foreach (['upload_max_filesize'=>100,'post_max_size'=>205] as $key=>$recommend) {
        $value=(string)ini_get($key); $bytes=iniBytes($value);
        if (!($key==='post_max_size' && $bytes===0) && $bytes<$recommend*1048576)
            $warnings[]=sprintf(tr('%s is %s. Set it to at least %s in web PHP configuration.'),$key,$value===''?'—':$value,$recommend.'M');
    }
    return $warnings;
}
function startWizard(): void {
    if (!function_exists('session_start')) stopInstall(tr('Missing PHP function: ').'session_start');
    session_name('__Host-OPDS_SETUP');
    session_cache_limiter('');
    if (!@session_start(['use_strict_mode'=>1,'use_only_cookies'=>1,'cookie_secure'=>true,'cookie_httponly'=>true,'cookie_samesite'=>'Strict','cookie_path'=>'/','cookie_domain'=>'']))
        stopInstall(tr('Cannot start the installation session.'));
}
function installLibrary(array $fields,string $url,int &$step): string {
    $step=1;
    checkEnvironment();
    $lock=@fopen(__DIR__,'r');
    if (!$lock || !flock($lock,LOCK_EX|LOCK_NB)) stopInstall(tr('Cannot acquire the installation lock. Try again shortly.'));
    $storageLock=null; $created=[]; $dirs=[]; $done=false;
    try {
        if (setupLocked(__DIR__)) stopInstall(tr('Already installed; reinitialization is not allowed.'));
        $step=2;
        [$title,$layout]=validateLibrary($fields);
        makeDirectory($layout['root'],0700,$dirs);
        $storageLock=@fopen($layout['root'],'r');
        if (!$storageLock || !flock($storageLock,LOCK_EX|LOCK_NB)) stopInstall(tr('Cannot acquire the data directory lock. Try again shortly.'));
        clearstatcache(true);
        $current=@stat($layout['root']); $lockedDir=fstat($storageLock);
        if (realpath($layout['root'])!==$layout['root'] || !$current || !$lockedDir || $current['dev']!==$lockedDir['dev'] || $current['ino']!==$lockedDir['ino'])
            stopInstall(tr('The data directory changed during installation. Check it again.'));
        // Repeat the storage checks while holding both directory locks.
        [$title,$layout]=validateLibrary($fields);
        verifyPublicUrl($url);
        $books=$layout['books']; $conf=$layout['conf'];
        $step=3;
        inspectUsername($layout,$fields['username']);
        $step=4;
        $files=payloadFiles(__DIR__);
        makeDirectory($books,0750,$dirs);
        makeDirectory($conf,0700,$dirs);
        makeDirectory($conf.'/cache',0700,$dirs);
        $step=3;
        inspectUsername($layout,$fields['username']);
        $personal=$books.'/'.$fields['username'];
        if (!@mkdir($personal,0750)) {
            inspectUsername($layout,$fields['username']);
            writableDirectory($books);
            stopInstall(tr('Cannot create directory. Check free space and filesystem policy: ').$personal);
        }
        $dirs[]=$personal;
        $step=4;
        foreach ($files as $name=>$content) {
            if (!file_exists(__DIR__.'/'.$name)) writeNew(__DIR__.'/'.$name,$content,$created,0640);
        }
        $config=['base_url'=>$url,'title'=>$title,'max_category_depth'=>1,'multiuser'=>true,'share_key'=>bin2hex(random_bytes(32))];
        writeNew($conf.'/config.php',"<?php\nreturn ".var_export($config,true).";\n",$created);
        $secret=bin2hex(random_bytes(32));
        $record=['state'=>'pending','activation'=>['digest'=>hash('sha256',$secret),'expires'=>time()+86400]];
        writeNew($conf.'/users.json',json_encode(['version'=>1,'records'=>(object)[$fields['username']=>$record]],JSON_THROW_ON_ERROR),$created);
        writeNew($conf.'/shares.json','{"version":1,"records":{}}',$created);
        writeNew($conf.'/installed.lock',"installed\n",$created);
        writeNew(__DIR__.'/install.lock',"installed\n",$created);
        // Publish paths last so application entry points cannot see a half-installed state.
        writeNew(__DIR__.'/paths.php',"<?php\nreturn ".var_export(['books_dir'=>$books,'config_dir'=>$conf],true).";\n",$created);
        $done=true;
        return $url.'up.php?'.http_build_query(['account'=>$fields['username'],'activate'=>$secret]);
    } finally {
        if (!$done) {
            foreach (array_reverse($created) as $path) @unlink($path);
            foreach (array_reverse($dirs) as $path) @rmdir($path);
        }
        if (is_resource($storageLock)) fclose($storageLock);
        fclose($lock);
    }
}

$activationUrl=''; $error=''; $commands=[]; $done=false; $success=false; $csrf=''; $step=1;
$jsonRequest=str_contains(strtolower((string)($_SERVER['HTTP_ACCEPT']??'')),'application/json');
$documentRoot=realpath((string)($_SERVER['DOCUMENT_ROOT']??__DIR__))?:__DIR__;
$siteUrl=currentInstallUrl();
$defaults=['data_dir'=>dirname($documentRoot).'/opds-data','title'=>'Personal OPDS','username'=>''];
$fields=$defaults;
$locked=setupLocked(__DIR__);
if ($locked) http_response_code(403);
else try {
    if (!in_array(strtolower((string)($_SERVER['HTTPS']??'')),['on','1'],true))
        stopInstall(tr('HTTPS is required for setup. Configure the server HTTPS state at your trusted proxy.'));
    $method=$_SERVER['REQUEST_METHOD']??'GET';
    if (!in_array($method,['GET','POST'],true)) { header('Allow: GET, POST'); stopInstall(tr('Method not allowed.')); }
    if ($siteUrl==='') stopInstall(tr('Open install.php directly at the HTTPS address you want readers to use.'));
    startWizard();
    $wizard=&$_SESSION['wizard'];
    if (($wizard['site_url']??null)!==$siteUrl) $wizard=['site_url'=>$siteUrl,'step'=>1,'csrf'=>bin2hex(random_bytes(32)),'fields'=>$defaults];
    $step=$wizard['step']; $csrf=$wizard['csrf']; $fields=$wizard['fields'];
    if ($method==='POST') {
        if (!hash_equals($csrf,input('csrf'))) stopInstall(tr('Invalid request token. Refresh.'));
        if (input('step')!==(string)$step) stopInstall(tr('This installation page is out of date. Continue from the current step.'));
        $action=input('action');
        if ($action==='back' && $step>1) {
            if ($step===2) foreach (['data_dir','title'] as $key) $fields[$key]=input($key);
            if ($step===3) $fields['username']=input('username');
            --$step;
        } elseif ($action==='next' && $step<4) {
            if ($step===1) checkEnvironment();
            if ($step===2) {
                foreach (['data_dir','title'] as $key) $fields[$key]=input($key);
                [$fields['title'],$layout]=validateLibrary($fields);
                $fields['data_dir']=$layout['root'];
                verifyPublicUrl($siteUrl);
            }
            if ($step===3) {
                $fields['username']=input('username');
                try { [,$layout]=validateLibrary($fields); }
                catch (Throwable $e) { $step=2; throw $e; }
                inspectUsername($layout,$fields['username']);
            }
            ++$step;
        } elseif ($action==='install' && $step===4) {
            $activationUrl=installLibrary($fields,$siteUrl,$step);
            $done=true;
        } else stopInstall(tr('Invalid request action.'));
        $success=true;
    }
} catch (Throwable $e) {
    http_response_code(400);
    $error=$e instanceof InstallProblem ? $e->getMessage() : tr('An unexpected setup error occurred. Check the PHP error log.');
    if ($e instanceof InstallProblem) $commands=$e->commands;
    else error_log('OPDS setup: '.get_class($e).': '.$e->getMessage());
} finally {
    if (session_status()===PHP_SESSION_ACTIVE) {
        if ($done) { unset($_SESSION['wizard']); session_destroy(); }
        else { $wizard['step']=$step; $wizard['fields']=$fields; session_write_close(); }
    }
}
if ($locked) $error=tr('Already installed. Setup is locked. Delete install.php.');
if ($jsonRequest) {
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode(['success'=>$success,'installed'=>$done,'message'=>$done?tr('Installation complete'):$error,
        'step'=>$step,'commands'=>$commands,'activation_url'=>$done?$activationUrl:null,
        'catalog_url'=>$done?$siteUrl.'index.php':null,'upload_url'=>$done?$siteUrl.'up.php':null],JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
$steps=['Environment','Library location','First account','Review and install'];
$descriptions=[
    'Check the server before entering your library settings.',
    'Name this site and choose where private data is stored.',
    'This username becomes the directory name. The account owner sets a password after installation.',
    'Review your settings. No existing book or account will be overwritten.',
];
$accountPath=rtrim($fields['data_dir'],'/').'/books/'.$fields['username'];
$headings=['Check the server','Set up your library','Choose the first username','Confirm your setup'];
?>
<!doctype html>
<html lang="<?=uiLanguage()==='zh'?'zh-CN':'en'?>">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?=tr_html('Set up Personal OPDS')?></title>
<style nonce="<?=esc($nonce)?>">
*{box-sizing:border-box}body{margin:0;background:#f4f7f7;color:#142f31;font:15px/1.6 system-ui,sans-serif}
:root{--ink:#123837;--muted:#4b666b;--line:#d9e5e3;--teal:#08685e}
.shell{max-width:860px;margin:0 auto;padding:38px 28px 50px}.brand{font-weight:750;letter-spacing:.14em;font-size:12px;color:var(--teal);margin:0}
h1,h2,p{margin:0}h1{font-size:clamp(26px,5vw,38px);letter-spacing:-.04em;line-height:1.22;margin:8px 0 24px}
h2{font-size:clamp(22px,4vw,28px);letter-spacing:-.025em;line-height:1.3}.intro{margin:6px 0 22px;color:var(--muted)}
.steps{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:0;margin:0 0 16px;list-style:none}
.steps li{display:flex;align-items:center;gap:9px;border-top:2px solid var(--line);padding:10px 0 3px;color:var(--muted);font-weight:600;font-size:13px;line-height:1.35}
.steps li[aria-current]{border-color:var(--teal);color:var(--ink);font-weight:750}.steps li.completed{border-color:#91bab0;color:var(--teal)}
.steps b{display:grid;place-items:center;width:23px;height:23px;border-radius:50%;background:#e7eeed;flex:none;font-size:12px}.steps li[aria-current] b{background:var(--teal);color:white}
.panel{background:white;border:1px solid var(--line);box-shadow:0 10px 26px #1238370d;border-radius:19px;padding:clamp(18px,4vw,32px)}
label{display:block;font-weight:680;margin:12px 0 4px}
input{width:100%;min-width:0;padding:9px 11px;background:#fbfdfc;border-radius:8px;border:1px solid #a9c1c0;color:var(--ink);font:inherit}
input:focus,button:focus-visible,a:focus-visible{outline:3px solid #4aa997;outline-offset:2px}small{display:block;color:var(--muted);margin-top:4px;font-size:13px}
.actions{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:24px;padding-top:18px;border-top:1px solid var(--line)}
button,.action{display:inline-flex;justify-content:center;align-items:center;min-height:43px;background:var(--teal);border:1px solid var(--teal);color:white;font:inherit;font-weight:680;padding:8px 16px;border-radius:9px;text-decoration:none;cursor:pointer}
.actions>.primary{margin-left:auto;order:2}.secondary{background:white;border-color:var(--line);color:var(--ink)}
.note,.alert,.hint{border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:12px 0;overflow-wrap:anywhere}.note{background:#fff9ee;border-color:#ead4a9;color:#5c4212}.alert{background:#fff2f0;border-color:#edc8c1;color:#782920}.hint{background:#f0f6f5;color:#234b4a}.message{white-space:pre-line;margin-top:4px}
ul{padding-inline-start:21px}.note ul{margin:3px 0 0}pre,code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.89em;white-space:pre-wrap;overflow-wrap:anywhere}pre{margin:7px 0 0}
dl{display:grid;grid-template-columns:minmax(100px,28%) minmax(0,1fr);margin:0}dt,dd{padding:9px 0;border-bottom:1px solid var(--line)}dt{color:var(--muted);font-weight:630}dd{margin:0;overflow-wrap:anywhere}
.done .action{margin:2px 0 10px}.foot{color:var(--muted);font-size:13px;margin-top:16px}
@media(max-width:550px){.shell{padding:24px 14px}.steps{gap:6px}.steps li{flex-direction:column;align-items:flex-start;gap:5px;font-size:11px}.actions{margin-top:18px}dl{grid-template-columns:1fr}dt{padding-bottom:0;border-bottom:0}dd{padding-top:2px}}
</style></head>
<body><main class="shell">
<p class="brand">PERSONAL OPDS</p>
<h1><?=tr_html('Set up your private OPDS library')?></h1>
<?php if (!$done && !$locked): ?>
<ol class="steps" aria-label="<?=tr_html('Installation steps')?>">
<?php foreach ($steps as $i=>$label): $n=$i+1; ?>
<li<?=$n===$step?' aria-current="step"':($n<$step?' class="completed"':'')?>><b aria-hidden="true"><?=$n<$step?'✓':$n?></b><span><?=tr_html($label)?></span></li>
<?php endforeach; ?>
</ol>
<?php endif; ?>
<section class="panel<?=$done?' done':''?>">
<?php if ($done): ?>
<h2><?=tr_html('Your library is installed')?></h2>
<p class="intro"><?=tr_html('Open the one-time activation link to set your password. It expires in 24 hours.')?></p>
<a class="action" href="<?=esc($activationUrl)?>"><?=tr_html('Activate first account')?></a>
<label for="activation"><?=tr_html('Activation URL')?></label><input id="activation" readonly value="<?=esc($activationUrl)?>">
<p class="foot"><?=tr_html('Remove install.php after setup.')?> <?=tr_html('If the first activation link was lost or expired, run in the application directory as the PHP service account:')?> <code>php admin.php invite <?=esc($fields['username'])?></code>.</p>
<?php else: ?>
<?php if (!$locked): ?>
<h2><?=tr_html($headings[$step-1])?></h2><p class="intro"><?=tr_html($descriptions[$step-1])?></p>
<?php endif; ?>
<?php if ($error!==''): ?>
<div class="alert" role="alert"><strong><?=tr_html($locked?'Setup locked':'Cannot continue')?></strong><p class="message"><?=esc($error)?></p>
<?php if ($commands): ?>
<p><?=tr_html(str_starts_with($commands[0],'sudo chown')?'If this directory is dedicated to this OPDS installation, run these commands, then retry:':'Run the following on the server, then retry:')?></p>
<pre><?=esc(implode("\n",$commands))?></pre>
<?php if (str_starts_with($commands[0],'sudo chown')): ?><small><?=tr_html('This changes only the listed directory, not its contents. If ownership must stay unchanged, ask the administrator to grant access using the server’s existing policy or choose another directory.')?></small><?php endif; ?>
<?php elseif (str_contains($error,tr('the PHP service account'))): ?><small><?=tr_html('Find the worker user in PHP-FPM pool settings or your hosting panel, then grant the permissions shown above.')?></small><?php endif; ?>
</div>
<?php endif; ?>
<?php if ($locked): ?>
<p><?=tr_html('If the first activation link was lost or expired, run in the application directory as the PHP service account:')?> <code>php admin.php invite USERNAME</code>.</p>
<?php endif; ?>
<?php if ($csrf!=='' && !$locked): ?>
<form method="post" novalidate>
<input type="hidden" name="csrf" value="<?=esc($csrf)?>"><input type="hidden" name="step" value="<?=$step?>">
<?php if ($step===1): ?>
<dl><dt>PHP</dt><dd><?=esc(PHP_VERSION)?> · <?=esc((string)(PHP_INT_SIZE*8))?>‑bit · <?=esc(PHP_SAPI)?></dd>
<dt><?=tr_html('Application directory')?></dt><dd><code><?=esc(__DIR__)?></code></dd></dl>
<div class="hint"><?=tr_html('Next checks HTTPS, required extensions, upload settings and write access. It does not install anything.')?></div>
<?php if ($warnings=uploadWarnings()): ?>
<div class="note"><strong><?=tr_html('Upload limit warnings (not blocking)')?></strong>
<ul><?php foreach ($warnings as $warning): ?><li><?=esc($warning)?></li><?php endforeach;?></ul></div>
<?php endif; ?>
<p class="foot"><?=tr_html('Verify reverse proxy limits with a real upload after installation.')?></p>
<?php elseif ($step===2): ?>
<label for="title"><?=tr_html('Site name')?></label><input id="title" name="title" maxlength="200" value="<?=esc($fields['title'])?>" required>
<small><?=tr_html('Shown on the website and in the OPDS catalog. It applies to all users.')?></small>
<label for="data_dir"><?=tr_html('Private data root')?></label><input id="data_dir" name="data_dir" aria-describedby="data_help" value="<?=esc($fields['data_dir'])?>" required>
<small id="data_help"><?=tr_html('Use a dedicated directory outside the website root, under an existing parent. Do not expose it through an alias.')?></small>
<div class="hint"><code>conf/</code> <?=tr_html('stores configuration')?><br><code>books/&lt;username&gt;/</code> <?=tr_html('is each user’s private book directory')?></div>
<?php elseif ($step===3): ?>
<label for="username"><?=tr_html('First username')?></label>
<input id="username" name="username" maxlength="32" autocapitalize="none" spellcheck="false" aria-describedby="username_help" value="<?=esc($fields['username'])?>" required>
<small id="username_help"><?=tr_html('Use 1–32 lowercase letters, digits, hyphens or underscores; start with a letter or digit.')?></small>
<div class="hint"><strong><?=tr_html('Personal library directory')?></strong><br><code id="personal_path" data-prefix="<?=esc(rtrim($fields['data_dir'],'/').'/books/')?>"><?=esc($accountPath?:'/')?></code></div>
<script nonce="<?=esc($nonce)?>">const u=document.getElementById('username'),p=document.getElementById('personal_path');function showPath(){p.textContent=p.dataset.prefix+(/^[a-z0-9][a-z0-9_-]{0,31}$/.test(u.value)?u.value:'<username>')+'/';}u.addEventListener('input',showPath);showPath();</script>
<?php else: ?>
<dl>
<dt><?=tr_html('Site name')?></dt><dd><?=esc($fields['title'])?></dd>
<dt><?=tr_html('OPDS address:')?></dt><dd><code><?=esc($siteUrl.'index.php')?></code></dd>
<dt><?=tr_html('Web dashboard:')?></dt><dd><code><?=esc($siteUrl.'up.php')?></code></dd>
<dt><?=tr_html('Private data root')?></dt><dd><code><?=esc($fields['data_dir'])?></code></dd>
<dt><?=tr_html('First username')?></dt><dd><?=esc($fields['username'])?></dd>
<dt><?=tr_html('Personal library directory')?></dt><dd><code><?=esc($accountPath.'/')?></code></dd>
</dl>
<p class="foot"><?=tr_html('Install rechecks these settings before creating any account. The first user chooses a password using the activation link.')?></p>
<?php endif; ?>
<div class="actions">
<button class="primary" type="submit" name="action" value="<?=$step===4?'install':'next'?>"><?=tr_html($step===4?'Install':($error!==''?'Check again':'Check and continue'))?></button>
<?php if ($step>1): ?><button class="secondary" type="submit" name="action" value="back"><?=tr_html('Previous step')?></button><?php endif; ?>
</div>
</form>
<?php endif; ?>
<?php endif; ?>
</section></main></body></html>
