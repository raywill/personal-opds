<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/security.php';
require __DIR__.'/upload-common.php';
require __DIR__.'/accounts.php';
require __DIR__.'/catalogue.php';

header('Cache-Control: private, no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
$nonce=base64_encode(random_bytes(18));
header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$nonce'; script-src 'nonce-$nonce'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
try { requireUploadHttps(); } catch (RequestError $e) { http_response_code($e->getCode()); exit($e->getMessage()); }
ini_set('session.use_strict_mode','1');
session_name('OPDS_LIBRARY');
session_set_cookie_params(['path'=>COOKIE_PATH,'secure'=>true,'httponly'=>true,'samesite'=>'Strict']);
session_start();
$_SESSION['csrf']??=bin2hex(random_bytes(32));
function h(string $value): string { return htmlspecialchars($value,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
function field(string $key,array $source): string {
    $v=$source[$key]??'';
    if (!is_string($v)||strlen($v)>2048) reject('Invalid input.');
    return $v;
}
function passwordField(string $key): string {
    $v=$_POST[$key]??'';
    if (!is_string($v)) reject('Invalid input.');
    return $v;
}
function go(string $dir=''): never {
    header('Location: '.BASE_URL.'up.php'.($dir===''?'':'?'.http_build_query(['dir'=>$dir],'','&',PHP_QUERY_RFC3986)),true,303);
    exit;
}
function managementDownload(string $dir,string $name): never {
    $path=managedBook($dir,$name);
    $f=fopen($path,'rb'); if (!$f) reject('Book not found.',404);
    $stat=fstat($f);
    if (!$stat) { fclose($f); reject('Book not found.',404); }
    header('Content-Type: application/octet-stream');
    header("Content-Disposition: attachment; filename*=UTF-8''".rawurlencode($name));
    header('Content-Length: '.$stat['size']);
    session_write_close();
    if ($_SERVER['REQUEST_METHOD']!=='HEAD') fpassthru($f);
    fclose($f); exit;
}
$method=$_SERVER['REQUEST_METHOD'];
$viewer=(string)($_SESSION['account']??'');
$user=activeAccount($viewer);
$now=time();
if (!$user || !hash_equals($user['password'],$_SESSION['password']??'') ||
    $now-($_SESSION['activity']??0)>SESSION_IDLE_TTL || $now-($_SESSION['issued']??0)>SESSION_ABSOLUTE_TTL) {
    $viewer=''; $user=null;
    unset($_SESSION['account'],$_SESSION['password'],$_SESSION['activity'],$_SESSION['issued']);
} else { $_SESSION['activity']=$now; setAccountScope($viewer); }
$error=''; $notice=''; $token=''; $dir=''; $activate=''; $activateFor=''; $preview=false;
$action=is_string($_POST['action']??null)?$_POST['action']:'';
try {
    if (!in_array($method,['GET','HEAD','POST'],true)) reject('Method not allowed.',405);
    $activate=field('activate',$_GET); $activateFor=field('account',$_GET);
    $dir=field('dir',$_GET);
    if ($method==='POST') {
        if ($action==='upload') { requireMultipart(); unset($_POST['dir']); }
        if (!hash_equals($_SESSION['csrf'],field('csrf',$_POST))) reject(tr('Session changed; reload the page.'),403);
        if ($action==='activate') {
            $activate=field('activate',$_POST); $activateFor=field('account',$_POST);
            reserveRateAttempt('activate',12,180);
            $password=passwordField('password');
            if ($password!==passwordField('confirm')) reject(tr('Passwords do not match.'));
            activateAccount($activateFor,$activate,$password);
            $_SESSION=[]; session_regenerate_id(true);
            $_SESSION['notice']=tr('Password set. Sign in with your new password.');
            go();
        }
        if ($action==='login') {
            $name=trim(field('username',$_POST)); $password=passwordField('password');
            reserveRateAttempt('login',LOGIN_IP_LIMIT,LOGIN_GLOBAL_LIMIT);
            $verified=loginAccount($name,$password);
            if (!$verified) reject(tr('Incorrect username or password, or account not activated.'),401);
            session_regenerate_id(true);
            $_SESSION=['csrf'=>bin2hex(random_bytes(32)),'account'=>$name,'password'=>$verified['password'],'activity'=>$now,'issued'=>$now];
            go();
        }
        if (!$user) reject(tr('Sign in again.'),401);
        if ($action==='logout') { $_SESSION=[]; session_regenerate_id(true); go(); }
        if ($action==='upload') {
            session_write_close();
            uploadJsonResponse(processUpload(singleFile:true,bearer:false));
        }
        $dir=field('dir',$_POST);
        resolveDestinationDirectory($dir);
        switch ($action) {
            case 'folder':
                $new=field('folder',$_POST); createCategory($new);
                if (($_SERVER['HTTP_ACCEPT']??'')==='application/json') jsonResponse(['success'=>true,'message'=>tr('Folder ready.'),'folder'=>$new]);
                $_SESSION['notice']=tr('Folder ready.'); go($new);
            case 'share':
            case 'revoke':
                manageShare($dir,$action==='revoke');
                $_SESSION['notice']=$action==='revoke'?tr('Share revoked.'):tr('Share link ready.'); go($dir);
            case 'move':
            case 'delete':
                manageBook($action,$dir,field('file',$_POST),field('destination',$_POST));
                $_SESSION['notice']=$action==='move'?tr('Book moved.'):tr('Book deleted.'); go($dir);
            case 'token':
                $token=rotateUploadToken($viewer,$user['password']);
                break;
            default: reject('Unknown action.');
        }
    }
    if ($user && $activate==='') {
        resolveDestinationDirectory($dir);
        if (($_GET['skill']??'')==='1') {
            $downloadSkill=true;
        }
        if (isset($_GET['download'])) managementDownload($dir,field('download',$_GET));
        $preview=($_GET['preview']??'')==='1'&&$dir!=='';
    }
} catch (Throwable $e) {
    $status=$e instanceof RequestError?$e->getCode():500;
    if ($action==='folder' && ($_SERVER['HTTP_ACCEPT']??'')==='application/json')
        jsonResponse(['success'=>false,'message'=>publicError($e)],$status);
    if ($action==='upload') jsonResponse(['success'=>false,'message'=>publicError($e),'results'=>[]],$status);
    http_response_code($status);
    $error=publicError($e);
    if ($user) { try { resolveDestinationDirectory($dir); } catch (Throwable) { $dir=''; } }
}
$notice=$_SESSION['notice']??''; unset($_SESSION['notice']);
$csrf=$_SESSION['csrf'];
session_write_close();
$directories=$user?array_map('strval',array_keys(libraryDirectories())):[];
$mine=[];
if ($user) foreach (stateRead('shares') as $id=>$row) {
    if ($row['owner']===$viewer) $mine[$row['category']]=['id'=>(string)$id]+$row;
}
function ownerShareStatus(array $share): string {
    try { $id=categoryIdentity(resolveDestinationDirectory($share['category'])); }
    catch (RequestError) { return 'Unavailable'; }
    return $id===$share['identity']?shareStatus($share):'Unavailable';
}
function libraryHref(string $dir,array $extra=[]): string {
    return 'up.php?'.http_build_query(['dir'=>$dir]+$extra,'','&',PHP_QUERY_RFC3986);
}
function hidden(string $csrf,string $action,string $dir=''): void {
    echo '<input type="hidden" name="csrf" value="'.h($csrf).'"><input type="hidden" name="action" value="'.h($action).'"><input type="hidden" name="dir" value="'.h($dir).'">';
}
$skill=<<<'SKILL'
---
name: personal-opds-upload
description: Upload EPUB and TXT to the authenticated user's personal OPDS library.
---

Use the configured OPDS_TOKEN environment variable. Do not print or store it in the skill.
Upload to the HTTPS URL below using multipart files[]. Omit directory for the library root.
For a subdirectory, add --form-string 'directory=Reading notes'; a valid missing folder is created.
Only one level is supported. Inspect success, results, and already_exists. Identical retries succeed
without replacing files; a conflicting file with different contents is never overwritten.
For partial success retry only failed files. For a network interruption, retry the identical file.
Limits: 20 files per API request, 100 MiB per file, 200 MiB combined, subject to user quotas.

    curl --fail-with-body --show-error -H "Authorization: Bearer $OPDS_TOKEN" \
      -F 'files[]=@./article.epub' -- '__OPDS_UPLOAD_URL__'

SKILL;
$skill=str_replace("__OPDS_UPLOAD_URL__",str_replace("'","'\"'\"'",PUBLIC_UPLOAD_URL),$skill);
if (!empty($downloadSkill)) {
    header('Content-Type: text/markdown; charset=UTF-8');
    header('Content-Disposition: attachment; filename="SKILL.md"');
    echo $skill; exit;
}
function shareBadge(string $status): string {
    return match($status) { 'Expiring soon'=>'badge pill-warn','Expired','Revoked','Unavailable','Not shared'=>'badge pill-off',default=>'badge' };
}
function folderNav(array $directories,string $dir,array $statuses): void {
    echo '<nav class="folders" aria-label="'.tr_html('Library folders').'">';
    foreach (['',...$directories] as $item) {
        $badge=isset($statuses[$item])?'<span class="'.shareBadge($statuses[$item]).'">'.h(tr($statuses[$item])).'</span>':'';
        echo '<a href="'.h(libraryHref($item)).'"'.($item===$dir?' aria-current="page"':'').'><span class="folder-name">'.h($item===''?tr('Library root'):$item).'</span>'.$badge.'</a>';
    }
    echo '</nav>';
}
function fileSizeLabel(int $size): string {
    return $size>=1048576?number_format($size/1048576,1).' MiB':($size>=1024?number_format($size/1024,1).' KiB':$size.' B');
}
?>
<!doctype html><html lang="<?=uiLanguage()==='zh'?'zh-CN':'en'?>"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?=h(LIBRARY_TITLE)?> · Personal OPDS</title>
<style nonce="<?=h($nonce)?>">
:root{color-scheme:light;--ink:#1c2b27;--soft:#50645b;--line:#dce5dc;--paper:#fff;--bg:#f5f7f2;--accent:#135a43;--mint:#e4f0e6;--warn:#98263d;--serif:Georgia,"Noto Serif CJK SC",serif}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,"Noto Sans CJK SC",sans-serif}
a{color:var(--accent)}:focus-visible{outline:3px solid #469777;outline-offset:3px}
.top{position:relative;display:flex;justify-content:space-between;align-items:center;gap:12px;min-height:76px;border-bottom:1px solid var(--line);background:var(--paper);padding:12px max(24px,calc((100vw - 1160px)/2))}
.top strong{display:block;font:700 1.15rem var(--serif);overflow-wrap:anywhere}.top small{display:block;font-size:.65rem;letter-spacing:.18em;font-weight:800;color:var(--accent);line-height:1.5}
.top .logout,.top-actions{display:flex;gap:10px;align-items:center}.top-actions{flex-wrap:wrap;justify-content:flex-end}.logout span{max-width:100px;overflow:hidden;text-overflow:ellipsis}.tools summary,.book-menu summary{list-style:none}.tools summary::-webkit-details-marker,.book-menu summary::-webkit-details-marker{display:none}
.tools-popover{position:absolute;z-index:2;top:calc(100% + 6px);inset-inline-end:max(12px,calc((100vw - 1160px)/2));width:min(430px,calc(100vw - 24px));max-height:min(70vh,550px);overflow:auto}.tools-popover form{margin-bottom:12px}.tools-popover textarea{display:block}
main{max-width:1208px;margin:auto;padding:34px 24px 70px}.layout{display:grid;grid-template-columns:218px minmax(0,1fr);gap:42px;align-items:start}.shelf>.sidebar,.shelf>.shelf-body{min-width:0}
.panel,.books-surface{background:var(--paper);border:1px solid var(--line);border-radius:18px}.panel{padding:22px;min-width:0}.auth{max-width:440px;margin:36px auto}
.side-title{display:flex;align-items:center;justify-content:space-between;gap:4px;border-bottom:1px solid var(--line);padding:0 0 12px;margin-bottom:9px}.side-title h2{margin:0}
.folders{display:grid;gap:4px}.folders a{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px;border:1px solid transparent;border-radius:10px;text-decoration:none;color:var(--ink)}
.folders a[aria-current]{border-color:#c6ddcd;background:var(--mint);color:var(--accent);font-weight:740}.folders a:hover{background:var(--mint)}.folder-name{min-width:0;overflow-wrap:anywhere}
.folder-trigger{display:none}.shelf-head{padding:5px 0 20px}.shelf-heading-row{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}.shelf-heading-row>div{min-width:0}.heading-title{font:700 clamp(28px,4vw,50px)/1.2 var(--serif);letter-spacing:-.025em;margin:0}
.eyebrow{font-size:.73rem;color:var(--accent);letter-spacing:.1em;font-weight:760;text-transform:uppercase;margin:0 0 8px}.shelf-meta{display:flex;align-items:center;flex-wrap:wrap;gap:8px 12px;margin-top:12px;color:var(--soft);font-size:.86rem}.upload-launch{flex:none}
.pill-trigger{display:inline-flex;gap:7px;align-items:center;flex-wrap:wrap;font-size:.76rem;padding:5px 9px;min-height:34px}.pill-trigger time{font-weight:550}.badge{display:inline-block;font-size:.68rem;background:var(--mint);color:var(--accent);border-radius:100px;padding:3px 7px;white-space:nowrap}.pill-warn{background:#fff1d8;color:#793e00}.pill-off{background:#edf0ec;color:#485b51}
.books-surface{padding:0 18px}.list-head{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:13px 1px;color:var(--soft)}.list-head h2{margin:0;color:var(--ink)}.book{position:relative;display:grid;grid-template-columns:38px minmax(0,1fr) auto auto;gap:10px;align-items:center;padding:11px 0;border-top:1px solid var(--line);min-height:71px}.book-icon{display:grid;place-items:center;width:36px;height:43px;border-radius:5px 9px 9px 5px;background:#e3eee6;color:#2d6a4f;border-left:3px solid #aac9b4;font-size:.55rem;font-weight:850;letter-spacing:.02em}.book-icon.txt{background:#f3ead8;color:#76571f;border-color:#dbbf83}.book-name{color:var(--ink);text-decoration:none;font-size:.96rem;font-weight:680;line-height:1.35;overflow-wrap:anywhere}.book-name:hover{text-decoration:underline}.book-info small{display:block;font-size:.74rem;margin-top:3px}.book-menu{position:relative}.book-actions{display:grid;gap:5px;position:absolute;z-index:1;inset-inline-end:0;top:calc(100% + 4px);min-width:128px;padding:6px;background:white;border:1px solid var(--line);border-radius:10px;box-shadow:0 8px 26px #17342625}.book-actions button{width:100%;text-align:start}
.empty{padding:30px 12px;text-align:center;border-top:1px solid var(--line)}.empty p{margin:0}.pagination{padding:12px 0;border-top:1px solid var(--line)}
h1,h2,h3,p{margin:0 0 10px}h2{font-size:1.06rem}.bar,.actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.bar{justify-content:space-between}.bar h2{margin:0}.muted,small{color:var(--soft)}
.status,.error{padding:9px 12px;border-radius:9px;margin-bottom:12px;background:var(--mint);overflow-wrap:anywhere}.error{background:#fae9ed;color:var(--warn)}.shelf-notice:empty{display:none}
button,.button{min-height:39px;font:inherit;font-size:.87rem;font-weight:680;background:#f4f7f3;color:var(--ink);border:1px solid var(--line);border-radius:9px;padding:7px 11px;cursor:pointer;text-decoration:none;display:inline-block;line-height:1.5}button:hover,.button:hover{border-color:#98b5a5}.primary{background:var(--accent);color:white;border-color:var(--accent)}button.danger{color:var(--warn)}button:disabled{opacity:.6;cursor:wait}
input,select,textarea{max-width:100%;font:inherit;border:1px solid #a8baae;padding:8px;border-radius:8px;background:white;color:var(--ink)}label{display:block;margin:10px 0;font-weight:600}.auth input{width:100%}.share-link,textarea{width:100%;font-family:ui-monospace,monospace}textarea{min-height:106px}.dialog-close{margin-inline-start:auto}
dialog{width:min(500px,calc(100% - 24px));max-height:calc(100% - 28px);border:1px solid var(--line);border-radius:18px;padding:20px;color:var(--ink);box-shadow:0 16px 64px #132f2a35}dialog::backdrop{background:#132c28a0}dialog h2{font-size:1.25rem}dialog select{width:100%}.dialog-intro{margin-top:8px}.folder-form{margin-top:12px}.folder-form input{min-width:0;flex:1}.dialog-head{margin-bottom:10px}.upload-form input[type=file]{display:block;width:100%;margin-top:5px}.upload-form input::file-selector-button{border:0;padding:6px 10px;border-radius:6px;background:var(--mint);color:var(--ink);font:inherit;margin-right:8px}.upload-form progress{accent-color:var(--accent)}progress{max-width:94px}.queue p{overflow-wrap:anywhere}.queue{margin-top:10px}.subscription-preview{margin-top:12px}.subscription-preview ul{max-height:180px;overflow:auto;padding-inline-start:20px}
@media(max-width:760px){.top{padding:10px 14px;min-height:64px}.top .logout{gap:5px}.logout span{display:none}.top-actions{gap:5px}.tools summary,.top .logout button{font-size:.72rem;padding:6px 7px;min-height:34px}main{padding:15px 12px 44px}.layout{display:block}.sidebar{display:none}.folder-trigger{display:inline-flex;align-items:center;gap:6px;margin-bottom:10px;font-size:.8rem}.shelf-head{padding:0 1px 13px}.shelf-heading-row .eyebrow{display:none}.books-surface{padding:0 11px;border-radius:13px}.book{grid-template-columns:32px minmax(0,1fr) auto auto;gap:6px;min-height:66px}.book-icon{width:30px;height:38px}.book .button,.book summary{min-height:36px;padding:6px 7px;font-size:.78rem}.heading-title{font-size:clamp(24px,7vw,36px)}.shelf-meta{margin-top:8px}.shelf-heading-row{gap:6px}}
@media(max-width:370px){.top{flex-wrap:wrap}.top-actions{margin-inline-start:auto}.top strong{font-size:1rem}}
</style></head><body>
<header class="top"><div><small>Personal OPDS</small><strong><?=h(LIBRARY_TITLE)?></strong></div>
<?php if ($user): ?><div class="top-actions">
<details class="tools" <?=$token!==''?'open':''?>><summary class="button"><?=tr_html('CLI / API & upload Skill')?></summary>
<div class="panel tools-popover">
<p><a href="index.php"><?=tr_html('OPDS catalog')?></a></p>
<p class="muted"><?=tr_html('The token is shown once. Keep it private. Generating one replaces any previous token.')?></p>
<form action="up.php" method="post" data-confirm="<?=tr_html('Generate a new upload token and invalidate the old one?')?>"><?php hidden($csrf,'token',$dir);?><button><?=tr_html('Generate upload token')?></button></form>
<?php if ($token!==''): ?><label><?=tr_html('Upload token')?><input class="share-link" readonly value="<?=h($token)?>"></label><?php endif;?>
<p class="muted"><?=tr_html('SKILL.md is written in English for your AI assistant. It does not include your token.')?></p>
<label>SKILL.md<textarea readonly lang="en"><?=h($skill)?></textarea></label>
<a href="up.php?skill=1"><?=tr_html('Download SKILL.md')?></a>
</div></details>
<form action="up.php" method="post" class="logout"><?php hidden($csrf,'logout');?><span><?=h($viewer)?></span><button><?=tr_html('Sign out')?></button></form>
</div><?php endif;?></header>
<main>
<?php if ($notice!==''): ?><p role="status" class="status"><?=h($notice)?></p><?php endif;?>
<?php if ($error!==''): ?><p role="alert" class="error"><?=h($error)?></p><?php endif;?>
<?php if ($activate!=='' || !$user): ?><section class="panel auth">
<p class="eyebrow"><?=tr_html('Private library')?></p>
<?php if ($activate!==''): ?><h1><?=tr_html('Set your password')?></h1><p class="muted"><?=h(sprintf(tr('Set a password for %s. Use the same password in your OPDS reader.'),$activateFor))?></p>
<form method="post" action="up.php"><?php hidden($csrf,'activate');?><input type="hidden" name="activate" value="<?=h($activate)?>"><input type="hidden" name="account" value="<?=h($activateFor)?>">
<label><?=tr_html('New password')?><input type="password" name="password" required autocomplete="new-password"></label><label><?=tr_html('Confirm password')?><input type="password" name="confirm" required autocomplete="new-password"></label><button class="primary"><?=tr_html('Set password')?></button></form>
<?php else: ?><h1><?=tr_html('Your reading room')?></h1><p class="muted"><?=tr_html('Sign in to manage your books and share folders.')?></p>
<form action="up.php" method="post"><?php hidden($csrf,'login');?><label><?=tr_html('Username')?><input name="username" required autocomplete="username" autocapitalize="none"></label><label><?=tr_html('Password')?><input type="password" name="password" required autocomplete="current-password"></label><button class="primary"><?=tr_html('Sign in')?></button></form>
<?php endif;?></section>
<?php else:
$selectedShare=$mine[$dir]??null; $status=$selectedShare?ownerShareStatus($selectedShare):'Not shared';
$active=in_array($status,['Shared','Expiring soon'],true);
$files=listBookFiles(resolveDestinationDirectory($dir));
$statuses=array_map('ownerShareStatus',$mine);
ksort($files,SORT_NATURAL|SORT_FLAG_CASE);
$fileCount=count($files);
$pages=max(1,(int)ceil($fileCount/40));
$pageParam=$_GET['page']??'1';
$page=is_string($pageParam)&&preg_match('/\A[0-9]{1,6}\z/D',$pageParam)?max(1,min($pages,(int)$pageParam)):1;
$pageFiles=array_slice($files,($page-1)*40,40,true);
natcasesort($directories);
$directories=array_values($directories);
$shelfName=$dir===''?tr('Library root'):$dir;
$expiry=$selectedShare?gmdate('Y-m-d',$selectedShare['expires']):'';
$previewBooks=[];
if ($preview) {
    $GLOBALS['shareCategory']=$dir;
    try {
        $previewBooks=books([$dir=>resolveDestinationDirectory($dir)]);
        usort($previewBooks,static fn($a,$b)=>strcasecmp($a['title'],$b['title']));
    } finally { unset($GLOBALS['shareCategory']); }
}
?>
<div class="layout shelf">
<aside class="sidebar">
 <div class="side-title"><h2><?=tr_html('Folders')?></h2><button type="button" data-dialog="folder-list" data-focus-folder><?=tr_html('New folder')?></button></div>
 <?php folderNav($directories,$dir,$statuses); ?>
</aside>
<div class="shelf-body">
 <div class="shelf-head">
  <button class="folder-trigger" type="button" data-dialog="folder-list"><?=tr_html('Choose folder')?> <span aria-hidden="true">⌄</span></button>
  <div class="shelf-heading-row">
   <div><p class="eyebrow"><?=tr_html('Your library')?></p><h1 class="heading-title"><?=h($shelfName)?></h1></div>
   <button class="primary upload-launch" type="button" data-dialog="upload-dialog"><?=tr_html('Upload books')?></button>
  </div>
  <div class="shelf-meta">
   <span id="shelf-count"><?=h(sprintf(tr('Total books: %s'),number_format($fileCount)))?></span>
   <?php if ($dir!==''): ?>
   <button class="pill-trigger" type="button" data-dialog="share-dialog" aria-label="<?=tr_html('Manage subscription sharing')?>" aria-describedby="share-current-status"><span id="share-current-status" class="<?=shareBadge($status)?>"><?=h(tr($status))?></span><?php if ($active): ?><time datetime="<?=h($expiry)?>"><?=h(sprintf(tr('Expires %s UTC'),$expiry))?></time><?php endif; ?><span aria-hidden="true">›</span></button>
   <?php endif; ?>
  </div>
 </div>
 <p role="status" class="status shelf-notice" id="upload-notice"></p>
 <section id="books-panel" class="books-surface" aria-labelledby="books-heading">
  <div class="list-head"><h2 id="books-heading"><?=tr_html('Books')?></h2><?php if ($files): ?><small><?=tr_html('Book actions')?></small><?php endif; ?></div>
  <?php if (!$files): ?><div class="empty"><p class="muted"><?=tr_html('No books here yet. Upload an EPUB or TXT to get started.')?></p></div><?php endif; ?>
  <?php foreach ($pageFiles as $name=>$size):
    $download=libraryHref($dir,['download'=>$name]);
    $format=strtolower(pathinfo($name,PATHINFO_EXTENSION)); $title=pathinfo($name,PATHINFO_FILENAME); ?>
  <div class="book">
   <span aria-hidden="true" class="book-icon <?=$format==='txt'?'txt':''?>"><?=h(strtoupper($format))?></span>
   <div class="book-info"><a class="book-name" href="<?=h($download)?>" title="<?=h($name)?>"><?=h($title)?></a><small><?=h(strtoupper($format).' · '.fileSizeLabel($size))?></small></div>
   <a class="button" href="<?=h($download)?>" aria-label="<?=h(sprintf(tr('Download %s'),$name))?>"><?=tr_html('Download')?></a>
   <details class="book-menu">
    <summary class="button" aria-label="<?=h(sprintf(tr('More actions for %s'),$name))?>">···</summary>
    <div class="book-actions">
     <?php if ($directories): ?><button type="button" data-book-move="<?=h($name)?>"><?=tr_html('Move')?></button><?php endif;?>
     <form action="up.php" method="post" data-confirm="<?=$active?tr_html('Delete this book? Subscribers will no longer be able to download it.'):tr_html('Delete this book?')?>"><?php hidden($csrf,'delete',$dir);?><input type="hidden" name="file" value="<?=h($name)?>"><button class="danger"><?=tr_html('Delete')?></button></form>
    </div>
   </details>
  </div>
  <?php endforeach; ?>
  <?php if ($pages>1): ?><nav class="bar pagination" aria-label="<?=tr_html('Pagination')?>"><?php if($page>1):?><a class="button" href="<?=h(libraryHref($dir,['page'=>$page-1]))?>"><?=tr_html('Previous')?></a><?php endif;?><small><?=$page?> / <?=$pages?></small><?php if($page<$pages):?><a class="button" href="<?=h(libraryHref($dir,['page'=>$page+1]))?>"><?=tr_html('Next')?></a><?php endif;?></nav><?php endif;?>
 </section>
</div>
</div>
<dialog id="folder-list" aria-labelledby="folder-dialog-title">
 <div class="bar dialog-head"><h2 id="folder-dialog-title"><?=tr_html('Folders')?></h2><button type="button" class="dialog-close" aria-label="<?=tr_html('Close')?>">×</button></div>
 <?php folderNav($directories,$dir,$statuses); ?>
 <form class="folder-form actions" method="post" action="up.php"><?php hidden($csrf,'folder',$dir);?><input name="folder" aria-label="<?=tr_html('New folder name')?>" placeholder="<?=tr_html('New folder name')?>" required maxlength="240"><button class="primary"><?=tr_html('New folder')?></button></form>
</dialog>
<?php if ($dir!==''): ?>
<dialog id="share-dialog" aria-labelledby="share-dialog-title" <?=$preview?'data-show':''?>>
 <div class="bar dialog-head"><h2 id="share-dialog-title"><?=tr_html('Subscription share')?></h2><button type="button" class="dialog-close" aria-label="<?=tr_html('Close')?>">×</button></div>
 <p><strong><?=h($shelfName)?></strong> <span class="<?=shareBadge($status)?>"><?=h(tr($status))?></span></p>
 <?php if ($selectedShare && in_array($status,['Shared','Expiring soon','Expired'],true)): ?><p class="muted"><?=h(sprintf(tr('Expires %s UTC'),$expiry))?></p><?php endif;?>
 <p class="muted"><?=tr_html('Anyone with this link can read only this folder. Links expire after 120 days.')?></p>
 <?php if ($active): $shareId=$selectedShare['id'].'-'.shareCode($selectedShare['id'],$selectedShare['salt']); $shareUrl=publicShareUrl($shareId); ?>
 <div class="actions">
 <button type="button" class="primary" id="copy-share" data-copied="<?=tr_html('Copied')?>" data-copy-failed="<?=tr_html('Copy failed. Select and copy the link manually.')?>"><?=tr_html('Copy URL')?></button>
 <form action="up.php" method="post" data-confirm="<?=tr_html('Revoke this share? Subscribers will immediately lose access.')?>"><?php hidden($csrf,'revoke',$dir);?><button class="danger"><?=tr_html('Revoke')?></button></form>
 </div><p id="copy-status" role="status"></p>
 <label><?=tr_html('Subscription URL')?><input class="share-link" id="share-url" readonly value="<?=h($shareUrl)?>"></label>
 <?php endif; ?>
 <div class="actions">
 <a class="button" href="<?=h(libraryHref($dir,['preview'=>$preview?'0':'1']))?>"><?=tr_html($preview?'Close preview':'Preview')?></a>
 <form action="up.php" method="post" <?=$active?'data-confirm="'.tr_html('Replace this link? The old link stops working immediately.').'"':''?>><?php hidden($csrf,'share',$dir);?><button class="<?=$active?'':'primary'?>"><?=tr_html($active?'Replace link':'Create share')?></button></form>
 </div>
 <?php if ($preview): ?><div class="subscription-preview"><p class="muted"><?=h(sprintf(tr('Read-only preview · Books in this subscription: %s'),number_format(count($previewBooks))))?></p><ul><?php foreach (array_slice($previewBooks,0,100) as $book): ?><li><?=h($book['title'])?></li><?php endforeach;?></ul></div><?php endif;?>
</dialog>
<?php endif;?>
<dialog id="upload-dialog" aria-labelledby="upload-dialog-title">
 <div class="bar dialog-head"><h2 id="upload-dialog-title"><?=tr_html('Upload books')?></h2><button type="button" class="dialog-close" aria-label="<?=tr_html('Close')?>">×</button></div>
 <form id="upload-folder" class="folder-form actions" method="post" action="up.php" hidden><?php hidden($csrf,'folder',$dir);?><input name="folder" aria-label="<?=tr_html('New folder name')?>" placeholder="<?=tr_html('New folder name')?>" required maxlength="240"><button type="submit"><?=tr_html('Create')?></button></form>
 <p id="upload-folder-status" role="status" class="status shelf-notice"></p>
 <form id="upload" class="upload-form" data-current="<?=h($dir)?>" data-interrupted="<?=tr_html('Connection interrupted. Save status is unknown; check the library before retrying.')?>" data-timeout="<?=tr_html('Request timed out. Save status is unknown; check the library before retrying.')?>" data-rejected="<?=tr_html('Server rejected the upload (HTTP %s).')?>" data-saved="<?=tr_html('Uploaded %s books.')?>" method="post" enctype="multipart/form-data" action="up.php">
 <?php hidden($csrf,'upload');?>
 <label><?=tr_html('Upload destination')?><select name="directory"><?php foreach (['',...$directories] as $dest): ?><option value="<?=h($dest)?>" <?=$dest===$dir?'selected':''?>><?=h($dest===''?tr('Library root'):$dest)?></option><?php endforeach;?></select></label>
 <button type="button" id="upload-folder-toggle" aria-expanded="false" aria-controls="upload-folder"><?=tr_html('New folder')?></button>
 <label><?=tr_html('Choose EPUB or TXT files')?><input id="files" type="file" name="files[]" accept=".epub,.txt" multiple required></label>
 <button class="primary" type="submit"><?=tr_html('Upload')?></button> <button type="button" id="retry" hidden><?=tr_html('Retry failed')?></button>
 </form><div class="queue" id="queue" aria-live="polite"></div>
</dialog>
<?php if ($directories): ?><dialog id="move-dialog" aria-labelledby="move-dialog-title"><form method="post" action="up.php" data-move="<?=$active?'1':'0'?>" data-shared-warning="<?=tr_html('Moving this book changes what subscribers can see. Continue?')?>"><?php hidden($csrf,'move',$dir);?>
<div class="bar dialog-head"><h2 id="move-dialog-title"><?=tr_html('Move')?></h2><button type="button" class="dialog-close" aria-label="<?=tr_html('Close')?>">×</button></div><p id="moving-book"></p>
<input type="hidden" name="file"><label><?=tr_html('Move destination')?><select name="destination">
<?php foreach (['',...$directories] as $dest): if($dest===$dir)continue;?><option value="<?=h($dest)?>" data-shared="<?=in_array($statuses[$dest]??'',['Shared','Expiring soon'],true)?'1':'0'?>"><?=h($dest===''?tr('Library root'):$dest)?></option><?php endforeach;?>
</select></label><button class="primary"><?=tr_html('Move')?></button></form></dialog><?php endif;?>
<?php endif;?>
</main>
<script nonce="<?=h($nonce)?>">
document.addEventListener('submit',e=>{
 const f=e.target;if(!f.matches('form[data-confirm],form[data-move]'))return;
 const message=f.dataset.confirm || ((f.dataset.move==='1'||f.elements.destination.selectedOptions[0]?.dataset.shared==='1')?f.dataset.sharedWarning:'');
 if(message&&!confirm(message))e.preventDefault();
});
const toolsMenu=document.querySelector('details.tools');
const shareDialog=document.querySelector('#share-dialog');
const uploadDialog=document.querySelector('#upload-dialog');
const moveDialog=document.querySelector('#move-dialog');
const form=document.querySelector('#upload'), retry=document.querySelector('#retry');
const destination=form?.elements.directory;
const folderForm=document.querySelector('#upload-folder');
const newFolder=document.querySelector('#upload-folder-toggle');
const filesInput=document.querySelector('#files');
let failed=[],busy=false,addingFolder=false,folderCreated=false,retryDestination='',uploaded=0;
document.addEventListener('click',e=>{
 if(toolsMenu?.open&&!toolsMenu.contains(e.target))toolsMenu.open=false;
 for(const menu of document.querySelectorAll('.book-menu[open]'))if(!menu.contains(e.target))menu.open=false;
 const open=e.target.closest('[data-dialog]');
 if(open){
  const target=document.getElementById(open.dataset.dialog);
  target?.showModal();
  if(open.hasAttribute('data-focus-folder'))target?.querySelector('[name=folder]')?.focus();
 }
 const close=e.target.closest('.dialog-close');
 if(close&&!(close.closest('dialog')===uploadDialog&&(busy||addingFolder)))close.closest('dialog')?.close();
 const trigger=e.target.closest('[data-book-move]');
 if(!trigger||!moveDialog)return;
 moveDialog.querySelector('[name=file]').value=trigger.dataset.bookMove;
 moveDialog.querySelector('#moving-book').textContent=trigger.dataset.bookMove;
 moveDialog.showModal();
});
document.addEventListener('keydown',e=>{
 if(e.key!=='Escape')return;
 if(toolsMenu?.open){toolsMenu.open=false;toolsMenu.querySelector('summary').focus();}
 const menu=document.activeElement?.closest('.book-menu[open]');
 if(menu){menu.open=false;menu.querySelector('summary').focus();}
});
shareDialog?.addEventListener('close',()=>{
 const url=new URL(location.href);
 if(url.searchParams.has('preview')){url.searchParams.delete('preview');history.replaceState(null,'',url);}
});
if(shareDialog?.hasAttribute('data-show'))shareDialog.showModal();
uploadDialog?.addEventListener('cancel',e=>{if(busy||addingFolder)e.preventDefault();});
uploadDialog?.addEventListener('close',()=>{if(folderCreated)location.reload();});
const copy=document.querySelector('#copy-share');
copy?.addEventListener('click',async()=>{const url=document.querySelector('#share-url'); try{await navigator.clipboard.writeText(url.value);document.querySelector('#copy-status').textContent=copy.dataset.copied;}catch{url.select();document.querySelector('#copy-status').textContent=copy.dataset.copyFailed;}});
function setUploadControls() {
 const blocked=busy||addingFolder;
 for(const control of [destination,filesInput,newFolder,retry,form.querySelector('[type=submit]'),uploadDialog.querySelector('.dialog-close')])control.disabled=blocked;
}
newFolder?.addEventListener('click',()=>{
 folderForm.hidden=!folderForm.hidden;newFolder.setAttribute('aria-expanded',String(!folderForm.hidden));
 if(!folderForm.hidden)folderForm.elements.folder.focus();
});
folderForm?.addEventListener('submit',async e=>{
 e.preventDefault();if(busy||addingFolder)return;
 addingFolder=true;setUploadControls();
 const button=folderForm.querySelector('button');button.disabled=true;
 const status=document.querySelector('#upload-folder-status');
 try {
  const res=await fetch('up.php',{method:'POST',headers:{Accept:'application/json'},body:new FormData(folderForm)});
  const result=await res.json();
  status.textContent=result.message;
  if(res.ok&&result.success){
   if(!Array.from(destination.options).some(o=>o.value===result.folder))destination.add(new Option(result.folder,result.folder));
   destination.value=result.folder;folderCreated=true;failed=[];retry.hidden=true;
   folderForm.reset();folderForm.hidden=true;newFolder.setAttribute('aria-expanded','false');
  }
 }catch{status.textContent=form.dataset.interrupted;}
 finally{addingFolder=false;button.disabled=false;setUploadControls();}
});
destination?.addEventListener('change',()=>{if(destination.value!==retryDestination){failed=[];retry.hidden=true;}});
async function transfer(files,dir,again=false) {
 if(busy||addingFolder||!files.length)return;
 busy=true;setUploadControls();retry.hidden=true;failed=[];retryDestination=dir;if(!again)uploaded=0;
 const list=document.querySelector('#queue');list.replaceChildren();let changed=false;let lastMessage='';
 for(const file of files){
   const row=document.createElement('p'), bar=document.createElement('progress'), result=document.createElement('span');
   bar.max=100;bar.value=0;row.append(document.createTextNode(file.name+' '),bar,result);list.append(row);
   const data=new FormData(form);data.delete('dir');data.delete('files[]');data.set('directory',dir);data.append('files[]',file);
   const [ok,msg]=await new Promise(resolve=>{
     const x=new XMLHttpRequest();x.open('POST','up.php');x.timeout=180000;
     x.upload.onprogress=e=>{if(e.lengthComputable)bar.value=e.loaded/e.total*100;};
     x.onerror=()=>resolve([false,form.dataset.interrupted]);
     x.ontimeout=()=>resolve([false,form.dataset.timeout]);
     x.onload=()=>{try{const j=JSON.parse(x.responseText);if(typeof j.message!=='string')throw Error();resolve([x.status===200&&j.success,j.message]);}catch{resolve([false,form.dataset.rejected.replace('%s',String(x.status))]);}};x.send(data);
   });
   result.textContent=' '+msg; if(!ok)failed.push(file);else{bar.value=100;changed=true;uploaded++;lastMessage=msg;}
 }
 if(changed&&dir===form.dataset.current){
  try{
    const res=await fetch(location.href,{cache:'no-store'}), tree=new DOMParser().parseFromString(await res.text(),'text/html');
    const books=tree.querySelector('#books-panel'), count=tree.querySelector('#shelf-count');
    if(res.ok&&books&&count){
     document.querySelector('#books-panel').replaceWith(books);
     document.querySelector('#shelf-count').replaceWith(count);
    }
  }catch{}
 }
 busy=false;setUploadControls();retry.hidden=!failed.length;
 if(!failed.length){
  filesInput.value='';
  if(dir!==form.dataset.current){
   const target=new URL('up.php',location.href);target.searchParams.set('dir',dir);location.assign(target);
  }else{
   document.querySelector('#upload-notice').textContent=uploaded===1&&lastMessage?lastMessage:form.dataset.saved.replace('%s',String(uploaded));
   uploadDialog.close();
  }
 }
}
form?.addEventListener('submit',e=>{e.preventDefault();transfer(Array.from(filesInput.files),destination.value);});
retry?.addEventListener('click',()=>transfer(failed.slice(),retryDestination,true));
</script></body></html>
