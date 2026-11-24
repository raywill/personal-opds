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
            $password=field('password',$_POST);
            if ($password!==field('confirm',$_POST)) reject(tr('Passwords do not match.'));
            activateAccount($activateFor,$activate,$password);
            $_SESSION=[]; session_regenerate_id(true);
            $_SESSION['notice']=tr('Password set. Sign in with your new password.');
            go();
        }
        if ($action==='login') {
            $name=trim(field('username',$_POST)); $password=field('password',$_POST);
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
function fileSizeLabel(int $size): string {
    return $size>=1048576?number_format($size/1048576,1).' MiB':($size>=1024?number_format($size/1024,1).' KiB':$size.' B');
}
?>
<!doctype html><html lang="<?=uiLanguage()==='zh'?'zh-CN':'en'?>"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?=h(LIBRARY_TITLE)?> · Personal OPDS</title>
<style nonce="<?=h($nonce)?>">
:root{color-scheme:light;--ink:#17292d;--soft:#4d666b;--line:#dbe7e7;--paper:#fff;--bg:#f0f7f6;--accent:#076e64;--mint:#daf4eb;--warn:#9d263a}*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,sans-serif}a{color:var(--accent)}header.top{background:#0c3437;color:#fff;padding:16px max(20px,calc((100vw - 1240px)/2));display:flex;justify-content:space-between;align-items:center;gap:12px}.top strong{display:block;font-size:1.1rem}.top small{color:#9cd8ce;letter-spacing:.12em;text-transform:uppercase}.top form{display:flex;gap:10px;align-items:center}
main{max-width:1280px;margin:auto;padding:28px 20px 60px}.layout{display:grid;grid-template-columns:minmax(200px,260px) minmax(0,1fr);gap:20px}.panel{border:1px solid var(--line);border-radius:19px;background:var(--paper);padding:22px;box-shadow:0 8px 25px #193d3b0a;min-width:0}.side{align-self:start}.side a{display:flex;align-items:center;justify-content:space-between;gap:9px;padding:9px;border-radius:10px;text-decoration:none;overflow-wrap:anywhere}.side a[aria-current]{background:var(--mint);font-weight:720}.auth{max-width:460px;margin:45px auto}.stack>*+*{margin-top:16px}.bar,.actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.bar{justify-content:space-between}.muted,small{color:var(--soft)}h1,h2,h3,p{margin:0 0 12px}h1{font-size:clamp(1.65rem,4vw,2.42rem);letter-spacing:-.04em;overflow-wrap:anywhere}h2{font-size:1.13rem}.eyebrow{font-size:.73rem;color:var(--accent);letter-spacing:.14em;font-weight:800;text-transform:uppercase}.badge{font-size:.74rem;background:var(--mint);color:#105c51;border-radius:100px;padding:3px 9px;white-space:nowrap}.status,.error{padding:11px 13px;border-radius:10px;margin-bottom:12px;background:var(--mint)}.error{background:#fae9ed;color:var(--warn)}button,.button{font:inherit;font-size:.9rem;font-weight:680;background:#edf5f4;color:var(--ink);border:1px solid var(--line);border-radius:9px;padding:7px 11px;cursor:pointer;text-decoration:none;display:inline-block}.primary{background:var(--accent);color:white;border-color:var(--accent)}button.danger{color:var(--warn)}button:disabled{opacity:.5}input,select,textarea{max-width:100%;font:inherit;border:1px solid #aec5c6;padding:8px;border-radius:8px;background:white;color:var(--ink)}label{display:block;margin-bottom:10px;font-weight:600}.auth input{width:100%}.book{padding:10px 0;border-top:1px solid var(--line);overflow-wrap:anywhere}.book strong{flex:1}.book form{display:inline-flex;gap:6px;align-items:center}.book select{max-width:180px}.share-link,textarea{width:100%;font-family:ui-monospace,monospace}textarea{min-height:130px}.upload{border:1px dashed #82b5ad;border-radius:13px;background:#f6fbfa;padding:14px}progress{max-width:120px}.folder-form{margin-top:14px;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:5px}.folder-form input{min-width:0;width:100%}.upload h2{margin-bottom:8px}.upload input[type=file]{display:block;width:100%;margin-top:5px}.upload input::file-selector-button{border:0;padding:6px 10px;border-radius:6px;background:var(--mint);color:var(--ink);font:inherit;margin-right:8px}.upload progress{accent-color:var(--accent)}.actions{margin-top:6px}.book .actions{margin-top:0}.pagination{margin-top:12px}.pill-warn{background:#fff1d8;color:#793e00}.pill-off{background:#edf1f3;color:#4d5d68}.code-short{font:700 .9rem ui-monospace,monospace;white-space:nowrap}.dialog-close{margin-left:auto}dialog{width:min(440px,calc(100% - 24px));border:1px solid var(--line);border-radius:16px;padding:22px;color:var(--ink)}dialog::backdrop{background:#0c343783}dialog select{width:100%}summary{cursor:pointer;font-weight:650}
@media(max-width:680px){main{padding:14px 10px}.layout{grid-template-columns:1fr;gap:10px}.panel{padding:15px}.folders{display:flex;overflow:auto;gap:4px;padding-bottom:4px}.folders a{white-space:nowrap}.folder-form{display:flex;gap:5px}.folder-form input{min-width:0;flex:1}}
</style></head><body>
<header class="top"><div><small>Personal OPDS</small><strong><?=h(LIBRARY_TITLE)?></strong></div>
<?php if ($user): ?><form action="up.php" method="post"><?php hidden($csrf,'logout');?><span><?=h($viewer)?></span><button><?=tr_html('Sign out')?></button></form><?php endif;?></header>
<main>
<?php if ($notice!==''): ?><p role="status" class="status"><?=h($notice)?></p><?php endif;?>
<?php if ($error!==''): ?><p role="alert" class="error"><?=h($error)?></p><?php endif;?>
<?php if ($activate!=='' || !$user): ?><section class="panel auth">
<p class="eyebrow"><?=tr_html('Private library')?></p>
<?php if ($activate!==''): ?><h1><?=tr_html('Set your password')?></h1><p class="muted">Activate <?=h($activateFor)?>. Use the same password in your OPDS reader.</p>
<form method="post" action="up.php"><?php hidden($csrf,'activate');?><input type="hidden" name="activate" value="<?=h($activate)?>"><input type="hidden" name="account" value="<?=h($activateFor)?>">
<label><?=tr_html('New password')?><input type="password" name="password" required minlength="12" autocomplete="new-password"></label><label><?=tr_html('Confirm password')?><input type="password" name="confirm" required autocomplete="new-password"></label><button class="primary"><?=tr_html('Set password')?></button></form>
<?php else: ?><h1><?=tr_html('Your reading room')?></h1><p class="muted"><?=tr_html('Sign in to organize your books and share a shelf.')?></p>
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
$previewBooks=[];
if ($preview) {
    $GLOBALS['shareCategory']=$dir;
    try {
        $previewBooks=books([$dir=>resolveDestinationDirectory($dir)]);
        usort($previewBooks,static fn($a,$b)=>strcasecmp($a['title'],$b['title']));
    } finally { unset($GLOBALS['shareCategory']); }
}
?>
<div class="layout"><aside class="panel side"><h2><?=tr_html('Folders')?></h2><nav class="folders" aria-label="Library folders">
<?php foreach (['',...$directories] as $item): $row=$mine[$item]??null; ?>
<a href="<?=h(libraryHref($item))?>" <?=$item===$dir?'aria-current="page"':''?>><?=h($item===''?tr('Library root'):$item)?><?php if ($row): ?><span class="<?=shareBadge($statuses[$item])?>"><?=h(tr($statuses[$item]))?></span><?php endif;?></a>
<?php endforeach;?></nav>
<form class="folder-form" method="post" action="up.php"><?php hidden($csrf,'folder',$dir);?><input name="folder" aria-label="<?=tr_html('New folder name')?>" placeholder="<?=tr_html('New folder name')?>" required maxlength="240"><button><?=tr_html('Create')?></button></form>
</aside><section class="panel stack">
<div><p class="eyebrow"><?=tr_html('Your library')?></p><div class="bar"><h1><?=h($dir===''?tr('Library root'):$dir)?></h1><a class="button" href="index.php"><?=tr_html('OPDS catalog')?></a></div>
</div>
<?php if ($dir!==''): ?>
<section aria-label="Subscription" class="upload"><div class="bar"><h2><?=tr_html('Subscription share')?></h2><?php if ($selectedShare): ?><small>Expires <?=h(gmdate('Y-m-d',$selectedShare['expires']))?> UTC</small><?php endif;?></div>
<?php if ($active): $shareId=$selectedShare['id'].'-'.shareCode($selectedShare['id'],$selectedShare['salt']); $shareUrl=publicShareUrl($shareId); ?>
<p><span class="<?=shareBadge($status)?>"><?=h(tr($status))?></span> <code class="code-short"><?=h($shareId)?></code></p>
<input class="share-link" id="share-url" readonly value="<?=h($shareUrl)?>" aria-label="<?=tr_html('Subscription URL')?>">
<?php else: ?><p><span class="<?=shareBadge($status)?>"><?=h(tr($status))?></span></p><?php endif; ?>
<div class="actions">
<a class="button" href="<?=h(libraryHref($dir,['preview'=>$preview?'0':'1']))?>"><?=tr_html($preview?'Close preview':'Preview')?></a>
<?php if ($active): ?><button type="button" id="copy-share"><?=tr_html('Copy URL')?></button><span id="copy-status" role="status"></span><?php endif;?>
<form action="up.php" method="post" <?=$active?'data-confirm="'.tr_html('Replace this link? The old link stops working immediately.').'"':''?>><?php hidden($csrf,'share',$dir);?><button class="primary"><?=tr_html($active?'Replace link':'Create share')?></button></form>
<?php if ($active): ?><form action="up.php" method="post" data-confirm="<?=tr_html('Revoke this share? Subscribers will immediately lose access.')?>"><?php hidden($csrf,'revoke',$dir);?><button class="danger"><?=tr_html('Revoke')?></button></form><?php endif;?>
</div>
<?php if ($preview): ?><p class="muted">Read-only preview · <?=count($previewBooks)?> titles visible in the subscription</p><ul><?php foreach (array_slice($previewBooks,0,100) as $book): ?><li><?=h($book['title'])?></li><?php endforeach;?></ul><?php endif;?>
</section>
<?php endif;?>
<section class="upload"><h2><?=tr_html('Upload books')?></h2>
<form id="upload" method="post" enctype="multipart/form-data" action="up.php"><?php hidden($csrf,'upload');?><input type="hidden" name="directory" value="<?=h($dir)?>">
<label>To <?=h($dir===''?tr('Library root'):$dir)?><input id="files" type="file" name="files[]" accept=".epub,.txt" multiple required></label>
<button class="primary"><?=tr_html('Upload')?></button> <button type="button" id="retry" hidden><?=tr_html('Retry failed')?></button>
</form><div id="queue" aria-live="polite"></div></section>
<section id="books-panel"><div class="bar"><h2><?=tr_html('Books')?></h2><small><?=number_format($fileCount)?> <?=tr_html('Books')?></small></div><?php if (!$files): ?><p class="muted"><?=tr_html('No books here yet. Upload an EPUB or TXT to get started.')?></p><?php endif;?>
<?php foreach ($pageFiles as $name=>$size): ?>
<div class="book bar"><strong><?=h($name)?> <small><?=h(fileSizeLabel($size))?></small></strong><div class="actions">
<a class="button" href="<?=h(libraryHref($dir,['download'=>$name]))?>"><?=tr_html('Download')?></a>
<?php if ($directories): ?><button type="button" data-book-move="<?=h($name)?>"><?=tr_html('Move')?></button><?php endif;?>
<form action="up.php" method="post" data-confirm="<?=$active?tr_html('Delete this book? Subscribers will no longer be able to download it.'):tr_html('Delete this book?')?>"><?php hidden($csrf,'delete',$dir);?><input type="hidden" name="file" value="<?=h($name)?>"><button class="danger"><?=tr_html('Delete')?></button></form>
</div></div><?php endforeach;?>
<?php if ($pages>1): ?><nav class="bar pagination" aria-label="Pagination"><?php if($page>1):?><a class="button" href="<?=h(libraryHref($dir,['page'=>$page-1]))?>"><?=tr_html('Previous')?></a><?php endif;?><small><?=$page?> / <?=$pages?></small><?php if($page<$pages):?><a class="button" href="<?=h(libraryHref($dir,['page'=>$page+1]))?>"><?=tr_html('Next')?></a><?php endif;?></nav><?php endif;?>
</section>
<?php if ($directories): ?><dialog id="move-dialog"><form method="post" action="up.php" data-move="<?=$active?'1':'0'?>"><?php hidden($csrf,'move',$dir);?>
<div class="bar"><h2><?=tr_html('Move')?></h2><button type="button" class="dialog-close" aria-label="<?=tr_html('Close')?>">×</button></div><p id="moving-book"></p>
<input type="hidden" name="file"><label><?=tr_html('Move destination')?><select name="destination">
<?php foreach (['',...$directories] as $dest): if($dest===$dir)continue;?><option value="<?=h($dest)?>" data-shared="<?=in_array($statuses[$dest]??'',['Shared','Expiring soon'],true)?'1':'0'?>"><?=h($dest===''?tr('Library root'):$dest)?></option><?php endforeach;?>
</select></label><button class="primary"><?=tr_html('Move')?></button></form></dialog><?php endif;?>

<details <?=$token!==''?'open':''?>><summary><?=tr_html('CLI / API & upload Skill')?></summary>
<p class="muted"><?=tr_html('The token is shown once. Keep it private. Generating one replaces any previous token.')?></p>
<form action="up.php" method="post" data-confirm="<?=tr_html('Generate a new upload token and invalidate the old one?')?>"><?php hidden($csrf,'token',$dir);?><button><?=tr_html('Generate upload token')?></button></form>
<?php if ($token!==''): ?><label><?=tr_html('Upload token')?><input class="share-link" readonly value="<?=h($token)?>"></label><?php endif;?>
<label>SKILL.md<textarea readonly><?=h($skill)?></textarea></label>
<a href="up.php?skill=1"><?=tr_html('Download SKILL.md')?></a>
</details></section></div>
<?php endif;?>
</main>
<script nonce="<?=h($nonce)?>">
document.addEventListener('submit',e=>{
 const f=e.target;if(!f.matches('form[data-confirm],form[data-move]'))return;
 const message=f.dataset.confirm || ((f.dataset.move==='1'||f.elements.destination.selectedOptions[0]?.dataset.shared==='1')?'Moving this book changes what subscribers can see. Continue?':'');
 if(message&&!confirm(message))e.preventDefault();
});
const dialog=document.querySelector('#move-dialog');
document.addEventListener('click',e=>{
 const trigger=e.target.closest('[data-book-move]');if(!trigger||!dialog)return;
 const name=trigger.dataset.bookMove;dialog.querySelector('[name=file]').value=name;
 dialog.querySelector('#moving-book').textContent=name;dialog.showModal();
});
dialog?.querySelector('.dialog-close').addEventListener('click',()=>dialog.close());
const copy=document.querySelector('#copy-share');
copy?.addEventListener('click',async()=>{const url=document.querySelector('#share-url'); try{await navigator.clipboard.writeText(url.value);document.querySelector('#copy-status').textContent='Copied';}catch{url.select();}});
const form=document.querySelector('#upload'), retry=document.querySelector('#retry');let failed=[],busy=false;
async function transfer(files) {
 if(busy||!files.length)return;busy=true;form.querySelector('button').disabled=true;retry.hidden=true;failed=[];
 const list=document.querySelector('#queue');list.replaceChildren();let changed=false;
 for(const file of files){
   const row=document.createElement('p'), bar=document.createElement('progress'), result=document.createElement('span');
   bar.max=100;bar.value=0;row.append(document.createTextNode(file.name+' '),bar,result);list.append(row);
   const data=new FormData(form);data.delete('dir');data.delete('files[]');data.append('files[]',file);
   const [ok,msg]=await new Promise(resolve=>{
     const x=new XMLHttpRequest();x.open('POST','up.php');x.timeout=180000;
     x.upload.onprogress=e=>{if(e.lengthComputable)bar.value=e.loaded/e.total*100;};
     x.onerror=x.ontimeout=()=>resolve([false,'Connection interrupted']);
     x.onload=()=>{try{const j=JSON.parse(x.responseText);resolve([x.status===200&&j.success,j.message]);}catch{resolve([false,'Server rejected the upload (HTTP '+x.status+')']);}};x.send(data);
   });
   result.textContent=' '+msg; if(!ok)failed.push(file);else{bar.value=100;changed=true;}
 }
 if(changed){
  try{
    const res=await fetch(location.href,{cache:'no-store'}), tree=new DOMParser().parseFromString(await res.text(),'text/html');
    const books=tree.querySelector('#books-panel');if(books)document.querySelector('#books-panel').replaceWith(books);
  }catch{}
 }
 retry.hidden=!failed.length;form.querySelector('button').disabled=false;busy=false;
}
form?.addEventListener('submit',e=>{e.preventDefault();transfer(Array.from(document.querySelector('#files').files));});
retry?.addEventListener('click',()=>transfer(failed.slice()));
</script></body></html>
