<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/security.php';
require __DIR__.'/upload-common.php';
require __DIR__.'/accounts.php';
require __DIR__.'/catalogue.php';
require __DIR__.'/agent-skill.php';

header('Cache-Control: private, no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
$nonce=base64_encode(random_bytes(18));
header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$nonce'; script-src 'nonce-$nonce'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
try {
    requireUploadHttps();
    startWebSession();
    $user=webSessionAccount();
} catch (Throwable $e) { http_response_code($e instanceof RequestError?$e->getCode():503); exit(publicError($e)); }
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
    header('Location: '.BASE_URL.(currentLibrary()?libraryHref($dir):'up.php'),true,303);
    exit;
}
function goMembers(string $dir,string $action): never {
    header('Location: '.BASE_URL.libraryHref($dir,['manage'=>in_array($action,['member_invite','member_cancel'],true)?'pending':'members']),true,303);
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
$viewer=$user?$_SESSION['account']:'';
$error=''; $notice=''; $permissions=[]; $webLibraries=[]; $allLibraries=[]; $library=null; $dir=''; $activate=''; $activateFor=''; $preview=false; $renameDraft=null;
$siteAdmin=($user['site_admin']??null)===true; $accountInviteLink=''; $accountInviteName=''; $accountNotice='';
$action=is_string($_POST['action']??null)?$_POST['action']:'';
$invitationTarget=''; $invitation=''; $incomingInvite=null; $incomingLibrary=null;
$isInvitation=isset($_GET['target'])||isset($_GET['invitation'])||
    ($action==='login'&&(isset($_POST['target'])||isset($_POST['invitation'])));
$createdInvitation=$_SESSION['created_invitation']??[];
unset($_SESSION['created_invitation']);
try {
    if (!in_array($method,['GET','HEAD','POST'],true)) reject('Method not allowed.',405);
    if (isset($_GET['skill'])) reject('Standalone Skill download was removed. Use Connect Agent to copy the complete setup.',410);
    $activate=field('activate',$_GET); $activateFor=field('account',$_GET);
    $dir=field('dir',$_GET);
    if ($isInvitation && $activate==='') {
        $source=$method==='POST'?$_POST:$_GET;
        $invitationTarget=field('target',$source); $invitation=field('invitation',$source);
        if (!libraryIdValid($invitationTarget)||!preg_match('/\A[a-f0-9]{32}\z/D',$invitation))
            reject('Library invitation is unavailable.',410);
        if ($user) {
            $incomingLibrary=libraryInfo($invitationTarget);
            $candidate=$incomingLibrary['invites'][$viewer]??null;
            if (!$candidate||empty($incomingLibrary['owner_active'])||!empty($incomingLibrary['archived'])||$candidate['expires']<=time()||
                !hash_equals(invitationId($invitationTarget,$viewer,$candidate),$invitation))
                reject('Library invitation is unavailable.',410);
            $incomingInvite=$candidate;
        }
    }
    if ($user && $activate==='' && !$isInvitation) {
        $allLibraries=availableLibraries($viewer);
        $webLibraries=array_filter($allLibraries,static fn($row)=>array_intersect(WEB_PERMISSIONS,$row['permissions']));
        $globalAction=$method==='POST' && in_array($action,['logout','login','invite_accept','invite_decline','library_restore','account_invite'],true);
        $selection=$globalAction?'':($method==='POST'&&$action!=='upload'?field('library',$_POST):field('library',$_GET));
        if (!$globalAction && $selection==='' && count($webLibraries)===1 && !isset($_GET['choose'])) $selection=(string)array_key_first($webLibraries);
        // The login redirect never carries a selection. Anonymous OPDS routing is independent.
        if ($selection!=='' && !isset($webLibraries[$selection])) reject('Library access denied.',403);
        if ($selection!=='') {
            $library=$webLibraries[$selection];
            setLibraryScope($library);
            $permissions=array_fill_keys($library['permissions'],true);
        }
    }
    if ($method==='POST') {
        if ($action==='upload') requireMultipart();
        if (!hash_equals($_SESSION['csrf'],field('csrf',$_POST))) reject(tr('Session changed; reload the page.'),403);
        if ($action==='activate') {
            $activate=field('activate',$_POST); $activateFor=field('account',$_POST);
            reserveRateAttempt('activate',12,180);
            $password=passwordField('password');
            if ($password!==passwordField('confirm')) reject(tr('Passwords do not match.'));
            activateAccount($activateFor,$activate,$password);
            $_SESSION=[]; session_regenerate_id(true);
            $_SESSION['notice']='Password set. Sign in with your new password.';
            go();
        }
        if ($action==='login') {
            $name=trim(field('username',$_POST)); $password=passwordField('password');
            reserveRateAttempt('login',LOGIN_IP_LIMIT,LOGIN_GLOBAL_LIMIT);
            $verified=loginAccount($name,$password);
            if (!$verified) reject(tr('Incorrect username or password, or account not activated.'),401);
            signInWebSession($name,$verified['password']);
            if ($isInvitation) {
                header('Location: '.invitationLink($invitationTarget,$invitation),true,303);
                exit;
            }
            go();
        }
        if (!$user) reject(tr('Sign in again.'),401);
        $signedIn=$_SESSION;
        $GLOBALS['opdsWebSessionGuard']=static function () use ($viewer,$signedIn) {
            $record=activeAccount($viewer);
            if (!$record || !hash_equals($record['password'],$signedIn['password'])) reject(tr('Sign in again.'),401);
        };
        if ($action==='logout') { signOutWebSession(); go(); }
        if (in_array($action,['invite_accept','invite_decline','library_restore'],true)) {
            $requested=field('target_library',$_POST);
            if ($action==='library_restore') librarySettings($requested,$viewer,$action);
            else libraryAnswerInvite($requested,$viewer,$action==='invite_accept',field('invitation_id',$_POST));
            $_SESSION['notice']=$action==='library_restore'?'Library restored.':($action==='invite_accept'?'Invitation accepted.':'Invitation declined.');
            go();
        }
        if ($action==='account_invite') {
            if (!$siteAdmin) reject('Site administrator access required.',403);
            reserveRateAttempt('account-invite',15,150);
            $accountInviteName=trim(field('username',$_POST));
            $operation=field('operation',$_POST);
            if ($operation==='disable') {
                disableAccount($accountInviteName,$viewer,$signedIn['password']);
                $_SESSION['disabled_account_notice']=$accountInviteName;
                $return=field('library',$_POST);
                $returnDir=field('dir',$_POST);
                header('Location: '.BASE_URL.'up.php?'.http_build_query(
                    (isset($webLibraries[$return])?['library'=>$return,'dir'=>$returnDir]:[])+['accounts'=>1],'','&',PHP_QUERY_RFC3986),true,303);
                exit;
            }
            if (!in_array($operation,['create','renew','restore'],true)) reject('Unknown action.');
            $accountInviteLink=issueAccountActivation($accountInviteName,$operation,$viewer,$signedIn['password']);
            // Preserve the active library when the modal was opened from one.
            $return=field('library',$_POST);
            if (isset($webLibraries[$return])) {
                $library=$webLibraries[$return];
                setLibraryScope($library);
                $permissions=array_fill_keys($library['permissions'],true);
                $dir=field('dir',$_POST);
            }
        } else {
            $required=[
                'upload'=>'web_upload','folder'=>'folder','share'=>'share','revoke'=>'share','rename'=>'organize',
                'move'=>'organize','delete'=>'delete','agent_setup'=>'agent_upload','agent_revoke'=>'agent_upload',
                'legacy_token_revoke'=>'settings','member_invite'=>'members','member_edit'=>'members','member_remove'=>'members','member_cancel'=>'members','managed_token_revoke'=>'tokens',
                'library_rename'=>'settings','library_archive'=>'settings',
            ][$action]??null;
            if ($required===null) reject('Unknown action.');
            if (!$library) reject('Choose a library first.',403);
            $signedIn=$_SESSION;
            $GLOBALS['opdsUploadGuard']=static fn()=>requireLibraryPermission($required,$viewer,$signedIn);
            ($GLOBALS['opdsUploadGuard'])();
            if ($action==='upload') {
                session_write_close();
                uploadJsonResponse(processUpload(singleFile:true,bearer:false,pageDirectory:$dir));
            }
            $dir=field('dir',$_POST);
            resolveDestinationDirectory($dir);
            switch ($action) {
                case 'folder':
                    $new=field('folder',$_POST); uploadCommit(static fn()=>createCategory($new));
                    if (($_SERVER['HTTP_ACCEPT']??'')==='application/json') jsonResponse(['success'=>true,'message'=>tr('Folder ready.'),'folder'=>$new]);
                    $_SESSION['notice']='Folder ready.'; go($new);
                case 'share':
                case 'revoke':
                    uploadCommit(static fn()=>manageShare($dir,$action==='revoke'));
                    noteLibraryAction('share.'.$action,['directory'=>$dir]);
                    $_SESSION['notice']=$action==='revoke'?'Share revoked.':'Share link ready.'; go($dir);
                case 'rename':
                    $renameDraft=['file'=>field('file',$_POST),'name'=>field('new_name',$_POST)];
                    manageBook('rename',$dir,$renameDraft['file'],$renameDraft['name']);
                    $_SESSION['notice']='Book renamed.'; go($dir);
                case 'move':
                case 'delete':
                    manageBook($action,$dir,field('file',$_POST),field('destination',$_POST));
                    if ($action==='delete') noteLibraryAction('book.deleted',['directory'=>$dir,'file'=>field('file',$_POST)]);
                    $_SESSION['notice']=$action==='move'?'Book moved.':'Book deleted.'; go($dir);
                case 'agent_setup':
                    reserveRateAttempt('agent-setup',30,300);
                    $grant=issueAgentToken($library['id'],$viewer);
                    jsonResponse(['success'=>true,'setup'=>agentSetup($grant,currentLibrary())]);
                case 'legacy_token_revoke':
                    uploadCommit(static function () use ($viewer,$library) {
                        if ($library['legacy']!==$viewer) reject('Library access denied.',403);
                        stateUpdate('users',static function (&$users) use ($viewer) { unset($users[$viewer]['token']); });
                    });
                    noteLibraryAction('legacy-token.revoked');
                    $_SESSION['notice']='Token revoked.'; go($dir);
                case 'agent_revoke':
                case 'managed_token_revoke':
                    revokeAgentToken($library['id'],$viewer,field('token_id',$_POST));
                    $_SESSION['notice']='Token revoked.'; go($dir);
                case 'member_invite':
                case 'member_edit':
                case 'member_remove':
                case 'member_cancel':
                    $role=in_array($action,['member_invite','member_edit'],true)?field('role',$_POST):null;
                    if (isset($_POST['roles']) || $role==='') reject('Choose one role.');
                    $newInvite=libraryMemberChange($library['id'],$viewer,field('member',$_POST),$action,$role,field('invitation_id',$_POST));
                    if ($newInvite!==null) $_SESSION['created_invitation']=['library'=>$library['id'],'id'=>$newInvite];
                    $_SESSION['notice']=match($action) {
                        'member_invite'=>'Library invitation sent.', 'member_cancel'=>'Invitation cancelled.',
                        default=>'Library membership saved.',
                    }; goMembers($dir,$action);
                case 'library_rename':
                case 'library_archive':
                    librarySettings($library['id'],$viewer,$action,field('title',$_POST));
                    if ($action==='library_archive') { unset($GLOBALS['opdsLibrary']); go(); }
                    $_SESSION['notice']='Library renamed.'; go($dir);
                default: reject('Unknown action.');
            }
        }
    }
    if ($library && $activate==='') {
        resolveDestinationDirectory($dir);
        if (isset($_GET['download'])) {
            if (!isset($permissions['download'])) reject('Library access denied.',403);
            managementDownload($dir,field('download',$_GET));
        }
        $preview=isset($permissions['share'])&&($_GET['preview']??'')==='1'&&$dir!=='';
    }
} catch (Throwable $e) {
    if ($action==='agent_setup') jsonResponse(['success'=>false,'message'=>publicError($e)],$e instanceof RequestError?$e->getCode():500);
    $status=$e instanceof RequestError?$e->getCode():($e instanceof AccountStorageError?503:500);
    if ($action==='folder' && ($_SERVER['HTTP_ACCEPT']??'')==='application/json')
        jsonResponse(['success'=>false,'message'=>publicError($e)],$status);
    if ($action==='upload') jsonResponse(['success'=>false,'message'=>publicError($e),'results'=>[]],$status);
    http_response_code($status);
    $error=publicError($e);
    if ($library) { try { resolveDestinationDirectory($dir); } catch (Throwable) { $dir=''; } }
}
$notice=tr($_SESSION['notice']??''); unset($_SESSION['notice']);
if ($siteAdmin && isset($_GET['accounts']) && isset($_SESSION['disabled_account_notice'])) {
    $accountNotice=sprintf(tr('%s was disabled. Their books were kept.'),$_SESSION['disabled_account_notice']);
    unset($_SESSION['disabled_account_notice']);
}
$siteAccounts=$siteAdmin?stateRead('users'):[];
ksort($siteAccounts,SORT_NATURAL);
$pendingInvites=$user?libraryInvites($viewer):[];
$archivedLibraries=$user?ownedArchivedLibraries($viewer):[];
$csrf=$_SESSION['csrf'];
session_write_close();
$directories=$library?array_map('strval',array_keys(libraryDirectories())):[];
$mine=[];
if ($library && (isset($permissions['view'])||isset($permissions['share']))) foreach (stateRead('shares') as $id=>$row) {
    if (shareLibraryId($row)===$library['id']) $mine[$row['category']]=['id'=>(string)$id]+$row;
}
function ownerShareStatus(array $share): string {
    try { $id=categoryIdentity(resolveDestinationDirectory($share['category'])); }
    catch (RequestError) { return 'Unavailable'; }
    return $id===$share['identity']?shareStatus($share):'Unavailable';
}
function libraryHref(string $dir,array $extra=[]): string {
    return 'up.php?'.http_build_query((currentLibrary()?['library'=>currentLibrary()['id']]:[])+['dir'=>$dir]+$extra,'','&',PHP_QUERY_RFC3986);
}
function hidden(string $csrf,string $action,string $dir=''): void {
    if (currentLibrary()) echo '<input type="hidden" name="library" value="'.h(currentLibrary()['id']).'">';
    echo '<input type="hidden" name="csrf" value="'.h($csrf).'"><input type="hidden" name="action" value="'.h($action).'"><input type="hidden" name="dir" value="'.h($dir).'">';
}
function shareBadge(string $status): string {
    return match($status) { 'Expiring soon'=>'badge pill-warn','Expired','Revoked','Unavailable','Not shared'=>'badge pill-off',default=>'badge' };
}
function icon(string $name): string {
    $paths=[
        'book'=>'<path d="M12 6v14M4 5h5a3 3 0 0 1 3 2 3 3 0 0 1 3-2h5v14h-5a3 3 0 0 0-3 2 3 3 0 0 0-3-2H4z"/>',
        'folder'=>'<path d="M3 19V6h6l2 2h10v11z"/>',
        'home'=>'<path d="m3 10 9-7 9 7M6 9v11h12V9"/>',
        'down'=>'<path d="m6 9 6 6 6-6"/>',
        'plus'=>'<path d="M12 5v14M5 12h14"/>',
        'refresh'=>'<path d="M20 10a8 8 0 1 0-1.8 7.2M20 4v6h-6"/>',
        'close'=>'<path d="m7 7 10 10M17 7 7 17"/>',
        'upload'=>'<path d="M12 16V3m-4 4 4-4 4 4M4 15v5h16v-5"/>',
        'download'=>'<path d="M12 3v13m-4-4 4 4 4-4M4 16v4h16v-4"/>',
        'link'=>'<path d="M10 13a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1 1m2 6a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1-1"/>',
        'more'=>'<circle cx="5" cy="12" r="1" fill="currentColor"/><circle cx="12" cy="12" r="1" fill="currentColor"/><circle cx="19" cy="12" r="1" fill="currentColor"/>',
        'terminal'=>'<path d="M4 5h16v14H4zM7 9l3 3-3 3m6 0h4"/>',
        'logout'=>'<path d="M10 5H4v14h6m5-11 5 4-5 4m5-4H9"/>',
    ];
    return '<svg aria-hidden="true" class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">'.$paths[$name].'</svg>';
}
function folderNav(array $directories,string $dir,array $statuses,string $libraryName): void {
    echo '<nav class="folders" aria-label="'.tr_html('Library folders').'">';
    foreach (['',...$directories] as $item) {
        $badge=isset($statuses[$item])?'<span class="'.shareBadge($statuses[$item]).'">'.h(tr($statuses[$item])).'</span>':'';
        echo '<a href="'.h(libraryHref($item)).'"'.($item===$dir?' aria-current="page"':'').'><span class="folder-name">'.icon($item===''?'home':'folder').h($item===''?$libraryName:$item).'</span>'.$badge.'</a>';
    }
    echo '</nav>';
}
function fileSizeLabel(int $size): string {
    return $size>=1048576?number_format($size/1048576,1).' MiB':($size>=1024?number_format($size/1024,1).' KiB':$size.' B');
}
?>
<!doctype html><html lang="<?=uiLanguageTag()?>"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?=h(LIBRARY_TITLE)?> · Personal OPDS</title>
<style nonce="<?=h($nonce)?>">
:root{color-scheme:light;--ink:#182739;--soft:#465d77;--line:#d9e3ee;--paper:#fff;--bg:#f8fafc;--accent:#204fce;--blue-soft:#e8eefc;--mint:#e6f5ed;--green:#056447;--warn:#9b263a}
*{box-sizing:border-box}[hidden]{display:none!important}.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 system-ui,"Noto Sans CJK SC",sans-serif}
a{color:var(--accent)}:focus-visible{outline:3px solid #5683f4;outline-offset:3px}
.icon{width:17px;height:17px;flex:none;vertical-align:-.16em}
.top{position:relative;display:flex;justify-content:space-between;align-items:center;gap:12px;min-height:72px;border-bottom:1px solid var(--line);background:var(--paper);padding:0 24px}
.brand{display:inline-flex;align-items:center;gap:11px;color:var(--ink);text-decoration:none;min-width:0;font-size:17px;font-weight:780;overflow-wrap:anywhere}
.brand-mark{display:grid;place-items:center;width:37px;height:37px;flex:none;border-radius:11px;background:var(--accent);color:white}
.account summary,.book-menu summary{list-style:none}.account summary::-webkit-details-marker,.book-menu summary::-webkit-details-marker{display:none}
.account summary{display:flex;align-items:center;gap:11px;min-height:44px;padding:4px 13px;border-radius:9px;cursor:pointer;font-weight:720}.account summary:hover,.account[open] summary{background:var(--bg)}
.account-name{max-width:170px;overflow:hidden;text-overflow:ellipsis}.avatar{display:inline-flex;width:30px;height:30px;align-items:center;justify-content:center;border-radius:50%;background:var(--blue-soft);color:var(--accent);font-size:14px;font-weight:780}
.account-popover{position:absolute;z-index:3;top:calc(100% + 6px);inset-inline-end:24px;width:min(270px,calc(100vw - 32px));padding:6px;background:white;border:1px solid var(--line);border-radius:12px;box-shadow:0 12px 36px #13264024}
.account-library{display:flex;align-items:center;justify-content:space-between;gap:6px;margin-top:7px}.account-library .role-chip{font-size:.72rem}.account-caption{display:block;padding:9px 10px;color:var(--soft);font-size:12px;overflow-wrap:anywhere;border-bottom:1px solid var(--line);margin-bottom:4px}.account-popover .menu-item{width:100%;display:flex;align-items:center;justify-content:flex-start;gap:10px;text-decoration:none;color:var(--ink);text-align:start;padding:9px;border:0;border-radius:7px;background:white;font-size:14px;font-weight:620}.account-popover .menu-item:hover,.account-popover .menu-item:focus-visible{background:var(--blue-soft)}.account-popover .sign-out{color:var(--warn)}.account-popover form{border-top:1px solid var(--line);margin-top:4px;padding-top:4px}
main{margin:auto}.page-message{margin:12px 24px 0}.layout{display:grid;grid-template-columns:254px minmax(0,1fr);min-height:calc(100vh - 72px)}
.sidebar{border-inline-end:1px solid var(--line);padding:47px 18px 24px 24px;min-width:0}.shelf-body{min-width:0;padding:39px 24px 52px clamp(32px,5vw,64px)}
.panel{background:white;border:1px solid var(--line);border-radius:16px;padding:22px;min-width:0}.auth{max-width:440px;margin:44px auto;padding:24px}
.side-title{display:flex;align-items:center;justify-content:space-between;gap:4px;padding:0 2px 13px}.side-title h2{margin:0;color:var(--soft);font-size:13px;font-weight:700}
.folders{display:grid;gap:4px}.folders a{display:flex;align-items:center;justify-content:space-between;gap:8px;min-height:45px;padding:8px 10px;border-radius:8px;text-decoration:none;color:var(--soft)}.folders a:hover{background:var(--bg)}
.folders a[aria-current]{background:var(--blue-soft);color:var(--accent);font-weight:740}.folder-name{display:flex;align-items:center;gap:9px;min-width:0;overflow-wrap:anywhere}
.folder-trigger{display:none}.shelf-head{padding-bottom:18px}.shelf-heading-row{display:flex;justify-content:space-between;align-items:center;gap:12px}.shelf-heading-row>div{min-width:0}
.shelf-path{font-size:1.25rem;line-height:1.4;overflow-wrap:anywhere}.shelf-path a{color:var(--soft);font-weight:530;text-decoration:none}.shelf-path a:hover{color:var(--accent);text-decoration:underline}.shelf-path .separator{margin-inline:.45em;color:var(--soft)}.shelf-path h1{display:inline;margin:0;font:inherit;font-weight:700}.shelf-invites{margin-bottom:8px}
.eyebrow{font-size:.78rem;color:var(--soft);font-weight:680;margin:0 0 9px}.shelf-meta{display:flex;align-items:center;flex-wrap:wrap;gap:6px 14px;margin-top:10px;color:var(--soft);font-size:.8rem}.upload-launch{flex:none}
.pill-trigger{display:inline-flex;align-items:center;gap:7px;white-space:normal;border:0;border-radius:100px;font-size:.8rem;padding:7px 11px;min-height:36px;background:#edf2f7;color:var(--soft)}.pill-trigger.live{color:var(--green);background:var(--mint)}.pill-trigger.live:hover{background:#d9eee3}.pill-trigger time{font-weight:inherit}
.badge{display:inline-block;font-size:.76rem;background:var(--mint);color:var(--green);border-radius:100px;padding:4px 8px;white-space:nowrap}.pill-warn{background:#fff1d8;color:#793e00}.pill-off{background:#edf2f7;color:var(--soft)}
.root-folder-arrow{transform:rotate(-90deg);display:flex;color:var(--soft)}
.shelf-list{list-style:none;margin:0;padding:0;border-top:1px solid var(--line);--row-grid:38px minmax(0,1fr) 42px 42px;--row-gap:12px}
.book,.shelf-folder{position:relative;border-bottom:1px solid var(--line)}
.book,.shelf-folder>a{display:grid;grid-template-columns:var(--row-grid);gap:var(--row-gap);align-items:center;min-height:64px;padding:8px 0}
.shelf-folder>a{color:var(--ink);text-decoration:none}.shelf-folder>a:hover{background:var(--bg)}
.shelf-folder-icon{display:grid;place-items:center;width:100%;height:38px;color:var(--accent)}
.shelf-folder-name,.book-name{display:block;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.shelf-folder-name{font-size:.95rem;font-weight:720}.shelf-folder-detail{grid-column:3 / 5;display:flex;align-items:center;justify-content:flex-end;gap:6px;padding-inline-end:8px}
.book-icon{display:grid;place-items:center;width:38px;height:46px;border-radius:7px;background:var(--blue-soft);color:#234cac;font-size:.7rem;font-weight:790;letter-spacing:.02em}.book-icon.txt{background:#eaf2ec;color:#285e4b}
.book-name{color:var(--ink);text-decoration:none;font-size:.95rem;font-weight:720;line-height:1.35}.book-name:hover{text-decoration:underline}.book-info small{display:block;font-size:.78rem;margin-top:2px}.book-menu{position:relative}
.book-actions{display:grid;gap:4px;position:absolute;z-index:2;inset-inline-end:0;top:calc(100% + 4px);min-width:130px;padding:5px;background:white;border:1px solid var(--line);border-radius:9px;box-shadow:0 8px 26px #13264024}.book-actions button{width:100%;text-align:start}.empty{padding:30px 10px;text-align:center}.empty p{margin:0}.pagination{padding:12px 0}
h1,h2,h3,p{margin:0 0 10px}h2{font-size:1.06rem}.bar,.actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.bar{justify-content:space-between}.bar h2{margin:0}.muted,small{color:var(--soft)}
.status,.error{padding:9px 12px;border-radius:9px;margin-bottom:12px;background:var(--mint);overflow-wrap:anywhere}.error{background:#fae9ed;color:var(--warn)}.shelf-notice:empty{display:none}
.drop-shelf{position:relative}.drop-shelf.is-drop-target{outline:2px dashed var(--accent);outline-offset:-5px;background:#f5f8ff}.drop-shelf .drop-caption{display:none}.drop-shelf.is-drop-target .drop-caption{display:block;position:sticky;top:10px;z-index:3;height:0;margin:0;text-align:center;pointer-events:none}.drop-caption span{display:inline-block;padding:8px 12px;border-radius:8px;background:var(--accent);color:white}
#upload-dialog.is-drop-target{outline:2px dashed var(--accent);outline-offset:-5px;background:#f5f8ff}.upload-hint{color:var(--soft);font-size:.84rem;margin:.45rem 0}.upload-summary:empty,.drop-error:empty{display:none}.upload-summary{color:var(--soft);font-size:.84rem}.upload-row{display:grid;grid-template-columns:minmax(0,1fr) minmax(45px,90px);gap:3px 10px;align-items:center;padding:8px 0;border-bottom:1px solid var(--line)}.upload-row progress{width:100%;accent-color:var(--accent)}.upload-result{grid-column:1 / -1;font-size:.8rem;color:var(--soft)}.upload-result[data-state=error]{color:var(--warn)}.upload-result[data-state=saved]{color:var(--green)}
button,.button{min-height:40px;font:inherit;font-size:.89rem;font-weight:680;background:white;color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:7px 11px;cursor:pointer;text-decoration:none;display:inline-flex;gap:7px;align-items:center;justify-content:center;line-height:1.5}button:hover,.button:hover{background:var(--bg)}.primary{background:var(--accent);color:white;border-color:var(--accent)}.primary:hover{background:#1744bd}.primary.upload-launch{min-height:42px;padding:8px 14px;font-size:.96rem}
.icon-button{border-color:transparent;background:transparent;width:42px;min-height:42px;padding:0}.icon-button:hover{background:var(--blue-soft)}button.danger{color:var(--warn)}button:disabled{opacity:.6;cursor:wait}
input,select,textarea{max-width:100%;font:inherit;border:1px solid #acbfd9;padding:8px;border-radius:8px;background:white;color:var(--ink)}label{display:block;margin:12px 0;font-weight:650}.auth input{width:100%}.share-link,textarea{width:100%;font-family:ui-monospace,monospace}textarea{min-height:116px}.dialog-close{margin-inline-start:auto}.rename-name{display:flex;align-items:center;gap:8px;margin-bottom:10px}.rename-name input{min-width:0;flex:1}.rename-name span{color:var(--soft);flex:none}
dialog{width:min(500px,calc(100% - 28px));max-height:calc(100% - 28px);border:1px solid var(--line);border-radius:16px;padding:18px;color:var(--ink);box-shadow:0 16px 64px #182c4a30}dialog::backdrop{background:#172b4470}dialog h2{font-size:1.23rem}dialog select{width:100%}.folder-form{margin-top:12px}.folder-form input{min-width:0;flex:1}.dialog-head{margin-bottom:10px}.upload-target{color:var(--soft);background:var(--bg);padding:.65rem .8rem;border-radius:8px;overflow-wrap:anywhere}.upload-form input[type=file]{display:block;width:100%;margin-top:5px}.upload-form input::file-selector-button{border:0;padding:6px 10px;border-radius:6px;background:var(--blue-soft);color:var(--ink);font:inherit;margin-right:8px}.upload-form progress{accent-color:var(--accent)}progress{max-width:94px}.queue p{overflow-wrap:anywhere}.queue{margin-top:10px}.subscription-preview{margin-top:12px}.subscription-preview ul{max-height:180px;overflow:auto;padding-inline-start:20px}
.share-summary{margin:7px 0 10px;color:var(--soft)}.share-summary time{white-space:nowrap}.share-secondary{border-top:1px solid var(--line);padding-top:9px;margin-top:12px}.share-secondary .button,.share-secondary button{border-color:transparent}.tool-divider{border-top:1px solid var(--line);margin-top:14px;padding-top:10px}
@media(max-width:760px){.top{min-height:60px;padding:0 16px}.account-name{display:none}.account summary{padding:4px 9px}.account-popover{inset-inline-end:16px}.layout{display:block;min-height:calc(100vh - 60px)}.sidebar{display:none}.shelf-body{padding:17px 16px 40px}.page-message{margin:10px 16px 0}.auth{margin:32px 14px}.folder-trigger{display:inline-flex;align-items:center;gap:7px;margin-bottom:3px;border:0;padding:4px 10px}.shelf-head{padding-bottom:14px}.shelf-path{font-size:1.0625rem}.shelf-meta{margin-top:6px}.shelf-heading-row{gap:8px}.shelf-list{--row-grid:34px minmax(0,1fr) 34px 32px;--row-gap:8px}.shelf-folder-detail{padding-inline-end:0}.shelf-folder-detail .badge{white-space:normal;line-height:1.2;text-align:center}.book-icon{width:34px;height:42px}.book .icon-button{width:100%;min-height:40px}.sheet{margin:auto 0 0;width:100%;max-width:none;max-height:88%;border-radius:18px 18px 0 0;padding:14px 16px max(20px,env(safe-area-inset-bottom));}}
.brand-area{display:flex;align-items:center;gap:12px;min-width:0}.switcher{overflow-wrap:anywhere;line-height:1.2}
.library-picker{width:min(910px,calc(100% - 36px));margin:clamp(24px,6vw,76px) auto}.library-picker h1{font-size:clamp(26px,5vw,44px);letter-spacing:-.045em}.library-picker h2{margin-top:24px}.library-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,235px),1fr));gap:12px}.library-card{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:10px;align-items:center;color:var(--ink);text-decoration:none}.library-card:hover{border-color:var(--accent);background:var(--blue-soft)}.library-card strong,.library-card small{display:block;overflow-wrap:anywhere}.library-card small{margin-top:4px}.member-row,.token-row{padding:10px 0;border-top:1px solid var(--line)}.member-row summary{cursor:pointer}.member-row p,.token-row p{overflow-wrap:anywhere}
@media(max-width:480px){.brand-area .brand>span:last-child{display:none}.brand-area{gap:8px}.switcher{min-height:36px}}
.manage-dialog{width:min(44rem,calc(100% - 2rem));padding:24px;border:1px solid var(--line);border-radius:18px}
.manage-dialog .dialog-head{margin-bottom:1rem}.manage-dialog .dialog-head .eyebrow{margin:0 0 .25rem;color:var(--soft)}
.member-toolbar,.member-tabs{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.member-toolbar{justify-content:space-between;margin-bottom:1rem}.member-tabs{padding:.25rem;background:#f1f5f9;border-radius:.75rem}
.member-tabs [role=tab]{border:0;background:transparent;color:#475569;padding:.55rem .65rem;font-size:.9rem;white-space:nowrap}
.member-tabs [aria-selected=true]{background:white;color:#15348a;box-shadow:0 1px 4px #182f5420}
.member-tabs span{font-variant-numeric:tabular-nums;margin-left:.3em}
.member-line{display:grid;grid-template-columns:2.3rem minmax(0,1fr) auto auto;align-items:center;gap:.7rem;border-bottom:1px solid var(--line);padding:.75rem 0}
.member-line>strong,.member-line>div>strong{overflow-wrap:anywhere}.member-line small{display:block;color:#64748b}.member-avatar{display:grid;place-items:center;width:2.15rem;height:2.15rem;border-radius:50%;background:#eef2ff;color:#1e40af;font-weight:650}
.member-menu{position:relative}.member-menu .book-actions{z-index:2;min-width:10rem}.member-menu .book-actions button{text-align:left}
.role-chip{background:#f1f5f9;color:#36465e;border-radius:99px;padding:.23rem .65rem;font-size:.83rem;white-space:nowrap}.role-owner{background:#e9efff;color:#1e40af}
.member-empty{padding:1.4rem;text-align:center;background:#f8fafc;border:1px dashed var(--line);border-radius:.8rem}
.role-options{border:0;padding:0;margin:1rem 0}.role-options>legend{font-weight:700}.role-group{margin-top:.9rem}.role-group h3{font-size:.85rem;color:#475569;margin:0 0 .35rem}
.role-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.55rem}.role-card{display:flex;align-items:flex-start;gap:.6rem;border:1px solid var(--line);padding:.7rem .75rem;border-radius:.75rem;cursor:pointer;margin:0;background:white}.role-card:hover{border-color:#94aae4}.role-card:has(input:checked){outline:1px solid #3863df;border-color:#3863df;background:#f1f5ff}.role-card input{margin:.22rem 0 0;accent-color:#3159d9;flex:none}.role-card strong,.role-card small{display:block}.role-card small{font-weight:400;color:#475569;margin-top:.22rem;line-height:1.4}
.role-footer{position:sticky;bottom:-24px;background:white;border-top:1px solid var(--line);padding:.7rem 0;display:flex;justify-content:flex-end}.member-name-input input{width:100%}
.invitation-toolbar,.invitation-actions{display:flex;align-items:center;justify-content:space-between;gap:.5rem;flex-wrap:wrap}
.invitation-toolbar{margin-bottom:.4rem}.invitation-toolbar h3{margin:0}
.invitation-entry{border-bottom:1px solid var(--line);padding:.65rem 0}.invitation-entry .member-line{border:0;padding:0}
.invitation-entry .invitation-actions{justify-content:flex-start}.invitation-actions label{width:100%;margin:0}
.invitation-new{border:1px solid #b7caff;border-radius:.8rem;background:#f5f8ff;padding:.7rem;margin:.65rem 0}
.invitation-entry details{margin-top:.5rem}.invitation-entry details summary{width:max-content;max-width:100%;cursor:pointer}
.invitation-entry details form{margin-top:.5rem}.copy-result:not(:empty){display:block;margin-top:.35rem;color:var(--soft)}
.settings-section{border-top:1px solid var(--line);margin-top:1rem;padding-top:.8rem}.settings-section h3{margin:0 0 .55rem}#library-settings-dialog{width:min(29rem,calc(100% - 2rem))}
.settings-tabs{width:fit-content;margin-bottom:1rem;gap:.25rem}
.settings-form label{margin:0 0 .4rem}.settings-form input{width:100%;font-weight:500}
.settings-footer{display:flex;justify-content:flex-end;margin-top:1rem}
.archive-card{border:1px solid var(--line);border-radius:12px;background:#f8fafc;padding:1rem}.archive-card h3{font-size:1rem;margin:0 0 .35rem}.archive-card p{margin-bottom:.8rem}
@media(max-width:600px){#library-settings-dialog{width:100%}}
@media(max-width:600px){.manage-dialog{width:100%;padding:17px}.role-grid{grid-template-columns:1fr}.role-footer{bottom:-17px}.member-line{gap:.45rem}.member-toolbar{align-items:stretch}.member-line form button{padding:.35rem .45rem}}
</style></head><body>
<header class="top">
<div class="brand-area"><a class="brand" href="<?=h($library?libraryHref(''):'up.php')?>"><span class="brand-mark"><?=icon('book')?></span><span><?=h(LIBRARY_TITLE)?></span></a>
<?php if ($library && count($webLibraries)>1): ?><a class="button switcher" href="up.php?choose=1" aria-label="<?=tr_html('Switch library')?>"><?=h(libraryTitle($library,$viewer))?><?=icon('down')?></a><?php endif; ?></div>
<?php if ($user): ?>
<details class="account">
<summary aria-label="<?=tr_html('Account menu')?>"><span class="avatar" aria-hidden="true"><?=h(strtoupper($viewer[0]))?></span><span class="account-name"><?=h($viewer)?></span><?=icon('down')?></summary>
<div class="account-popover">
<div class="account-caption"><strong><?=h(sprintf(tr('Signed in as %s'),$viewer))?></strong>
<?php if ($library): ?>
<div class="account-library" aria-label="<?=tr_html('Your role in this library')?>"><span><?=h(libraryTitle($library,$viewer))?></span><span class="role-chip <?=$library['owner']===$viewer?'role-owner':''?>"><?=h($library['owner']===$viewer?tr('Owner'):libraryRoleLabel($library['members'][$viewer]??null))?></span></div>
<?php endif; ?></div>
<?php if (isset($permissions['agent_upload'])): ?><button type="button" class="menu-item" data-dialog="tools-dialog"><?=icon('terminal')?><?=tr_html('Connect Agent')?></button><?php endif; ?>
<?php if (array_filter($allLibraries,static fn($row)=>in_array('opds',$row['permissions'],true))): ?>
<button type="button" class="menu-item" data-dialog="reader-dialog"><?=icon('book')?><?=tr_html('Connect e-reader')?></button><?php endif; ?>
<?php if (isset($permissions['settings'])): ?><button type="button" class="menu-item" data-dialog="library-settings-dialog"><?=icon('more')?><?=tr_html('Library settings')?></button><?php endif; ?>
<?php if ($siteAdmin): ?><button type="button" class="menu-item" data-dialog="accounts-dialog"><?=icon('plus')?><?=tr_html('Site accounts')?></button><?php endif; ?>
<?php if (isset($permissions['members'])): ?><button type="button" class="menu-item" data-dialog="members-dialog"><?=icon('folder')?><?=tr_html('Library members')?></button><?php endif; ?>
<?php if ($pendingInvites || $archivedLibraries): ?><button type="button" class="menu-item" data-dialog="account-libraries-dialog"><?=icon('folder')?><?=tr_html('Invitations and archived libraries')?><?php if ($pendingInvites): ?> · <?=count($pendingInvites)?><?php endif; ?></button><?php endif; ?>
<form action="up.php" method="post"><?php hidden($csrf,'logout');?><button class="menu-item sign-out"><?=icon('logout')?><?=tr_html('Sign out')?></button></form>
</div></details>
<?php endif; ?>
</header>
<?php if ($user): ?>
<?php if ($siteAdmin): ?>
<dialog id="accounts-dialog" class="sheet manage-dialog" aria-labelledby="accounts-title" <?=($action==='account_invite'||isset($_GET['accounts']))?'data-manage-open':''?>>
<div class="bar dialog-head"><h2 id="accounts-title"><?=tr_html('Site accounts')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
<p class="muted"><?=tr_html('Create an account and send the one-time activation link privately. The recipient sets their own password.')?></p>
<?php if ($action==='account_invite'&&$error!==''): ?><p class="error" role="alert"><?=h($error)?></p><?php endif; ?>
<?php if ($accountNotice!==''): ?><p class="status" role="status"><?=h($accountNotice)?></p><?php endif; ?>
<?php if ($accountInviteLink!==''): ?>
<p class="status" role="status"><?=h(sprintf(tr('Activation link ready for %s. It expires in 24 hours.'),$accountInviteName))?></p>
<label><?=tr_html('Activation URL')?><input class="share-link" id="account-activation-url" readonly value="<?=h($accountInviteLink)?>"></label>
<button type="button" class="primary" id="copy-activation" data-copied="<?=tr_html('Copied.')?>" data-manual="<?=tr_html('Select and copy the activation link.')?>"><?=tr_html('Copy activation link')?></button><span id="copy-activation-status" role="status"></span>
<p class="muted"><?=tr_html('To share a specific library, invite the new account from that library once it has been activated.')?></p>
<?php else: ?>
<form method="post" action="up.php"><?php hidden($csrf,'account_invite',$dir);?>
<label class="member-name-input"><?=tr_html('Username')?><input name="username" value="<?=h($accountInviteName)?>" maxlength="32" required autocapitalize="none"></label>
<div class="actions"><button class="primary" name="operation" value="create"><?=tr_html('Create account and get link')?></button>
<button name="operation" value="renew"><?=tr_html('Replace pending activation link')?></button></div>
</form>
<?php endif; ?>
<section class="settings-section" aria-labelledby="site-account-list-title">
<h3 id="site-account-list-title"><?=tr_html('All accounts')?></h3>
<?php foreach ($siteAccounts as $username=>$record): $username=(string)$username; $state=$record['state']??''; ?>
<div class="member-line account-record"><span class="member-avatar" aria-hidden="true"><?=h(strtoupper($username[0]))?></span>
<div><strong><?=h($username)?></strong><?php if (!empty($record['site_admin'])): ?><small><?=tr_html('Site administrator')?></small><?php endif; ?></div>
<span class="role-chip <?=$state==='active'?'role-owner':''?>"><?=tr_html(match($state){'active'=>'Active','pending'=>'Awaiting activation','disabled'=>'Disabled',default=>'Unavailable'})?></span>
<?php if ($username!==$viewer&&empty($record['site_admin'])&&in_array($state,['pending','active','disabled'],true)): ?>
<?php $disabled=$state==='disabled'; ?>
<form method="post" action="up.php" <?=$disabled?'':'data-confirm="'.h(sprintf(tr('Disable %s? Sign-in, uploads and their personal library links will stop working. Books will be kept.'),$username)).'"'?>>
<?php hidden($csrf,'account_invite',$dir);?><input type="hidden" name="username" value="<?=h($username)?>">
<button name="operation" value="<?=$disabled?'restore':'disable'?>" class="<?=$disabled?'':'danger'?>"><?=tr_html($disabled?'Restore account':'Disable account')?></button></form>
<?php endif; ?></div>
<?php endforeach; ?>
</section></dialog>
<?php endif; ?>
<dialog id="account-libraries-dialog" class="sheet" aria-labelledby="account-libraries-title">
<div class="bar dialog-head"><h2 id="account-libraries-title"><?=tr_html('Invitations and archived libraries')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
<?php foreach ($pendingInvites as $id=>$row): $invite=$row['invites'][$viewer]; ?>
<div class="member-row"><strong><?=h(libraryTitle(libraryInfo((string)$id),$viewer))?></strong><p class="muted"><?=h(libraryRoleLabel($invite['role']??null))?></p>
<div class="actions"><?php foreach (['invite_accept'=>'Accept invitation','invite_decline'=>'Decline'] as $inviteAction=>$label): ?>
<form method="post" action="up.php"><?php hidden($csrf,$inviteAction);?><input type="hidden" name="target_library" value="<?=h((string)$id)?>"><input type="hidden" name="invitation_id" value="<?=h(invitationId((string)$id,$viewer,$invite))?>"><button class="<?=$inviteAction==='invite_accept'?'primary':''?>"><?=tr_html($label)?></button></form>
<?php endforeach; ?></div></div>
<?php endforeach; ?>
<?php foreach ($archivedLibraries as $id=>$row): ?>
<div class="member-row bar"><strong><?=h(libraryTitle(libraryInfo((string)$id),$viewer))?></strong><form method="post" action="up.php"><?php hidden($csrf,'library_restore');?><input type="hidden" name="target_library" value="<?=h((string)$id)?>"><button><?=tr_html('Restore library')?></button></form></div>
<?php endforeach; ?></dialog>
<dialog id="reader-dialog" class="sheet" aria-labelledby="reader-title">
<div class="bar dialog-head"><h2 id="reader-title"><?=tr_html('Connect e-reader')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
<p class="muted"><?=tr_html('Add the OPDS address to your reader and sign in with your account.')?></p>
<?php foreach ($allLibraries as $id=>$item): if (!in_array('opds',$item['permissions'],true)) continue; ?>
<div class="copy-row"><label><?=h(libraryTitle($item,$viewer))?><input class="share-link" readonly value="<?=h(BASE_URL.'index.php?'.http_build_query(['library'=>$id]))?>"></label>
<button type="button" data-copy-url><?=icon('link')?><?=tr_html('Copy OPDS address')?></button><small role="status" class="copy-result" data-copied="<?=tr_html('Copied.')?>" data-manual="<?=tr_html('Copy failed. Select and copy the link manually.')?>"></small></div>
<?php endforeach; ?></dialog>
<?php endif; ?>
<?php if ($library): $libraryName=libraryTitle($library,$viewer); ?>
<?php require __DIR__.'/library-controls.php'; ?>
<?php endif; ?>
<main>
<?php if ($notice!==''): ?><p role="status" class="status page-message"><?=h($notice)?></p><?php endif;?>
<?php if ($error!=='' && !$renameDraft): ?><p role="alert" class="error page-message"><?=h($error)?></p><?php endif;?>
<?php if ($activate!=='' || !$user): ?><section class="panel auth">
<p class="eyebrow"><?=tr_html('Private library')?></p>
<?php if ($activate!==''): ?><h1><?=tr_html('Set your password')?></h1><p class="muted"><?=h(sprintf(tr('Set a password for %s. Use the same password in your OPDS reader.'),$activateFor))?></p>
<form method="post" action="up.php"><?php hidden($csrf,'activate');?><input type="hidden" name="activate" value="<?=h($activate)?>"><input type="hidden" name="account" value="<?=h($activateFor)?>">
<label><?=tr_html('New password')?><input type="password" name="password" required autocomplete="new-password"></label><label><?=tr_html('Confirm password')?><input type="password" name="confirm" required autocomplete="new-password"></label><button class="primary"><?=tr_html('Set password')?></button></form>
<?php else: ?><h1><?=tr_html($isInvitation?'Library invitation':'Your reading room')?></h1><p class="muted"><?=tr_html($isInvitation?'Sign in with the account that was invited.':'Sign in to manage your books and share folders.')?></p>
<form action="up.php" method="post"><?php hidden($csrf,'login');?><?php if ($isInvitation && libraryIdValid($invitationTarget) && preg_match('/\A[a-f0-9]{32}\z/D',$invitation)): ?><input type="hidden" name="target" value="<?=h($invitationTarget)?>"><input type="hidden" name="invitation" value="<?=h($invitation)?>"><?php endif; ?><label><?=tr_html('Username')?><input name="username" required autocomplete="username" autocapitalize="none"></label><label><?=tr_html('Password')?><input type="password" name="password" required autocomplete="current-password"></label><button class="primary"><?=tr_html('Sign in')?></button></form>
<?php endif;?></section>
<?php elseif ($isInvitation): ?>
<section class="panel auth">
<p class="eyebrow"><?=tr_html('Library invitation')?></p>
<?php if ($incomingInvite): ?>
<h1><?=h(libraryTitle($incomingLibrary,$viewer))?></h1>
<p class="muted"><?=h(sprintf(tr('Invited by %s · Role: %s'),$incomingInvite['from'],libraryRoleLabel($incomingInvite['role'])))?></p>
<form method="post" action="up.php"><?php hidden($csrf,'invite_accept');?>
<input type="hidden" name="target_library" value="<?=h($invitationTarget)?>"><input type="hidden" name="invitation_id" value="<?=h($invitation)?>">
<button class="primary"><?=tr_html('Accept invitation')?></button></form>
<?php endif; ?>
<a class="button" href="up.php"><?=tr_html('Back to my libraries')?></a>
</section>
<?php elseif (!$library): ?>
<section class="library-picker" aria-labelledby="choose-library-title">
<p class="eyebrow"><?=h(LIBRARY_TITLE)?></p><h1 id="choose-library-title"><?=tr_html('Choose a library')?></h1>
<p class="muted"><?=tr_html($webLibraries?'Choose the library you want to open.':'No libraries available on the web.')?></p>
<?php if ($pendingInvites): ?><button type="button" class="button" data-dialog="account-libraries-dialog"><?=tr_html('Review library invitations')?> · <?=count($pendingInvites)?></button><?php endif; ?>
<?php foreach ([true,false] as $owned): $group=array_filter($webLibraries,static fn($item)=>($item['owner']===$viewer)===$owned); if (!$group) continue; ?>
<h2><?=tr_html($owned?'Owned by me':'Shared with me')?></h2>
<div class="library-grid">
<?php foreach ($group as $id=>$item): ?>
<a class="panel library-card" href="<?=h('up.php?'.http_build_query(['library'=>$id]))?>">
<span class="brand-mark"><?=icon('book')?></span>
<span><strong><?=h(libraryTitle($item,$viewer))?></strong><small><?=h($owned?tr('Owner'):libraryRoleLabel($item['members'][$viewer]??null))?></small></span>
<span class="root-folder-arrow"><?=icon('down')?></span></a>
<?php endforeach; ?>
</div><?php endforeach; ?>
</section>
<?php else:
$selectedShare=$mine[$dir]??null; $status=$selectedShare?ownerShareStatus($selectedShare):'Not shared';
$active=in_array($status,['Shared','Expiring soon'],true);
$files=isset($permissions['view'])?listBookFiles(resolveDestinationDirectory($dir)):[];
$statuses=array_map('ownerShareStatus',$mine);
ksort($files,SORT_NATURAL|SORT_FLAG_CASE);
$fileCount=count($files);
$pages=max(1,(int)ceil($fileCount/40));
$pageParam=$_GET['page']??'1';
$page=is_string($pageParam)&&preg_match('/\A[0-9]{1,6}\z/D',$pageParam)?max(1,min($pages,(int)$pageParam)):1;
$pageFiles=array_slice($files,($page-1)*40,40,true);
natcasesort($directories);
$directories=array_values($directories);
$shelfName=$dir===''?$libraryName:$dir;
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
 <div class="side-title"><h2><?=tr_html('Folders')?></h2><?php if (isset($permissions['folder'])): ?><button type="button" class="icon-button" data-dialog="folder-list" data-focus-folder aria-label="<?=tr_html('New folder')?>"><?=icon('plus')?></button><?php endif; ?></div>
 <?php folderNav($directories,$dir,$statuses,$libraryName); ?>
</aside>
<div class="shelf-body<?=isset($permissions['web_upload'])?' drop-shelf':''?>"<?=isset($permissions['web_upload'])?' id="drop-shelf"':''?>>
 <?php if (isset($permissions['web_upload'])): ?><p class="drop-caption" aria-hidden="true"><span><?=tr_html('Drop to upload to this folder')?></span></p><?php endif; ?>
 <div class="shelf-head">
  <button class="folder-trigger" type="button" data-dialog="folder-list" aria-label="<?=tr_html('Choose folder')?>"><?=icon('folder')?><?=tr_html('Folders')?><?=icon('down')?></button>
  <div class="shelf-heading-row">
   <div>
    <?php if ($pendingInvites): ?><div class="shelf-invites"><button type="button" class="button" data-dialog="account-libraries-dialog"><?=tr_html('Review library invitations')?> · <?=count($pendingInvites)?></button></div><?php endif; ?>
    <?php if ($dir!==''): ?>
    <nav class="shelf-path" aria-label="<?=tr_html('Library location')?>">
     <a href="<?=h(libraryHref(''))?>"><?=h($libraryName)?></a><span class="separator" aria-hidden="true">/</span><h1 aria-current="page"><?=h($shelfName)?></h1>
    </nav>
    <?php else: ?>
    <div class="shelf-path"><h1><?=h($shelfName)?></h1></div>
    <?php endif; ?>
   </div>
   <?php if (isset($permissions['web_upload'])): ?><button class="primary upload-launch" type="button" data-dialog="upload-dialog" aria-label="<?=tr_html('Upload books')?>"><?=icon('upload')?><?=tr_html('Upload')?></button><?php endif; ?>
  </div>
  <div class="shelf-meta">
   <?php if (isset($permissions['view'])): ?><span id="shelf-count"><?=h(sprintf(tr('%s books'),number_format($fileCount)))?></span><?php endif; ?>
   <?php if ($dir!=='' && isset($permissions['share'])): ?>
   <button class="pill-trigger <?=$active?'live':''?>" type="button" data-dialog="share-dialog" aria-label="<?=tr_html('Manage subscription sharing')?>" aria-describedby="share-current-status"><?=icon('link')?><span id="share-current-status"><span><?=h(tr($status))?></span><?php if ($active): ?> · <time datetime="<?=h($expiry)?>"><?=h(sprintf(tr('Expires %s'),$expiry))?></time><?php endif; ?></span><?=icon('down')?></button>
   <?php endif; ?>
  </div>
 </div>
 <p role="status" class="status shelf-notice" id="upload-notice"></p>
 <?php $listedFolders=$dir===''?$directories:[]; $canViewBooks=isset($permissions['view']); ?>
 <?php if ($canViewBooks || $listedFolders): ?>
 <div <?=$canViewBooks?'id="books-panel"':''?>>
  <?php if ($listedFolders || $pageFiles): ?>
  <ul class="shelf-list" aria-label="<?=tr_html('Folder contents')?>">
   <?php foreach ($listedFolders as $item): ?>
   <li class="shelf-folder"><a href="<?=h(libraryHref($item))?>">
    <span class="shelf-folder-icon"><?=icon('folder')?></span><span class="shelf-folder-name" title="<?=h($item)?>"><?=h($item)?></span>
    <span class="shelf-folder-detail"><?php if (isset($statuses[$item])): ?><span class="<?=shareBadge($statuses[$item])?>"><?=h(tr($statuses[$item]))?></span><?php endif; ?><span class="root-folder-arrow"><?=icon('down')?></span></span>
   </a></li>
   <?php endforeach; ?>
  <?php foreach ($pageFiles as $name=>$size):
    $download=libraryHref($dir,['download'=>$name]);
    $read='preview.php?'.http_build_query(['library'=>$library['id'],'dir'=>$dir,'book'=>$name],'','&',PHP_QUERY_RFC3986);
    $format=strtolower(pathinfo($name,PATHINFO_EXTENSION)); $title=pathinfo($name,PATHINFO_FILENAME); ?>
  <li class="book">
   <span aria-hidden="true" class="book-icon <?=$format==='txt'?'txt':''?>"><?=h(strtoupper($format))?></span>
   <div class="book-info"><a class="book-name" href="<?=h($read)?>" title="<?=h($name)?>"><?=h($title)?></a><small><?=h(fileSizeLabel($size))?></small></div>
   <?php if (isset($permissions['download'])): ?><a class="button icon-button" href="<?=h($download)?>" title="<?=tr_html('Download')?>" aria-label="<?=h(sprintf(tr('Download %s'),$name))?>"><?=icon('download')?></a><?php else: ?><span></span><?php endif; ?>
   <?php if (isset($permissions['organize'])||isset($permissions['delete'])): ?><details class="book-menu">
    <summary class="button icon-button" aria-label="<?=h(sprintf(tr('More actions for %s'),$name))?>"><?=icon('more')?></summary>
    <div class="book-actions">
     <?php if (isset($permissions['organize'])): ?><button type="button" data-book-rename="<?=h($name)?>" data-book-stem="<?=h($title)?>" data-book-extension="<?=h('.'.pathinfo($name,PATHINFO_EXTENSION))?>"><?=tr_html('Rename')?></button>
     <?php if ($directories): ?><button type="button" data-book-move="<?=h($name)?>"><?=tr_html('Move')?></button><?php endif;?><?php endif; ?>
     <?php if (isset($permissions['delete'])): ?><form action="up.php" method="post" data-confirm="<?=$active?tr_html('Delete this book? Subscribers will no longer be able to download it.'):tr_html('Delete this book?')?>"><?php hidden($csrf,'delete',$dir);?><input type="hidden" name="file" value="<?=h($name)?>"><button class="danger"><?=tr_html('Delete')?></button></form><?php endif; ?>
    </div>
   </details><?php endif; ?>
  </li>
  <?php endforeach; ?>
  </ul>
  <?php elseif ($canViewBooks): ?>
  <div class="empty"><p class="muted"><?=tr_html(isset($permissions['web_upload'])?'No books here yet. Upload an EPUB or TXT to get started.':'No books here yet.')?></p></div>
  <?php endif; ?>
  <?php if ($pages>1): ?><nav class="bar pagination" aria-label="<?=tr_html('Pagination')?>"><?php if($page>1):?><a class="button" href="<?=h(libraryHref($dir,['page'=>$page-1]))?>"><?=tr_html('Previous')?></a><?php endif;?><small><?=$page?> / <?=$pages?></small><?php if($page<$pages):?><a class="button" href="<?=h(libraryHref($dir,['page'=>$page+1]))?>"><?=tr_html('Next')?></a><?php endif;?></nav><?php endif;?>
 </div>
 <?php endif; ?>
 <?php if (!$canViewBooks): ?><div class="panel"><p><?=tr_html('This role cannot browse books.')?></p></div><?php endif; ?>
</div>
</div>
<dialog id="folder-list" class="sheet" aria-labelledby="folder-dialog-title">
 <div class="bar dialog-head"><h2 id="folder-dialog-title"><?=tr_html('Folders')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
 <?php folderNav($directories,$dir,$statuses,$libraryName); ?>
 <?php if (isset($permissions['folder'])): ?><form class="folder-form actions" method="post" action="up.php"><?php hidden($csrf,'folder',$dir);?><input name="folder" aria-label="<?=tr_html('New folder name')?>" placeholder="<?=tr_html('New folder name')?>" required maxlength="240"><button class="primary"><?=tr_html('New folder')?></button></form><?php endif; ?>
</dialog>
<?php if ($dir!=='' && isset($permissions['share'])): ?>
<dialog id="share-dialog" class="sheet" aria-labelledby="share-dialog-title" <?=$preview?'data-show':''?>>
 <div class="bar dialog-head"><h2 id="share-dialog-title"><?=tr_html('Subscription share')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
 <p class="share-summary"><?=h($shelfName)?> · <?=h(tr($status))?><?php if ($selectedShare && in_array($status,['Shared','Expiring soon','Expired'],true)): ?> · <time datetime="<?=h($expiry)?>" title="<?=h(sprintf(tr('Expires %s UTC'),$expiry))?>"><?=h(sprintf(tr('Expires %s'),$expiry))?></time><?php endif; ?></p>
 <?php if ($active): $shareId=$selectedShare['id'].'-'.shareCode($selectedShare['id'],$selectedShare['salt']); $shareUrl=publicShareUrl($shareId); ?>
 <div class="actions">
 <button type="button" class="primary" id="copy-share" data-copied="<?=tr_html('Copied')?>" data-copy-failed="<?=tr_html('Copy failed. Select and copy the link manually.')?>"><?=icon('link')?><?=tr_html('Copy URL')?></button>
 <form action="up.php" method="post" data-confirm="<?=tr_html('Revoke this share? Subscribers will immediately lose access.')?>"><?php hidden($csrf,'revoke',$dir);?><button class="danger"><?=tr_html('Revoke')?></button></form>
 </div><p id="copy-status" role="status"></p>
 <label><?=tr_html('Subscription URL')?><input class="share-link" id="share-url" readonly value="<?=h($shareUrl)?>"></label>
 <?php endif; ?>
 <div class="actions share-secondary">
 <a class="button" href="<?=h(libraryHref($dir,['preview'=>$preview?'0':'1']))?>"><?=tr_html($preview?'Close preview':'Preview')?></a>
 <form action="up.php" method="post" <?=$active?'data-confirm="'.tr_html('Replace this link? The old link stops working immediately.').'"':''?>><?php hidden($csrf,'share',$dir);?><button class="<?=$active?'':'primary'?>"><?=tr_html($active?'Replace link':'Create share')?></button></form>
 </div>
 <?php if ($preview): ?><div class="subscription-preview"><p class="muted"><?=h(sprintf(tr('Read-only preview · Books in this subscription: %s'),number_format(count($previewBooks))))?></p><ul><?php foreach (array_slice($previewBooks,0,100) as $book): ?><li><?=h($book['title'])?></li><?php endforeach;?></ul></div><?php endif;?>
</dialog>
<?php endif;?>
<?php if (isset($permissions['web_upload'])): ?><dialog id="upload-dialog" class="sheet" aria-labelledby="upload-dialog-title">
 <div class="bar dialog-head"><h2 id="upload-dialog-title"><?=tr_html('Upload books')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
 <p id="upload-target" class="upload-target"><?=h(sprintf(tr('Upload to: %s'),$libraryName.($dir===''?'':' / '.$dir)))?></p>
 <form id="upload" aria-describedby="upload-target" class="upload-form" data-interrupted="<?=tr_html('Connection interrupted. Save status is unknown.')?>" data-timeout="<?=tr_html('Request timed out. Save status is unknown.')?>" data-rejected="<?=tr_html('Server rejected the upload (HTTP %s).')?>" data-saved="<?=tr_html('Uploaded %s books.')?>" data-working="<?=tr_html('Uploading %s of %s')?>" data-processing="<?=tr_html('Sent. Waiting for the server…')?>" data-unknown="<?=tr_html('No save confirmation (HTTP %s).')?>" data-check="<?=tr_html(isset($permissions['view'])?'Check this folder before retrying.':'Ask the library owner to check this folder before retrying.')?>" data-drop-invalid="<?=tr_html('Skipped items: %s. Drop EPUB or TXT files, not folders.')?>" method="post" enctype="multipart/form-data" action="<?=h(libraryHref($dir))?>">
 <input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="upload">
 <label><?=tr_html('Choose EPUB or TXT files')?><input id="files" type="file" name="files[]" accept=".epub,.txt" multiple required></label>
 <p class="upload-hint"><?=tr_html('You can also drop files here to start uploading.')?></p>
 <button class="primary" type="submit"><?=tr_html('Upload')?></button> <button type="button" id="retry" hidden><?=tr_html('Retry failed')?></button>
 </form>
 <p class="drop-error error" id="drop-error" role="status"></p>
 <div class="queue" id="queue"><p class="upload-summary" id="upload-summary" role="status"></p><div id="upload-rows"></div></div>
</dialog><?php endif; ?>
<?php if (isset($permissions['organize'])&&($files || $renameDraft)): ?>
<dialog id="rename-dialog" class="sheet" aria-labelledby="rename-dialog-title" <?=$renameDraft?'data-show':''?>>
 <div class="bar dialog-head"><h2 id="rename-dialog-title"><?=tr_html('Rename book')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div>
 <?php if ($renameDraft): ?><p role="alert" class="error" id="rename-error"><?=h($error)?></p><?php endif; ?>
 <form method="post" action="up.php"><?php hidden($csrf,'rename',$dir); ?>
  <input type="hidden" name="file" value="<?=h($renameDraft['file']??'')?>">
  <label for="rename-name"><?=tr_html('New book name')?></label>
  <div class="rename-name"><input id="rename-name" name="new_name" value="<?=h($renameDraft['name']??'')?>" required maxlength="240" aria-describedby="rename-hint"><span id="rename-extension"><?=h($renameDraft?'.'.pathinfo($renameDraft['file'],PATHINFO_EXTENSION):'')?></span></div>
  <p id="rename-hint" class="muted"><?=tr_html('This changes the filename, not the file format or the title stored inside an EPUB.')?></p>
  <?php if ($active): ?><p class="muted"><?=tr_html('The subscription URL stays the same, but the old download link for this book will stop working.')?></p><?php endif; ?>
  <button class="primary"><?=tr_html('Save name')?></button>
 </form>
</dialog>
<?php endif; ?>
<?php if ($directories && isset($permissions['organize'])): ?><dialog id="move-dialog" class="sheet" aria-labelledby="move-dialog-title"><form method="post" action="up.php" data-move="<?=$active?'1':'0'?>" data-shared-warning="<?=tr_html('Moving this book changes what subscribers can see. Continue?')?>"><?php hidden($csrf,'move',$dir);?>
<div class="bar dialog-head"><h2 id="move-dialog-title"><?=tr_html('Move')?></h2><button type="button" class="icon-button dialog-close" aria-label="<?=tr_html('Close')?>"><?=icon('close')?></button></div><p id="moving-book"></p>
<input type="hidden" name="file"><label><?=tr_html('Move destination')?><select name="destination">
<?php foreach (['',...$directories] as $dest): if($dest===$dir)continue;?><option value="<?=h($dest)?>" data-shared="<?=in_array($statuses[$dest]??'',['Shared','Expiring soon'],true)?'1':'0'?>"><?=h($dest===''?$libraryName:$dest)?></option><?php endforeach;?>
</select></label><button class="primary"><?=tr_html('Move')?></button></form></dialog><?php endif;?>
<?php endif;?>
</main>
<script nonce="<?=h($nonce)?>">
document.addEventListener('submit',e=>{
 const f=e.target;if(!f.matches('form[data-confirm],form[data-move]'))return;
 const message=f.dataset.confirm || ((f.dataset.move==='1'||f.elements.destination.selectedOptions[0]?.dataset.shared==='1')?f.dataset.sharedWarning:'');
 if(message&&!confirm(message))e.preventDefault();
});
const accountMenu=document.querySelector('details.account');
const accountButton=accountMenu?.querySelector('summary');
const toolsDialog=document.querySelector('#tools-dialog');
const shareDialog=document.querySelector('#share-dialog');
const uploadDialog=document.querySelector('#upload-dialog');
const moveDialog=document.querySelector('#move-dialog');
const renameDialog=document.querySelector('#rename-dialog');
const renameName=renameDialog?.querySelector('#rename-name');
const form=document.querySelector('#upload'), retry=document.querySelector('#retry');
const filesInput=document.querySelector('#files');
let failed=[],busy=false,uploaded=0;
document.addEventListener('click',e=>{
 if(accountMenu?.open&&!accountMenu.contains(e.target))accountMenu.open=false;
 for(const menu of document.querySelectorAll('.book-menu[open]'))if(!menu.contains(e.target))menu.open=false;
 const open=e.target.closest('[data-dialog]');
 if(open){
  const target=document.getElementById(open.dataset.dialog);
  if(target){target.showModal();if(open.hasAttribute('data-member'))target.dispatchEvent(new CustomEvent('edit-member',{detail:open.dataset}));}
  if(target&&accountMenu&&accountMenu.contains(open))accountMenu.open=false;
  if(open.hasAttribute('data-focus-folder'))target?.querySelector('[name=folder]')?.focus();
 }
 const copyUrl=e.target.closest('[data-copy-url]');
 if(copyUrl){
  const row=copyUrl.closest('.copy-row'), input=row.querySelector('input'), result=row.querySelector('.copy-result');
  (async()=>{try{await navigator.clipboard.writeText(input.value);result.textContent=result.dataset.copied;}
   catch{input.closest('label').hidden=false;input.focus();input.select();result.textContent=result.dataset.manual;}})();
 }
 const close=e.target.closest('.dialog-close');
 if(close&&!(close.closest('dialog')===uploadDialog&&busy))close.closest('dialog')?.close();
 const rename=e.target.closest('[data-book-rename]');
 if(rename&&renameDialog){
  renameDialog.querySelector('[name=file]').value=rename.dataset.bookRename;
  renameName.value=rename.dataset.bookStem;
  renameDialog.querySelector('#rename-extension').textContent=rename.dataset.bookExtension;
  const error=renameDialog.querySelector('#rename-error');if(error)error.hidden=true;
  renameDialog.showModal();renameName.select();return;
 }
 const trigger=e.target.closest('[data-book-move]');
 if(!trigger||!moveDialog)return;
 moveDialog.querySelector('[name=file]').value=trigger.dataset.bookMove;
 moveDialog.querySelector('#moving-book').textContent=trigger.dataset.bookMove;
 moveDialog.showModal();
});
document.addEventListener('keydown',e=>{
 if(e.key!=='Escape')return;
 if(accountMenu?.open){accountMenu.open=false;accountButton.focus();}
 const menu=document.activeElement?.closest('.book-menu[open]');
 if(menu){menu.open=false;menu.querySelector('summary').focus();}
});
shareDialog?.addEventListener('close',()=>{
 const url=new URL(location.href);
 if(url.searchParams.has('preview')){url.searchParams.delete('preview');history.replaceState(null,'',url);}
});
if(renameDialog?.hasAttribute('data-show')){renameDialog.showModal();renameName.focus();}
if(shareDialog?.hasAttribute('data-show'))shareDialog.showModal();
const membersDialog=document.querySelector('#members-dialog');
const roleEditor=document.querySelector('#edit-role-dialog');
document.querySelector('#accounts-dialog')?.addEventListener('close',()=>{
 const url=new URL(location.href);if(url.searchParams.has('accounts')){url.searchParams.delete('accounts');history.replaceState(null,'',url);}
});
membersDialog?.addEventListener('close',()=>{
 const current=new URL(location.href);
 if(current.searchParams.has('manage')){current.searchParams.delete('manage');history.replaceState(null,'',current);}
});
roleEditor?.addEventListener('edit-member',({detail})=>{
 roleEditor.querySelector('[name=member]').value=detail.member;
 roleEditor.querySelector('[data-current-member]').textContent=detail.member;
 roleEditor.querySelectorAll('[name=role]').forEach(input=>input.checked=input.value===detail.memberRole);
 const source=Array.from(membersDialog.querySelectorAll('[data-member]')).find(button=>button.dataset.member===detail.member);
 if(source) source.closest('details').open=false;
});
const librarySettings=document.querySelector('#library-settings-dialog');
for(const dialog of [membersDialog,librarySettings]){
 const tabs=Array.from(dialog?.querySelectorAll('[role=tab]')??[]);
 function activateTab(active,focus=false){
  for(const tab of tabs){
   const selected=tab===active;
   tab.setAttribute('aria-selected',String(selected));tab.tabIndex=selected?0:-1;
   document.getElementById(tab.getAttribute('aria-controls')).hidden=!selected;
  }
  if(focus)active.focus();
 }
 tabs.forEach((tab,index)=>{
  tab.addEventListener('click',()=>activateTab(tab));
  tab.addEventListener('keydown',event=>{
   if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;
   event.preventDefault();
   const next=event.key==='Home'?0:event.key==='End'?tabs.length-1:(index+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;
   activateTab(tabs[next],true);
  });
 });
}
const refreshInvitations=document.querySelector('#refresh-invitations');
refreshInvitations?.addEventListener('click',async()=>{
 if(refreshInvitations.disabled)return;
 const status=document.querySelector('#invitation-refresh-status');
 refreshInvitations.disabled=true;status.textContent='';
 try{
  const response=await fetch(refreshInvitations.dataset.url,{cache:'no-store',credentials:'same-origin'});
  if(!response.ok)throw new Error();
  const html=new DOMParser().parseFromString(await response.text(),'text/html');
  const ids=['member-current','invitation-rows','member-count','pending-count'];
  const updates=ids.map(id=>[document.getElementById(id),html.getElementById(id)]);
  if(updates.some(([oldNode,newNode])=>!oldNode||!newNode))throw new Error();
  for(const [oldNode,newNode] of updates)oldNode.replaceChildren(...newNode.childNodes);
  status.textContent=refreshInvitations.dataset.done;
 }catch{status.textContent=refreshInvitations.dataset.error;}
 finally{refreshInvitations.disabled=false;if(membersDialog.open&&document.activeElement===document.body)refreshInvitations.focus();}
});
const copyActivation=document.querySelector('#copy-activation');
copyActivation?.addEventListener('click',async()=>{
 const input=document.querySelector('#account-activation-url'), status=document.querySelector('#copy-activation-status');
 try{await navigator.clipboard.writeText(input.value);status.textContent=copyActivation.dataset.copied;}
 catch{input.focus();input.select();status.textContent=copyActivation.dataset.manual;}
});
for(const dialog of [membersDialog,librarySettings,document.querySelector('#invite-member-dialog'),roleEditor,document.querySelector('#accounts-dialog')])
 if(dialog?.hasAttribute('data-manage-open'))dialog.showModal();
const agentSetupForm=document.querySelector('#agent-setup');
const agentSetupText=document.querySelector('#agent-setup-text');
agentSetupForm?.addEventListener('submit',async e=>{
 e.preventDefault();
 const button=agentSetupForm.querySelector('button'), status=document.querySelector('#agent-setup-status');
 if(button.disabled)return;
 button.disabled=true;
 const fallback=()=>{
  agentSetupText.hidden=false;agentSetupText.focus();agentSetupText.select();status.textContent=button.dataset.fallback;
 };
 try{
  if(!agentSetupText.value){
   const response=await fetch('up.php',{method:'POST',body:new FormData(agentSetupForm),cache:'no-store'});
   const data=await response.json();
   if(!response.ok||!data.success){status.textContent=data.message||button.dataset.failed;return;}
   agentSetupText.value=data.setup;
   for(const input of agentSetupForm.querySelectorAll('input:not([type=hidden]),select'))input.disabled=true;
  }
  try{await navigator.clipboard.writeText(agentSetupText.value);status.textContent=button.dataset.copied;}
  catch{fallback();}
 }catch{status.textContent=button.dataset.failed;}
 finally{button.disabled=false;}
});
toolsDialog?.addEventListener('close',()=>{
 if(agentSetupText?.value) location.reload();
});
toolsDialog?.addEventListener('close',()=>accountButton?.focus());
uploadDialog?.addEventListener('cancel',e=>{if(busy)e.preventDefault();});
const copy=document.querySelector('#copy-share');
copy?.addEventListener('click',async()=>{const url=document.querySelector('#share-url'); try{await navigator.clipboard.writeText(url.value);document.querySelector('#copy-status').textContent=copy.dataset.copied;}catch{url.select();document.querySelector('#copy-status').textContent=copy.dataset.copyFailed;}});
function setUploadControls() {
 for(const control of [filesInput,retry,form.querySelector('[type=submit]'),uploadDialog.querySelector('.dialog-close')])if(control)control.disabled=busy;
}
const dropShelf=document.querySelector('#drop-shelf'), dropError=document.querySelector('#drop-error');
const uploadRows=document.querySelector('#upload-rows'), uploadSummary=document.querySelector('#upload-summary');
function sendUpload(file,bar,result){
 const data=new FormData(form);data.delete('files[]');data.append('files[]',file);
 return new Promise(resolve=>{
   const unknown=message=>resolve({state:'error',message:message+' '+form.dataset.check});
   const x=new XMLHttpRequest();x.open('POST',form.getAttribute('action'));x.timeout=180000;
   x.upload.onprogress=e=>{if(e.lengthComputable)bar.value=e.loaded/e.total*100;};
   x.upload.onload=()=>{bar.value=100;result.textContent=form.dataset.processing;};
   x.onerror=x.onabort=()=>unknown(form.dataset.interrupted);
   x.ontimeout=()=>unknown(form.dataset.timeout);
   x.onload=()=>{
    try {
     const j=JSON.parse(x.responseText);
     if(typeof j.message!=='string'||typeof j.success!=='boolean'||!Array.isArray(j.results))throw Error();
     if(x.status===200&&j.success&&j.results[0]?.success===true)return resolve({state:'saved',message:j.message});
     if(!j.success&&x.status>=400){
      if(x.status===500)return unknown(j.message);
      return resolve({state:'error',message:j.message,retryable:x.status===429});
     }
     throw Error();
    }catch{
     const message=(x.status>=400&&x.status<500?form.dataset.rejected:form.dataset.unknown).replace('%s',String(x.status));
     if(x.status>=400&&x.status<500)resolve({state:'error',message});
     else unknown(message);
    }
   };x.send(data);
 });
}
async function transfer(files,{again=false,skipped=0}={}) {
 if(busy)return;
 if(!again){
  dropError.textContent=skipped?form.dataset.dropInvalid.replace('%s',String(skipped)):'';
  uploadRows.replaceChildren();uploaded=0;
 }
 if(!files.length){
  uploadSummary.textContent='';failed=[];retry.hidden=true;return;
 }
 busy=true;setUploadControls();retry.hidden=true;failed=[];
 let changed=false,lastMessage='',hadError=!!dropError.textContent;
 for(const [i,item] of files.entries()){
   const file=again?item.file:item;
   const row=again?item.row:document.createElement('div');
   const bar=again?row.querySelector('progress'):document.createElement('progress');
   const result=again?row.querySelector('.upload-result'):document.createElement('span');
   if(!again){
    const label=document.createElement('strong');label.textContent=file.name;label.className='book-name';label.title=file.name;
    row.className='upload-row';result.className='upload-result';row.append(label,bar,result);uploadRows.append(row);
    bar.setAttribute('aria-label',file.name);
   }
   bar.max=100;bar.value=0;result.textContent='';result.removeAttribute('data-state');
   uploadSummary.textContent=form.dataset.working.replace('%s',String(i+1)).replace('%s',String(files.length));
   const receipt=await sendUpload(file,bar,result);
   result.textContent=receipt.message;result.dataset.state=receipt.state;
   if(receipt.state==='saved'){bar.value=100;changed=true;uploaded++;lastMessage=receipt.message;}
   else{hadError=true;if(receipt.retryable)failed.push({file,row});}
 }
 if(changed){
  try{
    const res=await fetch(location.href,{cache:'no-store'}), tree=new DOMParser().parseFromString(await res.text(),'text/html');
    const books=tree.querySelector('#books-panel'), count=tree.querySelector('#shelf-count');
    if(res.ok&&books&&count){
     document.querySelector('#books-panel')?.replaceWith(books);
     document.querySelector('#shelf-count')?.replaceWith(count);
    }
  }catch{}
 }
 busy=false;setUploadControls();retry.hidden=!failed.length;uploadSummary.textContent='';
 // Keep prior errors visible after retrying a separate temporary failure.
 if(!hadError&&!uploadRows.querySelector('[data-state=error]')){
  filesInput.value='';
  document.querySelector('#upload-notice').textContent=uploaded===1&&lastMessage?lastMessage:form.dataset.saved.replace('%s',String(uploaded));
  uploadDialog.close();
 }
}
form?.addEventListener('submit',e=>{e.preventDefault();transfer(Array.from(filesInput.files));});
retry?.addEventListener('click',()=>transfer(failed.slice(),{again:true}));
if(form&&dropShelf){
 const fileDrag=e=>e.dataTransfer&&Array.from(e.dataTransfer.types).includes('Files');
 const clean=()=>{dropShelf.classList.remove('is-drop-target');uploadDialog.classList.remove('is-drop-target');};
 const targetFor=e=>{
  if(busy)return null;
  if(uploadDialog.open)return uploadDialog.contains(e.target)?uploadDialog:null;
  if(document.querySelector('dialog[open]'))return null;
  return dropShelf.contains(e.target)?dropShelf:null;
 };
 document.addEventListener('dragover',e=>{
  if(!fileDrag(e))return;
  e.preventDefault();
  const target=targetFor(e);
  e.dataTransfer.dropEffect=target?'copy':'none';
  dropShelf.classList.toggle('is-drop-target',target===dropShelf);
  uploadDialog.classList.toggle('is-drop-target',target===uploadDialog);
 });
 document.addEventListener('dragleave',e=>{
  if(!e.relatedTarget&&(e.target===document.documentElement||e.clientX<=0||e.clientY<=0||e.clientX>=innerWidth||e.clientY>=innerHeight))clean();
 });
 uploadDialog.addEventListener('close',clean);
 document.addEventListener('drop',e=>{
  if(!fileDrag(e))return;
  e.preventDefault();
  const target=targetFor(e);clean();
  if(!target)return;
  const items=Array.from(e.dataTransfer.items||[]).filter(item=>item.kind==='file');
  const dropped=items.length?items.map(item=>item.webkitGetAsEntry?.()?.isDirectory?null:item.getAsFile()):Array.from(e.dataTransfer.files);
  const accepted=dropped.filter(file=>file&&/\.(epub|txt)$/i.test(file.name));
  if(!uploadDialog.open)uploadDialog.showModal();
  filesInput.value='';
  transfer(accepted,{skipped:dropped.length-accepted.length});
 });
}
</script></body></html>
