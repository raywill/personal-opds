<?php
declare(strict_types=1);

const LIBRARY_PERMISSIONS = [
    'view','download','opds','web_upload','agent_upload','folder','organize','delete','share','members','tokens','settings',
];
const LIBRARY_ROLES = [
    'reader'=>['view','download','opds'],
    'opds_reader'=>['opds'],
    'web_upload'=>['web_upload'],
    'agent_upload'=>['agent_upload'],
    'editor'=>['view','download','opds','web_upload','folder','organize'],
    'admin'=>['view','download','opds','web_upload','agent_upload','folder','organize','delete','share','members','tokens'],
];
const WEB_PERMISSIONS = ['view','web_upload','folder','members','tokens','settings','agent_upload'];
const AGENT_TOKEN_TTL = 90 * 86400;
const MEMBERSHIP_TTL = 7 * 86400;

function personalLibraryId(string $username): string { return 'p-'.$username; }
function libraryIdValid(string $id): bool
{
    return str_starts_with($id,'p-') && accountName(substr($id,2));
}
function libraryRecords(): array
{
    $path=CONFIG_DIR.'/libraries.json';
    clearstatcache(true,$path);
    return file_exists($path)||is_link($path)?stateRead('libraries'):[];
}

function libraryUpdate(callable $update): mixed
{
    return withLock('libraries',function () use ($update) {
        if (isset($GLOBALS['opdsWebSessionGuard'])) ($GLOBALS['opdsWebSessionGuard'])();
        $rows=libraryRecords();
        $result=$update($rows);
        stateWrite('libraries',$rows);
        return $result;
    });
}

function libraryInfo(string $id, ?array $rows=null, ?array $users=null): ?array
{
    if (!libraryIdValid($id)) return null;
    $rows??=libraryRecords();
    $users??=stateRead('users');
    $owner=substr($id,2);
    if (!isset($users[$owner])) return null;
    $row=$rows[$id]??['title'=>null,'members'=>[],'tokens'=>[]];
    $row['owner']=$owner;
    $row['owner_active']=($users[$owner]['state']??null)==='active';
    $row['named_default']=($users[$owner]['named_library_default']??false)===true;
    $row['path']=$owner;
    $row['legacy']=$owner;
    $row['quota_bytes']??=$users[$owner]['quota_bytes']??5*1024*1024*1024;
    $row['quota_files']??=$users[$owner]['quota_files']??5000;
    $row['id']=$id;
    return $row;
}

function libraryTitle(array $row,string $viewer): string
{
    return $row['title']??(!empty($row['named_default'])?sprintf(tr('%s’s library'),$row['owner']):($row['owner']===$viewer?tr('My personal library'):$row['legacy']));
}

function libraryPermissions(array $row,string $username): array
{
    if (empty($row['owner_active'])) return [];
    if (!empty($row['archived'])) return $row['owner']===$username?['settings']:[];
    if ($row['owner']===$username) return LIBRARY_PERMISSIONS;
    $role=$row['members'][$username]??null;
    return is_string($role)?(LIBRARY_ROLES[$role]??[]):[];
}

function availableLibraries(string $username): array
{
    $rows=libraryRecords();
    $users=stateRead('users');
    if (($users[$username]['state']??null)!=='active') return [];
    $ids=array_unique([personalLibraryId($username),...array_keys($rows)]);
    $out=[];
    foreach ($ids as $id) {
        $row=libraryInfo((string)$id,$rows,$users);
        if (!$row || !empty($row['archived']) || !($row['permissions']=libraryPermissions($row,$username))) continue;
        $root=accountBooks().'/'.$row['path'];
        if (!is_dir($root)||is_link($root)||realpath($root)!==$root) continue;
        $out[$id]=$row;
    }
    uasort($out,static fn($a,$b)=>($b['owner']===$username) <=> ($a['owner']===$username) ?:
        strnatcasecmp(libraryTitle($a,$username),libraryTitle($b,$username)));
    return $out;
}

function selectLibrary(string $id,string $username,string $permission): array
{
    $row=libraryInfo($id);
    if (!$row || !in_array($permission,libraryPermissions($row,$username),true)) reject('Library access denied.',403);
    setLibraryScope($row);
    return $row;
}

function setLibraryScope(array $row): void { $GLOBALS['opdsLibrary']=$row; }
function currentLibrary(): ?array { return $GLOBALS['opdsLibrary']??null; }
function libraryStorageKey(): string { return currentLibrary()['path']??accountScope(); }

function requireLibraryPermission(string $permission, string $username, array $session): void
{
    $user=activeAccount($username);
    if (!$user || !hash_equals($user['password'],$session['password']??'')) reject(tr('Sign in again.'),401);
    $id=currentLibrary()['id']??'';
    selectLibrary($id,$username,$permission);
}

function libraryAudit(array &$rows,string $event,string $actor,string $id,array $details=[]): void
{
    $events=$rows['_audit']??[];
    $events[]=['at'=>gmdate(DATE_ATOM),'actor'=>$actor,'library'=>$id,'event'=>$event]+$details;
    $rows['_audit']=array_slice($events,-2000);
}

// Locators are not credentials. Every read/response is scoped to the signed-in invitee.
function invitationId(string $library,string $member,array $invite): string
{
    return $invite['id']??substr(hash('sha256',implode(':',[$library,$member,$invite['from'],$invite['role'],$invite['expires']])),0,32);
}

function invitationLink(string $library,string $id): string
{
    return BASE_URL.'up.php?'.http_build_query(['target'=>$library,'invitation'=>$id],'','&',PHP_QUERY_RFC3986);
}

function invitationFinished(array &$row,string $member,string $status): void
{
    $invite=$row['invites'][$member];
    unset($row['invites'][$member]);
    $history=$row['invite_history']??[];
    $history[]=$invite+['member'=>$member,'status'=>$status];
    $row['invite_history']=array_slice($history,-100);
}

function libraryInvitationRows(array $row): array
{
    $now=time(); $out=[];
    foreach ($row['invites']??[] as $member=>$invite) {
        $member=(string)$member;
        $out[]=$invite+['id'=>invitationId($row['id'],$member,$invite),'member'=>$member,'status'=>$invite['expires']>$now?'pending':'expired'];
    }
    return [...array_reverse($out),...array_reverse($row['invite_history']??[])];
}

function libraryMemberChange(string $id,string $actor,string $member,string $action,?string $role=null,string $expected=''): ?string
{
    if (!accountName($member)||($role!==null&&!isset(LIBRARY_ROLES[$role]))) reject('Invalid username or role.');
    return libraryUpdate(function (&$rows) use ($id,$actor,$member,$action,$role,$expected) {
        $row=libraryInfo($id,$rows);
        if (!$row || !activeAccount($actor) || !in_array('members',libraryPermissions($row,$actor),true)) reject('Library access denied.',403);
        if ($member===$row['owner'] || $member===$actor) reject('You cannot change this member.',403);
        if ($role!==null && !activeAccount($member)) reject('Choose an active account.',404);
        $previous=$row['members'][$member]??null;
        $invite=$row['invites'][$member]??null;
        if ($actor!==$row['owner'] && ($previous==='admin'||$role==='admin'||($invite['role']??null)==='admin'))
            reject('Only the owner can manage library admins.',403);
        if ($action==='member_invite') {
            if ($previous!==null) reject('This account is already a member.',409);
            if (($invite['expires']??0)>time()) reject('This account already has a pending invitation.',409);
            if ($invite) invitationFinished($row,$member,'expired');
            $invitation=bin2hex(random_bytes(16));
            $row['invites'][$member]=['id'=>$invitation,'role'=>$role,'from'=>$actor,'expires'=>time()+MEMBERSHIP_TTL];
            $rows[$id]=libraryPersisted($row);
            libraryAudit($rows,'member.invited',$actor,$id,['member'=>$member,'role'=>$role]);
            return $invitation;
        }
        if ($action==='member_cancel') {
            if (!$invite||$invite['expires']<=time()||($expected!==''&&!hash_equals(invitationId($id,$member,$invite),$expected)))
                reject('Library invitation is unavailable.',410);
            invitationFinished($row,$member,'revoked');
            $rows[$id]=libraryPersisted($row);
            libraryAudit($rows,'member.invitation_cancelled',$actor,$id,['member'=>$member]);
            return null;
        }
        if ($previous===null) reject('Member not found.',404);
        if ($action==='member_edit') $row['members'][$member]=$role;
        elseif ($action==='member_remove') unset($row['members'][$member]);
        else reject('Unknown action.');
        $nowPermissions=libraryPermissions($row,$member);
        foreach ($row['tokens'] as &$token) if ($token['user']===$member &&
            (!in_array('agent_upload',$nowPermissions,true)||(agentTokenNeedsAdmin($token)&&!in_array('tokens',$nowPermissions,true))))
            $token['revoked']??=time();
        unset($token);
        $rows[$id]=libraryPersisted($row);
        libraryAudit($rows,'member.changed',$actor,$id,['member'=>$member,'before'=>$previous,'after'=>$role]);
        return null;
    });
}

function libraryPersisted(array $row): array { return array_intersect_key($row,array_flip(['title','members','tokens','invites','invite_history','archived','quota_bytes','quota_files'])); }

// Keep the old admin-only constraint for pre-upgrade whole-library tokens.
function agentTokenNeedsAdmin(array $token): bool
{
    return !empty($token['whole'])&&empty($token['agent_connection']);
}

function agentFolderNames(): array
{
    $names=array_map('strval',array_keys(array_filter(libraryDirectories(),
        static fn($folder)=>!folderPrivate((string)$folder),ARRAY_FILTER_USE_KEY)));
    $names=array_values(array_filter($names,'validCategory'));
    sort($names,SORT_NATURAL|SORT_FLAG_CASE);
    return $names;
}

function issueAgentToken(string $id,string $user): array
{
    return libraryUpdate(function (&$rows) use ($id,$user) {
        $row=libraryInfo($id,$rows);
        if (!$row || !activeAccount($user) || !in_array('agent_upload',libraryPermissions($row,$user),true))
            reject('Library access denied.',403);
        setLibraryScope($row);
        $folders=agentFolderNames();
        foreach ($row['tokens'] as $k=>$t) if ($t['expires']<=time() || !empty($t['revoked'])) unset($row['tokens'][$k]);
        if (count($row['tokens'])>=200 || count(array_filter($row['tokens'],static fn($t)=>$t['user']===$user))>=20)
            reject('Token limit reached. Revoke an unused token first.',507);
        $tokenId=bin2hex(random_bytes(12));
        $secret=bin2hex(random_bytes(32));
        $now=time();
        $expires=$now+AGENT_TOKEN_TTL;
        $row['tokens'][$tokenId]=['user'=>$user,'dir'=>'','identity'=>null,'name'=>'','whole'=>true,'mkdir'=>true,
            'agent_connection'=>true,'digest'=>hash('sha256',$secret),'expires'=>$expires,'created'=>$now];
        $rows[$id]=libraryPersisted($row);
        libraryAudit($rows,'token.created',$user,$id,['token'=>$tokenId,'directory'=>'']);
        return ['token'=>'opds1.'.$tokenId.'.'.$secret,'expires'=>$expires,'folders'=>$folders];
    });
}

function revokeAgentToken(string $id,string $username,string $tokenId): void
{
    libraryUpdate(function (&$rows) use ($id,$username,$tokenId) {
        $row=libraryInfo($id,$rows);
        $token=$row['tokens'][$tokenId]??null;
        if (!$token || !$row || !activeAccount($username) ||
            ($token['user']!==$username && !in_array('tokens',libraryPermissions($row,$username),true)))
            reject('Token not found.',404);
        $row['tokens'][$tokenId]['revoked']??=time();
        $rows[$id]=libraryPersisted($row);
        libraryAudit($rows,'token.revoked',$username,$id,['token'=>$tokenId]);
    });
}

function agentScope(string $token): ?array
{
    if (preg_match('/\Aopds1\.([a-f0-9]{24})\.([a-f0-9]{64})\z/D',$token,$m)) {
        $rows=libraryRecords();
        foreach ($rows as $id=>$stored) {
            $entry=$stored['tokens'][$m[1]]??null;
            if (!$entry) continue;
            if (!hash_equals($entry['digest'],hash('sha256',$m[2])) || !empty($entry['revoked']) ||
                $entry['expires']<=time() || !activeAccount($entry['user'])) return null;
            $row=libraryInfo((string)$id,$rows);
            if (!$row || !in_array('agent_upload',libraryPermissions($row,$entry['user']),true)) return null;
            $root=directoryUnder(accountBooks(),$row['path']);
            if ($entry['dir']!=='') {
                try { $identity=categoryIdentity(directoryUnder($root,$entry['dir'])); }
                catch (RequestError) { return null; }
                if ($identity===null || $identity!==$entry['identity']) return null;
            }
            $whole=!empty($entry['whole']);
            if (agentTokenNeedsAdmin($entry)&&!in_array('tokens',libraryPermissions($row,$entry['user']),true)) return null;
            return ['user'=>$entry['user'],'library'=>$row,'fixed'=>!$whole,'mkdir'=>!empty($entry['mkdir']),'dir'=>$entry['dir'],'expires'=>$entry['expires'],'folder_names'=>!empty($entry['agent_connection'])];
        }
    } elseif (preg_match('/\A[a-f0-9]{64}\z/D',$token) && ($user=tokenAccount($token))!==null) {
        $row=libraryInfo(personalLibraryId($user));
        if ($row && $row['owner']===$user && empty($row['archived'])) return ['user'=>$user,'library'=>$row,'fixed'=>false,'mkdir'=>true,'dir'=>'','expires'=>null];
    }
    return null;
}

const LIBRARY_ROLE_LABELS = [
    'reader'=>'Reader','opds_reader'=>'OPDS-only reader',
    'web_upload'=>'Web contributor','agent_upload'=>'Agent contributor',
    'editor'=>'Library editor','admin'=>'Library admin',
];
const LIBRARY_ROLE_GROUPS = [
    'Read books'=>['reader','opds_reader'],
    'Contribute books'=>['web_upload','agent_upload'],
    'Manage library'=>['editor','admin'],
];
const LIBRARY_ROLE_DESCRIPTIONS = [
    'reader'=>'Browse, download and read on the web or through OPDS.',
    'opds_reader'=>'Read in an OPDS reader, without access to the web catalog.',
    'web_upload'=>'Upload on the web to existing folders, without browsing books.',
    'agent_upload'=>'Set up an upload token for an Agent, without web uploads or reading.',
    'editor'=>'Read, upload on the web, create folders, rename and move books.',
    'admin'=>'Manage books, uploads, anonymous shares and ordinary members.',
];

function libraryRoleLabel(mixed $role): string
{
    return tr(is_string($role)?(LIBRARY_ROLE_LABELS[$role]??'Unknown role'):'Unknown role');
}

function validLibraryTitle(string $title): string
{
    $title=trim($title);
    if ($title==='' || strlen($title)>120 || !preg_match('//u',$title)||preg_match('/[\x00-\x1f\x7f]/',$title))
        reject('Enter a library name of up to 120 bytes.');
    return $title;
}

function libraryInvites(string $viewer): array
{
    return array_filter(libraryRecords(),static fn($row,$id)=>libraryIdValid((string)$id)&&empty($row['archived'])&&($row['invites'][$viewer]['expires']??0)>time()&&isset($row['invites'][$viewer]['role']),ARRAY_FILTER_USE_BOTH);
}

function libraryAnswerInvite(string $id,string $viewer,bool $accept,string $expected=''): void
{
    libraryUpdate(function (&$rows) use ($id,$viewer,$accept,$expected) {
        if (!activeAccount($viewer) || !($row=libraryInfo($id,$rows)) || empty($row['owner_active']) || !empty($row['archived']) ||
            ($row['invites'][$viewer]['expires']??0)<=time()) reject('Library invitation is unavailable.',410);
        $invite=$row['invites'][$viewer];
        if ($expected!==''&&!hash_equals(invitationId($id,$viewer,$invite),$expected)) reject('Library invitation is unavailable.',410);
        if ($accept) {
            $from=$invite['from'];
            if (!is_string($invite['role']??null)||!isset(LIBRARY_ROLES[$invite['role']])||isset($row['members'][$viewer])||!activeAccount($from) || !in_array('members',libraryPermissions($row,$from),true) ||
                ($invite['role']==='admin'&&$row['owner']!==$from)) reject('Library invitation is unavailable.',410);
            $row['members'][$viewer]=$invite['role'];
        }
        invitationFinished($row,$viewer,$accept?'accepted':'declined');
        $rows[$id]=libraryPersisted($row);
        libraryAudit($rows,$accept?'member.accepted':'member.declined',$viewer,$id);
    });
}

function ownedArchivedLibraries(string $viewer): array
{
    $id=personalLibraryId($viewer);
    $row=libraryInfo($id);
    return !empty($row['archived'])?[$id=>$row]:[];
}

function librarySettings(string $id,string $actor,string $action,string $title=''): void
{
    libraryUpdate(function (&$rows) use ($id,$actor,$action,$title) {
        if (!activeAccount($actor)||!($row=libraryInfo($id,$rows))||$row['owner']!==$actor) reject('Library access denied.',403);
        if ($action==='library_rename') $row['title']=validLibraryTitle($title);
        elseif ($action==='library_restore') unset($row['archived']);
        elseif ($action==='library_archive') {
            // Stop all legacy bearer grants before publishing the archive. A restore
            // must not bring back a token, share, or outstanding invitation.
            stateUpdate('shares',static function (&$shares) use ($id) {
                foreach ($shares as &$share) if (shareLibraryId($share)===$id) $share['revoked']??=time();
            });
            if ($row['legacy']!==null) {
                stateUpdate('users',static function (&$users) use ($row) { unset($users[$row['legacy']]['token']); });
            }
            $row['archived']=time();
            $row['tokens']=[];
            foreach (array_keys($row['invites']??[]) as $member) {
                invitationFinished($row,(string)$member,$row['invites'][$member]['expires']<=time()?'expired':'revoked');
            }
        } else reject('Unknown action.');
        $rows[$id]=libraryPersisted($row);
        libraryAudit($rows,$action,$actor,$id);
    });
}

function noteLibraryAction(string $event,array $details=[]): void
{
    $row=currentLibrary();
    if ($row) libraryUpdate(static function (&$rows) use ($event,$details,$row) {
        libraryAudit($rows,$event,accountScope(),$row['id'],$details);
    });
}

function libraryPreflight(): array
{
    $users=stateRead('users');
    $rows=libraryRecords();
    $shares=stateRead('shares');
    $root=accountBooks();
    $mapped=[];$errors=[];$report=[];
    foreach (array_unique([...array_map(static fn($u)=>personalLibraryId((string)$u),array_keys($users)),...array_keys($rows)]) as $id) {
        if ($id==='_audit') continue;
        $row=libraryInfo((string)$id,$rows,$users);
        if (!$row) { $errors[]=['library'=>$id,'issue'=>'invalid library record']; continue; }
        $key=strtolower($row['path']);
        if (isset($mapped[$key])) $errors[]=['library'=>$id,'issue'=>'duplicate storage mapping'];
        $mapped[$key]=$row['path'];
        $dir=$root.'/'.$row['path'];
        if (is_link($dir)||!is_dir($dir)||realpath($dir)!==$dir||!is_readable($dir)||!is_writable($dir)||!is_executable($dir)) {
            $errors[]=['library'=>$id,'issue'=>'storage missing, symlinked or inaccessible'];
            continue;
        }
        if (!isset($users[$row['owner']])) $errors[]=['library'=>$id,'issue'=>'owner account missing'];
        setLibraryScope($row);
        $folders=libraryDirectories(includePrivate:true);
        $files=0; $bytes=0;
        foreach ([$dir,...array_values($folders)] as $folder) {
            $books=listBookFiles($folder); $files+=count($books); $bytes+=array_sum($books);
        }
        $validShares=0;
        foreach ($shares as $share) {
            if (shareLibraryId($share)!==$id || !empty($share['revoked']) || $share['expires']<=time()) continue;
            if (empty($row['archived']) && isset($folders[$share['category']]) &&
                categoryIdentity($folders[$share['category']])===$share['identity']) $validShares++;
            else $errors[]=['library'=>$id,'issue'=>'unexpired subscription does not match its original folder','folder'=>$share['category']];
        }
        $report[]=['id'=>$id,'storage'=>$row['path'],'owner'=>$row['owner'],'files'=>$files,'bytes'=>$bytes,
            'quota_files'=>$row['quota_files'],'quota_bytes'=>$row['quota_bytes'],'members'=>count($row['members']),
            'legacy_token'=>isset($users[$row['legacy']??'']['token']),'scoped_tokens'=>count($row['tokens']),'active_shares'=>$validShares];
    }
    $entries=scandir($root);
    if ($entries===false) throw new RuntimeException('Cannot inspect private library storage.');
    foreach ($entries as $name) {
        if ($name==='.'||$name==='..') continue;
        if (($mapped[strtolower($name)]??null)!==$name && (is_dir($root.'/'.$name)||is_link($root.'/'.$name)))
            $errors[]=['storage'=>$name,'issue'=>'unmapped storage, not adopted'];
    }
    return ['libraries'=>$report,'issues'=>$errors];
}
