<?php
declare(strict_types=1);

const LIBRARY_PERMISSIONS = [
    'view','download','opds','web_upload','agent_upload','folder','organize','delete','share','members','tokens','settings',
];
const LIBRARY_ROLES = [
    'reader'=>['view','download','opds'],
    'web_view'=>['view'],
    'web_download'=>['view','download'],
    'opds_reader'=>['opds'],
    'web_upload'=>['web_upload'],
    'agent_upload'=>['agent_upload'],
    'folder_creator'=>['folder'],
    'organizer'=>['view','organize'],
    'deleter'=>['view','delete'],
    'share_manager'=>['view','share'],
    'admin'=>['view','download','opds','web_upload','agent_upload','folder','organize','delete','share','members','tokens'],
];
const WEB_PERMISSIONS = ['view','web_upload','folder','members','tokens','settings','agent_upload'];
const DEFAULT_AGENT_TOKEN_DAYS = 90;
const MEMBERSHIP_TTL = 7 * 86400;

function personalLibraryId(string $username): string { return 'p-'.$username; }
function libraryIdValid(string $id): bool
{
    return preg_match('/\Al-[a-f0-9]{32}\z/D',$id)===1 ||
        (str_starts_with($id,'p-') && accountName(substr($id,2)));
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
    if (str_starts_with($id,'p-')) {
        $original=substr($id,2);
        if (!isset($users[$original])) return null;
        $default=['owner'=>$original,'title'=>null,'members'=>[],'tokens'=>[]];
        $row=$rows[$id]??$default;
        $row['path']=$original;
        $row['legacy']=$original;
        $row['quota_bytes']??=$users[$original]['quota_bytes']??5*1024*1024*1024;
        $row['quota_files']??=$users[$original]['quota_files']??5000;
    } else {
        if (!isset($rows[$id])) return null;
        $row=$rows[$id];
        $row['path']=$id;
        $row['legacy']=null;
        $row['quota_bytes']??=5*1024*1024*1024;
        $row['quota_files']??=5000;
    }
    $row['id']=$id;
    return $row;
}

function libraryTitle(array $row,string $viewer): string
{
    return $row['title']??($row['owner']===$viewer?tr('My personal library'):$row['legacy']);
}

function libraryPermissions(array $row,string $username): array
{
    if (!empty($row['archived'])) return $row['owner']===$username?['settings']:[];
    if ($row['owner']===$username) return LIBRARY_PERMISSIONS;
    $permissions=[];
    foreach ($row['members'][$username]??[] as $role) $permissions=array_merge($permissions,LIBRARY_ROLES[$role]??[]);
    return array_values(array_unique($permissions));
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

function libraryCreate(string $title,string $owner): string
{
    $title=validLibraryTitle($title);
    if (!ALLOW_LIBRARY_CREATION) reject('The site does not allow creating libraries.',403);
    $created=null;
    try {
        return libraryUpdate(function (&$rows) use ($title,$owner,&$created) {
            if (!activeAccount($owner)) reject(tr('Sign in again.'),401);
            if (count(array_filter($rows,static fn($row)=>($row['owner']??null)===$owner))>=20)
                reject('Library limit reached.',507);
            do { $id='l-'.bin2hex(random_bytes(16)); } while (isset($rows[$id]) || accountDirectoryOccupied(accountBooks(),$id));
            $root=accountBooks().'/'.$id;
            if (!mkdir($root,0750)) throw new RuntimeException('Could not initialize library storage.');
            $created=$root;
            $rows[$id]=['owner'=>$owner,'title'=>$title,'members'=>[],'tokens'=>[]];
            libraryAudit($rows,'library.created',$owner,$id);
            return $id;
        });
    } catch (Throwable $e) {
        if ($created!==null) @rmdir($created);
        throw $e;
    }
}

function libraryMemberChange(string $id,string $actor,string $member,array $roles): void
{
    $roles=array_values(array_unique($roles));
    if (!accountName($member)||array_diff($roles,array_keys(LIBRARY_ROLES))) reject('Invalid username or role.');
    libraryUpdate(function (&$rows) use ($id,$actor,$member,$roles) {
        $row=libraryInfo($id,$rows);
        if (!$row || !activeAccount($actor) || !in_array('members',libraryPermissions($row,$actor),true)) reject('Library access denied.',403);
        if ($member===$row['owner'] || $member===$actor) reject('You cannot change this member.',403);
        if ($roles && !activeAccount($member)) reject('Choose an active account.',404);
        $previous=$row['members'][$member]??[];
        if ($actor!==$row['owner'] && (in_array('admin',$previous,true)||in_array('admin',$roles,true)||in_array('admin',$row['invites'][$member]['roles']??[],true)))
            reject('Only the owner can manage library admins.',403);
        if ($roles && !$previous) {
            $row['invites'][$member]=['roles'=>$roles,'from'=>$actor,'expires'=>time()+MEMBERSHIP_TTL];
            $rows[$id]=libraryPersisted($row);
            libraryAudit($rows,'member.invited',$actor,$id,['member'=>$member,'roles'=>$roles]);
            return;
        }
        unset($row['invites'][$member]);
        if ($roles) $row['members'][$member]=$roles;
        else unset($row['members'][$member]);
        $nowPermissions=libraryPermissions($row,$member);
        foreach ($row['tokens'] as &$token) if ($token['user']===$member &&
            (!in_array('agent_upload',$nowPermissions,true)||(!empty($token['whole'])&&!in_array('tokens',$nowPermissions,true))))
            $token['revoked']??=time();
        unset($token);
        if (($row['transfer']['to']??null)===$member && !in_array('view',libraryPermissions($row,$member),true)) unset($row['transfer']);
        $rows[$id]=libraryPersisted($row);
        libraryAudit($rows,'member.changed',$actor,$id,['member'=>$member,'before'=>$previous,'after'=>$roles]);
    });
}

function libraryPersisted(array $row): array { return array_intersect_key($row,array_flip(['owner','title','members','tokens','transfer','invites','archived','quota_bytes','quota_files'])); }

function issueAgentToken(array $library,string $user,string $directory,int $days=DEFAULT_AGENT_TOKEN_DAYS,string $name='',bool $whole=false,bool $mkdir=false): array
{
    if ($directory!=='' && !validCategory($directory)) reject(tr('Invalid destination directory.'));
    $name=trim($name);
    if ($days<1 || $days>365 || strlen($name)>80 || !preg_match('//u',$name) || preg_match('/[\x00-\x1f\x7f]/',$name))
        reject('Invalid token name or validity period.');
    if ($whole) $directory='';
    return libraryUpdate(function (&$rows) use ($library,$user,$directory,$days,$name,$whole,$mkdir) {
        $id=$library['id'];
        $row=libraryInfo($id,$rows);
        if (!$row || !activeAccount($user) || !in_array('agent_upload',libraryPermissions($row,$user),true))
            reject('Library access denied.',403);
        if ($whole&&!in_array('tokens',libraryPermissions($row,$user),true)) reject('Library access denied.',403);
        if ($mkdir&&!$whole) reject('Folder creation requires a whole-library token.');
        $root=directoryUnder(accountBooks(),$row['path']);
        $dest=$directory===''?$root:directoryUnder($root,$directory);
        $identity=$directory===''?null:categoryIdentity($dest,true);
        if ($directory!=='' && $identity===null) reject('Cannot identify the upload folder.',409);
        $tokenId=bin2hex(random_bytes(12));
        $secret=bin2hex(random_bytes(32));
        foreach ($row['tokens'] as $k=>$t) if ($t['expires']<=time() || !empty($t['revoked'])) unset($row['tokens'][$k]);
        if (count($row['tokens'])>=200 || count(array_filter($row['tokens'],static fn($t)=>$t['user']===$user))>=20)
            reject('Token limit reached. Revoke an unused token first.',507);
        $expires=time()+$days*86400;
        $row['tokens'][$tokenId]=['user'=>$user,'dir'=>$directory,'identity'=>$identity,'name'=>$name,'whole'=>$whole,'mkdir'=>$mkdir,'digest'=>hash('sha256',$secret),'expires'=>$expires,'created'=>time()];
        $rows[$id]=libraryPersisted($row);
        libraryAudit($rows,'token.created',$user,$id,['token'=>$tokenId,'directory'=>$directory]);
        return ['token'=>'opds1.'.$tokenId.'.'.$secret,'expires'=>$expires,'whole'=>$whole,'mkdir'=>$mkdir];
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
            if ($whole&&!in_array('tokens',libraryPermissions($row,$entry['user']),true)) return null;
            return ['user'=>$entry['user'],'library'=>$row,'fixed'=>!$whole,'mkdir'=>!empty($entry['mkdir']),'dir'=>$entry['dir'],'expires'=>$entry['expires']];
        }
    } elseif (preg_match('/\A[a-f0-9]{64}\z/D',$token) && ($user=tokenAccount($token))!==null) {
        $row=libraryInfo(personalLibraryId($user));
        if ($row && $row['owner']===$user && empty($row['archived'])) return ['user'=>$user,'library'=>$row,'fixed'=>false,'mkdir'=>true,'dir'=>'','expires'=>null];
    }
    return null;
}

const LIBRARY_ROLE_LABELS = [
    'reader'=>'Reader (web and OPDS)','web_view'=>'Web browse only','web_download'=>'Web browse and download',
    'opds_reader'=>'OPDS reader','web_upload'=>'Web upload','agent_upload'=>'Agent upload',
    'folder_creator'=>'Create folders','organizer'=>'Rename and move books','deleter'=>'Delete books',
    'share_manager'=>'Manage anonymous shares','admin'=>'Library admin',
];

function libraryCapabilityLabels(array $permissions,bool $owner): array
{
    if ($owner) return ['Owner'];
    if (in_array('members',$permissions,true)) return ['Library admin'];
    return array_values(array_intersect_key([
        'view'=>'Web browse','download'=>'Download','web_upload'=>'Web upload',
        'agent_upload'=>'Agent upload','opds'=>'OPDS reader','folder'=>'Create folders',
    ],array_fill_keys($permissions,true)));
}

function libraryTransfer(string $id,string $actor,string $action,string $member): void
{
    libraryUpdate(function (&$rows) use ($id,$actor,$action,$member) {
        $row=libraryInfo($id,$rows);
        if (!$row || !activeAccount($actor)) reject('Library access denied.',403);
        if ($action==='transfer_accept') {
            if (($row['transfer']['to']??null)!==$actor || ($row['transfer']['expires']??0)<=time())
                reject('Ownership invitation is unavailable.',410);
            if (!isset($row['members'][$actor])) reject('Ownership invitation is unavailable.',410);
            $former=$row['owner'];
            $row['owner']=$actor;
            unset($row['members'][$actor],$row['transfer']);
            foreach ($row['tokens'] as &$token) if ($token['user']===$former) $token['revoked']??=time();
            unset($token);
        } else {
            if ($row['owner']!==$actor) reject('Library access denied.',403);
            if ($action==='transfer_cancel') unset($row['transfer']);
            else {
                if ($member===$actor || !isset($row['members'][$member]) || !activeAccount($member) ||
                    !in_array('view',libraryPermissions($row,$member),true))
                    reject('Choose an active member with web browsing permission.',400);
                $row['transfer']=['to'=>$member,'expires'=>time()+7*86400];
            }
        }
        if (isset($former) && $row['legacy']===$former) {
            stateUpdate('users',static function (&$users) use ($former) { unset($users[$former]['token']); });
        }
        $rows[$id]=libraryPersisted($row);
        libraryAudit($rows,$action,$actor,$id,['member'=>$member]);
    });
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
    return array_filter(libraryRecords(),static fn($row)=>empty($row['archived'])&&($row['invites'][$viewer]['expires']??0)>time());
}

function libraryAnswerInvite(string $id,string $viewer,bool $accept): void
{
    libraryUpdate(function (&$rows) use ($id,$viewer,$accept) {
        if (!activeAccount($viewer) || !($row=libraryInfo($id,$rows)) || !empty($row['archived']) ||
            ($row['invites'][$viewer]['expires']??0)<=time()) reject('Library invitation is unavailable.',410);
        $invite=$row['invites'][$viewer];
        if ($accept) {
            $from=$invite['from'];
            if (!activeAccount($from) || !in_array('members',libraryPermissions($row,$from),true) ||
                (in_array('admin',$invite['roles'],true)&&$row['owner']!==$from)) reject('Library invitation is unavailable.',410);
            $row['members'][$viewer]=$invite['roles'];
        }
        unset($row['invites'][$viewer]);
        $rows[$id]=libraryPersisted($row);
        libraryAudit($rows,$accept?'member.accepted':'member.declined',$viewer,$id);
    });
}

function ownedArchivedLibraries(string $viewer): array
{
    return array_filter(libraryRecords(),static fn($row)=>!empty($row['archived']) && ($row['owner']??null)===$viewer);
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
            $row['tokens']=[]; $row['invites']=[];
            unset($row['transfer']);
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
        $folders=libraryDirectories();
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
