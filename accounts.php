<?php
declare(strict_types=1);

const ACTIVATION_TTL = 86400;
const SHARE_TTL = 120 * 86400;

/* BEGIN ACCOUNT DIRECTORY RULES */
function accountName(string $name): bool { return preg_match('/\A[a-z0-9][a-z0-9_-]{0,31}\z/D', $name) === 1; }

function accountNameReserved(string $name): bool
{
    return preg_match('/\A(?:root|admin|administrator|postmaster|system|opds|books|conf|con|prn|aux|nul|com[1-9]|lpt[1-9])\z/D',$name) === 1;
}

function accountDirectoryOccupied(string $books,string $name): bool
{
    clearstatcache(true);
    $target=$books.'/'.$name;
    if (file_exists($target) || is_link($target)) return true;
    if (!is_dir($books)) return false;
    $entries=@scandir($books);
    if ($entries===false) throw new RuntimeException(tr('Cannot list the private books directory.'));
    foreach ($entries as $entry) if (strcasecmp($entry,$name)===0) return true;
    return false;
}

/* END ACCOUNT DIRECTORY RULES */
const ACCOUNT_PASSWORD_FORMAT='sha256-v1:';

function accountPasswordMaterial(string $value): string
{
    // A fixed-length, NUL-free input prevents bcrypt from truncating long passwords.
    // This is not the stored hash; password_hash still applies a salted slow KDF.
    return base64_encode(hash('sha256',"personal-opds password v1\0".$value,true));
}

function verifyAccountPassword(string $password,string $stored): bool
{
    if (str_starts_with($stored,ACCOUNT_PASSWORD_FORMAT))
        return password_verify(accountPasswordMaterial($password),substr($stored,strlen(ACCOUNT_PASSWORD_FORMAT)));
    // Existing accounts contain unversioned bcrypt hashes. Retain their original
    // upper bound so a password plus an extra suffix cannot match a 72-byte hash.
    return strlen($password)<=72 && !str_contains($password,"\0") && password_verify($password,$stored);
}
function validCategory(string $name): bool { return validDirectoryName($name) && trim($name)===$name; }

function stateRead(string $key): array
{
    privateDirectory();
    $file=CONFIG_DIR.'/'.$key.'.json';
    if (is_link($file)) throw new RuntimeException('Invalid private state.');
    $stream=fopen($file,'rb');
    if (!$stream) throw new RuntimeException('Cannot read private state.');
    try {
        $stat=fstat($stream);
        if (!$stat || ($stat['mode']&0170077)!==0100000 || $stat['nlink']<0 || $stat['nlink']>1 || $stat['size']>8*1024*1024)
            throw new RuntimeException('Invalid private state.');
        $raw=stream_get_contents($stream,8*1024*1024+1);
        if ($raw===false || strlen($raw)>8*1024*1024) throw new RuntimeException('Cannot read private state.');
    } finally { fclose($stream); }
    $state=json_decode($raw,true,32,JSON_THROW_ON_ERROR);
    if (!is_array($state) || ($state['version']??null)!==1 || !is_array($state['records']??null)) throw new RuntimeException('Invalid private state schema.');
    return $state['records'];
}

function withLock(string $name, callable $fn): mixed
{
    $lock=openPrivateState(CONFIG_DIR.'/.'.$name.'.lock');
    try {
        if (!flock($lock,LOCK_EX)) throw new RuntimeException('Cannot lock private state.');
        return $fn();
    } finally { fclose($lock); }
}

function stateUpdate(string $key, callable $change): mixed
{
    return withLock($key,function () use ($key,$change) {
        $records=stateRead($key);
        $result=$change($records);
        $data=json_encode(['version'=>1,'records'=>(object)$records],JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE);
        if (strlen($data)>8*1024*1024) reject('State capacity reached.',507);
        $temp=CONFIG_DIR.'/.'.bin2hex(random_bytes(16)).'.tmp';
        try {
            $f=fopen($temp,'xb');
            if (!$f) throw new RuntimeException('Cannot write private state.');
            try { writeAll($f,$data); if (!fflush($f) || !fsync($f)) throw new RuntimeException('Cannot flush private state.'); }
            finally { fclose($f); }
            if (!rename($temp,CONFIG_DIR.'/'.$key.'.json')) throw new RuntimeException('Cannot publish private state.');
        } finally { if (is_file($temp)) @unlink($temp); }
        return $result;
    });
}

function setAccountScope(string $name): void
{
    if (!accountName($name)) throw new RuntimeException('Invalid account scope.');
    $GLOBALS['opdsAccount']=$name;
}
function accountScope(): string
{
    return $GLOBALS['opdsAccount'] ?? throw new RuntimeException('Authentication required.');
}
function activeAccount(string $name): ?array
{
    if (!accountName($name)) return null;
    $user=stateRead('users')[$name]??null;
    return is_array($user) && ($user['state']??null)==='active' ? $user : null;
}
function loginAccount(string $name,string $password): ?array
{
    $user=activeAccount($name);
    $valid=verifyAccountPassword($password,$user['password']??ACCOUNT_PASSWORD_FORMAT.'$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.');
    return $valid && $password!=='' ? $user : null;
}
function directoryUnder(string $parent,string $name,bool $create=false): string
{
    $path=$parent.'/'.$name;
    clearstatcache(true,$path);
    if ($create && !is_dir($path) && !is_link($path)) @mkdir($path,0750);
    clearstatcache(true,$path);
    if (is_link($path) || !is_dir($path) || realpath($path)!==$path) reject($create?'Cannot create the selected directory.':'Directory not found.',$create?409:404);
    return $path;
}
function accountBooks(): string
{
    $root=realpath(DATA_DIR);
    if ($root===false || !is_dir($root) || is_link(DATA_DIR)) throw new RuntimeException('Invalid private books directory.');
    return $root;
}
function createCategory(string $name): string
{
    if (!validCategory($name)) reject('Enter a valid single-level category name.');
    $root=getLibraryRoot();
    return withLock('category-'.accountScope(),function () use ($root,$name) {
        if (!is_dir($root.'/'.$name) && count(libraryDirectories())>=1000) reject('Category limit reached.',507);
        return directoryUnder($root,$name,true);
    });
}
function newActivation(string $name): array
{
    $secret=bin2hex(random_bytes(32));
    return [['digest'=>hash('sha256',$secret),'expires'=>time()+ACTIVATION_TTL],BASE_URL.'up.php?'.http_build_query(['account'=>$name,'activate'=>$secret])];
}
function activateAccount(string $name,string $secret,string $password): void
{
    if (!accountName($name) || !preg_match('/\A[a-f0-9]{64}\z/D',$secret)) reject('Activation link is invalid or expired.',403);
    if ($password==='') reject(tr('Password cannot be empty.'));
    stateUpdate('users',function (&$users) use ($name,$secret,$password) {
        $row=$users[$name]??[];
        if (!in_array($row['state']??null,['pending','active'],true) || ($row['activation']['expires']??0)<=time() ||
            !hash_equals($row['activation']['digest']??'',hash('sha256',$secret))) reject('Activation link is invalid or expired.',403);
        directoryUnder(accountBooks(),$name);
        $row['password']=ACCOUNT_PASSWORD_FORMAT.password_hash(accountPasswordMaterial($password),PASSWORD_DEFAULT);
        $row['state']='active'; unset($row['activation']); $users[$name]=$row;
    });
}
function rotateUploadToken(string $name,string $passwordVersion): string
{
    $token=bin2hex(random_bytes(32));
    stateUpdate('users',function (&$users) use ($name,$token,$passwordVersion) {
        if (($users[$name]['state']??null)!=='active'||!hash_equals($users[$name]['password']??'',$passwordVersion)) reject('Sign in again.',401);
        $users[$name]['token']=hash('sha256',$token);
    });
    return $token;
}
function tokenAccount(string $token): ?string
{
    $digest=hash('sha256',$token);
    foreach (stateRead('users') as $name=>$user)
        if (($user['state']??null)==='active' && isset($user['token']) && hash_equals($user['token'],$digest)) return (string)$name;
    return null;
}

// Derive a reproducible code with a deployment key so the owner can copy
// the link later without storing the four-character bearer code in shares.json.
function shareCode(string $id,string $salt): string
{
    $alphabet='23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
    for ($attempt=0;;$attempt++) {
        $bytes=hash_hmac('sha256',$id.':'.$salt.':'.$attempt,SHARE_KEY,true);
        $code='';
        for ($i=0;$i<strlen($bytes)&&strlen($code)<4;$i++) {
            $byte=ord($bytes[$i]);
            if ($byte<256-(256%strlen($alphabet))) $code.=$alphabet[$byte%strlen($alphabet)];
        }
        if (strlen($code)===4 && preg_match('/[0-9]/',$code) && preg_match('/[A-Z]/',$code)) return $code;
    }
}
function categoryIdentity(string $directory,bool $create=false): ?string
{
    $file=$directory.'/.opds-category';
    if ($create && !file_exists($file) && !is_link($file)) {
        $f=@fopen($file,'xb');
        if ($f) { try { writeAll($f,bin2hex(random_bytes(24))); } finally { fclose($f); } }
    }
    if (!is_file($file) || is_link($file)) return null;
    $value=file_get_contents($file,false,null,0,49);
    return is_string($value)&&preg_match('/\A[a-f0-9]{48}\z/D',$value)?$value:null;
}
function shareStatus(array $share): string
{
    if (!empty($share['revoked'])) return 'Revoked';
    if ($share['expires']<=time()) return 'Expired';
    return $share['expires']-time()<14*86400?'Expiring soon':'Shared';
}
function publicShareUrl(string $key): string { return BASE_URL.'index.php?s='.$key; }

function manageShare(string $category,bool $revoke): void
{
    if (!validCategory($category)) reject('Select a subdirectory to share.');
    $owner=accountScope();
    stateUpdate('shares',function (&$records) use ($category,$revoke,$owner) {
        foreach ($records as &$old) {
            if ($old['owner']===$owner && $old['category']===$category && empty($old['revoked'])) $old['revoked']=time();
        }
        unset($old);
        if ($revoke) return;
        $id=categoryIdentity(resolveDestinationDirectory($category),true);
        if ($id===null) reject('Cannot identify the share directory.',409);
        do { $number=''; for ($i=0;$i<8;$i++) $number.=random_int(1,9); } while(isset($records[$number]));
        $records[$number]=['owner'=>$owner,'category'=>$category,'identity'=>$id,'salt'=>bin2hex(random_bytes(16)),'created'=>time(),'expires'=>time()+SHARE_TTL];
    });
}
function resolveShare(string $key): array
{
    if (preg_match('/\A([1-9]{8})-([A-Z0-9]{4})\z/iD',$key,$m)) {
        $row=stateRead('shares')[$m[1]]??null;
        if (is_array($row) && hash_equals(shareCode($m[1],$row['salt']),strtoupper($m[2]))) {
            if (!empty($row['revoked']) || $row['expires']<=time() || !activeAccount($row['owner']))
                reject('Subscription unavailable. Ask the owner for a new link.',410);
            setAccountScope($row['owner']);
            try { $identity=categoryIdentity(resolveDestinationDirectory($row['category'])); }
            catch (RequestError) { $identity=null; }
            if ($identity!==null && hash_equals($row['identity'],$identity)) return $row;
            reject('Subscription unavailable. Ask the owner for a new link.',410);
        }
    }
    reserveRateAttempt('share-invalid',30,1500);
    reject('Subscription not found.',404);
}

function listBookFiles(string $dir): array
{
    $files=[];
    foreach (scandir($dir) ?: [] as $name) {
        try { safeFilename($name); } catch (RequestError) { continue; }
        $path=$dir.'/'.$name;
        if (is_link($path)||!is_file($path)||realpath($path)!==$path) continue;
        $size=filesize($path);
        if ($size!==false) $files[$name]=$size;
    }
    return $files;
}
function enforceAccountQuota(int $incoming, ?array &$quota=null): void
{
    if ($quota===null) {
        $account=activeAccount(accountScope())??throw new RequestError('Account disabled.',401);
        $quota=['bytes'=>0,'files'=>0,'max_bytes'=>$account['quota_bytes']??5*1024*1024*1024,'max_files'=>$account['quota_files']??5000];
        foreach ([getLibraryRoot(),...array_values(libraryDirectories())] as $dir) {
            $items=listBookFiles($dir); $quota['bytes']+=array_sum($items); $quota['files']+=count($items);
        }
    }
    if ($quota['bytes']+$incoming>$quota['max_bytes']||$quota['files']>=$quota['max_files'])
        reject('Your library quota is full.',507);
}
function managedBook(string $category,string $name): string
{
    $dir=resolveDestinationDirectory($category); safeFilename($name);
    $path=$dir.'/'.$name;
    clearstatcache(true,$path);
    if (is_link($path)||!is_file($path)||realpath($path)!==$path) reject('Book not found.',404);
    return $path;
}
function manageBook(string $action,string $category,string $name,string $to): void
{
    withLock('books-'.accountScope(),function () use ($action,$category,$name,$to) {
        $source=managedBook($category,$name);
        if ($action==='delete') {
            if (!unlink($source)) reject('Could not delete the book.',409);
            return;
        }
        if ($action==='rename') {
            $stem=$to;
            if ($stem===pathinfo($name,PATHINFO_FILENAME)) return;
            $suffix='.'.pathinfo($name,PATHINFO_EXTENSION);
            if (trim($stem)==='' || trim($stem)!==$stem) reject('Enter a valid book name.');
            $newName=safeFilename($stem.$suffix);
            if ($newName===$name) return;
            $target=dirname($source).'/'.$newName;
            if (!@link($source,$target)) {
                clearstatcache(true,$target);
                if (file_exists($target) || is_link($target)) reject('A book with this name already exists.',409);
                reject('Could not rename the book.',409);
            }
        } elseif ($action==='move') {
            if ($category===$to) reject('Choose a different destination.');
            $target=resolveDestinationDirectory($to).'/'.$name;
            if (!@link($source,$target)) reject('Could not move; check for an existing book with the same name.',409);
        } else reject('Unknown action.');
        if (!@unlink($source)) {
            @unlink($target);
            reject('Could not remove the original book.',409);
        }
    });
}
