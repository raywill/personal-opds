<?php
declare(strict_types=1);
if (PHP_SAPI!=='cli') { http_response_code(404);exit; }
require __DIR__.'/bootstrap.php';
require __DIR__.'/security.php';
require __DIR__.'/upload-common.php';
require __DIR__.'/accounts.php';

// Running write commands as root replaces 0600 state with root-owned files.
function checkOperatorIdentity(): void
{
    $uid=function_exists('posix_geteuid')?posix_geteuid():null;
    $owner=@fileowner(CONFIG_DIR);
    if ($uid!==null && $owner!==false && $uid!==$owner) {
        throw new RuntimeException("Run admin.php as the PHP service user (private config directory owner UID $owner, current UID $uid). Use sudo -u USER php admin.php ...");
    }
}

function doctorAccounts(string $username): int
{
    $issues=0;
    $uid=function_exists('posix_geteuid')?posix_geteuid():null;
    $dir=CONFIG_DIR;
    $owner=@fileowner($dir);
    if ($uid!==null && $owner!==false && $uid!==$owner) {
        echo "ERROR: Run this check as the PHP service user. Config owner UID $owner; current UID $uid.
";
        return 2;
    }
    if ($username!==''&&!accountName($username)) throw new RuntimeException('Specify a lowercase username.');
    $inspect=static function (string $path,bool $write,bool $optional=false,bool $directory=false) use (&$issues,$owner): bool {
        clearstatcache(true,$path);
        $info=@lstat($path);
        if (!$info && $optional) {
            echo "OK: $path does not exist yet; created on first use.
";
            return true;
        }
        $reasons=[];
        if (!$info) $reasons[]='missing or inaccessible';
        else {
            if (($info['mode']&0170000)!==($directory?0040000:0100000)) $reasons[]='wrong file type (no symlinks)';
            if (!$directory&&$info['nlink']!==1) $reasons[]='not a single-link file';
            if (($info['mode']&0077)!==0) $reasons[]='accessible by other accounts';
            if ($owner!==false&&$info['uid']!==$owner) $reasons[]="owner UID {$info['uid']} differs from PHP service UID $owner";
            if (!is_readable($path)) $reasons[]='not readable';
            if ($write&&!is_writable($path)) $reasons[]='not writable';
            if ($directory&&!is_executable($path)) $reasons[]='not traversable';
        }
        if ($reasons) { ++$issues; echo 'ERROR: '.$path.' — '.implode('; ',$reasons).PHP_EOL; return false; }
        echo "OK: $path
"; return true;
    };
    if (!$inspect($dir,true,false,true)) return 2;
    if ($inspect($dir.'/users.json',false)) {
        try {
            $accounts=stateRead('users');
            echo "OK: users.json format.
";
            if ($username!=='') {
                if (!isset($accounts[$username])) { ++$issues; echo "ERROR: Account does not exist.
"; }
                else {
                    try {
                        $root=directoryUnder(accountBooks(),$username);
                        if (!is_executable($root)) throw new RuntimeException('Personal book directory cannot be entered.');
                        echo "OK: Personal book directory.
";
                    } catch (Throwable $e) { ++$issues; echo 'ERROR: Personal book directory: '.$e->getMessage().PHP_EOL; }
                }
            }
        } catch (Throwable $e) { ++$issues; echo 'ERROR: users.json: '.$e->getMessage().PHP_EOL; }
    }
    foreach (['.users.lock','.libraries.lock','.rate.json'] as $file) $inspect($dir.'/'.$file,true,true);
    return $issues?2:0;
}

try {
    [$script,$command,$user]=array_pad($argv,3,'');
    if ($command==='doctor') exit(doctorAccounts($user));
    if ($command!=='rbac-audit') checkOperatorIdentity();
    if ($command==='rbac-check') {
        $report=withLock('libraries','libraryPreflight');
        echo json_encode($report,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR).PHP_EOL;
        exit($report['issues']?2:0);
    }
    if ($command==='rbac-audit') {
        $events=libraryRecords()['_audit']??[];
        echo json_encode($events,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR).PHP_EOL;
        exit;
    }
    if ($command==='library-quota') {
        $bytes=filter_var($argv[3]??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
        $files=filter_var($argv[4]??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1,'max_range'=>5000]]);
        if ($bytes===false||$files===false) reject('Usage: php admin.php library-quota LIBRARY_ID BYTES FILES (max 5000 files).');
        libraryUpdate(static function (&$rows) use ($user,$bytes,$files) {
            $row=libraryInfo($user,$rows);
            if (!$row) reject('Library not found.');
            $row['quota_bytes']=$bytes;
            $row['quota_files']=$files;
            $rows[$user]=libraryPersisted($row);
            libraryAudit($rows,'quota.changed','site-operator',$user);
        });
        echo "Library quota saved.
"; exit;
    }
    if (!accountName($user)) reject('Specify a lowercase username.');
    setAccountScope($user);
    if ($command==='invite'||$command==='reset') {
        echo issueAccountActivation($user,$command).PHP_EOL;
    } elseif (in_array($command,['grant-site-admin','revoke-site-admin'],true)) {
        stateUpdate('users',static function (&$users) use ($user,$command) {
            if (($users[$user]['state']??null)!=='active') reject('Only an active account can be a site administrator.');
            if ($command==='grant-site-admin') $users[$user]['site_admin']=true;
            else unset($users[$user]['site_admin']);
        });
        echo "Site administrator permission updated.
";
    } elseif ($command==='disable') {
        withLock('libraries',static function () use ($user) {
            $rows=libraryRecords();
            $library=libraryInfo(personalLibraryId($user),$rows);
            if (activeAccount($user) && $library && empty($library['archived']))
                reject('Archive this account’s personal library before disabling it.');
            stateUpdate('users',function (&$users) use ($user) {
            if (!isset($users[$user])) reject('Account not found.');
            $users[$user]['state']='disabled';
                unset($users[$user]['activation'],$users[$user]['token'],$users[$user]['password']);
            });
            libraryAudit($rows,'account.disabled','site-operator','',['member'=>$user]);
            stateWrite('libraries',$rows);
        });
        echo "Account disabled; library files were retained.\n";
    } elseif ($command==='quota') {
        $bytes=filter_var($argv[3]??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
        $files=filter_var($argv[4]??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1,'max_range'=>5000]]);
        if ($bytes===false||$files===false) reject('Usage: php admin.php quota USER BYTES FILES (max 5000 files).');
        stateUpdate('users',function (&$users) use ($user,$bytes,$files) {
            if (!isset($users[$user])) reject('Account not found.');
            $users[$user]['quota_bytes']=$bytes; $users[$user]['quota_files']=$files;
        });
        echo "Quota saved.\n";
    } elseif ($command==='migrate') {
        $source=realpath($argv[3]??''); $apply=($argv[4]??'')==='--apply';
        if (!$source || !is_dir($source) || is_link($argv[3]??'') || !activeAccount($user)) reject('Use an existing old books directory and an active account.');
        if ($source===accountBooks() || str_starts_with($source,accountBooks().'/') || str_starts_with(accountBooks(),rtrim($source,'/').'/'))
            reject('Migration source must be separate from the new books directory.');
        $legacy=libraryInfo(personalLibraryId($user));
        if (!$legacy || $legacy['owner']!==$user || !empty($legacy['archived'])) reject('Use an active personal library still owned by this account.');
        setLibraryScope($legacy);
        withLock('books-'.$user,function () use ($source,$apply) {
            $dirs=[''=>$source];
            foreach (scandir($source)?:[] as $name) {
                $path=$source.'/'.$name;
                if (validCategory($name)&&is_dir($path)&&!is_link($path)&&realpath($path)===$path) $dirs[$name]=$path;
            }
            $conflicts=0;
            foreach ($dirs as $dir=>$path) foreach (listBookFiles($path) as $name=>$size) {
                $dir=(string)$dir; $target=getLibraryRoot().($dir===''?'':'/'.$dir).'/'.$name;
                if (file_exists($target)||is_link($target)) { echo "CONFLICT ".json_encode([$dir,$name],JSON_UNESCAPED_UNICODE)."\n"; $conflicts++; }
                else echo "COPY ".json_encode([$dir,$name],JSON_UNESCAPED_UNICODE)."\n";
            }
            if (!$apply) { echo "Preview only. Re-run with --apply to copy; originals are kept.\n";return; }
            if ($conflicts) reject('Resolve conflicts before applying; no files were copied.');
            foreach ($dirs as $dir=>$path) {
                $dir=(string)$dir; $target=$dir===''?getLibraryRoot():createCategory($dir);
                foreach (listBookFiles($path) as $name=>$size) {
                    enforceAccountQuota($size);
                    $src=$path.'/'.$name;
                    if (is_link($src)||realpath($src)!==$src) reject('Source changed; stop migration.');
                    if (strtolower(pathinfo($src,PATHINFO_EXTENSION))==='epub') validateEpub($src); else validateTxt($src);
                    if ($size<1 || $size>MAX_FILE_SIZE) reject('File outside upload size limit.');
                    $temp=tempnam($target,'.migrate-');
                    if ($temp===false) throw new RuntimeException('Cannot stage migration.');
                    try { if (!copy($src,$temp)||!chmod($temp,0640)||!link($temp,$target.'/'.$name)) reject('Migration stopped. Already copied files and originals are retained.'); }
                    finally { unlink($temp); }
                }
            }
            echo "Copied; original library retained.\n";
        });
    } else reject('Usage: php admin.php invite|reset|disable|quota|migrate|grant-site-admin|revoke-site-admin USER [options], library-quota LIBRARY_ID BYTES FILES, rbac-check, rbac-audit, or doctor [USERNAME]');
} catch (Throwable $e) {
    fwrite(STDERR,$e->getMessage().PHP_EOL);exit(1);
}
