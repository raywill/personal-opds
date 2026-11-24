<?php
declare(strict_types=1);
if (PHP_SAPI!=='cli') { http_response_code(404);exit; }
require __DIR__.'/bootstrap.php';
require __DIR__.'/security.php';
require __DIR__.'/upload-common.php';
require __DIR__.'/accounts.php';

try {
    [$script,$command,$user]=array_pad($argv,3,'');
    if (!accountName($user)) reject('Specify a lowercase username.');
    setAccountScope($user);
    if ($command==='invite'||$command==='reset') {
        echo stateUpdate('users',function (&$users) use ($user,$command) {
            $row=$users[$user]??null;
            if ($command==='reset' && ($row['state']??null)!=='active') reject('Only active accounts can be reset.');
            if ($command==='invite' && $row!==null && ($row['state']??null)!=='pending') reject('Account already exists.');
            if (!$row && (file_exists(accountBooks().'/'.$user)||is_link(accountBooks().'/'.$user))) reject('Existing library path; refusing to claim it.');
            $dir=directoryUnder(accountBooks(),$user,true);
            [$activation,$link]=newActivation($user);
            $users[$user]=array_merge($row??['state'=>'pending'],['activation'=>$activation]);
            return $link;
        }).PHP_EOL;
    } elseif ($command==='disable') {
        stateUpdate('users',function (&$users) use ($user) {
            if (!isset($users[$user])) reject('Account not found.');
            $users[$user]['state']='disabled';
            unset($users[$user]['activation'],$users[$user]['token'],$users[$user]['password']);
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
    } else reject('Usage: php admin.php invite|reset|disable|quota|migrate USER [options]');
} catch (Throwable $e) {
    fwrite(STDERR,$e->getMessage().PHP_EOL);exit(1);
}
