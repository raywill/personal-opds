<?php
declare(strict_types=1);

// Private rules live outside the document root. Never infer the principal
// from accountScope(): anonymous shares and bearer tokens also set that scope.
function canSeePrivateBooks(): bool
{
    $owner = currentLibrary()['owner'] ?? null;
    return is_string($owner) && $owner === ($GLOBALS['opdsInteractiveViewer'] ?? null)
        && !isset($GLOBALS['shareCategory']);
}

function privacyRules(): array
{
    $key = 'privacy-'.libraryStorageKey();
    if (!isset($GLOBALS['opdsPrivacyRules'][$key])) {
        $file=CONFIG_DIR.'/'.$key.'.json';
        clearstatcache(true,$file);
        $rules=file_exists($file) || is_link($file) ? stateRead($key) : [];
        foreach ($rules as $path=>$value) {
            if (!is_string($path) || strlen($path)<3 || !in_array(substr($path,0,2),['b:','d:'],true) || $value!==true)
                throw new RuntimeException('Invalid private visibility rules.');
        }
        $GLOBALS['opdsPrivacyRules'][$key]=$rules;
    }
    return $GLOBALS['opdsPrivacyRules'][$key];
}

function storePrivacyRules(array $rules): void
{
    $key='privacy-'.libraryStorageKey();
    stateWrite($key,$rules);
    $GLOBALS['opdsPrivacyRules'][$key]=$rules;
}

function folderPrivate(string $folder, ?array $rules=null): bool
{
    if ($folder==='') return false;
    $rules??=privacyRules();
    do {
        if (isset($rules['d:'.$folder])) return true;
        $slash=strrpos($folder,'/');
        if ($slash===false) return false;
        $folder=substr($folder,0,$slash);
    } while ($folder!=='');
    return false;
}

function bookRuleKey(string $folder,string $book): string
{
    return 'b:'.($folder===''?'':$folder.'/').$book;
}

function requireVisibleFolder(string $folder): void
{
    if (!canSeePrivateBooks() && folderPrivate($folder)) reject('No permission.',403);
}

function requireVisibleBook(string $folder,string $name): void
{
    if (!canSeePrivateBooks() && (isset(privacyRules()[bookRuleKey($folder,$name)])||folderPrivate($folder)))
        reject('No permission.',403);
}

// Readers take a shared lock before loading the rules and resolving paths.
// Writers keep the existing per-library exclusive books lock. A download can
// release its lock after opening the already-authorized file descriptor.
function lockBookRead(): void
{
    if (isset($GLOBALS['opdsBookReadLock'])) return;
    $lock=openPrivateState(CONFIG_DIR.'/.books-'.libraryStorageKey().'.lock');
    if (!flock($lock,LOCK_SH)) { fclose($lock); throw new RuntimeException('Cannot lock book state.'); }
    $GLOBALS['opdsBookReadLock']=$lock;
    clearPrivacySnapshot();
}

function clearPrivacySnapshot(): void
{
    unset($GLOBALS['opdsPrivacyRules']['privacy-'.libraryStorageKey()],$GLOBALS['opdsExactNames']);
}

function withBookWrite(callable $write): mixed
{
    return withLock('books-'.libraryStorageKey(),static function () use ($write) {
        clearPrivacySnapshot();
        return $write();
    });
}

// Do not let an alternate spelling on a case-insensitive filesystem bypass
// a rule or let an owner accidentally apply a rule to an alias of a name.
function exactLibraryName(string $directory,string $basename): bool
{
    if (!isset($GLOBALS['opdsExactNames'][$directory])) {
        $entries=scandir($directory);
        if ($entries===false) throw new RuntimeException('Cannot list book names.');
        $GLOBALS['opdsExactNames'][$directory]=array_fill_keys($entries,true);
    }
    return isset($GLOBALS['opdsExactNames'][$directory][$basename]);
}

function unlockBookRead(): void
{
    if (!isset($GLOBALS['opdsBookReadLock'])) return;
    fclose($GLOBALS['opdsBookReadLock']);
    unset($GLOBALS['opdsBookReadLock']);
}

function privacyShareImpact(string $category,array $records): int
{
    $count=0;
    foreach ($records as $share) {
        if (shareLibraryId($share)!==currentLibrary()['id'] || !empty($share['revoked']) || $share['expires']<=time()) continue;
        if ($share['category']===$category || str_starts_with($share['category'],$category.'/')) ++$count;
    }
    return $count;
}

function managePrivacy(string $kind,string $folder,string $name,bool $hide,bool $confirmed): void
{
    withBookWrite(static fn()=>uploadCommit(static function () use ($kind,$folder,$name,$hide,$confirmed) {
        if (!canSeePrivateBooks()) reject('Library owner access required.',403);
        $rules=privacyRules();
        if ($kind==='folder' && $name!=='') {
            if ($folder!=='') resolveDestinationDirectory($folder);
            $folder=$folder===''?$name:$folder.'/'.$name;
            $path=resolveDestinationDirectory($folder);
            if (!exactLibraryName(dirname($path),$name)) reject('Directory not found.',404);
            $key='d:'.$folder;
            $slash=strrpos($folder,'/');
            $parent=$slash===false?'':substr($folder,0,$slash);
        } elseif ($kind==='book') {
            $path=managedBook($folder,$name);
            if (!exactLibraryName(dirname($path),$name)) reject('Book not found.',404);
            $key=bookRuleKey($folder,$name);
            $parent=$folder;
        } else reject('Invalid input.');
        if (folderPrivate($parent,$rules)) reject('Private through the parent folder.',409);
        if ($hide===isset($rules[$key])) return;
        if (!$hide && !$confirmed) reject('Confirm restoring normal visibility.',409);
        if ($hide && $kind==='folder') {
            withLock('shares',static function () use ($folder,$confirmed) {
                $shares=stateRead('shares');
                if (privacyShareImpact($folder,$shares)>0 && !$confirmed) reject('Confirm revoking affected subscription links.',409);
                $changed=false;
                foreach ($shares as &$share) {
                    if (shareLibraryId($share)===currentLibrary()['id'] && empty($share['privacy_revoked']) &&
                        ($share['category']===$folder || str_starts_with($share['category'],$folder.'/'))) {
                        $share['revoked']??=time();
                        $share['privacy_revoked']=true;
                        $changed=true;
                    }
                }
                unset($share);
                // Revoke before publishing privacy, so cancellation never
                // revives a link even if publishing the rule fails.
                if ($changed) stateWrite('shares',$shares);
            });
        }
        if ($hide) $rules[$key]=true;
        else unset($rules[$key]);
        storePrivacyRules($rules);
    }));
}
