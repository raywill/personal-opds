<?php
declare(strict_types=1);

function metadata(string $path, array $format,MetadataBudget $budget): array
{
    if (!$format['enabled']) return [];
    $data=BookFormatRegistry::get()->handler($format)->metadata($path,$budget);
    return array_filter(array_intersect_key($data,array_flip(['title','author','language'])),
        static fn($value): bool=>is_string($value)&&$value!==''&&strlen($value)<=512&&preg_match('//u',$value)===1);
}
function bookPath(string $relative, bool $listed = false): string
{
    if (isset($GLOBALS['shareCategory']) && !str_starts_with($relative,$GLOBALS['shareCategory'].'/')) reject('Book not found.',404);
    $parts = explode('/', $relative);
    if (count($parts) > MAX_CATEGORY_DEPTH + 1) reject(tr('Invalid book path.'), 404);
    $name = array_pop($parts);
    safeFilename($name);
    requireVisibleBook(implode('/',$parts),$name);
    $directory = $parts ? resolveDestinationDirectory(implode('/', $parts)) : getLibraryRoot();
    if (!$listed && privacyRules() && !exactLibraryName($directory,$name)) reject('Book not found.',404);
    $path = $directory . '/' . $name;
    if (is_link($path) || !is_file($path) || !is_readable($path)
        || dirname((string) realpath($path)) !== $directory) reject(tr('Book not found.'), 404);
    return $path;
}
function books(array $directories, string $requiredCategory = '', bool $requireComplete = false): array
{
    $lock = openPrivateState(CONFIG_DIR . '/index-'.libraryStorageKey().'.lock');
    if (!$lock || !flock($lock, LOCK_EX)) throw new RuntimeException('Index lock unavailable.');
    $temp = null;
    try {
        $ownerIndex = canSeePrivateBooks() && privacyRules() ? '-owner' : '';
        $cachePath = CONFIG_DIR . '/cache/index-'.libraryStorageKey().(isset($GLOBALS['shareCategory'])?'-'.hash('sha256',$GLOBALS['shareCategory']):$ownerIndex).'.json';
        $raw = is_file($cachePath) ? file_get_contents($cachePath, false, null, 0, 16*1024*1024) : '';
        $cache = $raw ? json_decode($raw, true) : [];
        if (!is_array($cache)) $cache = [];
        $updated = []; $budget = 120; $count = 0; $pending = false;
        $deadline = hrtime(true) + 1_000_000_000;
        $metadataBudget=new MetadataBudget($deadline);
        // Include existing loose books as well as top-level categories.
        foreach ((isset($GLOBALS['shareCategory'])?$directories:[''=>getLibraryRoot()] + $directories) as $category => $directory) {
            foreach (scandir($directory) ?: [] as $name) {
                if ($name === '' || $name[0] === '.') continue;
                try { safeFilename($name); $format=bookFormat($name); } catch (RequestError $e) { continue; }
                $relative = (string)$category === '' ? $name : (string)$category . '/' . $name;
                try { $path = bookPath($relative,listed:true); } catch (RequestError $e) { continue; }
                if (++$count > 5000) reject(tr('The library exceeds the current indexing limit.'), 503);
                $stat = stat($path);
                if (!$stat || $stat['size'] < 1 || $stat['size'] > MAX_FILE_SIZE) continue;
                $old = $cache[$relative] ?? [];
                $formatVersion=$format['id'].':'.$format['metadata_version'].':'.(int)$format['enabled'];
                if (($old['mtime'] ?? null) === $stat['mtime'] && ($old['size'] ?? null) === $stat['size']
                    && ($old['ctime'] ?? null) === $stat['ctime'] && ($old['ino']??null)===$stat['ino'] && ($old['dev']??null)===$stat['dev'] && !($old['pending'] ?? false)
                    && ($old['format_version']??null)===$formatVersion) {
                    $updated[$relative] = $old; continue;
                }
                $record = ['path'=>$relative, 'category'=>(string)$category, 'mtime'=>$stat['mtime'],
                    'size'=>$stat['size'], 'ctime'=>$stat['ctime'], 'ino'=>$stat['ino'], 'dev'=>$stat['dev'], 'title'=>pathinfo($name, PATHINFO_FILENAME),
                    'author'=>'', 'language'=>'', 'format_version'=>$formatVersion];
                if ($requiredCategory !== '' && (string)$category !== $requiredCategory) {
                    $record['pending'] = true; $updated[$relative] = $record; continue;
                }
                if ($budget <= 0 || hrtime(true) >= $deadline) {
                    $record['pending'] = true; $updated[$relative] = $record; $pending = true; continue;
                }
                --$budget;
                try { $record = array_merge($record, metadata($path,$format,$metadataBudget)); }
                catch (MetadataDeferred) { $record['pending']=true; $pending=true; }
                catch (Throwable $e) { $record['invalid'] = true; error_log('OPDS: metadata rejected.'); }
                $updated[$relative] = $record;
            }
        }
        $json = json_encode($updated, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
        $temp = CONFIG_DIR . '/cache/.index-' . bin2hex(random_bytes(16));
        if (file_put_contents($temp, $json, LOCK_EX) !== strlen($json) || !rename($temp, $cachePath)) throw new RuntimeException('Index save failed.');
        $temp = null;
        // Partial feeds look complete or shift entries across offset boundaries as index work progresses.
        if ($pending && $requireComplete) {
            header('Retry-After: 2');
            reject(tr('The library index is updating. Refresh the catalog shortly.'),503);
        }
        return array_values(array_filter($updated, static fn ($b) => !($b['invalid'] ?? false) && !($b['pending'] ?? false)));
    } finally { if ($temp !== null) @unlink($temp); flock($lock, LOCK_UN); fclose($lock); }
}
