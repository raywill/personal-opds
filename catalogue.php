<?php
declare(strict_types=1);

function xmlDocument(string $text): DOMDocument
{
    if (strlen($text) > MAX_CONTAINER_SIZE || preg_match('//u', $text) !== 1
        || str_contains($text, "\0") || preg_match('/<!\s*(DOCTYPE|ENTITY)\b/i', $text)
        || (preg_match('/<\?xml\b[^?]*encoding\s*=\s*([\'"])([^\'"]+)\1/i', $text, $m)
            && !in_array(strtoupper($m[2]), ['UTF-8','UTF8','ASCII','US-ASCII'], true))) reject(tr('Invalid metadata.'), 422);
    $previous = libxml_use_internal_errors(true);
    libxml_set_external_entity_loader(static fn () => null);
    try {
        $doc = new DOMDocument();
        if (!$doc->loadXML($text, LIBXML_NONET)) reject(tr('Invalid metadata XML.'), 422);
        return $doc;
    } finally { libxml_clear_errors(); libxml_use_internal_errors($previous); }
}
function metadata(string $path, string $name): array
{
    $result = ['title' => pathinfo($name, PATHINFO_FILENAME), 'author' => 'Unknown', 'language' => ''];
    if (strtolower(pathinfo($name, PATHINFO_EXTENSION)) === 'txt') { validateTxt($path); return $result; }
    validateEpub($path);
    $zip = new ZipArchive();
    if ($zip->open($path, ZipArchive::RDONLY) !== true) reject(tr('Cannot read book.'), 422);
    try {
        $container = xmlDocument(readZipEntry($zip, 'META-INF/container.xml', MAX_CONTAINER_SIZE));
        $xp = new DOMXPath($container);
        $xp->registerNamespace('c', 'urn:oasis:names:tc:opendocument:xmlns:container');
        $node = $xp->query('/c:container/c:rootfiles/c:rootfile')->item(0);
        if (!$node) reject(tr('Missing metadata entry point.'), 422);
        $opf = $node->getAttribute('full-path');
        $stat = $zip->statName($opf);
        if (!$stat || $stat['size'] > MAX_CONTAINER_SIZE) reject(tr('OPF metadata is too large.'), 422);
        $doc = xmlDocument(readZipEntry($zip, $opf, MAX_CONTAINER_SIZE));
        $xp = new DOMXPath($doc);
        foreach (['title'=>'title', 'author'=>'creator', 'language'=>'language'] as $key=>$tag) {
            $nodes = $xp->query('/*[local-name()="package"]/*[local-name()="metadata"]/*[local-name()="' . $tag . '"]');
            $text = $nodes && $nodes->length ? trim($nodes->item(0)->textContent) : '';
            if ($text !== '') { preg_match('/\A.{0,128}/us', $text, $m); $result[$key] = $m[0]; }
        }
        return $result;
    } finally { $zip->close(); }
}
function bookPath(string $relative): string
{
    if (isset($GLOBALS['shareCategory']) && !str_starts_with($relative,$GLOBALS['shareCategory'].'/')) reject('Book not found.',404);
    $parts = explode('/', $relative);
    if (count($parts) > MAX_CATEGORY_DEPTH + 1) reject(tr('Invalid book path.'), 404);
    $name = array_pop($parts);
    safeFilename($name);
    $directory = $parts ? resolveDestinationDirectory(implode('/', $parts)) : getLibraryRoot();
    $path = $directory . '/' . $name;
    if (is_link($path) || !is_file($path) || !is_readable($path)
        || dirname((string) realpath($path)) !== $directory) reject(tr('Book not found.'), 404);
    return $path;
}
function books(array $directories): array
{
    $lock = openPrivateState(CONFIG_DIR . '/index-'.accountScope().'.lock');
    if (!$lock || !flock($lock, LOCK_EX)) throw new RuntimeException('Index lock unavailable.');
    $temp = null;
    try {
        $cachePath = CONFIG_DIR . '/cache/index-'.accountScope().(isset($GLOBALS['shareCategory'])?'-'.hash('sha256',$GLOBALS['shareCategory']):'').'.json';
        $raw = is_file($cachePath) ? file_get_contents($cachePath, false, null, 0, 16*1024*1024) : '';
        $cache = $raw ? json_decode($raw, true) : [];
        if (!is_array($cache)) $cache = [];
        $updated = []; $budget = 20; $count = 0;
        // Include existing loose books as well as top-level categories.
        foreach ((isset($GLOBALS['shareCategory'])?$directories:[''=>getLibraryRoot()] + $directories) as $category => $directory) {
            foreach (scandir($directory) ?: [] as $name) {
                if ($name === '' || $name[0] === '.') continue;
                try { safeFilename($name); } catch (RequestError $e) { continue; }
                $relative = (string)$category === '' ? $name : (string)$category . '/' . $name;
                try { $path = bookPath($relative); } catch (RequestError $e) { continue; }
                if (++$count > 5000) reject(tr('The library exceeds the current indexing limit.'), 503);
                $stat = stat($path);
                if (!$stat || $stat['size'] < 1 || $stat['size'] > MAX_FILE_SIZE) continue;
                $old = $cache[$relative] ?? [];
                if (($old['mtime'] ?? null) === $stat['mtime'] && ($old['size'] ?? null) === $stat['size']
                    && ($old['ctime'] ?? null) === $stat['ctime'] && ($old['ino']??null)===$stat['ino'] && ($old['dev']??null)===$stat['dev'] && !($old['pending'] ?? false)) {
                    $updated[$relative] = $old; continue;
                }
                $record = ['path'=>$relative, 'category'=>(string)$category, 'mtime'=>$stat['mtime'],
                    'size'=>$stat['size'], 'ctime'=>$stat['ctime'], 'ino'=>$stat['ino'], 'dev'=>$stat['dev'], 'title'=>pathinfo($name, PATHINFO_FILENAME),
                    'author'=>'Unknown', 'language'=>''];
                if ($budget <= 0) { $record['pending'] = true; $updated[$relative] = $record; continue; }
                --$budget;
                try { $record = array_merge($record, metadata($path, $name)); }
                catch (Throwable $e) { $record['invalid'] = true; error_log('OPDS: metadata rejected.'); }
                $updated[$relative] = $record;
            }
        }
        $json = json_encode($updated, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
        $temp = CONFIG_DIR . '/cache/.index-' . bin2hex(random_bytes(16));
        if (file_put_contents($temp, $json, LOCK_EX) !== strlen($json) || !rename($temp, $cachePath)) throw new RuntimeException('Index save failed.');
        $temp = null;
        return array_values(array_filter($updated, static fn ($b) => !($b['invalid'] ?? false) && !($b['pending'] ?? false)));
    } finally { if ($temp !== null) @unlink($temp); flock($lock, LOCK_UN); fclose($lock); }
}
