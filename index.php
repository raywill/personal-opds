<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/security.php';
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-cache');
const ATOM = 'http://www.w3.org/2005/Atom';

function requireOpdsAccess(): void
{
    $config = readCredentials();
    if (!isset($config['opds_user'])) return;

    header('Cache-Control: private, no-store');
    header('Vary: Authorization');
    if (!in_array(strtolower((string) ($_SERVER['HTTPS'] ?? '')), ['on', '1'], true)) {
        reject(tr('HTTPS is required to access this private OPDS library.'), 403);
    }

    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null;
    $user = $password = '';
    if ($header === null) {
        $user = (string) ($_SERVER['PHP_AUTH_USER'] ?? '');
        $password = (string) ($_SERVER['PHP_AUTH_PW'] ?? '');
    } elseif (strlen($header) <= 24000 && preg_match('/\ABasic +([a-z0-9+\/=]+)\z/iD', $header, $match)) {
        $decoded = base64_decode($match[1], true);
        if ($decoded !== false && str_contains($decoded, ':')) {
            [$user, $password] = explode(':', $decoded, 2);
        }
    }
    $validUser = hash_equals(hash('sha256', $config['opds_user']), hash('sha256', $user));
    $validPassword = hash_equals(hash('sha256', $config['opds_pwd']), hash('sha256', $password));
    if (!$validUser || !$validPassword) {
        header('WWW-Authenticate: Basic realm="OPDS", charset="UTF-8"');
        reject(tr('Enter the OPDS reading username and password.'), 401);
    }
}

function parameter(string $name, string $default = ''): string
{
    $value = $_GET[$name] ?? $default;
    if (!is_string($value) || strlen($value) > 2048 || preg_match('//u', $value) !== 1
        || preg_match('/[\x00-\x1f\x7f]/', $value)) reject(tr('Invalid parameter.'));
    return $value;
}
function catalogueUrl(array $params = []): string
{
    return BASE_URL . 'index.php' . ($params ? '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986) : '');
}
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
    $lock = fopen(CONFIG_DIR . '/index.lock', 'c+b');
    if (!$lock || !flock($lock, LOCK_EX)) throw new RuntimeException('Index lock unavailable.');
    $temp = null;
    try {
        $cachePath = CONFIG_DIR . '/cache/index.json';
        $raw = is_file($cachePath) ? file_get_contents($cachePath, false, null, 0, 16*1024*1024) : '';
        $cache = $raw ? json_decode($raw, true) : [];
        if (!is_array($cache)) $cache = [];
        $updated = []; $budget = 20; $count = 0;
        // Include existing loose books as well as top-level categories.
        foreach ([''=>getLibraryRoot()] + $directories as $category => $directory) {
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
                    && ($old['ctime'] ?? null) === $stat['ctime'] && !($old['pending'] ?? false)) {
                    $updated[$relative] = $old; continue;
                }
                $record = ['path'=>$relative, 'category'=>(string)$category, 'mtime'=>$stat['mtime'],
                    'size'=>$stat['size'], 'ctime'=>$stat['ctime'], 'title'=>pathinfo($name, PATHINFO_FILENAME),
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
function add(DOMDocument $doc, DOMElement $parent, string $name, string $value): DOMElement
{
    $node = $doc->createElementNS(ATOM, $name); $node->appendChild($doc->createTextNode($value)); $parent->appendChild($node); return $node;
}
function linkNode(DOMDocument $doc, DOMElement $parent, string $rel, string $url, string $type): void
{
    $node = $doc->createElementNS(ATOM, 'link');
    foreach (['rel'=>$rel,'href'=>$url,'type'=>$type] as $k=>$v) $node->setAttribute($k,$v);
    $parent->appendChild($node);
}
try {
    if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET','HEAD'], true)) { header('Allow: GET, HEAD'); reject(tr('Method not allowed.'),405); }
    requireOpdsAccess();
    if (isset($_GET['search'])) {
        if (parameter('search') !== '1') reject(tr('Invalid search parameter.'));
        $doc=new DOMDocument('1.0','UTF-8');
        $root=$doc->createElementNS('http://a9.com/-/spec/opensearch/1.1/','OpenSearchDescription'); $doc->appendChild($root);
        foreach (['ShortName'=>LIBRARY_TITLE,'Description'=>tr('Search book titles and authors'),'InputEncoding'=>'UTF-8'] as $name=>$text) {
            $node=$doc->createElementNS($root->namespaceURI,$name); $node->appendChild($doc->createTextNode($text)); $root->appendChild($node);
        }
        $node=$doc->createElementNS($root->namespaceURI,'Url'); $node->setAttribute('type','application/atom+xml');
        $node->setAttribute('template',BASE_URL.'index.php?feed=books&q={searchTerms}'); $root->appendChild($node);
        header('Content-Type: application/opensearchdescription+xml; charset=UTF-8');
        if ($_SERVER['REQUEST_METHOD']!=='HEAD') echo $doc->saveXML(); exit;
    }
    if (isset($_GET['download'])) {
        $relative = parameter('download'); $path = bookPath($relative);
        $handle = fopen($path, 'rb'); if (!$handle) reject(tr('Book is unreadable.'),404);
        $stat = fstat($handle); if (!$stat || $stat['size'] > MAX_FILE_SIZE) reject(tr('Invalid file size.'),413);
        header('Content-Type: ' . (strtolower(pathinfo($path,PATHINFO_EXTENSION)) === 'epub' ? 'application/epub+zip' : 'text/plain'));
        header('Content-Disposition: attachment; filename*=UTF-8\'\'' . rawurlencode(basename($path)));
        header('Content-Length: ' . $stat['size']);
        if ($_SERVER['REQUEST_METHOD'] !== 'HEAD') fpassthru($handle); fclose($handle); exit;
    }
    $directories = libraryDirectories();
    $mode = parameter('feed'); $category = parameter('category'); $query = trim(parameter('q'));
    if ($mode !== '' && $mode !== 'books') reject('Not Found',404);
    if ($category !== '' && !isset($directories[$category])) reject(tr('Category not found.'),404);
    $doc = new DOMDocument('1.0','UTF-8'); $doc->formatOutput = true;
    $feed = $doc->createElementNS(ATOM,'feed'); $doc->appendChild($feed);
    $params = $mode === 'books' ? ['feed'=>'books'] : [];
    if ($category !== '') $params['category']=$category;
    if ($query !== '') $params['q']=$query;
    add($doc,$feed,'id',catalogueUrl($params)); add($doc,$feed,'title',$category ?: LIBRARY_TITLE);
    add($doc,$feed,'updated',gmdate('Y-m-d\TH:i:s\Z'));
    $catalogType='application/atom+xml;profile=opds-catalog;kind=' . ($mode === '' ? 'navigation' : 'acquisition');
    linkNode($doc,$feed,'self',catalogueUrl($params),$catalogType);
    linkNode($doc,$feed,'search',catalogueUrl(['search'=>1]),'application/opensearchdescription+xml');
    if ($mode === '') {
        $navigation=[['category'=>'','title'=>tr('All books')]];
        foreach (array_keys($directories) as $key) $navigation[]=['category'=>(string)$key,'title'=>(string)$key];
        foreach ($navigation as $nav) {
            $key=$nav['category']; $title=$nav['title'];
            $p=['feed'=>'books']; if ((string)$key !== '') $p['category']=(string)$key;
            $entry=add($doc,$feed,'entry',''); add($doc,$entry,'id',catalogueUrl($p)); add($doc,$entry,'title',$title); add($doc,$entry,'updated',gmdate('Y-m-d\TH:i:s\Z'));
            linkNode($doc,$entry,'subsection',catalogueUrl($p),'application/atom+xml;profile=opds-catalog;kind=acquisition');
        }
    } else {
        $all = array_filter(books($directories), static fn ($b) => ($category === '' || $b['category'] === $category)
            && ($query === '' || stripos($b['title'].' '.$b['author'].' '.$b['path'],$query) !== false));
        usort($all,static fn ($a,$b)=>strcasecmp($a['title'],$b['title']));
        $offset=parameter('offset','0'); if (!preg_match('/\A\d{1,6}\z/D',$offset)) reject(tr('Invalid pagination parameter.'));
        $offset=(int)$offset;
        if ($offset+100<count($all)) linkNode($doc,$feed,'next',catalogueUrl($params+['offset'=>$offset+100]),$catalogType);
        foreach (array_slice($all,$offset,100) as $book) {
            $entry=add($doc,$feed,'entry',''); add($doc,$entry,'id','urn:sha256:'.hash('sha256',$book['path']));
            add($doc,$entry,'title',$book['title']); add($doc,$entry,'updated',gmdate('Y-m-d\TH:i:s\Z',$book['mtime']));
            $author=add($doc,$entry,'author',''); add($doc,$author,'name',$book['author']);
            if ($book['language'] !== '') {
                $language=$doc->createElementNS('http://purl.org/dc/elements/1.1/','dc:language');
                $language->appendChild($doc->createTextNode($book['language'])); $entry->appendChild($language);
            }
            linkNode($doc,$entry,'http://opds-spec.org/acquisition',catalogueUrl(['download'=>$book['path']]),
                strtolower(pathinfo($book['path'],PATHINFO_EXTENSION)) === 'epub' ? 'application/epub+zip' : 'text/plain');
        }
    }
    header('Content-Type: application/atom+xml; charset=UTF-8');
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') echo $doc->saveXML();
} catch (Throwable $e) {
    http_response_code($e instanceof RequestError ? $e->getCode() : 500);
    header('Content-Type: text/plain; charset=UTF-8');
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') {
        echo $e instanceof RequestError ? $e->getMessage() : tr('The library is temporarily unavailable.');
    }
    if (!$e instanceof RequestError) error_log('OPDS: internal catalogue error.');
}
