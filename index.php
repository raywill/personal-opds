<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/security.php';
require __DIR__ . '/upload-common.php';
require __DIR__ . '/accounts.php';
require __DIR__ . '/catalogue.php';
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: private, no-store');
const ATOM = 'http://www.w3.org/2005/Atom';
// Leave room below the entry cap on constrained readers such as CrossPoint.
const OPDS_PAGE_SIZE = 50;

function requireOpdsAccess(): void
{
    requireUploadHttps();
    header('Vary: Authorization',false);
    if (isset($_SERVER['HTTP_AUTHORIZATION'],$_SERVER['REDIRECT_HTTP_AUTHORIZATION']) &&
        $_SERVER['HTTP_AUTHORIZATION']!==$_SERVER['REDIRECT_HTTP_AUTHORIZATION']) reject('Ambiguous authorization.',401);
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
    if (!loginAccount($user,$password)) {
        if ($user!=='' || $password!=='') reserveRateAttempt('opds-login',30,600);
        header('WWW-Authenticate: Basic realm="OPDS", charset="UTF-8"');
        reject('Enter your OPDS username and password.',401);
    }
    setAccountScope($user);
    $GLOBALS['opdsInteractiveViewer']=$user;
    selectLibrary(parameter('library',personalLibraryId($user)),$user,'opds');
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
    if (isset($GLOBALS['shareKey'])) $params=['s'=>$GLOBALS['shareKey']]+$params;
    elseif (isset($_GET['library'])) $params=['library'=>currentLibrary()['id']]+$params;
    return BASE_URL . 'index.php' . ($params ? '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986) : '');
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
    requireUploadHttps();
    if (isset($_GET['s'])) {
        $key=parameter('s'); $share=resolveShare($key);
        $GLOBALS['shareKey']=strtoupper($key); $GLOBALS['shareCategory']=$share['category'];
    } else { requireOpdsAccess(); lockBookRead(); }
    if (isset($_GET['search'])) {
        if (parameter('search') !== '1') reject(tr('Invalid search parameter.'));
        $doc=new DOMDocument('1.0','UTF-8');
        $root=$doc->createElementNS('http://a9.com/-/spec/opensearch/1.1/','OpenSearchDescription'); $doc->appendChild($root);
        foreach (['ShortName'=>LIBRARY_TITLE,'Description'=>tr('Search book titles and authors'),'InputEncoding'=>'UTF-8'] as $name=>$text) {
            $node=$doc->createElementNS($root->namespaceURI,$name); $node->appendChild($doc->createTextNode($text)); $root->appendChild($node);
        }
        $node=$doc->createElementNS($root->namespaceURI,'Url'); $node->setAttribute('type','application/atom+xml');
        $node->setAttribute('template',catalogueUrl(['feed'=>'books']).'&q={searchTerms}'); $root->appendChild($node);
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
        unlockBookRead();
        if ($_SERVER['REQUEST_METHOD'] !== 'HEAD') fpassthru($handle); fclose($handle); exit;
    }
    $directories = isset($share)?[$share['category']=>resolveDestinationDirectory($share['category'])]:libraryDirectories();
    $mode = parameter('feed',isset($share)?'books':''); $category = parameter('category'); $query = trim(parameter('q'));
    if ($mode !== '' && $mode !== 'books') reject('Not Found',404);
    if (!isset($share)) requireVisibleFolder($category);
    if ($category !== '' && !isset($directories[$category])) reject(tr('Category not found.'),404);
    $doc = new DOMDocument('1.0','UTF-8'); $doc->formatOutput = true;
    $feed = $doc->createElementNS(ATOM,'feed'); $doc->appendChild($feed);
    $params = $mode === 'books' ? ['feed'=>'books'] : [];
    if ($category !== '') $params['category']=$category;
    if ($query !== '') $params['q']=$query;
    $offset = 0;
    if ($mode === 'books') {
        $rawOffset = parameter('offset','0');
        if (!preg_match('/\A\d{1,6}\z/D',$rawOffset)) reject(tr('Invalid pagination parameter.'));
        $offset = (int)$rawOffset;
    }
    add($doc,$feed,'id',catalogueUrl($params)); add($doc,$feed,'title',$category ?: ($share['category']??(isset($_GET['library'])?libraryTitle(currentLibrary(),accountScope()):LIBRARY_TITLE)));
    add($doc,$feed,'updated',gmdate('Y-m-d\TH:i:s\Z'));
    $catalogType='application/atom+xml;profile=opds-catalog;kind=' . ($mode === '' ? 'navigation' : 'acquisition');
    linkNode($doc,$feed,'self',catalogueUrl($offset > 0 ? $params+['offset'=>$offset] : $params),$catalogType);
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
        $all = array_filter(books($directories,$category,true), static fn ($b) => ($category === '' || $b['category'] === $category)
            && ($query === '' || stripos($b['title'].' '.$b['author'].' '.$b['path'],$query) !== false));
        usort($all,static fn ($a,$b)=>strcasecmp($a['title'],$b['title']) ?: strcmp($a['path'],$b['path']));
        if ($offset > 0) {
            $previous = max(0,$offset-OPDS_PAGE_SIZE);
            linkNode($doc,$feed,'previous',catalogueUrl($previous ? $params+['offset'=>$previous] : $params),$catalogType);
        }
        if ($offset+OPDS_PAGE_SIZE<count($all)) linkNode($doc,$feed,'next',catalogueUrl($params+['offset'=>$offset+OPDS_PAGE_SIZE]),$catalogType);
        foreach (array_slice($all,$offset,OPDS_PAGE_SIZE) as $book) {
            $entry=add($doc,$feed,'entry',''); add($doc,$entry,'id','urn:sha256:'.hash('sha256',accountScope().'/'.$book['path']));
            add($doc,$entry,'title',$book['title']); add($doc,$entry,'updated',gmdate('Y-m-d\TH:i:s\Z',$book['mtime']));
            $author=add($doc,$entry,'author',''); add($doc,$author,'name',$book['author']===''?tr('Unknown author'):$book['author']);
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
        echo $e instanceof RequestError ? tr($e->getMessage()) : tr('The library is temporarily unavailable.');
    }
    if (!$e instanceof RequestError) error_log('OPDS: internal catalogue error.');
}
