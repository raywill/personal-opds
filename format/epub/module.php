<?php
declare(strict_types=1);
namespace OPDS\Format\Epub;
use BookFormat, BookChapter, BookImage, ChapterBookReader, Closure, DOMDocument, DOMXPath, MetadataBudget, RequestError, RuntimeException, SimpleXMLElement, ZipArchive;

if (!interface_exists(BookFormat::class,false)) { http_response_code(404); exit; }

function tr(string $message): string { return \formatMessage('epub',$message); }
function reject(string $message,int $status=400): never { \reject(tr($message),$status); }

const MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024;
const MAX_CONTAINER_SIZE = 1024 * 1024;

function validArchivePath(string $name): bool
{
    if ($name === '' || strlen($name) > 1024 || preg_match('//u', $name) !== 1
        || preg_match('~[\\\\:\x00-\x1F\x7F]~', $name) || $name[0] === '/') {
        return false;
    }
    foreach (explode('/', rtrim($name, '/')) as $part) {
        if ($part === '' || $part === '.' || $part === '..') {
            return false;
        }
    }
    return true;
}

function readZipEntry(ZipArchive $zip, string $name, int $limit): string
{
    $stream = $zip->getStream($name);
    if ($stream === false) {
        reject(tr('Cannot read EPUB metadata.'), 422);
    }
    try {
        $value = stream_get_contents($stream, $limit + 1);
        if ($value === false || strlen($value) > $limit || !feof($stream)) {
            reject(tr('EPUB metadata is too large or unreadable.'), 422);
        }
        return $value;
    } finally {
        fclose($stream);
    }
}

function validateEpub(string $path,?MetadataBudget $budget=null): void
{
    if (!class_exists(ZipArchive::class) || !function_exists('simplexml_load_string')) {
        throw new RuntimeException('ZIP and SimpleXML extensions are required.');
    }
    $budget?->check();
    $zip = new ZipArchive();
    if ($zip->open($path, ZipArchive::RDONLY | ZipArchive::CHECKCONS) !== true) {
        reject(tr('The EPUB is not a valid ZIP archive.'), 422);
    }
    try {
        if ($zip->numFiles < 3 || $zip->numFiles > 10000) {
            reject(tr('Invalid EPUB entry count.'), 422);
        }
        // Inspect ALL size metadata before decompressing any entry.
        $total = 0;
        $entries = [];
        for ($i = 0; $i < $zip->numFiles; ++$i) {
            if (($i%64)===0) $budget?->check();
            $stat = $zip->statIndex($i);
            if ($stat === false || !isset($stat['name'], $stat['size'], $stat['comp_size'])
                || !is_int($stat['size']) || !is_int($stat['comp_size'])
                || $stat['size'] < 0 || $stat['comp_size'] < 0
                || !validArchivePath($stat['name']) || isset($entries[$stat['name']])) {
                reject(tr('The EPUB contains invalid or duplicate entries.'), 422);
            }
            if ($stat['size'] > MAX_TOTAL_UNCOMPRESSED - $total
                || $stat['size'] / max(1, $stat['comp_size']) > 200) {
                reject(tr('The EPUB expansion size or compression ratio is excessive.'), 422);
            }
            if (($stat['encryption_method'] ?? 0) !== 0) {
                reject(tr('ZIP-encrypted EPUB files are not accepted.'), 422);
            }
            $opsys = $attributes = 0;
            if ($zip->getExternalAttributesIndex($i, $opsys, $attributes)
                && $opsys === ZipArchive::OPSYS_UNIX
                && (($attributes >> 16) & 0170000) === 0120000) {
                reject(tr('EPUB symbolic-link entries are not allowed.'), 422);
            }
            $total += $stat['size'];
            $entries[$stat['name']] = $stat;
            if ($i === 0 && ($stat['name'] !== 'mimetype' || $stat['size'] !== 20
                || ($stat['comp_method'] ?? -1) !== ZipArchive::CM_STORE)) {
                reject(tr('The first EPUB mimetype entry is invalid.'), 422);
            }
        }
        if (readZipEntry($zip, 'mimetype', 20) !== 'application/epub+zip') {
            reject(tr('Incorrect EPUB mimetype.'), 422);
        }
        $containerStat = $entries['META-INF/container.xml'] ?? null;
        if ($containerStat === null || $containerStat['size'] < 1
            || $containerStat['size'] > MAX_CONTAINER_SIZE) {
            reject(tr('EPUB container.xml is missing or has an invalid size.'), 422);
        }
        $budget?->check();
        $container = readZipEntry($zip, 'META-INF/container.xml', MAX_CONTAINER_SIZE);
        // Only UTF-8/ASCII metadata is accepted, so NUL/UTF-16 cannot bypass
        // the DTD check. Never enable NOENT, DTDLOAD, DTDVALID or PARSEHUGE.
        if (preg_match('//u', $container) !== 1 || str_contains($container, "\0")
            || preg_match('/<!\s*(?:DOCTYPE|ENTITY)\b/i', $container)
            || (preg_match('/<\?xml\b[^?]*\bencoding\s*=\s*([\'"])([^\'"]+)\1/i', $container, $m)
                && !in_array(strtoupper($m[2]), ['UTF-8', 'UTF8', 'US-ASCII', 'ASCII'], true))) {
            reject(tr('EPUB container.xml has an invalid encoding or DTD/entity declaration.'), 422);
        }
        $previous = libxml_use_internal_errors(true);
        $loader = function_exists('libxml_get_external_entity_loader')
            ? libxml_get_external_entity_loader() : null;
        libxml_set_external_entity_loader(static fn () => null);
        try {
            $xml = simplexml_load_string($container, SimpleXMLElement::class, LIBXML_NONET);
            if ($xml === false) {
                reject(tr('Malformed EPUB container.xml.'), 422);
            }
            $xml->registerXPathNamespace('c', 'urn:oasis:names:tc:opendocument:xmlns:container');
            $rootfiles = $xml->xpath('/c:container/c:rootfiles/c:rootfile');
            if (!$rootfiles) {
                reject(tr('The EPUB has no rootfile declaration.'), 422);
            }
            foreach ($rootfiles as $rootfile) {
                $fullPath = (string) $rootfile['full-path'];
                if (!validArchivePath($fullPath) || str_ends_with($fullPath, '/')
                    || !isset($entries[$fullPath]) || $entries[$fullPath]['size'] < 1
                    || (string) $rootfile['media-type'] !== 'application/oebps-package+xml') {
                    reject(tr('Invalid EPUB rootfile path, media type, or entry.'), 422);
                }
            }
        } finally {
            libxml_set_external_entity_loader($loader);
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
    } finally {
        $zip->close();
    }
}

function xmlDocument(string $text): DOMDocument
{
    if (strlen($text) > MAX_CONTAINER_SIZE || preg_match('//u', $text) !== 1
        || str_contains($text, "\0") || preg_match('/<!\s*(DOCTYPE|ENTITY)\b/i', $text)
        || (preg_match('/<\?xml\b[^?]*encoding\s*=\s*([\'"])([^\'"]+)\1/i', $text, $m)
            && !in_array(strtoupper($m[2]), ['UTF-8','UTF8','ASCII','US-ASCII'], true))) reject(tr('Invalid metadata.'), 422);
    $previous = libxml_use_internal_errors(true);
    $loader = function_exists('libxml_get_external_entity_loader')?libxml_get_external_entity_loader():null;
    libxml_set_external_entity_loader(static fn () => null);
    try {
        $doc = new DOMDocument();
        if (!$doc->loadXML($text, LIBXML_NONET)) reject(tr('Invalid metadata XML.'), 422);
        return $doc;
    } finally { libxml_set_external_entity_loader($loader); libxml_clear_errors(); libxml_use_internal_errors($previous); }
}
function epubMetadata(string $path,MetadataBudget $budget): array
{
    $result = [];
    validateEpub($path,$budget);
    $budget->check();
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
// Resolve only names inside the archive. These names are never disk paths.
function readerReference(string $base, string $href): ?array
{
    [$raw,$fragment]=array_pad(explode('#',trim($href),2),2,'');
    if (str_contains($raw,'?')) return null;
    $raw=rawurldecode($raw); $fragment=rawurldecode($fragment);
    if ($raw==='') return [$base,$fragment];
    if ($raw[0]==='/'||preg_match('~[\\\\:\x00-\x1f\x7f]~',$raw)) return null;
    $parts=explode('/',$base); array_pop($parts);
    foreach (explode('/',$raw) as $part) {
        if ($part===''||$part==='.') continue;
        if ($part==='..') { if (!$parts) return null; array_pop($parts); }
        else $parts[]=$part;
    }
    $name=implode('/',$parts);
    return validArchivePath($name)?[$name,$fragment]:null;
}
function readerEntry(ZipArchive $zip,string $entry,int $max): string
{
    $stat=$zip->statName($entry);
    if (!$stat||$stat['size']>$max||$stat['size']<1)
        reject('This EPUB entry is missing or too large to display.',422);
    return readZipEntry($zip,$entry,$max);
}
function readerEpub(ZipArchive $zip): array
{
    $container=xmlDocument(readerEntry($zip,'META-INF/container.xml',MAX_CONTAINER_SIZE));
    $root=(new DOMXPath($container))->query('/*[local-name()="container"]/*[local-name()="rootfiles"]/*[local-name()="rootfile"]')->item(0);
    $opf=$root?->getAttribute('full-path')??'';
    if (!validArchivePath($opf)) reject('Cannot read this EPUB.',422);
    $xp=new DOMXPath(xmlDocument(readerEntry($zip,$opf,MAX_CONTAINER_SIZE)));
    $base='/*[local-name()="package"]';
    $items=[]; $byPath=[]; $nav=null;
    foreach ($xp->query($base.'/*[local-name()="manifest"]/*[local-name()="item"]') as $item) {
        $ref=readerReference($opf,$item->getAttribute('href'));
        $id=$item->getAttribute('id'); $type=$item->getAttribute('media-type');
        if (!$ref||$id===''||$ref[1]!=='') continue;
        $items[$id]=['path'=>$ref[0],'type'=>$type];
        $byPath[$ref[0]]=$items[$id];
        if (preg_match('/(?:^|\s)nav(?:\s|$)/',$item->getAttribute('properties'))) $nav=$items[$id];
    }
    $spine=$xp->query($base.'/*[local-name()="spine"]')->item(0); $chapters=[]; $positions=[];
    foreach ($spine?$xp->query('./*[local-name()="itemref"]',$spine):[] as $item) {
        $id=$item->getAttribute('idref'); $chapter=$items[$id]??null;
        if (!$chapter||!in_array($chapter['type'],['application/xhtml+xml','text/html'],true)||isset($positions[$chapter['path']])) continue;
        $positions[$chapter['path']]=count($chapters); $chapters[]=$chapter['path'];
    }
    if (!$chapters||count($chapters)>2000) reject('Cannot read this EPUB.',422);
    return [$chapters,$positions,$byPath,$nav,$items[$spine->getAttribute('toc')]??null];
}
function readerHtmlDocument(string $html): DOMDocument
{
    if (preg_match('//u',$html)!==1 || str_contains($html,"\0")) reject('Cannot read this EPUB.',422);
    $previous=libxml_use_internal_errors(true);
    $doc=new DOMDocument();
    try {
        if (!$doc->loadHTML('<?xml encoding="UTF-8">'.$html,LIBXML_NONET)) reject('Cannot read this EPUB.',422);
        return $doc;
    } finally { libxml_clear_errors(); libxml_use_internal_errors($previous); }
}
function readerToc(ZipArchive $zip,array $book): array
{
    [$chapters,$positions,,$nav,$ncx]=$book;
    $out=[];
    try {
        if ($nav) {
            $path=$nav['path'];
            $doc=readerHtmlDocument(readerEntry($zip,$path,MAX_CONTAINER_SIZE));
            $xpath=new DOMXPath($doc);
            $links=$xpath->query('//nav[@role="doc-toc" or @id="toc"]//a');
            // DOM's HTML parser does not consistently preserve namespace prefixes.
            if (!$links||!$links->length) {
                $navNode=null;
                foreach ($doc->getElementsByTagName('nav') as $candidate) {
                    if ($candidate->getAttribute('epub:type')==='toc') { $navNode=$candidate; break; }
                    $navNode??=$candidate;
                }
                $links=$navNode?$xpath->query('.//a',$navNode):[];
            }
            foreach ($links as $node) {
                $target=readerReference($path,$node->getAttribute('href'));
                if ($target&&isset($positions[$target[0]])) $out[]=[$positions[$target[0]],$target[1],trim($node->textContent)];
                if (count($out)>=2000) break;
            }
        }
        if (!$out&&$ncx) {
            $path=$ncx['path'];
            $xp=new DOMXPath(xmlDocument(readerEntry($zip,$path,MAX_CONTAINER_SIZE)));
            foreach ($xp->query('//*[local-name()="navPoint"]') as $node) {
                $target=readerReference($path,$xp->query('./*[local-name()="content"]/@src',$node)->item(0)?->nodeValue??'');
                if ($target&&isset($positions[$target[0]])) $out[]=[$positions[$target[0]],$target[1],trim($xp->query('./*[local-name()="navLabel"]',$node)->item(0)?->textContent??'')];
                if (count($out)>=2000) break;
            }
        }
    } catch (RequestError) { /* A bad optional TOC should not stop reading. */ }
    if (!$out) foreach ($chapters as $i=>$unused) $out[]=[$i,'',sprintf(tr('Chapter %d'),$i+1)];
    return $out;
}
return new class implements BookFormat, ChapterBookReader {
    public function validate(string $path): void { validateEpub($path); }
    public function metadata(string $path,MetadataBudget $budget): array { return epubMetadata($path,$budget); }

    private function withZip(string $path, Closure $read): mixed
    {
        $zip=new \ZipArchive();
        if ($zip->open($path,\ZipArchive::RDONLY)!==true) reject('Cannot read this EPUB.',422);
        try { return $read($zip,readerEpub($zip)); }
        finally { $zip->close(); }
    }
    public function chapter(string $path,int $index): BookChapter
    {
        return $this->withZip($path,static function (\ZipArchive $zip,array $book) use ($index): BookChapter {
            [$chapters,$positions,$byPath]=$book;
            $name=$chapters[$index]??null;
            if ($name===null) reject('Book not found.',404);
            $doc=readerHtmlDocument(readerEntry($zip,$name,2*1024*1024));
            $body=$doc->getElementsByTagName('body')->item(0);
            if (!$body) reject('Cannot read this EPUB.',422);
            return new BookChapter($body,count($chapters),
                static function (string $reference) use ($name,$byPath): ?string {
                    $image=readerReference($name,$reference);
                    return $image && readerImageAllowed($byPath[$image[0]]['type']??'')?$image[0]:null;
                },
                static function (string $reference) use ($name,$positions): ?array {
                    $target=readerReference($name,$reference);
                    return $target && isset($positions[$target[0]])?[$positions[$target[0]],$target[1]]:null;
                });
        });
    }
    public function contents(string $path): array
    {
        return $this->withZip($path,static fn(\ZipArchive $zip,array $book): array=>readerToc($zip,$book));
    }
    public function image(string $path,string $key): BookImage
    {
        return $this->withZip($path,static function (\ZipArchive $zip,array $book) use ($key): BookImage {
            $type=$book[2][$key]['type']??'';
            if (!readerImageAllowed($type)) reject('Book not found.',404);
            return new BookImage($type,readerEntry($zip,$key,\READER_MAX_IMAGE));
        });
    }
};
