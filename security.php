<?php
declare(strict_types=1);
final class RequestError extends RuntimeException {}
function reject(string $message, int $status = 400): never { throw new RequestError($message, $status); }
function getLibraryRoot(): string
{
    clearstatcache(true);
    $root = realpath(DATA_DIR);
    if (is_link(DATA_DIR) || $root === false || !is_dir($root)) {
        throw new RuntimeException('Invalid library root.');
    }
    // PHP may write the child book directories, but must not replace them.
    if (is_writable($root)) {
        throw new RuntimeException('Library root must not be writable by PHP.');
    }
    return $root;
}

function validDirectoryName(string $name): bool
{
    return $name !== '' && $name[0] !== '.' && strlen($name) <= 240
        && preg_match('//u', $name) === 1
        && !preg_match('~[/\\\\\x00-\x1F\x7F]~', $name);
}

// Traversal supports bounded depth; bootstrap currently enforces depth === 1.
function libraryDirectories(bool $writableOnly = false): array
{
    $root = getLibraryRoot();
    $result = [];
    $walk = function (string $parent, string $prefix, int $depth) use (&$walk, &$result, $writableOnly): void {
        if ($depth >= MAX_CATEGORY_DEPTH) return;
        foreach (scandir($parent) ?: [] as $name) {
            $path = $parent . '/' . $name;
            if (!validDirectoryName($name) || is_link($path) || !is_dir($path)
                || dirname((string) realpath($path)) !== $parent) continue;
            $relative = $prefix === '' ? $name : $prefix . '/' . $name;
            if (!$writableOnly || is_writable($path)) $result[$relative] = $path;
            if (count($result) > 1000) reject(tr('Too many categories.'), 503);
            $walk($path, $relative, $depth + 1);
        }
    };
    $walk($root, '', 0);
    return $result;
}
function resolveDestinationDirectory(string $name): string
{
    $parts = explode('/', $name);
    if (count($parts) > MAX_CATEGORY_DEPTH) reject(tr('Only one category level is currently supported.'));
    $parent = getLibraryRoot();
    foreach ($parts as $part) {
        if (!validDirectoryName($part)) reject(tr('Invalid destination category.'));
        $candidate = $parent . '/' . $part;
        if (is_link($candidate) || !is_dir($candidate)) reject(tr('Destination category does not exist.'));
        $real = realpath($candidate);
        if ($real === false || dirname($real) !== $parent || basename($real) !== $part) reject(tr('Category is outside the allowed location.'));
        $parent = $real;
    }
    return $parent;
}
function getDirectories(): array { return array_map('strval', array_keys(libraryDirectories(true))); }

function safeFilename(string $name): string
{
    if ($name === '' || strlen($name) > 240 || preg_match('//u', $name) !== 1
        || $name[0] === '.' || trim($name) !== $name || str_ends_with($name, '.')
        || str_contains($name, '..') || preg_match('~[/\\\\:\x00-\x1F\x7F]~', $name)) {
        reject(tr('Invalid filename.'));
    }
    if (!in_array(strtolower(pathinfo($name, PATHINFO_EXTENSION)), ['epub', 'txt'], true)) {
        reject(tr('Only EPUB and TXT files are accepted.'), 422);
    }
    // Defense in depth for servers with unsafe multiple-extension handlers.
    if (preg_match('/(?:^|\.)(?:php\d*|phtml|pht|phar|cgi|pl|shtml|htaccess)(?:\.|$)/i', $name)) {
        reject(tr('The filename contains a disallowed extension.'), 422);
    }
    return $name;
}

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

function validateEpub(string $path): void
{
    if (!class_exists(ZipArchive::class) || !function_exists('simplexml_load_string')) {
        throw new RuntimeException('ZIP and SimpleXML extensions are required.');
    }
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

function validateTxt(string $path): void
{
    $handle = fopen($path, 'rb');
    if ($handle === false) {
        throw new RuntimeException('Cannot read TXT file.');
    }
    try {
        while (!feof($handle)) {
            $chunk = fread($handle, 65536);
            if ($chunk === false || ($chunk === '' && !feof($handle))) {
                throw new RuntimeException('Cannot read TXT file.');
            }
            if (str_contains($chunk, "\0")) {
                reject(tr('The TXT contains binary NUL bytes. Use a text encoding such as UTF-8 or GBK.'), 422);
            }
        }
    } finally {
        fclose($handle);
    }
}
