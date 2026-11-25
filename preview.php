<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/security.php';
require __DIR__.'/upload-common.php';
require __DIR__.'/accounts.php';
require __DIR__.'/catalogue.php';
require __DIR__.'/reader-content.php';

header('Cache-Control: private, no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
function readerParam(string $name): string {
    $value=$_GET[$name]??'';
    if (!is_string($value)||strlen($value)>2048) reject('Invalid input.');
    return $value;
}
function readerNumber(string $name): int {
    $value=readerParam($name);
    if (!preg_match('/\A[0-9]{1,9}\z/D',$value)) reject('Invalid input.');
    return (int)$value;
}
function readerJson(array $data,int $status=200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($data,JSON_THROW_ON_ERROR|JSON_INVALID_UTF8_SUBSTITUTE|JSON_UNESCAPED_UNICODE);
    exit;
}
$back='up.php'; $error=''; $bookName=''; $page=[];
$api=isset($_GET['part'])||isset($_GET['asset'])||isset($_GET['toc']);
try {
    requireUploadHttps();
    if ($_SERVER['REQUEST_METHOD']!=='GET') reject('Method not allowed.',405);
    if (!isset($_COOKIE[WEB_SESSION_NAME])) reject('Sign in again.',401);
    startWebSession();
    $user=webSessionAccount();
    $viewer=$user?$_SESSION['account']:'';
    session_write_close();
    if (!$user) reject('Sign in again.',401);
    $id=readerParam('library'); $dir=readerParam('dir'); $bookName=readerParam('book');
    $row=selectLibrary($id,$viewer,'view');
    $query=['library'=>$id,'dir'=>$dir];
    $back='up.php?'.http_build_query($query,'','&',PHP_QUERY_RFC3986);
    $path=managedBook($dir,$bookName);
    $stat=stat($path);
    if (!$stat||$stat['size']>MAX_FILE_SIZE) reject('This file is too large for online reading.',422);
    $version=hash_hmac('sha256',implode(':',[$id,$stat['dev'],$stat['ino'],$stat['size'],$stat['mtime']]),SHARE_KEY);
    $url='preview.php?'.http_build_query($query+['book'=>$bookName],'','&',PHP_QUERY_RFC3986);
    $format=strtolower(pathinfo($bookName,PATHINFO_EXTENSION));
    if ($api) {
        if (!hash_equals($version,readerParam('version'))) reject('This book changed. Reopen it from the library.',409);
        if ($format==='txt') {
            if (!isset($_GET['part'])||isset($_GET['asset'])||isset($_GET['toc'])) reject('Book not found.',404);
            readerJson(readerTextChunk($path,readerNumber('part'),readerParam('encoding')));
        }
        $zip=new ZipArchive();
        if ($zip->open($path,ZipArchive::RDONLY)!==true) reject('Cannot read this EPUB.',422);
        try {
            $epub=readerEpub($zip);
            if (isset($_GET['asset'])) {
                $name=readerParam('asset');
                $type=$epub[2][$name]['type']??'';
                if (!in_array($type,READER_IMAGES,true)) reject('Book not found.',404);
                $bytes=readerEntry($zip,$name,12*1024*1024);
                header('Content-Type: '.$type);
                header('Content-Length: '.strlen($bytes));
                echo $bytes;
            } elseif (isset($_GET['toc'])) {
                readerJson(['toc'=>readerToc($zip,$epub)]);
            } else {
                $i=readerNumber('part');
                $name=$epub[0][$i]??null;
                if ($name===null) reject('Book not found.',404);
                $doc=readerHtmlDocument(readerEntry($zip,$name,2*1024*1024));
                $body=$doc->getElementsByTagName('body')->item(0);
                if (!$body) reject('Cannot read this EPUB.',422);
                $html=readerMarkup($body,$name,$epub[1],$epub[2],$url.'&version='.$version);
                readerJson(['html'=>$html,'count'=>count($epub[0])]);
            }
        } finally { $zip->close(); }
        exit;
    }
    $page=[
        'format'=>$format,'url'=>$url.'&version='.$version,
        'profile'=>hash_hmac('sha256',$viewer,SHARE_KEY),'book'=>$version,
        'loading'=>tr('Opening book…'),'failed'=>tr('Could not load this part. Try again.'),
        'section'=>tr('Next section'),'chapter'=>tr('Next chapter'),
        'part'=>tr('Chapter %d of %d'),'start'=>tr('Start of book'),
    ];
} catch (Throwable $e) {
    $status=$e instanceof RequestError?$e->getCode():($e instanceof AccountStorageError?503:500);
    $error=publicError($e);
    if ($api) readerJson(['error'=>$error],$status);
    http_response_code($status);
}
function re(string $text): string { return readerEscape($text); }
$title=$bookName!==''?pathinfo($bookName,PATHINFO_FILENAME):tr('Reader');
?>
<!doctype html>
<html lang="<?=re(uiLanguageTag())?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title><?=re($title)?></title>
<link rel="stylesheet" href="reader.css?v=<?=filemtime(__DIR__.'/reader.css')?>">
<?php if (!$error): ?><script src="reader.js?v=<?=filemtime(__DIR__.'/reader.js')?>" defer></script><?php endif; ?>
</head>
<body>
<header class="reader-bar">
 <a class="reader-back" href="<?=re($back)?>"><span aria-hidden="true">‹</span> <?=tr_html('Back to library')?></a>
 <h1 title="<?=re($title)?>"><?=re($title)?></h1>
 <?php if (!$error): ?><button id="controls" type="button" aria-label="<?=tr_html('Reading controls')?>" aria-expanded="false" aria-controls="toolbar">⋯</button><?php endif; ?>
</header>
<?php if ($error): ?>
 <main class="reader-error" role="alert"><?=re($error)?></main>
<?php else: ?>
<div id="reader" data-format="<?=re($page['format'])?>" data-config="<?=re(json_encode($page,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE))?>">
 <div class="reader-toolbar" id="toolbar" hidden>
  <?php if ($page['format']==='txt'): ?><button id="contents" type="button"><?=tr_html('Contents')?></button><?php endif; ?>
  <button id="settings" type="button"><?=tr_html('Reading settings')?></button>
 </div>
 <div class="reader-message" id="reader-message">
   <p id="status" role="status"><?=tr_html('Opening book…')?></p>
   <button id="retry" type="button" hidden><?=tr_html('Retry')?></button>
 </div>
 <div id="viewport" tabindex="0" aria-label="<?=tr_html('Book text')?>">
  <article id="book" aria-busy="true"></article>
  <button class="continue" id="continue" type="button" hidden><?=tr_html('Next section')?></button>
 </div>
 <?php if ($page['format']==='txt'): ?>
 <footer class="reader-footer">
  <button id="previous" type="button" aria-label="<?=tr_html('Previous page')?>" disabled>‹</button>
  <span id="progress"></span>
  <button id="next" type="button" aria-label="<?=tr_html('Next page')?>" disabled>›</button>
 </footer>
 <?php else: ?>
 <button id="contents" class="contents-fab" type="button" aria-controls="toc" aria-expanded="false" aria-haspopup="dialog">
  <svg aria-hidden="true" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round"><path d="M9 6h10M9 12h10M9 18h10M5 6h.01M5 12h.01M5 18h.01"/></svg>
  <?=tr_html('Contents')?>
 </button>
 <?php endif; ?>
 <dialog id="toc"<?=$page['format']==='epub'?' class="contents-drawer"':''?> aria-labelledby="toc-title">
  <button type="button" class="dialog-close" aria-label="<?=tr_html('Close')?>">×</button>
  <h2 id="toc-title"><?=tr_html('Contents')?></h2>
  <?php if ($page['format']==='epub'): ?><p id="progress" class="contents-progress"></p><?php endif; ?>
  <div id="chapters"></div>
 </dialog>
 <dialog id="preferences" aria-labelledby="prefs-title">
  <button type="button" class="dialog-close" aria-label="<?=tr_html('Close')?>">×</button>
  <h2 id="prefs-title"><?=tr_html('Reading settings')?></h2>
  <label><?=tr_html('Font size')?><input id="size" type="range" min="15" max="34" value="20"></label>
  <label><?=tr_html('Line spacing')?><select id="spacing"><option value="1.5"><?=tr_html('Compact')?></option><option value="1.75" selected><?=tr_html('Comfortable')?></option><option value="2.05"><?=tr_html('Spacious')?></option></select></label>
  <label><?=tr_html('Theme')?><select id="theme"><option value="light"><?=tr_html('Light')?></option><option value="warm"><?=tr_html('Warm')?></option><option value="dark"><?=tr_html('Dark')?></option></select></label>
  <label><?=tr_html('Reading mode')?><select id="mode"><option value="scroll"><?=tr_html('Scroll')?></option><option value="page"><?=tr_html('By screen')?></option></select></label>
  <?php if ($page['format']==='txt'): ?><label><?=tr_html('Text encoding')?><select id="encoding"><option value=""><?=tr_html('Automatic')?></option><option value="utf-8">UTF-8</option><option value="gb18030">GB18030 / GBK</option></select></label><?php endif; ?>
 </dialog>
</div>
<noscript><p class="reader-error"><?=tr_html('Enable JavaScript to read in the browser.')?></p></noscript>
<?php endif; ?>
</body>
</html>
