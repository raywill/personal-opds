<?php
declare(strict_types=1);

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
function readerEscape(string $s): string { return htmlspecialchars($s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
const READER_IMAGES=['image/jpeg','image/png','image/gif','image/webp','image/avif'];
function readerMarkup(DOMNode $node,string $path,array $positions,array $byPath,string $url,int $depth=0): string
{
    if ($depth>96) return '';
    if ($node instanceof DOMText) return readerEscape($node->data);
    if (!$node instanceof DOMElement) return '';
    $tag=strtolower($node->tagName);
    if (in_array($tag,['script','style','iframe','object','embed','form','input','textarea','select','button','template','noscript','math'],true)) return '';
    $ref=fn(string $attr)=>$node->hasAttribute($attr)?readerReference($path,$node->getAttribute($attr)):null;
    // Many EPUB covers use an SVG wrapper around a raster image. Replace the
    // wrapper with a plain image; never deliver the SVG document as-is.
    if (in_array($tag,['img','image'],true)) {
        $image=$ref('src')??$ref('href')??$ref('xlink:href');
        if (!$image||!in_array($byPath[$image[0]]['type']??'',READER_IMAGES,true)) return '';
        return '<img loading="lazy" decoding="async" src="'.readerEscape($url.'&asset='.rawurlencode($image[0])).'" alt="'.readerEscape($node->getAttribute('alt')).'">';
    }
    $content=''; foreach ($node->childNodes as $child) $content.=readerMarkup($child,$path,$positions,$byPath,$url,$depth+1);
    $id=$node->getAttribute('id')?:($tag==='a'?$node->getAttribute('name'):'');
    $attrs=$id!==''?' data-book-anchor="'.readerEscape($id).'"':'';
    if (in_array($node->getAttribute('dir'),['rtl','ltr','auto'],true)) $attrs.=' dir="'.$node->getAttribute('dir').'"';
    if ($tag==='a') {
        $target=$ref('href');
        if ($target&&isset($positions[$target[0]]))
            return '<a'.$attrs.' href="#" data-part="'.$positions[$target[0]].'" data-fragment="'.readerEscape($target[1]).'">'.$content.'</a>';
        return '<span'.$attrs.'>'.$content.'</span>';
    }
    if (in_array($tag,['br','hr'],true)) return '<'.$tag.'>';
    if (in_array($tag,['h1','h2','h3','h4','h5','h6','p','div','span','section','article','strong','b','em','i','u','s','small','sup','sub','blockquote','pre','code','ul','ol','li','dl','dt','dd','table','thead','tbody','tfoot','tr','th','td','figure','figcaption','ruby','rt','rp','q','abbr','bdi','bdo'],true))
        return '<'.$tag.$attrs.'>'.$content.'</'.$tag.'>';
    return $attrs!==''?'<span'.$attrs.'>'.$content.'</span>':$content;
}
function readerTextChunk(string $path,int $requested,string $specified): array
{
    $file=fopen($path,'rb');
    if (!$file) reject('Book not found.',404);
    try {
        $size=fstat($file)['size'];
        $sample=fread($file,16388);
        if ($sample===false||str_contains($sample,"\0")) reject('Cannot read this TXT file.',422);
        $encoding=$specified;
        if ($encoding==='') {
            $encoding='gb18030';
            for ($trim=0;$trim<4&&$trim<=strlen($sample);$trim++) {
                if (preg_match('//u',$trim===0?$sample:substr($sample,0,-$trim))) { $encoding='utf-8'; break; }
            }
        }
        if (!in_array($encoding,['utf-8','gb18030'],true)) reject('Invalid input.',400);
        $start=min($requested,$size);
        if (fseek($file,$start)!==0) reject('Cannot read this TXT file.',422);
        $bytes=$start<$size?fread($file,24580):'';
        if ($bytes===false||str_contains($bytes,"\0")) reject('Cannot read this TXT file.',422);
        $end=strlen($bytes);
        if ($end>24576) {
            $newline=strrpos(substr($bytes,0,24576),"\n");
            if ($newline!==false&&$newline>=12288) $end=$newline+1;
            else {
                $end=0;
                while ($end<24576) {
                    $c=ord($bytes[$end]);
                    if ($encoding==='utf-8') $end+=$c<192?1:($c<224?2:($c<240?3:4));
                    else $end+=$c<129||$c>254?1:($bytes[$end+1]>='0'&&$bytes[$end+1]<='9'?4:2);
                }
            }
        }
        return ['offset'=>$start,'next'=>$start+$end,'total'=>$size,'encoding'=>$encoding,'bytes'=>base64_encode(substr($bytes,0,$end))];
    } finally { fclose($file); }
}
