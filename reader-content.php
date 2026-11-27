<?php
declare(strict_types=1);

function readerEscape(string $s): string { return htmlspecialchars($s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
const READER_MAX_IMAGE=12*1024*1024;
function readerImageAllowed(string $mime): bool { return in_array($mime,['image/jpeg','image/png','image/gif','image/webp','image/avif'],true); }
function readerMarkup(DOMNode $node,BookChapter $chapter,string $url,int $depth=0): string
{
    if ($depth>96) return '';
    if ($node instanceof DOMText) return readerEscape($node->data);
    if (!$node instanceof DOMElement) return '';
    $tag=strtolower($node->tagName);
    if (in_array($tag,['script','style','iframe','object','embed','form','input','textarea','select','button','template','noscript','math'],true)) return '';
    $ref=fn(string $attr)=>$node->hasAttribute($attr)?$node->getAttribute($attr):null;
    // Many EPUB covers use an SVG wrapper around a raster image. Replace the
    // wrapper with a plain image; never deliver the SVG document as-is.
    if (in_array($tag,['img','image'],true)) {
        $reference=$ref('src')??$ref('href')??$ref('xlink:href');
        $image=$reference===null?null:($chapter->resolveImage)($reference);
        if ($image===null||$image==='') return '';
        return '<img loading="lazy" decoding="async" src="'.readerEscape($url.'&asset='.rawurlencode($image)).'" alt="'.readerEscape($node->getAttribute('alt')).'">';
    }
    $content=''; foreach ($node->childNodes as $child) $content.=readerMarkup($child,$chapter,$url,$depth+1);
    $id=$node->getAttribute('id')?:($tag==='a'?$node->getAttribute('name'):'');
    $attrs=$id!==''?' data-book-anchor="'.readerEscape($id).'"':'';
    if (in_array($node->getAttribute('dir'),['rtl','ltr','auto'],true)) $attrs.=' dir="'.$node->getAttribute('dir').'"';
    if ($tag==='a') {
        $href=$ref('href');
        $target=$href===null?null:($chapter->resolveLink)($href);
        if ($target!==null && is_int($target[0]) && $target[0]>=0 && $target[0]<$chapter->count)
            return '<a'.$attrs.' href="#" data-part="'.$target[0].'" data-fragment="'.readerEscape($target[1]).'">'.$content.'</a>';
        return '<span'.$attrs.'>'.$content.'</span>';
    }
    if (in_array($tag,['br','hr'],true)) return '<'.$tag.'>';
    if (in_array($tag,['h1','h2','h3','h4','h5','h6','p','div','span','section','article','strong','b','em','i','u','s','small','sup','sub','blockquote','pre','code','ul','ol','li','dl','dt','dd','table','thead','tbody','tfoot','tr','th','td','figure','figcaption','ruby','rt','rp','q','abbr','bdi','bdo'],true))
        return '<'.$tag.$attrs.'>'.$content.'</'.$tag.'>';
    return $attrs!==''?'<span'.$attrs.'>'.$content.'</span>':$content;
}
