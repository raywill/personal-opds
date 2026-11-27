<?php
declare(strict_types=1);
namespace OPDS\Format\Txt;
use BookFormat, ByteBookReader, MetadataBudget, RuntimeException;

if (!interface_exists(BookFormat::class,false)) { http_response_code(404); exit; }

function tr(string $message): string { return \formatMessage('txt',$message); }
function reject(string $message,int $status=400): never { \reject(tr($message),$status); }

function validateTxt(string $path,?MetadataBudget $budget=null): void
{
    $handle = fopen($path, 'rb');
    if ($handle === false) {
        throw new RuntimeException('Cannot read TXT file.');
    }
    try {
        while (!feof($handle)) {
            $budget?->check();
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

const READER_TEXT_SIZE = 24576;
function readerTextAt($file,int $offset,int $length): string
{
    if ($length===0) return '';
    if (fseek($file,$offset)!==0||($bytes=fread($file,$length))===false||str_contains($bytes,"\0"))
        reject('Cannot read this TXT file.',422);
    return $bytes;
}
function readerTextWidth(string $bytes,int $i,string $encoding): int
{
    $c=ord($bytes[$i]); $second=$bytes[$i+1]??'';
    if ($encoding==='utf-8') return $c<194||$c>244?1:($c<224?2:($c<240?3:4));
    return $c<129||$c>254?1:($second>='0'&&$second<='9'?4:2);
}
function readerTextAlign($file,int $target,int $size,string $encoding): int
{
    if ($target<=0||$target>=$size) return max(0,min($target,$size));
    if ($encoding==='utf-8') {
        $probe=readerTextAt($file,$target,min(4,$size-$target)); $steps=0;
        while (isset($probe[$steps])&&(ord($probe[$steps])&192)===128) $steps++;
        $target+=$steps;
    } else {
        // These ASCII characters cannot occur inside a GB18030 sequence.
        // Find a trusted boundary near the destination instead of loading the book.
        $base=max(0,$target-65536); $probe=readerTextAt($file,$base,$target-$base); $cursor=0;
        for ($i=strlen($probe)-1;$i>=0;$i--) {
            $c=ord($probe[$i]);
            if ($c<48||($c>=58&&$c<=63)||$c===127) { $cursor=$base+$i+1; break; }
        }
        while ($cursor<$target) {
            $bytes=readerTextAt($file,$cursor,min(65540,$size-$cursor));
            $span=min(65536,$target-$cursor,strlen($bytes));
            if (!$span) reject('Cannot read this TXT file.',422);
            for ($i=0;$i<$span;$i+=readerTextWidth($bytes,$i,$encoding)) {}
            $cursor+=$i;
        }
        $target=min($cursor,$size);
    }
    if ($target>0&&$target<$size&&readerTextAt($file,$target-1,2)==="\r\n") $target++;
    return $target;
}
function readerTextChunk(string $path,int $requested,string $specified,string $direction=''): array
{
    $file=fopen($path,'rb');
    if (!$file) reject('Book not found.',404);
    try {
        $size=fstat($file)['size'];
        $encoding=$specified;
        if ($encoding==='') {
            $sample=readerTextAt($file,0,min(16388,$size));
            $encoding='gb18030';
            for ($trim=0;$trim<4&&$trim<=strlen($sample);$trim++) {
                if (preg_match('//u',$trim===0?$sample:substr($sample,0,-$trim))) { $encoding='utf-8'; break; }
            }
        }
        if (!in_array($encoding,['utf-8','gb18030'],true)||!in_array($direction,['','seek','before'],true)) reject('Invalid input.',400);
        $target=min($requested,$size); $start=$target;
        if ($direction==='before') {
            // The end is a chunk boundary previously returned to the client.
            $start=readerTextAlign($file,max(0,$target-READER_TEXT_SIZE),$size,$encoding);
            $bytes=readerTextAt($file,$start,$target-$start); $end=strlen($bytes);
        } else {
            if ($direction==='seek')
                $start=readerTextAlign($file,$target===$size?max(0,$target-READER_TEXT_SIZE):$target,$size,$encoding);
            $bytes=readerTextAt($file,$start,min(READER_TEXT_SIZE+4,$size-$start)); $end=strlen($bytes);
            if ($end>READER_TEXT_SIZE) {
                $newline=strrpos(substr($bytes,0,READER_TEXT_SIZE),"\n");
                if ($newline!==false&&$newline>=intdiv(READER_TEXT_SIZE,2)&&!($direction==='seek'&&$target===$size)) $end=$newline+1;
                else {
                    for ($end=0;$end<READER_TEXT_SIZE;$end+=readerTextWidth($bytes,$end,$encoding)) {}
                    if (substr($bytes,$end-1,2)==="\r\n") $end++;
                }
            }
        }
        return ['offset'=>$start,'next'=>$start+$end,'total'=>$size,'encoding'=>$encoding,'bytes'=>base64_encode(substr($bytes,0,$end))];
    } finally { fclose($file); }
}

return new class implements BookFormat, ByteBookReader {
    public function validate(string $path): void { validateTxt($path); }
    public function metadata(string $path,MetadataBudget $budget): array { validateTxt($path,$budget); return []; }
    public function chunk(string $path,int $offset,string $encoding,string $direction): array
    {
        return readerTextChunk($path,$offset,$encoding,$direction);
    }
};
