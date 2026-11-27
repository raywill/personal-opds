<?php
declare(strict_types=1);
namespace OPDS\Format\Mobi;

use BookFormat, MetadataBudget, RuntimeException;

if (!interface_exists(BookFormat::class,false)) { http_response_code(404); exit; }

/*
 * Server-side metadata: read the Palm record table and book headers, not the text
 * compression streams. Layout reference: calibre/format_docs/pdb/mobi.txt.
 */
final class MobiFormat implements BookFormat
{
    private const MAX_HEADER=1024*1024;

    public function validate(string $path): void { $this->inspect($path,null); }
    public function metadata(string $path,MetadataBudget $budget): array { return $this->inspect($path,$budget); }

    private static function bad(): never
    {
        reject(formatMessage('mobi','The MOBI file has an invalid or truncated structure.'),422);
    }

    private static function read($file,int $offset,int $length): string
    {
        if ($length<1 || $length>self::MAX_HEADER || fseek($file,$offset)!==0) self::bad();
        $data=fread($file,$length);
        if ($data===false || strlen($data)!==$length) self::bad();
        return $data;
    }

    private static function word(string $data,int $offset): int { return unpack('n',$data,$offset)[1]; }
    private static function dword(string $data,int $offset): int { return unpack('N',$data,$offset)[1]; }

    private static function decode(string $value,int $codepage): string
    {
        if ($codepage===1252 && function_exists('iconv')) {
            $value=@iconv('Windows-1252','UTF-8//IGNORE',$value)?:'';
        }
        if (!preg_match('//u',$value)) return '';
        $value=trim(preg_replace('/[\p{Cc}\x{FFFE}\x{FFFF}]/u',' ',$value)??'');
        preg_match('/\A.{0,128}/us',$value,$m);
        return $m[0]??'';
    }

    private function inspect(string $path,?MetadataBudget $budget): array
    {
        $file=fopen($path,'rb');
        if (!$file) throw new RuntimeException('Cannot read MOBI file.');
        try {
            $budget?->check();
            $size=fstat($file)['size']??0;
            if ($size<96) self::bad();
            $pdb=self::read($file,0,78);
            $kind=substr($pdb,60,8);
            if (!in_array($kind,['BOOKMOBI','TEXtREAd'],true)) self::bad();
            if (self::dword($pdb,72)!==0) reject(formatMessage('mobi','This MOBI variant is not supported.'),422);
            $count=self::word($pdb,76);
            $first=78+8*$count;
            if ($count<2 || $first>=$size) self::bad();
            $records=self::read($file,78,8*$count);
            $offsets=[]; $previous=$first;
            for ($i=0;$i<$count;$i++) {
                if (($i%256)===0) $budget?->check();
                $offset=self::dword($records,8*$i);
                // Auxiliary records can have zero bytes.
                if ($offset<$previous || $offset>$size) self::bad();
                $offsets[]=$previous=$offset;
            }
            $offsets[]=$size;
            if ($kind==='TEXtREAd') {
                if ($offsets[1]-$offsets[0]<16) self::bad();
                $palmDoc=self::read($file,$offsets[0],16);
                if (self::word($palmDoc,12)!==0)
                    reject(formatMessage('mobi','DRM-protected MOBI files are not accepted.'),422);
                reject(formatMessage('mobi','This MOBI variant is not supported.'),422);
            }
            [$data,$hybrid]=$this->header($file,$offsets,0,$budget);
            if ($hybrid!==null) {
                if ($hybrid<2 || $hybrid>=$count || $offsets[$hybrid]-$offsets[$hybrid-1]!==8
                    || self::read($file,$offsets[$hybrid-1],8)!=='BOUNDARY') self::bad();
                [$secondary,$nested]=$this->header($file,$offsets,$hybrid,$budget);
                if ($nested!==null) self::bad();
                $data=$secondary+$data;
            }
            return $data;
        } finally { fclose($file); }
    }

    private function header($file,array $offsets,int $base,?MetadataBudget $budget): array
    {
        $budget?->check();
        $raw=self::read($file,$offsets[$base],$offsets[$base+1]-$offsets[$base]);
        $length=strlen($raw);
        if ($length<40 || substr($raw,16,4)!=='MOBI') self::bad();
        if (self::word($raw,12)!==0) reject(formatMessage('mobi','DRM-protected MOBI files are not accepted.'),422);
        $contentRecords=self::word($raw,8);
        if ($contentRecords<1 || self::dword($raw,4)===0 || !isset($offsets[$base+1+$contentRecords])
            || $offsets[$base+1+$contentRecords]<=$offsets[$base+1]) self::bad();
        $mobiLength=self::dword($raw,20);
        $end=16+$mobiLength;
        $version=self::dword($raw,36);
        $compression=self::word($raw,0);
        if ($mobiLength<0x4c || $end>$length) self::bad();
        if ($version<2 || $version>8 || !in_array($compression,[1,2,0x4448],true))
            reject(formatMessage('mobi','This MOBI variant is not supported.'),422);
        $codepage=self::dword($raw,28);
        $titleAt=self::dword($raw,0x54);
        $titleLength=self::dword($raw,0x58);
        $data=[]; $hybrid=null;
        if ($titleLength!==0) {
            if ($titleAt<$end || $titleAt+$titleLength>$length) self::bad();
            $data['title']=self::decode(substr($raw,$titleAt,min(4096,$titleLength)),$codepage);
        }
        if ($end>=0x84 && (self::dword($raw,0x80)&0x40)!==0) {
            if ($end+12>$length || substr($raw,$end,4)!=='EXTH') self::bad();
            $exthLength=self::dword($raw,$end+4);
            $count=self::dword($raw,$end+8);
            if ($exthLength<12 || $end+$exthLength>$length || $count>intdiv($exthLength-12,8)) self::bad();
            $limit=$end+$exthLength; $cursor=$end+12;
            for ($i=0;$i<$count;$i++) {
                if (($i%64)===0) $budget?->check();
                if ($cursor+8>$limit) self::bad();
                $tag=self::dword($raw,$cursor);
                $recordLength=self::dword($raw,$cursor+4);
                if ($recordLength<8 || $cursor+$recordLength>$limit) self::bad();
                $key=[100=>'author',503=>'title',524=>'language'][$tag]??null;
                if ($key!==null) {
                    $value=self::decode(substr($raw,$cursor+8,min(4096,$recordLength-8)),$codepage);
                    if ($value!=='' && ($key!=='language' || preg_match('/\A[a-z]{2,8}(?:-[a-z0-9]{1,8})*\z/iD',$value)))
                        $data[$key]=$value;
                } elseif ($tag===121 && $version<8 && $base===0) {
                    if ($recordLength!==12) self::bad();
                    $index=self::dword($raw,$cursor+8);
                    if ($index!==0xffffffff) $hybrid=$index;
                }
                $cursor+=$recordLength;
            }
        }
        return [$data,$hybrid];
    }
}

return new MobiFormat();
