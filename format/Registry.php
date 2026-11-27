<?php
declare(strict_types=1);
require_once __DIR__.'/Contracts.php';

final class BookFormatRegistry
{
    private array $byExtension=[];
    private array $handlers=[];
    private array $translations=[];
    private static ?self $instance=null;

    public static function get(): self { return self::$instance ??= new self(); }

    private function __construct()
    {
        foreach (glob(__DIR__.'/*/manifest.json') ?: [] as $manifest) {
            $dir=dirname($manifest);
            $id=basename($dir);
            if (!preg_match('/\A[a-z][a-z0-9_-]{0,31}\z/D',$id) || is_link($dir) || is_link($manifest))
                throw new RuntimeException('Invalid book format module path.');
            $descriptor=json_decode(file_get_contents($manifest,false,null,0,65536),true,16,JSON_THROW_ON_ERROR);
            if (!is_array($descriptor)
                || !is_array($descriptor['extensions']??null) || !array_is_list($descriptor['extensions']) || !$descriptor['extensions']
                || !is_string($descriptor['mime']??null)
                || !preg_match('~\A(?:application|text|image)/[a-z0-9][a-z0-9.+_-]*\z~D',$descriptor['mime'])
                || !is_string($descriptor['label']??null) || !preg_match('/\A[A-Z0-9]{1,8}\z/D',$descriptor['label'])
                || !is_int($descriptor['metadata_version']??null) || $descriptor['metadata_version']<1
                || !array_key_exists('reader',$descriptor) || !in_array($descriptor['reader'],[null,'bytes','chapters'],true)
                || !is_array($descriptor['requires']??null) || !array_is_list($descriptor['requires']))
                throw new RuntimeException('Invalid book format manifest: '.$id);
            $enabled=!in_array($id,defined('DISABLED_BOOK_FORMATS')?DISABLED_BOOK_FORMATS:[],true);
            foreach ($descriptor['requires'] as $extension) {
                if (!is_string($extension) || !preg_match('/\A[a-z][a-z0-9_]{0,31}\z/D',$extension))
                    throw new RuntimeException('Invalid book format dependency: '.$id);
                $enabled=$enabled && extension_loaded($extension);
            }
            $this->translations[$id]=is_array($descriptor['zh']??null)?$descriptor['zh']:[];
            foreach ($descriptor['extensions'] as $extension) {
                if (!is_string($extension) || !preg_match('/\A[a-z][a-z0-9]{0,11}\z/D',$extension) || isset($this->byExtension[$extension]))
                    throw new RuntimeException('Invalid or duplicate book extension: '.$id);
                $this->byExtension[$extension]=[
                    'id'=>$id, 'label'=>$descriptor['label'], 'mime'=>$descriptor['mime'],
                    'badge'=>($descriptor['badge']??null)==='text'?'text':'default',
                    'metadata_version'=>$descriptor['metadata_version'], 'reader'=>$descriptor['reader'], 'enabled'=>$enabled,
                ];
            }
        }
        ksort($this->byExtension,SORT_STRING);
    }

    public function find(string $filename): ?array
    {
        return $this->byExtension[strtolower(pathinfo($filename,PATHINFO_EXTENSION))]??null;
    }

    /** List of lowercase extensions without dots. Empty means no enabled uploads. */
    public function accepted(): array
    {
        return array_keys(array_filter($this->byExtension,static fn(array $format): bool=>$format['enabled']));
    }

    public function translate(string $id,string $key): string
    {
        $localized=$this->translations[$id][$key]??null;
        return uiLanguage()==='zh'&&is_string($localized)?$localized:tr($key);
    }

    public function handler(array $format): BookFormat
    {
        if (!$format['enabled']) reject(tr('This book format is currently unavailable.'),503);
        $id=$format['id'];
        if (!isset($this->handlers[$id])) {
            $path=__DIR__.'/'.$id.'/module.php';
            if (!is_file($path) || is_link($path)) throw new RuntimeException('Missing book format module: '.$id);
            $handler=require $path;
            if (!$handler instanceof BookFormat
                || ($format['reader']==='bytes' && !$handler instanceof ByteBookReader)
                || ($format['reader']==='chapters' && !$handler instanceof ChapterBookReader))
                throw new RuntimeException('Invalid book format handler: '.$id);
            $this->handlers[$id]=$handler;
        }
        return $this->handlers[$id];
    }
}

function bookFormat(string $filename): array
{
    return BookFormatRegistry::get()->find($filename) ?? reject(tr('Unsupported book format.'),422);
}

function validateBookUpload(string $path,string $filename): void
{
    BookFormatRegistry::get()->handler(bookFormat($filename))->validate($path);
}

function acceptedBookFormats(): array { return BookFormatRegistry::get()->accepted(); }

function formatMessage(string $id,string $key): string { return BookFormatRegistry::get()->translate($id,$key); }
