<?php
declare(strict_types=1);

interface BookFormat
{
    /** Validate the supplied contents; the path need not have an extension. */
    public function validate(string $path): void;
    /** Return any of title, author, language; omitted fields use core defaults. */
    public function metadata(string $path, MetadataBudget $budget): array;
}

interface ByteBookReader
{
    /** Return offset, next, total, encoding and base64 bytes for a bounded chunk. */
    public function chunk(string $path, int $offset, string $encoding, string $direction): array;
}

interface ChapterBookReader
{
    public function chapter(string $path, int $index): BookChapter;
    /** List of [chapter index, anchor, label]. */
    public function contents(string $path): array;
    public function image(string $path, string $key): BookImage;
}

final class BookChapter
{
    /** resolveImage: (string) => ?string; resolveLink: (string) => ?array [chapter, anchor]. */
    public function __construct(public DOMNode $body, public int $count,
        public Closure $resolveImage, public Closure $resolveLink) {}
}

final class BookImage
{
    public function __construct(public string $mime, public string $bytes) {}
}

/** Cooperative limit within a catalogue scan; not a hard timeout for native I/O. */
final class MetadataBudget
{
    public function __construct(private int $deadline) {}
    public function check(): void
    {
        if (hrtime(true)>=$this->deadline) throw new MetadataDeferred();
    }
}

final class MetadataDeferred extends RuntimeException {}
