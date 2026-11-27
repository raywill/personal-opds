<?php
declare(strict_types=1);
if (!interface_exists(BookFormat::class,false)) { http_response_code(404); exit; }
return new class implements BookFormat {
    public function validate(string $path): void
    {
        if (file_get_contents($path,false,null,0,7)!=="PTEST!\n")
            reject(formatMessage('probe','Invalid test book signature.'),422);
    }
    public function metadata(string $path,MetadataBudget $budget): array
    {
        $this->validate($path);
        return ['author'=>'Format fixture'];
    }
};
