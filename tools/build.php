<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$root = dirname(__DIR__);
$payload = [];
foreach (['i18n.php','bootstrap.php','security.php','index.php','up.php','api.php','upload-common.php','accounts.php','catalogue.php','admin.php','LICENSE','NOTICE'] as $name) {
    $content = file_get_contents($root . '/' . $name);
    if ($content === false) throw new RuntimeException('Missing source: ' . $name);
    $payload[$name] = ['sha256'=>hash('sha256',$content),'content'=>base64_encode($content)];
}
$compressed=gzencode(json_encode($payload,JSON_THROW_ON_ERROR),9);
// zlib writes the build host's OS into the gzip header. Normalize it to
// "unknown" so identical sources produce the same artifact on macOS/Linux.
$compressed[9]="\xff";
$data=base64_encode($compressed);
$template=file_get_contents(__DIR__.'/install.template.php');
if (substr_count($template,'__OPDS_PAYLOAD__')!==1) throw new RuntimeException('Invalid template.');
$i18n=file_get_contents($root.'/i18n.php');
$i18n=substr($i18n,strpos($i18n,'const UI_TRANSLATIONS'));
$template=str_replace('/*__OPDS_I18N__*/',$i18n,$template);
file_put_contents($root.'/install.php',str_replace('__OPDS_PAYLOAD__',$data,$template));
echo "Built install.php\n";
