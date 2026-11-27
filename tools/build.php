<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$root = dirname(__DIR__);
$payload = [];
$files=['i18n.php','bootstrap.php','security.php','index.php','up.php','api.php','upload-common.php','accounts.php','libraries.php','privacy.php','agent-skill.php','library-controls.php','advanced-settings.php','site-link-settings.php','catalogue.php','preview.php','reader-content.php','reader.js','reader.css','admin.php','LICENSE','NOTICE','format/Contracts.php','format/Registry.php'];
foreach (glob($root.'/format/*/manifest.json') ?: [] as $manifest) {
    $dir=dirname($manifest); $id=basename($dir);
    if (!preg_match('/\A[a-z][a-z0-9_-]{0,31}\z/D',$id) || is_link($dir) || is_link($manifest))
        throw new RuntimeException('Invalid format package: '.$id);
    $files[]='format/'.$id.'/manifest.json';
    $files[]='format/'.$id.'/module.php';
    foreach (glob($dir.'/*.php') ?: [] as $helper) {
        $file=basename($helper);
        if ($file==='module.php') continue;
        if (!preg_match('/\A[a-z][a-z0-9_-]{0,31}\.php\z/iD',$file))
            throw new RuntimeException('Invalid format helper: '.$file);
        $files[]='format/'.$id.'/'.$file;
    }
}
sort($files,SORT_STRING);
foreach ($files as $name) {
    if (is_link($root.'/'.$name)) throw new RuntimeException('Application files must not be symbolic links: '.$name);
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
if (substr_count($template,'/*__OPDS_PAYLOAD_FILES__*/[]')!==1) throw new RuntimeException('Invalid payload manifest slot.');
$template=str_replace('/*__OPDS_PAYLOAD_FILES__*/[]',var_export($files,true),$template);
$i18n=file_get_contents($root.'/i18n.php');
$i18n=substr($i18n,strpos($i18n,'const UI_TRANSLATIONS'));
$template=str_replace('/*__OPDS_I18N__*/',$i18n,$template);
if (!preg_match('~^/\* BEGIN ACCOUNT DIRECTORY RULES \*/\R(.*?)^/\* END ACCOUNT DIRECTORY RULES \*/~ms',file_get_contents($root.'/accounts.php'),$rules))
    throw new RuntimeException('Missing account directory rules.');
$template=str_replace('/*__OPDS_ACCOUNT_RULES__*/',$rules[1],$template);
file_put_contents($root.'/install.php',str_replace('__OPDS_PAYLOAD__',$data,$template));
echo "Built install.php\n";
