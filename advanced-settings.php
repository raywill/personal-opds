<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/security.php';
require __DIR__.'/upload-common.php';
require __DIR__.'/accounts.php';

header('Cache-Control: private, no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
$nonce=base64_encode(random_bytes(18));
header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$nonce'; script-src 'nonce-$nonce'; connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
$method=$_SERVER['REQUEST_METHOD']??'GET';
try {
    requireSiteLinkAdmin();
    if (!in_array($method,['GET','HEAD','POST'],true)) { header('Allow: GET, HEAD, POST'); reject('Method not allowed.',405); }
} catch (Throwable $e) {
    http_response_code($e instanceof RequestError?$e->getCode():503);
    header('Content-Type: text/plain; charset=UTF-8');
    exit(publicError($e));
}
$_SESSION['csrf']??=bin2hex(random_bytes(32));
$csrf=$_SESSION['csrf'];
$current=activeSiteLinkMode();
$selected=$current;
$notice=($_SESSION['site_link_notice']??false)===true;
unset($_SESSION['site_link_notice']);
$error='';
if ($method==='POST') {
    try {
        requireSiteLinkCsrf($_POST['csrf']??null);
        $candidate=$_POST['link_mode']??null;
        if (!in_array($candidate,OPDS_LINK_MODES,true)) reject('Invalid input.');
        $selected=$candidate;
        if (!siteRewriteVerified($selected)) reject('Test the selected rewrite before saving.',422);
        withLock('site-links',static fn()=>stateWrite('site-links',['mode'=>$selected,'base'=>BASE_URL]));
        $_SESSION['site_link_notice']=true;
        session_write_close();
        header('Location: advanced-settings.php',true,303);
        exit;
    } catch (Throwable $e) {
        http_response_code($e instanceof RequestError?$e->getCode():503);
        $error=publicError($e);
    }
}
session_write_close();
function sh(string $s): string { return htmlspecialchars($s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
$modes=[
    'original'=>[tr('Original links'),tr('Default. No changes to your web server.')],
    'reader'=>[tr('Short reader links'),tr('Use the library owner’s username in the reader address. Share links stay unchanged.')],
    'reader-share'=>[tr('Short reader and share links'),tr('Shorten both entry addresses. Share codes, expiry and revocation stay unchanged.')],
];
$folder=parse_url(BASE_URL,PHP_URL_PATH);
$rules=nginxLinkRules();
$examples=[
    'original'=>[$folder.'index.php?library=p-alex',$folder.'index.php?s=12345678-AB12'],
    'reader'=>[$folder.'alex',$folder.'index.php?s=12345678-AB12'],
    'reader-share'=>[$folder.'alex',$folder.'s/12345678-AB12'],
];
$probes=array_map(static fn($route)=>'./'.$route[0].OPDS_REWRITE_TEST_QUERY,OPDS_REWRITE_PROBES);
?>
<!doctype html>
<html lang="<?=uiLanguageTag()?>"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title><?=tr_html('Advanced settings')?> · <?=sh(LIBRARY_TITLE)?></title>
<link rel="icon" type="image/svg+xml" href="opds-icon.svg">
<style nonce="<?=sh($nonce)?>">
*{box-sizing:border-box} :root{color-scheme:light;--ink:#172337;--muted:#526176;--blue:#254ab8;--selected:#eef3ff;--line:#dfe6ef;--background:#f6f8fb;--white:#fff}
body{margin:0;background:var(--background);color:var(--ink);font:15px/1.55 system-ui,-apple-system,sans-serif} button,input{font:inherit} a{color:var(--blue)} [hidden]{display:none!important}
.top{height:62px;background:var(--white);border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 clamp(16px,4vw,54px);gap:16px}.back{white-space:nowrap;text-decoration:none;font-weight:650}.site{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;border-inline-start:1px solid var(--line);padding-inline-start:16px}
.shell{max-width:1200px;margin:auto;padding:32px clamp(16px,4vw,42px) 44px}.intro{margin-bottom:24px}.eyebrow{font-size:.76rem;letter-spacing:.04em;font-weight:750;color:var(--blue);margin:0 0 3px}
h1,h2,h3,p{margin:0}h1{font-size:clamp(1.65rem,4vw,2.1rem);line-height:1.28;margin-bottom:6px}h2{font-size:1.25rem}h3{font-size:1rem}.subtle,small{color:var(--muted)}
.workspace{display:grid;grid-template-columns:220px minmax(0,1fr);gap:28px;align-items:start}.rail{position:sticky;top:16px}.rail label{display:block} .rail input{display:block;width:100%;background:white;border:1px solid #aebdce;border-radius:8px;padding:8px 11px;margin-bottom:17px}
[data-setting-group]+[data-setting-group]{margin-top:14px}.nav-title{display:block;font-size:.8rem;font-weight:740;color:var(--muted);padding:0 10px 5px}.rail a{display:block;padding:7px 10px;border-radius:8px;text-decoration:none;font-weight:700}.rail a[aria-current]{background:var(--selected)}
.setting{border:1px solid var(--line);background:var(--white);border-radius:15px;padding:clamp(14px,3vw,26px);min-width:0;scroll-margin:16px}.setting-head{display:flex;gap:10px;align-items:start;justify-content:space-between;flex-wrap:wrap;margin-bottom:16px}
.badge{background:var(--selected);color:#22429e;border-radius:20px;padding:4px 9px;font-size:.77rem;font-weight:700;overflow-wrap:anywhere}
fieldset{border:0;padding:0;margin:0;min-width:0}legend{font-weight:720;margin-bottom:8px}.choice{display:flex;align-items:flex-start;gap:10px;padding:10px 12px;border:1px solid var(--line);border-radius:8px;margin-bottom:7px;cursor:pointer}.choice:has(input:checked){border-color:#6885d3;background:var(--selected)}.choice input{accent-color:var(--blue);margin:5px 0 0;flex:none}.choice small,.choice strong{display:block;overflow-wrap:anywhere}
.examples{margin:13px 0;display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:10px}.example{min-width:0;background:var(--background);border-radius:8px;padding:8px 10px}.example small{display:block;font-weight:700}.example code{overflow-wrap:anywhere}
details{border-top:1px solid var(--line);padding:12px 0 0;margin:12px 0 0}summary{cursor:pointer;font-weight:740}details p{margin:7px 0}.snippet pre{font-size:.85rem;overflow:auto;direction:ltr;background:#152139;color:#edf3ff;border-radius:8px;padding:12px;margin:8px 0;white-space:pre}.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
button,.button{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:6px 12px;border-radius:8px;color:var(--ink);border:1px solid #b9c6d8;background:white;text-decoration:none;font-weight:670;cursor:pointer}.primary{background:var(--blue);color:white;border-color:var(--blue)}button:disabled{opacity:.55;cursor:not-allowed}:focus-visible{outline:2px solid #3158d0;outline-offset:3px}
.save{display:flex;gap:8px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-top:18px;background:var(--white);border:1px solid var(--line);border-radius:12px;padding:11px 14px;box-shadow:0 5px 18px #24395a13}.save p{color:var(--muted);font-size:.84rem;flex:1 1 220px}
.feedback{margin:0 0 12px;background:#e8f6ed;color:#235137;border-radius:8px;padding:9px 12px;overflow-wrap:anywhere}.error{background:#ffedf0;color:#922638}.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}
@media(max-width:690px){.shell{padding-top:20px}.workspace{grid-template-columns:minmax(0,1fr);gap:14px}.rail{position:static}.rail input{margin-bottom:8px}[data-setting-group]{display:flex;align-items:center;flex-wrap:wrap}.nav-title{padding-bottom:0}.examples{grid-template-columns:minmax(0,1fr)}.save button{margin-inline-start:auto}}
</style></head>
<body><header class="top"><a class="back" href="up.php">← <?=tr_html('Back to libraries')?></a><span class="site"><?=sh(LIBRARY_TITLE)?></span></header>
<main class="shell">
 <header class="intro"><p class="eyebrow"><?=tr_html('Site administration')?></p><h1><?=tr_html('Advanced settings')?></h1><p class="subtle"><?=tr_html('Deployment settings that apply to every library on this site.')?></p></header>
 <?php if ($notice): ?><p class="feedback" role="status"><?=tr_html('Link format saved.')?></p><?php endif; ?>
 <?php if ($error!==''): ?><p class="feedback error" role="alert"><?=sh($error)?></p><?php endif; ?>
 <div class="workspace">
  <aside class="rail">
   <label for="find" class="sr-only"><?=tr_html('Search settings')?></label>
   <input id="find" type="search" placeholder="<?=tr_html('Search settings')?>" autocomplete="off">
   <nav aria-label="<?=tr_html('Settings categories')?>">
    <div data-setting-group><span class="nav-title"><?=tr_html('Network and links')?></span><a href="#link-format" data-setting-nav="link-format" aria-current="location"><?=tr_html('Link format')?></a></div>
   </nav>
  </aside>
  <div>
   <p id="no-settings" class="feedback" role="status" hidden><?=tr_html('No matching settings.')?></p>
   <form method="post" action="advanced-settings.php#link-format" data-link-settings>
    <input type="hidden" name="csrf" value="<?=sh($csrf)?>">
    <section class="setting" id="link-format" data-setting data-keywords="nginx rewrite url OPDS <?=tr_html('Network and links')?>" aria-labelledby="link-format-title">
     <div class="setting-head"><div><h2 id="link-format-title"><?=tr_html('Link format')?></h2><p class="subtle"><?=tr_html('Choose the addresses users copy for readers and anonymous sharing.')?></p></div><span class="badge"><?=sh(sprintf(tr('Active: %s'),$modes[$current][0]))?></span></div>
     <fieldset>
      <legend><?=tr_html('Preferred link format')?></legend>
      <?php foreach ($modes as $value=>[$title,$description]): ?>
       <label class="choice"><input type="radio" name="link_mode" value="<?=sh($value)?>" <?=$selected===$value?'checked':''?>><span><strong><?=sh($title)?></strong><small><?=sh($description)?></small></span></label>
      <?php endforeach; ?>
     </fieldset>
     <div class="examples" aria-label="<?=tr_html('Example links')?>">
      <div class="example"><small><?=tr_html('Reader address')?></small><code id="reader-example"><?=sh($examples[$selected][0])?></code></div>
      <div class="example"><small><?=tr_html('Anonymous share address')?></small><code id="share-example"><?=sh($examples[$selected][1])?></code></div>
     </div>
     <details id="nginx" <?=$selected==='original'?'hidden':'open'?>>
      <summary><?=tr_html('Nginx setup')?></summary>
      <p class="subtle"><?=tr_html('Add these rules to this site’s server block, not inside a location. Keep the existing PHP handler.')?></p>
      <div class="snippet"><pre id="nginx-rules" tabindex="0"><?=sh($rules[$selected]??'')?></pre></div>
      <p class="subtle"><?=tr_html('Check with nginx -t, reload Nginx, then test the rewrite here.')?></p>
      <div class="actions">
       <button type="button" id="copy-rules"><?=tr_html('Copy rules')?></button>
       <button type="button" id="test-rewrite"><?=tr_html('Test rewrite')?></button>
       <span id="rewrite-status" role="status"></span>
      </div>
     </details>
     <p class="subtle"><?=tr_html('Original links keep working. Keep the Nginx rules if people still use previously shared short links.')?></p>
    </section>
    <footer class="save"><p><?=tr_html('Changes apply site-wide. A new site address or installation path needs a fresh test.')?></p><button class="primary" id="save-links" type="submit"><?=tr_html('Save link format')?></button></footer>
   </form>
  </div>
 </div>
</main>
<script nonce="<?=sh($nonce)?>">
const config=<?=json_encode(['rules'=>$rules,'examples'=>$examples,'probes'=>$probes,'current'=>$current,'labels'=>[
    'testing'=>tr('Testing rewrite…'),'passed'=>tr('Rewrite verified.'),
    'reader'=>tr('Reader rewrite did not pass. Check the Nginx rule and reload.'),
    'share'=>tr('Share rewrite did not pass. Check the Nginx rule and reload.'),
    'copied'=>tr('Copied.'),'manual'=>tr('Select and copy the rules manually.'),
]],JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_THROW_ON_ERROR)?>;
const form=document.querySelector('[data-link-settings]');
const status=document.querySelector('#rewrite-status');
const snippet=document.querySelector('#nginx-rules');
const testButton=document.querySelector('#test-rewrite');
const save=document.querySelector('#save-links');
const choice=()=>form.elements.link_mode.value;
const nginx=document.querySelector('#nginx');
let verified='', testing=false;
function sync(){
 const mode=choice();
 const previous=nginx.hidden;
 nginx.hidden=mode==='original';
 if(previous&&!nginx.hidden)nginx.open=true;
 snippet.textContent=config.rules[mode]||'';
 document.querySelector('#reader-example').textContent=config.examples[mode][0];
 document.querySelector('#share-example').textContent=config.examples[mode][1];
 save.disabled=testing||mode===config.current||(mode!=='original'&&mode!==verified);
}
form.addEventListener('change',()=>{status.textContent='';sync();});
sync();
testButton.addEventListener('click',async()=>{
 const mode=choice();
 verified='';testing=true;testButton.disabled=true;status.textContent=config.labels.testing;sync();
 try{
  for(const kind of mode==='reader'?['reader']:['reader','share']){
   const response=await fetch(config.probes[kind],{method:'POST',redirect:'error',cache:'no-store',credentials:'same-origin',signal:AbortSignal.timeout(8000),headers:{
    'X-OPDS-Rewrite-Test':kind,'X-OPDS-Rewrite-CSRF':form.elements.csrf.value
   }}).catch(()=>null);
   if(!response||response.status!==204||response.headers.get('X-OPDS-Rewrite-Verified')!==kind){status.textContent=config.labels[kind];return;}
  }
  verified=mode;status.textContent=choice()===mode?config.labels.passed:'';
 }finally{testing=false;testButton.disabled=false;sync();}
});
document.querySelector('#copy-rules').addEventListener('click',async()=>{
 try{await navigator.clipboard.writeText(snippet.textContent);status.textContent=config.labels.copied;}
 catch{const selected=getSelection(),range=document.createRange();range.selectNodeContents(snippet);selected.removeAllRanges();selected.addRange(range);status.textContent=config.labels.manual;}
});
document.querySelector('#find').addEventListener('input',event=>{
 const terms=event.target.value.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
 let matches=0;
 for(const section of document.querySelectorAll('[data-setting]')){
  const searchable=(section.textContent+' '+section.dataset.keywords).toLocaleLowerCase();
  const visible=terms.every(term=>searchable.includes(term));
  section.hidden=!visible;
  const item=document.querySelector('[data-setting-nav="'+section.id+'"]');
  if(item)item.hidden=!visible;
  if(visible)matches++;
 }
 for(const group of document.querySelectorAll('[data-setting-group]'))group.hidden=!group.querySelector('[data-setting-nav]:not([hidden])');
 document.querySelector('#no-settings').hidden=matches>0;
 form.querySelector('.save').hidden=!form.querySelector('[data-setting]:not([hidden])');
});
</script></body></html>
