// Node 20+, native PHP with the documented extensions, and OpenSSL CLI.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {spawn,execFileSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
const project=path.resolve(path.dirname(new URL(import.meta.url).pathname),'..');
const php=process.env.PHP_BINARY || 'php';
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'opds-test-'));
const web=path.join(temp,'web'),app=path.join(web,'library');fs.mkdirSync(app,{recursive:true});
fs.copyFileSync(path.join(project,'install.php'),path.join(app,'install.php'));
const cert=path.join(temp,'cert.pem'),tlsKey=path.join(temp,'key.pem');
execFileSync(process.env.OPENSSL_BIN || 'openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',tlsKey,'-out',cert],{stdio:'ignore'});
async function port(){const s=net.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
const back=await port(),front=await port(),base=`https://localhost:${front}/library/`;
// Only the test TLS terminator sets HTTPS. The application does not trust a
// client-provided forwarding header; production code is otherwise unchanged.
fs.writeFileSync(path.join(web,'router.php'),`<?php $_SERVER['HTTPS']='on'; return false;`);
fs.mkdirSync(path.join(temp,'sessions'));
const log=fs.openSync(path.join(temp,'php.log'),'w');
const server=spawn(php,['-d','display_errors=0','-d','session.upload_progress.enabled=0','-d','max_file_uploads=21','-d','upload_max_filesize=100M','-d','post_max_size=205M','-d',`openssl.cafile=${cert}`,'-d',`session.save_path=${temp}/sessions`,'-S',`127.0.0.1:${back}`,'-t',web,path.join(web,'router.php')],{env:{...process.env,PHP_CLI_SERVER_WORKERS:'4'},stdio:['ignore',log,log],detached:true});
let protect=false;
const proxy=https.createServer({key:fs.readFileSync(tlsKey),cert:fs.readFileSync(cert)},(req,res)=>{
 if(protect && /\/conf(?:\/|$)/.test(req.url)){res.writeHead(404);res.end();return;}
 const upstream=http.request({host:'127.0.0.1',port:back,path:req.url,method:req.method,headers:req.headers},out=>{res.writeHead(out.statusCode,out.headers);out.pipe(res);});
 upstream.on('error',()=>{res.writeHead(502);res.end();});req.pipe(upstream);
});await new Promise(r=>proxy.listen(front,'127.0.0.1',r));
let cookie='';const results=[];
const pass=name=>{console.log('PASS '+name);results.push(name);};
async function request(endpoint='install.php',options={}){
 return new Promise((resolve,reject)=>{
  const req=https.request(new URL(endpoint,base),{rejectUnauthorized:false,method:options.method||'GET',headers:{'accept-language':'zh-CN',...(cookie?{cookie}:{}),...options.headers,...(options.body?{'content-length':options.body.length}:{})}},res=>{
   const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>{if(res.headers['set-cookie'])cookie=res.headers['set-cookie'][0].split(';')[0];const text=Buffer.concat(chunks).toString();let json;try{json=JSON.parse(text);}catch{}resolve({status:res.statusCode,text,json,headers:res.headers});});
  });req.on('error',reject);if(options.body)req.write(options.body);req.end();
 });
}
const form=fields=>({method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:Buffer.from(new URLSearchParams(fields).toString())});
const csrf=r=>{const m=r.text.match(/name="csrf" value="([a-f0-9]+)"/);assert(m,r.text.slice(0,400));return m[1];};
try{
 let ready=false;for(let i=0;i<60;++i){try{const r=await request();if(r.status!==502){ready=true;break;}}catch{}await delay(100);}assert(ready);
 let r=await request('install.php',{headers:{'accept-language':'en-US,en;q=0.9,zh;q=0.5'}});assert.equal(r.status,200,r.text);assert(r.text.includes('Install your OPDS library'));assert(!r.text.includes('安装 OPDS 书库'));pass('installer selects English by browser language preference');
 r=await request();assert.equal(r.status,200,r.text);const installCsrf=csrf(r);assert(r.text.includes('安装 OPDS 书库'));pass('standalone installer opens in Chinese over HTTPS');
 const fields={csrf:installCsrf,base_url:base,title:'测试书库',password:'test-password-123',password_confirm:'test-password-123',categories:'books\n中文\n2026'};
 assert(!r.text.includes('name="install_key"'));pass('installer runs without an installation code or source edits');
 r=await request('install.php',form({...fields,csrf:'bad'}));assert.equal(r.status,400);pass('installation CSRF enforced');
 r=await request('install.php',form({...fields,categories:'../escape'}));assert.equal(r.status,400);pass('installation rejects category traversal');
 r=await request('install.php',form(fields));assert.equal(r.status,400);assert(r.text.includes('尚未写入凭据'),r.text.slice(0,500));assert(!fs.existsSync(path.join(app,'conf/pass.conf')));pass('unprotected conf blocks installation without storing credentials');
 protect=true;
 const readonly=path.join(web,'readonly');fs.mkdirSync(readonly);fs.chmodSync(readonly,0o555);
 const readonlyPath=fs.realpathSync(readonly);
 r=await request('install.php',{...form({...fields,action:'check',target_dir:readonlyPath,password:'',password_confirm:''}),headers:{'content-type':'application/x-www-form-urlencoded',accept:'application/json'}});
 assert.equal(r.status,400);assert(r.json.commands.some(c=>c.includes('chmod')&&c.includes(readonlyPath)));assert(r.json.commands.some(c=>c.includes('chown')));assert(!r.json.commands.join(' ').includes('777'));fs.chmodSync(readonly,0o755);pass('Check returns actionable permission commands for the actual selected directory');
 r=await request('install.php',{...form({...fields,action:'check',password:'',password_confirm:''}),headers:{'content-type':'application/x-www-form-urlencoded',accept:'application/json'}});
 assert.equal(r.status,200,r.text);assert.equal(r.json.success,true);assert.equal(r.json.installed,false);assert(!fs.existsSync(path.join(app,'index.php')));assert(!fs.existsSync(path.join(app,'conf/pass.conf')));assert(!fs.existsSync(path.join(app,'install.lock')));pass('Check validates the environment and URL without installing or requiring a password');
 r=await request('install.php',form({...fields,base_url:base+'wrong/'}));assert.equal(r.status,400);assert(!fs.existsSync(path.join(app,'conf/pass.conf')));pass('BASE_URL is checked against this installation using a random probe');
 r=await request('install.php',form({...fields,password:'',password_confirm:''}));assert.equal(r.status,200,r.text);assert(r.text.includes('安装完成'));pass('retry reuses the session password hash without re-entering a password');
 for(const file of ['i18n.php','bootstrap.php','security.php','index.php','up.php','LICENSE','NOTICE'])assert.equal(fs.readFileSync(path.join(app,file),'utf8'),fs.readFileSync(path.join(project,file),'utf8'));
 assert(fs.existsSync(path.join(app,'install.lock')));assert(fs.existsSync(path.join(app,'conf/installed.lock')));assert(fs.existsSync(path.join(app,'books-data/中文')));pass('one file generates complete app, configuration, cache and categories');
 const config=fs.readFileSync(path.join(app,'conf/pass.conf'),'utf8');assert(!config.includes('test-password-123'));const token=config.match(/api_token=([a-f0-9]{64})/)[1];assert.equal(fs.statSync(path.join(app,'conf/pass.conf')).mode&0o777,0o600);pass('password hashed and unique 256-bit token stored in private file');
 r=await request();assert.equal(r.status,403);pass('completed installation cannot run again');
 r=await request('conf/pass.conf');assert.equal(r.status,404);pass('configuration cannot be downloaded');
 // Fixture EPUBs are made by native ZipArchive, without Python dependencies.
 const fixtureCode=`$z=new ZipArchive();$z->open(getenv('FIXTURE'),ZipArchive::CREATE|ZipArchive::OVERWRITE);$z->addFromString('mimetype','application/epub+zip');$z->setCompressionName('mimetype',ZipArchive::CM_STORE);$z->addFromString('META-INF/container.xml','<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="book.opf" media-type="application/oebps-package+xml"/></rootfiles></container>');$z->addFromString('book.opf','<package xmlns="http://www.idpf.org/2007/opf"><metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Shared title</dc:title><dc:creator>测试作者</dc:creator></metadata></package>');$z->close();`;
 for(const category of ['books','中文'])execFileSync(php,['-r',fixtureCode],{env:{...process.env,FIXTURE:path.join(app,'books-data',category,'same.epub')}});
 fs.writeFileSync(path.join(app,'books-data/2026/note.txt'),'Some text');
 fs.mkdirSync(path.join(app,'books-data/books/nested'));fs.writeFileSync(path.join(app,'books-data/books/nested/hidden.txt'),'hidden');
 r=await request('index.php');assert.equal(r.status,200,r.text);assert(r.text.includes('2026'));assert(r.text.includes('中文'));assert(!r.text.includes('books-data'));pass('navigation lists multiple categories including numeric and Unicode names without physical directory');
 r=await request('index.php?feed=books');assert.equal((r.text.match(/<entry>/g)||[]).length,3,r.text);assert(!r.text.includes('books-data'));assert(!r.text.includes('hidden.txt'));pass('all-books feed includes EPUB/TXT, distinct same-named books, no deeper files');
 r=await request('index.php?feed=books&category='+encodeURIComponent('中文'));assert.equal((r.text.match(/<entry>/g)||[]).length,1);pass('category acquisition feed');
 r=await request('index.php?feed=books&q='+encodeURIComponent('测试作者'));assert.equal((r.text.match(/<entry>/g)||[]).length,2);pass('cross-category title/author search');
 r=await request('index.php?download=2026%2Fnote.txt');assert.equal(r.text,'Some text');assert.match(r.headers['content-disposition'],/attachment/);pass('controlled TXT download');
 r=await request('index.php?download=books%2Fsame.epub');assert.equal(r.status,200);assert.equal(r.headers['content-type'],'application/epub+zip');pass('controlled EPUB download');
 for(const value of ['../conf/pass.conf','books/nested/hidden.txt','/etc/passwd']){r=await request('index.php?download='+encodeURIComponent(value));assert(r.status>=400);}pass('download rejects traversal and depth beyond temporary limit');
 fs.symlinkSync(path.join(app,'conf/pass.conf'),path.join(app,'books-data/books/link.txt'));r=await request('index.php?download=books%2Flink.txt');assert.equal(r.status,404);pass('symlink download rejected');
 r=await request('up.php');assert.equal(r.status,200,r.text);const uploadCsrf=csrf(r);
 r=await request('up.php',form({action:'login',csrf:uploadCsrf,password:'test-password-123'}));assert.equal(r.status,303);
 r=await request('up.php');assert(r.text.includes(token));assert(r.text.includes('<dialog id="apiDialog"'));assert(r.text.includes(base+'up.php'));pass('generated uploader login, API dialog and deployment-specific command');
 r=await request('up.php',{headers:{'accept-language':'en-US'}});assert(r.text.includes('Upload books'));assert(!r.text.includes('上传电子书'));assert(r.text.includes('const tr ='));pass('uploader renders English UI with localized JavaScript messages');
 r=await request('index.php?search=1');assert(r.text.includes('OpenSearchDescription'));assert(r.text.includes('{searchTerms}'));pass('OPDS exposes OpenSearch discovery');
 const data=new FormData();data.append('directory','books');data.append('files[]',new File(['uploaded'],'api.txt'));
 const encoded=new Request(base+'up.php',{method:'POST',body:data});const body=Buffer.from(await encoded.arrayBuffer());
 r=await request('up.php',{method:'POST',body,headers:{'content-type':encoded.headers.get('content-type'),authorization:'Bearer '+token}});assert.equal(r.status,200,r.text);pass('generated application accepts Bearer upload without login dependency');
 r=await request('index.php?feed=books&q=api');assert(r.text.includes('api.txt'));pass('uploaded book is indexed automatically');
 r=await request('books-data/2026/note.txt');assert.equal(r.text,'Some text');pass('direct book access remains allowed by default');
 const cfg=path.join(app,'conf/config.php');const original=fs.readFileSync(cfg,'utf8');fs.writeFileSync(cfg,original.replace("'max_category_depth' => 1","'max_category_depth' => 2"));r=await request('index.php');assert.equal(r.status,503);fs.writeFileSync(cfg,original);pass('server temporarily enforces exactly one category level');
 const setup=path.join(web,'custom-setup');fs.mkdirSync(setup);fs.copyFileSync(path.join(project,'install.php'),path.join(setup,'install.php'));
 const custom=path.join(fs.realpathSync(web),'custom-library');const customUrl=base.replace('/library/','/custom-library/');
 r=await request('../custom-setup/install.php');const customFields={...fields,csrf:csrf(r),target_dir:custom,base_url:customUrl};
 r=await request('../custom-setup/install.php',{...form({...customFields,action:'check',password:'',password_confirm:''}),headers:{'content-type':'application/x-www-form-urlencoded',accept:'application/json'}});
 assert.equal(r.status,200,r.text);assert(!fs.existsSync(path.join(custom,'index.php')));assert(!fs.existsSync(path.join(setup,'install.lock')));pass('Check supports a different, newly created installation directory');
 fs.writeFileSync(path.join(custom,'index.php'),'existing application');
 r=await request('../custom-setup/install.php',{...form({...customFields,action:'check',password:'',password_confirm:''}),headers:{'content-type':'application/x-www-form-urlencoded',accept:'application/json'}});
 assert.equal(r.status,400);assert.equal(fs.readFileSync(path.join(custom,'index.php'),'utf8'),'existing application');fs.unlinkSync(path.join(custom,'index.php'));pass('Check detects existing application conflicts without overwriting files');
 r=await request('../custom-setup/install.php',form(customFields));assert.equal(r.status,200,r.text);assert(fs.existsSync(path.join(custom,'index.php')));assert(!fs.existsSync(path.join(setup,'index.php')));assert(fs.existsSync(path.join(setup,'install.lock')));pass('custom installation writes application files into the selected target and locks the original installer');
 r=await request('../custom-setup/install.php',form({...customFields,target_dir:custom+'-other'}));assert.equal(r.status,403);assert(!fs.existsSync(custom+'-other'));pass('install.lock blocks reuse even when a different target is submitted');
 if(process.env.PLAYWRIGHT_MODULE){
  const {chromium}=await import(process.env.PLAYWRIGHT_MODULE);
  const browser=await chromium.launch({...(process.env.CHROME_BIN?{executablePath:process.env.CHROME_BIN}:{}),headless:true});
  try{
   for(const locale of ['en-US','zh-CN']){
    const context=await browser.newContext({locale,ignoreHTTPSErrors:true,viewport:{width:390,height:844},permissions:['clipboard-read','clipboard-write']});
    const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto(base+'up.php');await page.locator('input[name=password]').fill('test-password-123');
    await page.locator('button[type=submit]').click();await page.locator('#apiSettingsButton').waitFor();
    assert.equal(await page.locator('html').getAttribute('lang'),locale==='zh-CN'?'zh-CN':'en');
    assert.equal(await page.locator('#apiDialog').isVisible(),false);
    assert.equal(await page.locator('h2').textContent(),locale==='zh-CN'?'上传电子书':'Upload books');
    await page.locator('#apiSettingsButton').click();await page.locator('#copyToken').click();assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),token);
    assert((await page.locator('#curlCommand').textContent()).includes(base+'up.php'));
    await page.keyboard.press('Escape');assert.equal(await page.locator('#apiDialog').isVisible(),false);
    await page.locator('#fileInput').setInputFiles([{name:'ui-'+locale+'.txt',mimeType:'text/plain',buffer:Buffer.from('from browser')}]);
    await page.locator('#uploadButton').click();await page.waitForFunction(()=>document.getElementById('uploadButton').disabled && !document.getElementById('fileInput').disabled);
    assert((await page.locator('#batchStatus').textContent()).includes(locale==='zh-CN'?'已保存 1':'saved 1'));
    assert.deepEqual(errors,[]);assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    if(process.env.SCREENSHOT_DIR){fs.mkdirSync(process.env.SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:path.join(process.env.SCREENSHOT_DIR,locale+'.png'),fullPage:true});}
    const wizardName='wizard-'+locale;const wizard=path.join(web,wizardName);fs.mkdirSync(wizard);fs.copyFileSync(path.join(project,'install.php'),path.join(wizard,'install.php'));
    const wizardTarget=path.join(fs.realpathSync(web),'wizard-target-'+locale);const wizardUrl=base.replace('/library/','/wizard-target-'+locale+'/');
    await page.goto(base.replace('/library/','/'+wizardName+'/install.php'));
    assert.equal(await page.locator('input[name=install_key]').count(),0);
    await page.locator('#targetDir').fill(wizardTarget);await page.locator('input[name=base_url]').fill(wizardUrl);
    await page.locator('#checkButton').click();await page.locator('#checkResults .success').waitFor();assert.equal(await page.locator('input[name=password]').inputValue(),'');
    assert(!fs.existsSync(path.join(wizardTarget,'index.php')));pass('real browser: '+locale+' immediate Check needs no password and keeps setup unlocked');
    await page.locator('input[name=password]').fill('retry-password-123');await page.locator('input[name=password_confirm]').fill('retry-password-123');
    const ro=path.join(fs.realpathSync(web),'wizard-readonly-'+locale);fs.mkdirSync(ro);fs.chmodSync(ro,0o555);
    await page.locator('#targetDir').fill(ro);await page.locator('#checkButton').click();await page.locator('#checkResults .error').waitFor();
    assert((await page.locator('#checkResults pre').textContent()).includes(ro));assert((await page.locator('#checkResults pre').textContent()).includes('chmod'));
    assert.equal(await page.locator('input[name=password]').inputValue(),'retry-password-123');fs.chmodSync(ro,0o755);
    if(process.env.SCREENSHOT_DIR)await page.screenshot({path:path.join(process.env.SCREENSHOT_DIR,'installer-'+locale+'.png'),fullPage:true});
    pass('real browser: '+locale+' permission checks show commands and retain entered passwords');
    await page.locator('#targetDir').fill(wizardTarget);await page.locator('input[name=base_url]').fill(wizardUrl+'missing/');
    await page.locator('#installButton').click();await page.locator('#checkResults .error').waitFor();assert.equal(await page.locator('input[name=password]').inputValue(),'retry-password-123');
    assert(!fs.existsSync(path.join(wizard,'install.lock')));assert((await page.locator('#passwordHint').textContent()).includes(locale==='zh-CN'?'暂存':'saved'));
    await page.locator('input[name=password]').fill('');await page.locator('input[name=password_confirm]').fill('');await page.locator('input[name=base_url]').fill(wizardUrl);
    await page.locator('#installButton').click();await page.waitForFunction(()=>document.getElementById('setupForm').hidden);
    assert(fs.existsSync(path.join(wizard,'install.lock')));assert.equal(await page.locator('#checkResults a').first().getAttribute('href'),wizardUrl+'index.php');
    assert.deepEqual(errors,[]);pass('real browser: '+locale+' failed install retries with retained password hash and locks only on success');
    await context.close();pass('real browser: '+locale+' adaptive UI, API dialog, clipboard, and live upload');
   }
  }finally{await browser.close();}
 }
 console.log(`${results.length} integration checks passed.`);
 if(process.env.TEST_REPORT)fs.writeFileSync(process.env.TEST_REPORT,JSON.stringify(results,null,2));
}catch(e){console.error('Test files retained at '+temp);console.error(fs.readFileSync(path.join(temp,'php.log'),'utf8').slice(-3000));throw e;}
finally{proxy.closeAllConnections();proxy.close();try{process.kill(-server.pid,'SIGTERM');}catch{} }
