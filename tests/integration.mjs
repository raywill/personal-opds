// Node 20+, native PHP with the documented extensions, and OpenSSL CLI.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {spawn,execFile,execFileSync} from 'node:child_process';
import {promisify} from 'node:util';
import {setTimeout as delay} from 'node:timers/promises';
const project=path.resolve(path.dirname(new URL(import.meta.url).pathname),'..');
const php=process.env.PHP_BINARY || 'php';
const runFile=promisify(execFile);
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

let denySetupProbe=false, holdUploadResponse=null;
const proxy=https.createServer({key:fs.readFileSync(tlsKey),cert:fs.readFileSync(cert)},(req,res)=>{
 if(denySetupProbe&&req.url.startsWith('/library/install-check-')){res.writeHead(403);res.end();return;}
 const upstream=http.request({host:'127.0.0.1',port:back,path:req.url,method:req.method,headers:req.headers},async out=>{
   const hold=holdUploadResponse;
   if(hold&&req.method==='POST'&&req.url.startsWith('/library/up.php?')){
     holdUploadResponse=null;hold.arrive(req.url);
     await hold.gate;
   }
   res.writeHead(out.statusCode,out.headers);out.pipe(res);
 });
 upstream.on('error',()=>{res.writeHead(502);res.end();});req.pipe(upstream);
});await new Promise(r=>proxy.listen(front,'127.0.0.1',r));
const cookies=new Map(),results=[];
const pass=name=>{console.log('PASS '+name);results.push(name);};
async function request(endpoint='install.php',options={}){
 return new Promise((resolve,reject)=>{
  const req=https.request(new URL(endpoint,base),{rejectUnauthorized:false,method:options.method||'GET',headers:{'accept-language':'en',cookie:[...cookies.values()].join('; '),...options.headers,...(options.body?{'content-length':options.body.length}:{})}},res=>{
   const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>{for(const cookie of res.headers['set-cookie']??[])cookies.set(cookie.split('=')[0],cookie.split(';')[0]);const text=Buffer.concat(chunks).toString();let json;try{json=JSON.parse(text);}catch{}resolve({status:res.statusCode,text,json,headers:res.headers});});
  });req.on('error',reject);if(options.body)req.write(options.body);req.end();
 });
}
const form=fields=>({method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:Buffer.from(new URLSearchParams(fields).toString())});
const csrf=r=>{const m=r.text.match(/name="csrf" value="([a-f0-9]+)"/);assert(m,r.text.slice(0,400));return m[1];};
const dataParent=path.join(temp,'storage-parent');fs.mkdirSync(dataParent,0o700);
const data=path.join(dataParent,'opds-data');
const settings={data_dir:data,title:'Test Site',username:'alice'};
const auth=(user,password)=>({authorization:'Basic '+Buffer.from(user+':'+password).toString('base64')});
const password='safe-test-password-123';
function cli(...args){return execFileSync(php,[path.join(app,'admin.php'),...args],{encoding:'utf8'}).trim();}
const post=(url,f,h={})=>{const o=form(f);Object.assign(o.headers,h);return request(url,o);};
async function ui(fields){let page=await request('up.php'); return post('up.php',{csrf:csrf(page),...fields});}
async function activate(u,link,secret=password){
 const page=await request(link);assert.equal(page.status,200);
 return post('up.php',{action:'activate',csrf:csrf(page),account:u,activate:new URL(link).searchParams.get('activate'),password:secret,confirm:secret});
}
function upload(token,dir,files,url='api.php',fields={}){
 const b='OPDSTEST'+crypto.randomBytes(12).toString('hex'); let text='';const chunks=[];
 const add=(name,val)=>{text+=`--${b}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${val}\r\n`;};
 for(const [name,val] of Object.entries(fields))add(name,val);
 if(dir!==undefined)add('directory',dir);
 chunks.push(Buffer.from(text));
 for(const [name,content] of files)chunks.push(Buffer.from(`--${b}\r\nContent-Disposition: form-data; name="files[]"; filename="${name}"\r\nContent-Type: application/octet-stream\r\n\r\n`),Buffer.from(content),Buffer.from('\r\n'));
 chunks.push(Buffer.from(`--${b}--\r\n`));
 const headers={'content-type':'multipart/form-data; boundary='+b};if(token)headers.authorization='Bearer '+token;
 return request(url,{method:'POST',headers,body:Buffer.concat(chunks)});
}
const url=(f)=>'index.php?'+new URLSearchParams(f);
const opds=(u,params={})=>request(url(params),{headers:auth(u,password)});
// Seed the old hash-only token schema without exposing an issuance path in the new UI.
const getLegacyToken=(user)=>{
 const token=crypto.randomBytes(32).toString('hex'), file=path.join(data,'conf','users.json');
 const state=JSON.parse(fs.readFileSync(file));state.records[user].token=crypto.createHash('sha256').update(token).digest('hex');
 fs.writeFileSync(file,JSON.stringify(state));return token;
};
try{
 // Exercise owner combinations even when this runner cannot chown files.
 const template=fs.readFileSync(path.join(project,'tools','install.template.php'),'utf8');
 const dictionary=fs.readFileSync(path.join(project,'i18n.php'),'utf8');
 const translationKeys=[...dictionary.matchAll(/^  '((?:[^'\\]|\\.)*)' =>/gm)].map(m=>m[1]);
 const uniqueKeys=new Set(translationKeys);
 assert.equal(uniqueKeys.size,translationKeys.length,'Duplicate translation entries');
 for(const source of ['tools/install.template.php','bootstrap.php','up.php','accounts.php','catalogue.php','index.php','api.php','upload-common.php','security.php','libraries.php','library-controls.php','preview.php','reader-content.php']){
   for(const [,label] of fs.readFileSync(path.join(project,source),'utf8').matchAll(/\b(?:tr|tr_html|reject|RequestError)\('((?:[^'\\]|\\.)*)'/g))
     assert(uniqueKeys.has(label),`Missing Chinese translation in ${source}: ${label}`);
 }
 const literals=source=>[...source.matchAll(/'((?:[^'\\]|\\.)*)'/g)].map(m=>m[1]);
 const librarySource=fs.readFileSync(path.join(project,'libraries.php'),'utf8');
 const flowSource=fs.readFileSync(path.join(project,'up.php'),'utf8');
 const dynamicLabels=[
   ...literals(template.match(/\$steps=\[(.*?)\];/s)[1]),
   ...literals(template.match(/\$headings=\[(.*?)\];/s)[1]),
   ...literals(template.match(/\$descriptions=\[(.*?)\];/s)[1]),
   ...literals(librarySource.match(/const LIBRARY_ROLE_LABELS = \[(.*?)\];/s)[1]).filter(t=>/^[A-Z]/.test(t)),
   ...literals(librarySource.match(/const LIBRARY_ROLE_GROUPS = \[(.*?)\];/s)[1]).filter(t=>/^[A-Z]/.test(t)),
   ...literals(librarySource.match(/const LIBRARY_ROLE_DESCRIPTIONS = \[(.*?)\];/s)[1]).filter(t=>/^[A-Z]/.test(t)),
   ...literals(flowSource.match(/tr_html\(match\(\$state\)\{([^}]+)\}/)[1]).filter(t=>/^[A-Z]/.test(t)),
   'Shared','Expiring soon','Expired','Revoked','Not shared','Unavailable',
   'Library invitation sent.','Invitation cancelled.','Library membership saved.','Invitation accepted.','Invitation declined.',
 ];
 for(const label of dynamicLabels)assert(uniqueKeys.has(label),'Missing dynamic Chinese label: '+label);
 const placeholder=/%(?:\d+\$)?[sd]/g;
 for(const [,source,target] of dictionary.matchAll(/^  '((?:[^'\\]|\\.)*)' => '((?:[^'\\]|\\.)*)',/gm)){
   assert.deepEqual(source.match(placeholder)??[],target.match(placeholder)??[],'Translation placeholders: '+source);
 }
 pass('Chinese dictionary covers literal and dynamic labels without duplicate keys or mismatched placeholders');
 const extract=(name,next)=>template.slice(template.indexOf('function '+name+'('),template.indexOf('function '+next+'('));
 const example='/home/wwwroot/www.reactshare.cn/personal-opds';
 const permissionNonOwner=JSON.parse(execFileSync(php,['-r',
   extract('shellArg','phpProcessIds')+extract('permissionCommands','directoryAdvice')+
   'echo json_encode([permissionCommands($argv[1],33,0,false,true),permissionCommands($argv[1],33,33,false,true),permissionCommands($argv[1],33,0,true,false),permissionCommands($argv[1],33,0,false,false),permissionCommands($argv[1],33,33,true,false),permissionCommands($argv[1],33,false,false,true)]);',example
 ],{encoding:'utf8'}));
 assert.deepEqual(permissionNonOwner,[
   ["sudo chown -- '33' '"+example+"'","sudo chmod u+rwx -- '"+example+"'"],
   ["sudo chmod u+rwx -- '"+example+"'"],
   [],
   [],
   ["sudo chmod u+x -- '"+example+"'"],
   []
 ]);
 assert(!fs.readFileSync(path.join(project,'install.php'),'utf8').includes('setfacl'));
 pass('installer permission commands: dedicated directory without ACL, unchanged ownership for shared directories');
 let r=await request(); for(let n=0;n<50&&r.status===502;n++){await delay(25);r=await request();} const setup=csrf(r);
 const setupPost=(step,action,fields={})=>post('install.php',{csrf:setup,step,action,...fields},{accept:'application/json'});
 r=await setupPost(4,'install',settings);assert.equal(r.status,400);assert.equal(r.json.step,1);
 const readOnly=path.join(temp,'restricted');fs.mkdirSync(readOnly,0o500);
 fs.chmodSync(app,0o500);
 r=await setupPost(1,'next');assert.equal(r.status,400);assert.equal(r.json.step,1);
 assert(r.json.commands[0].includes('chmod u+rwx'));assert(r.json.message.includes(app));
 fs.chmodSync(app,0o700);
 r=await setupPost(1,'next');assert.equal(r.status,200,r.text);assert.equal(r.json.step,2);
 r=await setupPost(2,'next',{...settings,data_dir:path.join(web,'data')});assert.equal(r.status,400);assert.equal(r.json.step,2);
 const locationStep=await request();assert(!locationStep.text.includes(base));
 const zhSetup=await request('install.php',{headers:{'accept-language':'zh-CN'}});
 assert.equal(zhSetup.headers['content-language'],'zh-CN');
 assert.match(zhSetup.headers.vary,/Accept-Language/i);
 assert(zhSetup.text.includes('lang="zh-CN"'));assert(zhSetup.text.includes('设置书库与存储'));assert(zhSetup.text.includes('私有数据根目录'));
 const badStorage=await post('install.php',{csrf:setup,step:2,action:'next',...settings,data_dir:path.join(web,'data')},{'accept':'application/json','accept-language':'zh-CN'});
 assert.equal(badStorage.status,400);assert(badStorage.json.message.includes('网站根目录'));

 assert(!locationStep.text.includes('name="base_url"'));assert(locationStep.text.includes('Site name'));
 r=await setupPost(2,'next',{...settings,title:''});assert.equal(r.status,400);assert.equal(r.json.step,2);
 assert(r.json.message.includes('Invalid site name'));
 const protectedData=path.join(readOnly,"opds-data's");
 r=await setupPost(2,'next',{...settings,data_dir:protectedData});
 assert.equal(r.status,400);assert.equal(r.json.step,2);
 assert(r.json.message.includes(protectedData));assert(r.json.message.includes(readOnly));
 const quote=p=>"'"+p.replaceAll("'", "'\"'\"'")+"'";
 assert.deepEqual(r.json.commands,[`sudo mkdir -m 0700 -- ${quote(protectedData)} && sudo chown -- '${process.getuid()}' ${quote(protectedData)}`]);
 assert(!fs.existsSync(protectedData));
 r=await setupPost(2,'next',{...settings,data_dir:path.join(readOnly,'missing','opds-data')});
 assert.equal(r.status,400);assert.match(r.json.message,/does not exist or PHP cannot see it/);assert.deepEqual(r.json.commands,[]);
 fs.chmodSync(readOnly,0o600);
 r=await setupPost(2,'next',{...settings,data_dir:protectedData});
 assert.equal(r.json.step,2);assert.deepEqual(r.json.commands,[`sudo chmod u+x -- ${quote(readOnly)}`]);
 assert.match(r.json.message,/traverse \(x\)/);
 fs.chmodSync(readOnly,0o700);fs.mkdirSync(protectedData,0o700);fs.chmodSync(readOnly,0o100);
 r=await setupPost(2,'next',{...settings,data_dir:protectedData});
 assert.equal(r.status,200,r.text);assert.equal(r.json.step,3);
 assert.equal(fs.statSync(readOnly).mode&0o777,0o100);
 r=await setupPost(3,'back');assert.equal(r.json.step,2);
 fs.chmodSync(protectedData,0o500);
 r=await setupPost(2,'next',{...settings,data_dir:protectedData});
 assert.equal(r.status,400);assert.deepEqual(r.json.commands,[`sudo chmod u+rwx -- ${quote(protectedData)}`]);
 fs.chmodSync(readOnly,0o700);
 pass('private leaf creation advice contains no ACL or parent writes; precreated root works with traverse-only ancestors');
 denySetupProbe=true;
 r=await setupPost(2,'next',settings);assert.equal(r.status,400);assert.equal(r.json.step,2);assert(r.json.message.includes('HTTP 403'));
 denySetupProbe=false;
 assert(!fs.readdirSync(app).some(p=>p.startsWith('install-check-')));
 r=await setupPost(2,'next',{...settings,base_url:'https://untrusted.example/anything/'});assert.equal(r.status,200,r.text);assert.equal(r.json.step,3);
 assert(!fs.existsSync(data));assert(!fs.readdirSync(app).some(p=>p.startsWith('install-check-')));
 r=await setupPost(3,'next',{username:'root'});assert.equal(r.status,400);assert.equal(r.json.step,3);
 r=await setupPost(3,'next',{username:'Alice'});assert.equal(r.status,400);assert.equal(r.json.step,3);
 r=await setupPost(3,'next',{username:'7'});assert.equal(r.status,200);assert.equal(r.json.step,4);
 assert((await request()).text.includes(path.join(data,'books','7')));
 r=await setupPost(4,'back',{username:'7'});assert.equal(r.json.step,3);
 r=await setupPost(3,'next',{username:'alice'});assert.equal(r.status,200,r.text);assert.equal(r.json.step,4);
 const reviewStep=await request();
 assert(reviewStep.text.includes('<dt>OPDS address:</dt><dd><code>'+base+'index.php</code>'));
 assert(reviewStep.text.includes('<dt>Web dashboard:</dt><dd><code>'+base+'up.php</code>'));
 assert(!reviewStep.text.includes('<code>'+base+'</code>'));
 const reviewZh=await request('install.php',{headers:{'accept-language':'en; q=0.2, zh-CN; q=0.9'}});
 assert.equal(reviewZh.headers['content-language'],'zh-CN');
 assert(reviewZh.text.includes('<dt>OPDS 地址：</dt>')&&reviewZh.text.includes('<dt>网页后台：</dt>'));
 r=await setupPost(4,'back');assert.equal(r.json.step,3);
 r=await setupPost(3,'back',{username:'alice'});assert.equal(r.json.step,2);
 const occupied=path.join(temp,'occupied');
 const occupiedUser=path.join(occupied,'books','Alice');fs.mkdirSync(occupiedUser,{recursive:true});
 fs.writeFileSync(path.join(occupiedUser,'keep.txt'),'unchanged');
 r=await setupPost(2,'next',{...settings,data_dir:occupied});
 assert.equal(r.status,200,r.text);assert.equal(r.json.step,3);
 r=await setupPost(3,'next',{username:'alice'});assert.equal(r.status,400);assert.equal(r.json.step,3);
 assert(r.json.message.includes('already exists'));assert.equal(fs.readFileSync(path.join(occupiedUser,'keep.txt'),'utf8'),'unchanged');
 r=await setupPost(3,'back',{username:'alice'});assert.equal(r.json.step,2);
 r=await setupPost(2,'next',settings);assert.equal(r.json.step,3);
 r=await setupPost(3,'next',{username:'alice'});assert.equal(r.json.step,4);
 const latePath=path.join(data,'books','alice');
 fs.mkdirSync(latePath,{recursive:true});
 r=await setupPost(4,'install');assert.equal(r.status,400);assert.equal(r.json.step,3);
 assert(fs.existsSync(latePath));assert(!fs.existsSync(path.join(app,'paths.php')));
 fs.rmdirSync(latePath);
 fs.chmodSync(dataParent,0o100);
 r=await setupPost(3,'next',{username:'alice'});assert.equal(r.json.step,4);
 r=await setupPost(4,'install',{username:'tampered'});assert.equal(r.status,200,r.text);assert(r.json.installed);const aliceLink=r.json.activation_url;
 assert.equal(fs.statSync(dataParent).mode&0o777,0o100);
 fs.chmodSync(dataParent,0o700);
 assert.equal(r.json.catalog_url,base+'index.php');assert.equal(r.json.upload_url,base+'up.php');
 assert.equal(new URL(aliceLink).pathname,'/library/up.php');
 assert(fs.readFileSync(path.join(data,'conf','config.php'),'utf8').includes('Test Site'));
 assert(fs.existsSync(path.join(data,'books','alice')));assert(!fs.existsSync(path.join(data,'books','tampered')));
 assert.equal((await request()).status,403);
 assert.equal(await fs.promises.stat(path.join(data,'conf','users.json')).then(s=>s.mode&0o777),0o600);
 assert.equal((await request('admin.php')).status,404);
 pass('four installer gates, actionable permissions, changed-root revalidation, case collisions and final no-clobber check');

 assert.equal((await opds('alice')).status,401);
 assert.equal((await ui({action:'login',username:'alice',password})).status,401);
 const replacementFirstLink=cli('invite','alice');
 assert.notEqual(replacementFirstLink,aliceLink);
 assert.equal((await activate('alice',aliceLink)).status,403);
 const activationLock=path.join(data,'conf','.libraries.lock');
 const accountFile=path.join(data,'conf','users.json');
 const pendingBefore=fs.readFileSync(accountFile,'utf8');
 fs.chmodSync(activationLock,0o644);
 const blockedActivation=await activate('alice',replacementFirstLink);
 assert.equal(blockedActivation.status,503);
 assert(blockedActivation.text.includes('Account activation could not save the password.'));
 assert(!blockedActivation.text.includes('.libraries.lock'));
 assert.equal(fs.readFileSync(accountFile,'utf8'),pendingBefore);
 const doctor=await runFile(php,[path.join(app,'admin.php'),'doctor','alice']).catch(error=>error);
 assert.equal(doctor.code,2);assert.match(doctor.stdout,/ERROR: .*\.libraries\.lock/);
 assert(!doctor.stdout.includes(JSON.parse(pendingBefore).records.alice.activation.digest));
 fs.chmodSync(activationLock,0o600);
 assert.match(cli('doctor','alice'),/OK: users.json format/);
 assert.equal(fs.readFileSync(accountFile,'utf8'),pendingBefore);
 pass('account diagnostics names the blocked write lock without exposing secrets or consuming the activation link');
 assert.equal((await activate('alice',replacementFirstLink)).status,303);
 assert.equal((await activate('alice',replacementFirstLink)).status,403);
 // Simulate an existing deployment with an unversioned bcrypt hash.
 const recordsPath=path.join(data,'conf','users.json');
 const oldState=JSON.parse(fs.readFileSync(recordsPath,'utf8'));
 oldState.records.alice.password=execFileSync(php,['-r','echo password_hash($argv[1], PASSWORD_BCRYPT);',password],{encoding:'utf8'});
 fs.writeFileSync(recordsPath,JSON.stringify(oldState));
 assert.equal((await opds('alice')).status,200);
 assert.throws(()=>cli('invite','root'),/reserved/);
 fs.mkdirSync(path.join(data,'books','Orphan'));
 assert.throws(()=>cli('invite','orphan'),/refusing to claim/);
 assert(fs.existsSync(path.join(data,'books','Orphan')));
 const bobOld=cli('invite','bob');const bobLink=cli('invite','bob');
 assert.equal((await activate('bob',bobOld)).status,403);
 assert.equal((await activate('bob',bobLink)).status,303);
 assert.equal((await ui({action:'login',username:'alice',password})).status,303);
 const aliceToken=getLegacyToken('alice');assert(aliceToken);
 assert(!fs.readFileSync(path.join(data,'conf','users.json'),'utf8').includes(aliceToken));
 assert.equal((await request('index.php')).status,401,'browser cookie must not grant Basic-feed access');
 assert((await request('up.php',{headers:{'accept-language':'zh-CN'}})).text.includes('alice 的书库'));
 const skill=await request('up.php?skill=1');
 assert.equal(skill.status,410);
 assert(skill.text.includes('Standalone Skill download was removed.')&&!skill.text.includes(aliceToken));
 assert(!skill.headers['content-disposition']);
 pass('first and later activation recovery, one-time links, separate login channels and hashed token');

 r=await upload(aliceToken,undefined,[['private.txt','Alice root content']]);assert.equal(r.status,200,r.text);
 const uploads=await Promise.all([
   upload(aliceToken,'Share shelf',[['same.txt','Alice shared content']]),
   upload(aliceToken,'Share shelf',[['other.txt','Another shared book']]),
 ]);
 for(const u of uploads)assert.equal(u.status,200,u.text);
 r=await upload(aliceToken,'Share shelf',[['same.txt','Alice shared content']]);assert.equal(r.status,409,r.text);assert.equal(r.json.results[0].status,409);assert.equal((await opds('alice',{download:'Share shelf/same.txt'})).text,'Alice shared content');
 r=await upload(aliceToken,'Share shelf',[['same.txt','changed'],['new.txt','saved']]);assert.equal(r.status,422,r.text);assert.equal(r.json.results[0].status,409);assert(r.json.results[1].success);
 r=await upload(aliceToken,'nested/folder',[['no.txt','no']]);assert.equal(r.status,400);
 r=await upload(aliceToken,undefined,[['x.txt','x']],'api.php',{username:'bob'});assert.equal(r.status,400);
 r=await ui({action:'folder',folder:'中文 阅读',dir:''});assert.equal(r.status,303,r.text);
 const page=await request('up.php?dir='+encodeURIComponent('中文 阅读'));
 const browserLocation='up.php?dir='+encodeURIComponent('中文 阅读');
 r=await upload(null,'Share shelf',[['wrong-folder.txt','must not be saved']],browserLocation,{action:'upload',csrf:csrf(page)});
 assert.equal(r.status,400);
 assert(!fs.existsSync(path.join(data,'books','alice','Share shelf','wrong-folder.txt')));
 r=await upload(null,undefined,[['browser.txt','Browser upload']],browserLocation,{action:'upload',csrf:csrf(page)});assert.equal(r.status,200,r.text);
 r=await request('up.php?dir='+encodeURIComponent('中文 阅读')+'&download=browser.txt');assert.equal(r.text,'Browser upload');
 pass('root, concurrent auto-creation, duplicate-name conflict even for identical bytes, partial success and browser download');
 const epub=path.join(temp,'book.epub');
 execFileSync(php,['-r',`$z=new ZipArchive();$z->open($argv[1],ZipArchive::CREATE);
 $z->addFromString("mimetype","application/epub+zip");$z->setCompressionName("mimetype",ZipArchive::CM_STORE);
 $z->addFromString("META-INF/container.xml",'<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="book.opf" media-type="application/oebps-package+xml"/></rootfiles></container>');
 $z->addFromString("book.opf",'<package xmlns="http://www.idpf.org/2007/opf"><metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Golden EPUB</dc:title><dc:creator>Test Author</dc:creator></metadata></package>');
 $z->close();`,epub]);
 const epubBytes=fs.readFileSync(epub);
 r=await upload(aliceToken,undefined,[['sample.epub',epubBytes]]);assert.equal(r.status,200,r.text);
 assert.equal((await upload(aliceToken,undefined,[['invalid.epub','not a zip']])).status,422);
 assert((await opds('alice',{feed:'books',q:'Golden EPUB'})).text.includes('Test Author'));
 const book=await opds('alice',{download:'sample.epub'});
 assert.equal(book.status,200); assert.equal(book.headers['content-type'],'application/epub+zip');
 pass('valid EPUB upload, metadata search and download; malformed EPUB rejected');
 const feedZh=await request(url({feed:'books',q:'private'}),{headers:{...auth('alice',password),'accept-language':'zh-CN'}});
 const feedEn=await request(url({feed:'books',q:'private'}),{headers:{...auth('alice',password),'accept-language':'en'}});
 assert.equal(feedZh.headers['content-language'],'zh-CN');
 assert.match(feedZh.headers.vary,/Accept-Language/i);
 assert.match(feedZh.headers.vary,/Authorization/i);
 assert(feedZh.text.includes('<name>未知作者</name>')&&feedEn.text.includes('<name>Unknown author</name>'));
 const zhApiError=await request('api.php?action=verify',{headers:{'accept-language':'zh-CN'}});
 assert.equal(zhApiError.status,401);
 assert.equal(zhApiError.headers['content-language'],'zh-CN');
 assert.match(zhApiError.json.message,/令牌|token/);
 pass('OPDS and API agree with the negotiated language even on a warm metadata cache');


 r=await ui({action:'share',dir:'Share shelf'});assert.equal(r.status,303,r.text);
 r=await request('up.php?dir=Share+shelf&preview=1');assert(r.text.includes('Books in this subscription:'));
 const key=r.text.match(/\?s=([1-9]{8}-[A-Z0-9]{4})/)?.[1]; assert(key,r.text); assert(/[A-Z]/.test(key.slice(9)) && /[0-9]/.test(key.slice(9)));
 assert.equal((await request(url({s:key.toLowerCase(),download:'Share shelf/same.txt'}))).text,'Alice shared content');
 assert.equal((await request(url({s:key,download:'private.txt'}))).status,404);
 r=await request(url({s:key}));assert.equal(r.status,200);assert(r.text.includes('same'));assert(!r.text.includes('private.txt'));
 assert.equal((await request(url({s:key,category:'中文 阅读'}))).status,404);
 assert.equal((await request(url({s:key,search:'1'}))).status,200);
 assert.equal((await opds('bob',{download:'Share shelf/same.txt'})).status,400);
 assert.equal((await opds('alice',{download:'private.txt'})).text,'Alice root content');
 pass('subscription case-folding, live scoped feed/search and account isolation');
 const original='Share shelf/new.txt', renamed='Share shelf/改名后的书.txt';
 assert.equal((await ui({action:'rename',dir:'Share shelf',file:'new.txt',new_name:'same'})).status,409);
 assert.equal((await ui({action:'rename',dir:'Share shelf',file:'new.txt',new_name:'../outside'})).status,400);
 assert.equal((await ui({action:'rename',dir:'Share shelf',file:'new.txt',new_name:'  '})).status,400);
 assert.equal((await request(url({s:key,download:original}))).text,'saved');
 assert.equal((await ui({action:'rename',dir:'Share shelf',file:'new.txt',new_name:'改名后的书'})).status,303);
 assert.equal((await request(url({s:key,download:original}))).status,404);
 assert.equal((await request(url({s:key,download:renamed}))).text,'saved');
 assert((await request(url({s:key}))).text.includes('改名后的书'));
 assert.equal((await ui({action:'rename',dir:'Share shelf',file:'改名后的书.txt',new_name:'改名后的书'})).status,303);
 assert.equal((await ui({action:'rename',dir:'Share shelf',file:'改名后的书.txt',new_name:'new'})).status,303);
 pass('rename preserves the extension and sharing, rejects invalid names and never overwrites a book');


 r=await ui({action:'move',dir:'Share shelf',file:'other.txt',destination:''});assert.equal(r.status,303,r.text);
 assert.equal((await request(url({s:key,download:'Share shelf/other.txt'}))).status,404);
 assert.equal((await opds('alice',{download:'other.txt'})).text,'Another shared book');
 r=await ui({action:'delete',dir:'',file:'other.txt'});assert.equal(r.status,303,r.text);
 assert.equal((await opds('alice',{download:'other.txt'})).status,404);
 r=await ui({action:'share',dir:'Share shelf'});assert.equal(r.status,303,r.text);
 assert.equal((await request(url({s:key,download:'Share shelf/same.txt'}))).status,410);
 const rotated=(await request('up.php?dir=Share+shelf')).text.match(/\?s=([1-9]{8}-[A-Z0-9]{4})/)[1];
 r=await ui({action:'revoke',dir:'Share shelf'});assert.equal(r.status,303,r.text);
 assert.equal((await request(url({s:rotated,download:'Share shelf/same.txt'}))).status,410);
 assert((await request('up.php?dir=Share+shelf')).text.includes('Revoked'));
 await ui({action:'share',dir:'Share shelf'});
 const third=(await request('up.php?dir=Share+shelf')).text.match(/\?s=([1-9]{8}-[A-Z0-9]{4})/)[1];
 const shares=path.join(data,'conf','shares.json');
 const state=JSON.parse(fs.readFileSync(shares));const thirdId=third.split('-')[0];
 assert.equal(state.records[thirdId].expires-state.records[thirdId].created,120*86400);
 state.records[thirdId].expires=Math.floor(Date.now()/1000)-1;fs.writeFileSync(shares,JSON.stringify(state));
 assert.equal((await request(url({s:third,download:'Share shelf/same.txt'}))).status,410);
 await ui({action:'share',dir:'Share shelf'});
 const fourth=(await request('up.php?dir=Share+shelf')).text.match(/\?s=([1-9]{8}-[A-Z0-9]{4})/)[1];
 const shelf=path.join(data,'books','alice','Share shelf');fs.renameSync(shelf,shelf+' old');fs.mkdirSync(shelf);
 fs.writeFileSync(path.join(shelf,'same.txt'),'replacement');assert.equal((await request(url({s:fourth,download:'Share shelf/same.txt'}))).status,410);
 pass('authenticated move/delete, share replacement, revocation, expiry and safe same-name recreation');

 // Stage 101 small, independently valid EPUBs on disk so both catalogue indexes start cold.
 const numberedName=i=>'Numbered '+String(i).padStart(3,'0');
 const numberedDir='Pagination shelf';
 let numbered=path.join(data,'books','alice',numberedDir);
 fs.mkdirSync(numbered);
 const makeBooks=`for($i=1;$i<=101;$i++){
 $z=new ZipArchive();$name=sprintf("Numbered %03d",$i);
 if($z->open($argv[1]."/".$name.".epub",ZipArchive::CREATE)!==true)exit(1);
 $z->addFromString("mimetype","application/epub+zip");$z->setCompressionName("mimetype",ZipArchive::CM_STORE);
 $z->addFromString("META-INF/container.xml",'<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="book.opf" media-type="application/oebps-package+xml"/></rootfiles></container>');
 $z->addFromString("book.opf",'<package xmlns="http://www.idpf.org/2007/opf"><metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>'.$name.'</dc:title><dc:creator>Pagination QA</dc:creator></metadata></package>');
 $z->close();}`;
 execFileSync(php,['-r',makeBooks,numbered]);
 assert.equal((await ui({action:'share',dir:numberedDir})).status,303);
 const numberedKey=(await request('up.php?dir=Pagination+shelf')).text.match(/\?s=([1-9]{8}-[A-Z0-9]{4})/)[1];
 const feedLink=(res,rel)=>res.text.match(new RegExp('<link rel="'+rel+'" href="([^"]+)"'))?.[1].replaceAll('&amp;','&');
 const titles=r=>[...r.text.matchAll(/<entry>[\s\S]*?<title>([^<]+)<\/title>/g)].map(m=>m[1]);
 async function checkPagination(params,headers={}){
   let target=url(params), previous;
   for(const [page,count] of [50,50,1].entries()){
     const response=await request(target,{headers});
     assert.equal(response.status,200,response.text);
     assert.deepEqual(titles(response),Array.from({length:count},(_,i)=>numberedName(page*50+i+1)));
     const self=feedLink(response,'self');
     const sp=new URL(self).searchParams;
     for(const [k,v] of Object.entries(params)) assert.equal(sp.get(k),v);
     assert.equal(Number(sp.get('offset')),page*50);
     assert.equal(feedLink(response,'previous'),previous);
     previous=self;
     target=feedLink(response,'next');
     assert.equal(Boolean(target),page<2);
   }
 }
 const pagingAuth=auth('alice',password);
 const pagedParams={feed:'books',category:numberedDir,q:'Pagination QA'};
 // A non-existent offset must not be used to warm the fixture before testing the first page.
 assert.equal((await request(url({...pagedParams,offset:'invalid'}),{headers:pagingAuth})).status,400);
 await checkPagination(pagedParams,pagingAuth);
 await checkPagination({s:numberedKey,feed:'books',category:numberedDir,q:'Pagination QA'});
 await checkPagination(pagedParams,pagingAuth);
 assert.equal((await opds('alice',{download:numberedDir+'/'+numberedName(101)+'.epub'})).headers['content-type'],'application/epub+zip');

 // A cold backlog above the work cap must not return a misleading partial 200 response.
 const backlog='Cold backlog';
 const cold=path.join(data,'books','alice',backlog);fs.mkdirSync(cold);
 for(let i=0;i<121;i++)fs.writeFileSync(path.join(cold,String(i).padStart(3,'0')+'.txt'),'A valid book.');
 const coldUrl=url({feed:'books',category:backlog});
 const busy=await request(coldUrl,{headers:pagingAuth});
 assert.equal(busy.status,503);assert.equal(busy.headers['retry-after'],'2');assert.equal(titles(busy).length,0);
 const ready=await request(coldUrl,{headers:pagingAuth});
 assert.equal(ready.status,200);assert.equal(titles(ready).length,50);
 pass('cold and warm 101-EPUB paging (50/50/1), private and shared links, bounded cold backlog');


 r=await ui({action:'logout'});assert.equal(r.status,303);
 assert.equal((await ui({action:'login',username:'bob',password})).status,303);
 const bobToken=getLegacyToken('bob');assert(bobToken && bobToken!==aliceToken);
 const parallel=await Promise.all([upload(bobToken,undefined,[['private.txt','Bob only']]),upload(aliceToken,undefined,[['parallel.txt','Alice only']])]);
 for (const resp of parallel) assert.equal(resp.status,200,resp.text);
 assert.equal((await opds('bob',{download:'parallel.txt'})).status,404);
 assert.equal((await opds('bob',{download:'private.txt'})).text,'Bob only');
 assert.equal((await opds('alice',{download:'private.txt'})).text,'Alice root content');
 cli('quota','bob','8','1');
 assert.equal((await upload(bobToken,undefined,[['overflow.txt','over limit']])).status,507);
 const reset=cli('reset','bob');
 assert.equal((await activate('bob',reset,'new-test-password-123')).status,303);
 assert.equal((await opds('bob')).status,401);
 assert.equal((await request(url({download:'private.txt'}),{headers:auth('bob','new-test-password-123')})).text,'Bob only');
 const old=path.join(temp,'old-books');fs.mkdirSync(old);fs.writeFileSync(path.join(old,'old.txt'),'old file');
 assert(cli('migrate','alice',old).includes('Preview only'));assert(!fs.existsSync(path.join(data,'books','alice','old.txt')));
 assert(cli('migrate','alice',old,'--apply').includes('original library retained'));assert(fs.existsSync(path.join(old,'old.txt')));
 pass('individual quotas, password reset and non-destructive migration');

 const shortUser='7', shortLink=cli('invite',shortUser);
 const passwordPage=await request(shortLink,{headers:{'accept-language':'zh-CN'}});
 assert.equal(passwordPage.status,200);assert(passwordPage.text.includes('设置密码'));
 assert(!passwordPage.text.includes('minlength'));
 r=await activate(shortUser,shortLink,'');
 assert.equal(r.status,400);assert(r.text.includes('Password cannot be empty.'));
 assert.equal((await activate(shortUser,shortLink,'0')).status,303);
 assert.equal((await ui({action:'login',username:shortUser,password:'0'})).status,303);
 assert.equal((await request('index.php',{headers:auth(shortUser,'0')})).status,200);
 assert.equal((await request('index.php',{headers:auth(shortUser,'')})).status,401);
 const longPrefix='p'.repeat(2500);
 const longPassword=longPrefix+':  密码 ';
 assert.equal((await activate(shortUser,cli('reset',shortUser),longPassword)).status,303);
 assert.equal((await ui({action:'login',username:shortUser,password:longPassword})).status,303);
 assert.equal((await request('index.php',{headers:auth(shortUser,longPassword)})).status,200);
 assert.equal((await request('index.php',{headers:auth(shortUser,longPrefix+':  密码')})).status,401);
 assert.equal((await request('index.php',{headers:auth(shortUser,'0')})).status,401);
 pass('single-character username and password, empty rejection, long exact matching, and old password hashes');

 if(process.env.CHROME_BIN && process.env.PLAYWRIGHT_MODULE){
   const {chromium}=await import(process.env.PLAYWRIGHT_MODULE);
   const browser=await chromium.launch({executablePath:process.env.CHROME_BIN,args:['--no-sandbox']});
   try{
     const page=await browser.newPage({viewport:{width:1260,height:900},ignoreHTTPSErrors:true});
     const errors=[];page.on('pageerror',e=>errors.push(e.message));
     await page.goto(base+'up.php');await page.getByLabel('Username').fill('alice');await page.getByLabel('Password',{exact:true}).fill(password);
     await page.getByRole('button',{name:'Sign in'}).click();await page.getByRole('heading',{name:'alice’s library'}).waitFor();
     await page.getByRole('button',{name:'Upload books',exact:true}).click();
     const uploadSheet=page.getByRole('dialog',{name:'Upload books'});
     await uploadSheet.getByText('Upload to: alice’s library',{exact:true}).waitFor();
     assert.equal(await uploadSheet.locator('select').count(),0);
     assert.equal(await uploadSheet.getByRole('button',{name:'New folder'}).count(),0);
     await page.locator('#files').setInputFiles({name:'web-ui.txt',mimeType:'text/plain',buffer:Buffer.from('Browser UI upload')});
     await page.getByRole('button',{name:'Upload',exact:true}).click();await page.locator('#upload-notice').getByText('Saved: web-ui.txt').waitFor();
     await page.locator('#books-panel').getByRole('link',{name:'web-ui',exact:true}).waitFor();
     const rootFolder=page.locator('.shelf-list .shelf-folder a[href="up.php?library=p-alice&dir=Share%20shelf"]');
     assert(await rootFolder.isVisible());
     assert.equal(await page.locator('#books-panel .shelf-list').count(),1);
     assert.equal(await page.locator('#books-panel .shelf-list > :first-child').getAttribute('class'),'shelf-folder');
     assert.equal(await page.locator('#books-panel .shelf-list > :last-child').getAttribute('class'),'book');
     assert.equal(await page.locator('#books-panel .shelf-list .shelf-folder + .book').count(),1);
     assert.equal(await page.locator('#books-panel').getByRole('heading').count(),0);
     await rootFolder.click();
     await page.getByRole('heading',{name:'Share shelf',exact:true}).waitFor();
     const breadcrumb=page.getByRole('navigation',{name:'Library location'});
     const shelfRoot=breadcrumb.getByRole('link',{name:'alice’s library',exact:true});
     await shelfRoot.waitFor();
     assert.equal(await breadcrumb.locator('h1').getAttribute('aria-current'),'page');
     assert.equal(await breadcrumb.locator('.separator').textContent(),'/');
     for(const width of [1260,390]){
       await page.setViewportSize({width,height:900});
       const rootBox=await shelfRoot.boundingBox();
       const folderBox=await breadcrumb.getByRole('heading',{name:'Share shelf',exact:true}).boundingBox();
       const fontSize=await breadcrumb.locator('h1').evaluate(h=>parseFloat(getComputedStyle(h).fontSize));
       assert(Math.abs(rootBox.y-folderBox.y)<=1 && rootBox.x<folderBox.x,'Breadcrumb is on one line');
       assert(fontSize>=16&&fontSize<=20,'Breadcrumb uses restrained readable text');
     }
     await page.setViewportSize({width:1260,height:900});
     assert.equal(await page.locator('.shelf-list .shelf-folder').count(),0);
     await shelfRoot.click();
     await page.getByRole('heading',{name:'alice’s library',exact:true}).waitFor();

     const download=page.waitForEvent('download');
     await page.getByRole('link',{name:'Download web-ui.txt'}).click();
     assert.equal((await download).suggestedFilename(),'web-ui.txt');
     await page.getByLabel('More actions for web-ui.txt').click();
     await page.getByRole('button',{name:'Rename',exact:true}).click();
     const renameModal=page.getByRole('dialog',{name:'Rename book'});
     assert.equal(await renameModal.getByLabel('New book name').inputValue(),'web-ui');
     await renameModal.getByLabel('New book name').fill('private');
     await renameModal.getByRole('button',{name:'Save name'}).click();
     await renameModal.getByRole('alert').getByText('A book with this name already exists.').waitFor();
     assert.equal(await renameModal.getByLabel('New book name').inputValue(),'private');
     await renameModal.getByLabel('New book name').fill('web-ui-renamed');
     await renameModal.getByRole('button',{name:'Save name'}).click();
     await page.getByRole('link',{name:'Download web-ui-renamed.txt'}).waitFor();

     await page.setViewportSize({width:390,height:844});
     assert(await rootFolder.isVisible());
     await page.getByRole('button',{name:'Choose folder'}).click();
     await page.getByRole('dialog').getByRole('link',{name:/^Share shelf(?: Unavailable)?$/}).click();
     await page.getByRole('button',{name:'Manage subscription sharing'}).click();
     await page.getByRole('button',{name:'Create share'}).click();
     await page.getByRole('button',{name:'Manage subscription sharing'}).getByText('Shared',{exact:true}).waitFor();
     assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
     await page.getByRole('button',{name:'Manage subscription sharing'}).click();
     await page.getByRole('button',{name:'Revoke',exact:true}).waitFor();
     page.once('dialog',d=>d.accept());await page.getByRole('button',{name:'Revoke',exact:true}).click();
     await page.getByRole('status').getByText('Share revoked.').waitFor();
     await page.getByRole('button',{name:'Manage subscription sharing'}).getByText('Revoked',{exact:true}).waitFor();
     await page.getByRole('button',{name:'Choose folder'}).click();
     const folderSheet=page.locator('#folder-list');
     await folderSheet.getByLabel('New folder name').fill('Browser-created folder');
     await folderSheet.getByRole('button',{name:'New folder',exact:true}).click();
     await page.getByRole('heading',{name:'Browser-created folder'}).waitFor();
     await page.getByRole('button',{name:'Upload books',exact:true}).click();
     await uploadSheet.getByText('Upload to: alice’s library / Browser-created folder',{exact:true}).waitFor();
     await page.locator('#files').setInputFiles({name:'new-shelf.txt',mimeType:'text/plain',buffer:Buffer.from('Uploaded to a new folder')});
     await uploadSheet.getByRole('button',{name:'Upload',exact:true}).click();
     await page.getByRole('heading',{name:'Browser-created folder'}).waitFor();
     await page.getByRole('link',{name:'new-shelf',exact:true}).waitFor();
     const drop=async (target,names)=>{
       const handle=await page.evaluateHandle(names=>{
         const dt=new DataTransfer();
         for(const name of names)dt.items.add(new File(['Drop upload fixture'],name,{type:'text/plain'}));
         return dt;
       },names);
       await target.dispatchEvent('dragover',{dataTransfer:handle});
       await target.evaluate(el=>{if(!el.classList.contains('is-drop-target'))throw Error('Target not highlighted');});
       await target.dispatchEvent('drop',{dataTransfer:handle});
       await handle.dispose();
     };
     const dropTarget=page.locator('#drop-shelf');
     const dropModal=page.locator('#upload-dialog');
     let release,seen;
     const gate=new Promise(resolve=>{release=resolve;}), arrived=new Promise(resolve=>{seen=resolve;});
     const isWebUpload=u=>u.pathname.endsWith('/up.php');
     holdUploadResponse={arrive:seen,gate};
     try {
       await drop(dropTarget,['drop-list.txt']);
       const hit=await Promise.race([arrived,delay(5000).then(()=>{throw Error('No dragged upload reached the server');})]);
       assert.equal(new URL(hit,base).searchParams.get('dir'),'Browser-created folder');
       await dropModal.getByRole('progressbar',{name:'drop-list.txt'}).waitFor();
       await dropModal.getByText('Uploading 1 of 1').waitFor();
       await dropModal.getByText('Sent. Waiting for the server…').waitFor();
       assert.equal(await dropModal.locator('progress').evaluate(el=>el.value),100);
     } finally { holdUploadResponse=null;release(); }
     await page.getByRole('link',{name:'drop-list',exact:true}).waitFor();
     assert.equal((await opds('alice',{download:'Browser-created folder/drop-list.txt'})).text,'Drop upload fixture');
     assert.equal((await opds('alice',{download:'drop-list.txt'})).status,404);
     await page.getByRole('button',{name:'Upload books',exact:true}).click();
     await drop(dropModal,['drop-dialog.txt','not-a-book.jpg']);
     await dropModal.getByText('Skipped items: 1. Drop EPUB or TXT files, not folders.').waitFor();
     await dropModal.getByText('Saved: drop-dialog.txt').waitFor();
     await dropModal.getByRole('button',{name:'Close'}).click();
     await page.getByRole('link',{name:'drop-dialog',exact:true}).waitFor();
     assert.equal((await opds('alice',{download:'Browser-created folder/drop-dialog.txt'})).text,'Drop upload fixture');
     assert.equal((await opds('alice',{download:'Browser-created folder/not-a-book.jpg'})).status,422);
     // Do not retry ambiguous gateway results; an explicit 429 is safe to retry.
     let unknown=0,temporary=0;
     const outcomes=async route=>{
       if(route.request().method()!=='POST')return route.continue();
       if(route.request().postData().includes('unknown-save.txt')){
         unknown++;return route.fulfill({status:502,contentType:'text/html',body:'bad gateway'});
       }
       if(temporary++===0)return route.fulfill({status:429,json:{success:false,message:'The service is busy. Try again later.',results:[]}});
       return route.continue();
     };
     await page.route(isWebUpload,outcomes);
     await drop(dropTarget,['unknown-save.txt','temporary.txt']);
     await dropModal.getByText(/No save confirmation.*Check this folder/).waitFor();
     await dropModal.getByRole('button',{name:'Retry failed'}).click();
     await dropModal.getByText('Saved: temporary.txt').waitFor();
     assert.equal(unknown,1);assert.equal(temporary,2);
     assert(await dropModal.getByText(/No save confirmation.*Check this folder/).isVisible());
     await dropModal.getByRole('button',{name:'Close'}).click();
     await page.unroute(isWebUpload,outcomes);
     assert.equal((await opds('alice',{download:'Browser-created folder/temporary.txt'})).text,'Drop upload fixture');
     pass('drag from the shelf and upload dialog keeps the current folder and shows progress, skips invalid files, and retries only confirmed temporary failures');
     const longTitle='A very long book filename that should stay on one line even when the reader is using a narrow mobile screen';
     await page.getByRole('button',{name:'Upload books',exact:true}).click();
     await page.locator('#files').setInputFiles({name:longTitle+'.txt',mimeType:'text/plain',buffer:Buffer.from('Long filename example')});
     await uploadSheet.getByRole('button',{name:'Upload',exact:true}).click();
     const longBook=page.getByRole('link',{name:longTitle,exact:true});
     await longBook.waitFor();
     assert.equal(await longBook.getAttribute('title'),longTitle+'.txt');
     assert(await longBook.evaluate(el=>getComputedStyle(el).whiteSpace==='nowrap' &&
       getComputedStyle(el).textOverflow==='ellipsis' && el.scrollWidth>el.clientWidth));
     assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
     assert.deepEqual(errors,[]);
     pass('desktop and mobile dashboard: book-first navigation, download, current-folder uploads from desktop and mobile, share and revoke');
     await page.close();
     const zh=await browser.newPage({locale:'zh-CN',ignoreHTTPSErrors:true});
     await zh.goto(base+'up.php');
     await zh.getByText('登录后可管理书籍并分享目录。').waitFor();
     await zh.getByLabel('用户名').fill('alice');await zh.getByLabel('密码',{exact:true}).fill(password);
     await zh.getByRole('button',{name:'登录',exact:true}).click();
     await zh.getByRole('heading',{name:'alice 的书库'}).waitFor();
     await zh.getByRole('button',{name:'上传书籍',exact:true}).waitFor();
     const account=zh.locator('header.top details.account');
     const avatar=account.getByLabel('账号菜单');
     const cliMenu=account.getByRole('button',{name:'连接Agent'});
     const tools=zh.locator('#tools-dialog');
     assert.equal(await cliMenu.isVisible(),false);
     await avatar.focus();await zh.keyboard.press('Enter');
     await cliMenu.waitFor();
     await account.getByRole('button',{name:'连接阅读器'}).waitFor();
     assert.deepEqual(await account.locator('button.menu-item[data-dialog]').allTextContents(),['连接Agent','连接阅读器','书库设置','站点账号','书库成员']);
     await account.getByRole('button',{name:'连接阅读器'}).click();
     await zh.getByRole('dialog',{name:'连接阅读器'}).getByRole('button',{name:'复制 OPDS 地址'}).waitFor();
     await zh.getByRole('dialog',{name:'连接阅读器'}).getByLabel('关闭').click();
     await avatar.click();
     await account.getByRole('button',{name:'退出登录'}).waitFor();
     await zh.keyboard.press('Escape');assert.equal(await account.getAttribute('open'),null);
     await zh.locator('.sidebar a[href="up.php?library=p-alice&dir=Share%20shelf"]').click();
     await zh.setViewportSize({width:390,height:844});
     await avatar.click();
     const toolBounds=await account.locator('.account-popover').boundingBox();
     assert(toolBounds.x>=0 && toolBounds.x+toolBounds.width<=390);
     await cliMenu.click();
     assert.equal(await account.getAttribute('open'),null);
     await tools.getByRole('heading',{name:'连接Agent'}).waitFor();
     for (const old of ['终端命令','API 接口','旧版个人上传令牌','下载 SKILL.md','本库成员令牌','有效上传令牌']) {
       assert.equal(await tools.getByText(old,{exact:true}).count(),0);
     }
     const setupResponse=zh.waitForResponse(r=>r.url().endsWith('up.php')&&r.request().method()==='POST');
     await tools.getByRole('button',{name:'复制完整 Agent 配置'}).click();
     assert.match((await (await setupResponse).json()).setup,/opds1\.[a-f0-9]{24}\.[a-f0-9]{64}/);
     await zh.waitForFunction(()=>document.querySelector('#agent-setup-text').value.includes('library_id'));
     const reloaded=zh.waitForLoadState();
     await zh.keyboard.press('Escape');await reloaded;
     await tools.waitFor({state:'hidden'});

     await zh.getByRole('button',{name:'管理目录订阅'}).click();
     await zh.getByRole('button',{name:'创建分享',exact:true}).click();
     await zh.getByRole('button',{name:'管理目录订阅'}).getByText(/到期 \d{4}-\d{2}-\d{2}/).waitFor();
     await zh.getByRole('button',{name:'管理目录订阅'}).click();
     await zh.getByRole('link',{name:'预览',exact:true}).click();
     await zh.getByText(/只读预览 · 此订阅可查看 [0-9]+ 本书/).waitFor();
     await zh.locator('#share-dialog').getByRole('button',{name:'关闭',exact:true}).click();
     await zh.locator('.book-menu summary').first().click();
     await zh.getByRole('button',{name:'移动',exact:true}).first().click();
     let warning='';
     zh.once('dialog',d=>{warning=d.message();return d.dismiss();});
     await zh.locator('#move-dialog .primary').click();
     assert.equal(warning,'移动这本书会改变订阅者可见的内容。继续吗？');
     await zh.getByRole('button',{name:'关闭',exact:true}).click();
     await zh.getByRole('button',{name:'上传书籍',exact:true}).click();
     await zh.route(u=>u.pathname.endsWith('/up.php'),route=>route.request().method()==='POST'?route.fulfill({status:413,contentType:'text/plain',body:'proxy limit'}):route.continue());
     await zh.locator('#files').setInputFiles({name:'zh-test.txt',mimeType:'text/plain',buffer:Buffer.from('Browser UI upload')});
     await zh.getByRole('button',{name:'上传',exact:true}).click();
     await zh.getByText('服务器拒绝了上传请求（HTTP 413）。',{exact:false}).waitFor();
     await zh.getByRole('button',{name:'重试失败项'}).waitFor({state:'hidden'});
     if(process.env.SCREENSHOT_DIR){
       const demo='reader';
       assert.equal((await activate(demo,cli('invite',demo))).status,303);
       assert.equal((await ui({action:'login',username:demo,password})).status,303);
       const demoToken=getLegacyToken(demo);
       const books=[
         ['01 分布式数据库：从复制到共识.epub',epubBytes],['02 云数据库架构设计.epub',epubBytes],
         ['03 日志与事件流.epub',epubBytes],['04 对象存储与数据湖.epub',epubBytes],
         ['05 数据库读书会笔记.txt','阅读笔记'.repeat(1600)],['06 下次阅读清单.txt','读书摘记'.repeat(1600)],
       ];
       assert.equal((await upload(demoToken,'架构与数据库',books)).status,200);
       assert.equal((await upload(demoToken,'周末阅读',[['城市漫游.epub',epubBytes]])).status,200);
       assert.equal((await upload(demoToken,'阅读笔记',[['本周阅读清单.txt','书目']])).status,200);
       assert.equal((await ui({action:'share',dir:'架构与数据库'})).status,303);
       const config=path.join(data,'conf','config.php');
       fs.writeFileSync(config,fs.readFileSync(config,'utf8').replace("'title' => 'Test Site'","'title' => '个人书库'"));
       await zh.unrouteAll();
       await zh.context().clearCookies();
       await zh.setViewportSize({width:1260,height:840});
       await zh.goto(base+'up.php');
       await zh.getByLabel('用户名').fill(demo);await zh.getByLabel('密码',{exact:true}).fill(password);
       await zh.getByRole('button',{name:'登录',exact:true}).click();
       await zh.locator('.shelf-list').getByRole('link',{name:/架构与数据库/}).click();
       for(const name of ['架构与数据库','周末阅读','阅读笔记'])await zh.locator('.sidebar').getByRole('link',{name:new RegExp(name)}).waitFor();
       await zh.getByRole('button',{name:'管理目录订阅'}).getByText('分享中',{exact:true}).waitFor();
       const shot=(name)=>zh.screenshot({path:path.join(process.env.SCREENSHOT_DIR,name)});
       await shot('opds-desktop.png');
       await avatar.click();
       await shot('opds-account-menu.png');
       await zh.locator('h1').click();
       await zh.setViewportSize({width:390,height:844});
       const firstBook=await zh.locator('.book-name').first().boundingBox();
       assert(firstBook.y+firstBook.height<844);
       await shot('opds-mobile.png');
       await zh.getByRole('button',{name:'管理目录订阅'}).click();
       // Mask the bearer URL even though this isolated fixture has no real books or users.
       await zh.screenshot({path:path.join(process.env.SCREENSHOT_DIR,'opds-share.png'),mask:[zh.locator('#share-url')],maskColor:'#c8d8cc'});
     }
     await zh.close();
     pass('Chinese installer and dashboard: localized labels, count, share preview, move confirmation and proxy upload error');
   }finally{await browser.close();}
 }
 // The browser suite rotates/revokes the deliberately stale Share shelf URL.
 // Clean up the same fixture when CI runs just the HTTP tests.
 if(!process.env.CHROME_BIN||!process.env.PLAYWRIGHT_MODULE){
   const state=JSON.parse(fs.readFileSync(shares));
   state.records[fourth.split('-')[0]].expires=Math.floor(Date.now()/1000)-1;
   fs.writeFileSync(shares,JSON.stringify(state));
 }
 // RBAC upgrade: build an old-format deployment in place, including a real share
 // from the previous release when its source files are supplied.
 const legacySource=process.env.OPDS_LEGACY_SOURCE;
 const runtime=['i18n.php','bootstrap.php','security.php','index.php','up.php','api.php','upload-common.php','accounts.php','catalogue.php','admin.php'];
 const libState=path.join(data,'conf','libraries.json');
 fs.rmSync(libState,{force:true});
 const legacyAccounts=path.join(data,'conf','users.json');
 const legacyAccountState=JSON.parse(fs.readFileSync(legacyAccounts));
 delete legacyAccountState.records.alice.named_library_default;
 fs.writeFileSync(legacyAccounts,JSON.stringify(legacyAccountState));
 if (legacySource) for (const file of runtime) fs.copyFileSync(path.join(legacySource,file),path.join(app,file));
 await ui({action:'logout'});
 assert.equal((await ui({action:'login',username:'alice',password})).status,303);
 const oldUpgradeToken=getLegacyToken('alice');
 assert.equal((await upload(oldUpgradeToken,'Legacy upgrade',[['same.txt','kept in the original library']])).status,200);
 assert.equal((await ui({action:'share',dir:'Legacy upgrade'})).status,303);
 const legacyKey=(await request('up.php?dir=Legacy+upgrade')).text.match(/\?s=([1-9]{8}-[A-Z0-9]{4})/)[1];
 const shareFile=path.join(data,'conf','shares.json'), keyId=legacyKey.split('-')[0];
 function readState(file){return JSON.parse(fs.readFileSync(file));}
 const oldShares=readState(shareFile);
 // Schema v1 from the older build has no library field.
 if (legacySource) assert.equal(oldShares.records[keyId].library,undefined);
 else { delete oldShares.records[keyId].library; fs.writeFileSync(shareFile,JSON.stringify(oldShares)); }
 const oldShareRow=oldShares.records[keyId];
 assert.equal((await request(url({s:legacyKey,download:'Legacy upgrade/same.txt'}),{headers:{cookie:''}})).text,'kept in the original library');
 if (legacySource) {
   for (const file of runtime) fs.copyFileSync(path.join(project,file),path.join(app,file));
   // Older versions used PHP's default session store; sign in once after upgrade.
   cookies.clear();
   assert.equal((await ui({action:'login',username:'alice',password})).status,303);
 }
 const legacyFolder=path.join(data,'books','alice','Legacy upgrade');
 const identity=fs.readFileSync(path.join(legacyFolder,'.opds-category'),'utf8');
 assert.equal((await request(url({s:legacyKey,download:'Legacy upgrade/same.txt'}),{headers:{cookie:''}})).text,'kept in the original library');
 assert.deepEqual(readState(shareFile).records[keyId],oldShareRow);
 assert.equal(fs.readFileSync(path.join(legacyFolder,'.opds-category'),'utf8'),identity);
 assert.equal((await opds('alice',{download:'Legacy upgrade/same.txt'})).text,'kept in the original library');
 assert.equal((await upload(oldUpgradeToken,'Legacy upgrade',[['ping.txt','old token is still scoped here']])).status,200);
 assert((await request('up.php')).text.includes('My personal library'));
 if (fs.existsSync(path.join(data,'books','Orphan'))) fs.rmdirSync(path.join(data,'books','Orphan'));
 const preflight=JSON.parse(cli('rbac-check'));
 assert(preflight.libraries.some(l=>l.id==='p-alice'&&l.active_shares>0&&l.legacy_token));
 pass('upgrade keeps hashed passwords, existing anonymous URL and identity, legacy OPDS and legacy upload token');

 // Test users share the same localhost address across the otherwise independent suites.
 fs.rmSync(path.join(data,'conf','.rate.json'),{force:true});
 const libraryWeb=(id,params={})=>'up.php?'+new URLSearchParams({library:id,...params});
 const switchUser=async (username,secret=password)=>{
   cookies.clear();
   assert.equal((await ui({action:'login',username,password:secret})).status,303);
 };
 const savedSession=()=>[...cookies.entries()];
 const restoreSession=session=>{cookies.clear();for(const [k,v] of session)cookies.set(k,v);};
 const thirdUser='casey', librarian='dana';
 const family='p-dana',tech='p-casey';
 cookies.clear();
 assert.equal((await activate(librarian,cli('invite',librarian))).status,303);
 assert.equal((await activate(thirdUser,cli('invite',thirdUser))).status,303);
 assert(fs.existsSync(path.join(data,'books',librarian)));
 assert(fs.existsSync(path.join(data,'books',thirdUser)));
 await switchUser(thirdUser);
 const caseySession=savedSession();
 assert.equal((await ui({action:'member_invite',library:tech,member:'bob',role:'opds_reader'})).status,303);
 assert.equal((await ui({action:'member_invite',library:tech,member:librarian,role:'reader'})).status,303);
 await switchUser(librarian);
 const ownerSession=savedSession();
 assert(!(await request('up.php')).text.includes('create-library-dialog'));
 assert((await request('up.php')).text.includes('id="books-panel"'));
 assert.equal((await ui({action:'create_library',title:'No extra library'})).status,400);
 assert.equal((await ui({action:'transfer_begin',library:family,member:'bob'})).status,400);
 assert(!fs.readdirSync(path.join(data,'books')).some(name=>/^l-[0-9a-f]{32}$/.test(name)));
 assert.equal((await ui({action:'invite_accept',target_library:tech})).status,303);
 assert.equal((await ui({action:'library_rename',library:family,title:'家庭书库'})).status,303);
 assert((await request('up.php')).text.includes('Choose a library'));
 assert(!(await request('up.php')).text.includes('id="books-panel"'));
 assert.equal((await request(libraryWeb(family))).status,200);
 assert.equal((await ui({action:'folder',library:family,folder:'Legacy upgrade'})).status,303);
 const scopedUpload=async (id,dir,name,content,extra={})=>{
   const target=libraryWeb(id,{dir});
   const page=await request(target);
   return upload(null,undefined,[[name,content]],target,{csrf:csrf(page),action:'upload',...extra});
 };
 assert.equal((await scopedUpload(family,'Legacy upgrade','same.txt','only in shared library')).status,200);
 assert.equal((await opds(librarian,{library:family,download:'Legacy upgrade/same.txt'})).text,'only in shared library');
 assert.equal((await opds('alice',{download:'Legacy upgrade/same.txt'})).text,'kept in the original library');
 assert.equal((await request(url({s:legacyKey,download:'Legacy upgrade/same.txt',library:family}),{headers:{cookie:''}})).text,'kept in the original library');
 const catalogFamily=await opds(librarian,{library:family,feed:'books',category:'Legacy upgrade'});
 assert.match(catalogFamily.text,new RegExp('library='+family+'&amp;download='));
 assert(!catalogFamily.text.includes('ping.txt'));
 assert.equal((await ui({action:'share',library:family,dir:'Legacy upgrade'})).status,303);
 const modernKey=(await request(libraryWeb(family,{dir:'Legacy upgrade'}))).text.match(/\?s=([1-9]{8}-[A-Z0-9]{4})/)[1];
 assert.equal((await request(url({s:modernKey,download:'Legacy upgrade/same.txt'}),{headers:{cookie:''}})).text,'only in shared library');
 assert.equal((await ui({action:'member_invite',library:family,member:'bob',role:'web_upload'})).status,303);
 const firstInvitePage=await request(libraryWeb(family,{manage:'pending'}));
 const oldInvite=firstInvitePage.text.match(/target=p-dana&amp;invitation=([a-f0-9]{32})/)[1];
 const directInvite=id=>'up.php?target=p-dana&invitation='+id;
 const inviteState=path.join(data,'conf','libraries.json');
 const inviteRecords=readState(inviteState);
 inviteRecords.records[family].invites.bob.expires=1;
 fs.writeFileSync(inviteState,JSON.stringify(inviteRecords));
 const expiredPage=await request(libraryWeb(family,{manage:'pending'}));
 assert(expiredPage.text.includes('>Expired</span>'));
 assert.equal((await ui({action:'member_invite',library:family,member:'bob',role:'web_upload'})).status,303);
 const replacementPage=await request(libraryWeb(family,{manage:'pending'}));
 const replacementId=replacementPage.text.match(/target=p-dana&amp;invitation=([a-f0-9]{32})/)[1];
 assert.notEqual(replacementId,oldInvite);
 assert.equal((await ui({action:'member_cancel',library:family,member:'bob',invitation_id:oldInvite})).status,410);
 assert.equal((await ui({action:'member_cancel',library:family,member:'bob',invitation_id:replacementId})).status,303);
 assert((await request(libraryWeb(family,{manage:'pending'}))).text.includes('>Revoked</span>'));
 assert.equal((await ui({action:'member_invite',library:family,member:'bob',role:'web_upload'})).status,303);
 const currentInvite=(await request(libraryWeb(family,{manage:'pending'}))).text.match(/target=p-dana&amp;invitation=([a-f0-9]{32})/)[1];
 restoreSession(caseySession);
 const wrongInvite=await request(directInvite(currentInvite));
 assert.equal(wrongInvite.status,410); assert(!wrongInvite.text.includes('>Accept invitation</button>'));

 assert.equal((await ui({action:'invite_accept',target_library:family})).status,410);
 assert.equal((await request(libraryWeb(family))).status,403);
 await switchUser('bob','new-test-password-123');
 const bobSession=savedSession();
 assert.equal((await request(libraryWeb(family))).status,403);
 assert((await request('up.php')).text.includes('Review library invitations'));
 assert.equal((await request(directInvite(oldInvite))).status,410);
 assert.equal((await request(directInvite(replacementId))).status,410);
 assert.equal((await request(directInvite(currentInvite))).status,200);
 assert.equal((await ui({action:'invite_accept',target_library:family,invitation_id:oldInvite})).status,410);
 assert.equal((await ui({action:'invite_accept',target_library:family,invitation_id:currentInvite})).status,303);
 const zhFlash=await request('up.php',{headers:{'accept-language':'zh-CN'}});
 assert(zhFlash.text.includes('已接受邀请。')&&!zhFlash.text.includes('Invitation accepted.'));

 assert.equal((await ui({action:'invite_accept',target_library:family})).status,410);
 assert.equal((await ui({action:'invite_accept',target_library:tech})).status,303);
 const bobPicker=await request('up.php');
 assert(bobPicker.text.includes('Choose a library')&&bobPicker.text.includes('家庭书库'));
 assert(!bobPicker.text.match(new RegExp('class="panel library-card" href="up.php\\?library='+tech)));
 assert.equal((await request(libraryWeb(tech))).status,403);
 assert.equal((await request(url({library:tech}),{headers:auth('bob','new-test-password-123')})).status,200);
 assert.equal((await request(url({library:family}),{headers:auth('bob','new-test-password-123')})).status,403);
 const bobFamily=await request(libraryWeb(family,{dir:'Legacy upgrade'}));
 assert(bobFamily.text.includes('This role cannot browse books.'));
 assert(!bobFamily.text.includes('same.txt')&&!bobFamily.text.includes('id="tools-dialog"'));
 assert.equal((await request(libraryWeb(family,{dir:'Legacy upgrade',download:'same.txt'}))).status,403);
 for(const options of [{},{part:0,version:'none'},{asset:'cover.png',version:'none'}]){
   const blocked='preview.php?'+new URLSearchParams({library:family,dir:'Legacy upgrade',book:'same.txt',...options});
   assert.equal((await request(blocked)).status,403);
 }
 assert.equal((await ui({action:'folder',library:family,folder:'Forbidden folder'})).status,403);
 assert.equal((await ui({action:'agent_setup',library:family,destination:'Legacy upgrade'})).status,403);
 assert.equal((await ui({action:'delete',library:family,dir:'Legacy upgrade',file:'same.txt'})).status,403);
 assert.equal((await scopedUpload(family,'Legacy upgrade','web-only.txt','web upload worked')).status,200);
 assert.equal((await scopedUpload(family,'Legacy upgrade','web-only.txt','web upload worked')).status,409);
 assert.equal((await scopedUpload(tech,'','wrong.txt','must not be created')).status,403);

 restoreSession(ownerSession);
 assert.equal((await ui({action:'member_edit',library:family,member:'bob','role[]':'editor'})).status,400);
 assert.equal((await ui({action:'member_edit',library:family,member:'bob',role:'reader','roles[]':'admin'})).status,400);
 assert.equal((await ui({action:'member_edit',library:family,member:'bob',role:'web_view'})).status,400);
 assert.equal((await ui({action:'member_invite',library:family,member:'bob',role:'admin'})).status,409);
 assert.equal((await ui({action:'member_edit',library:family,member:'bob',role:'agent_upload'})).status,303);
 assert.equal(readState(libState).records[family].members.bob,'agent_upload');
 assert.equal((await ui({action:'member_invite',library:family,member:thirdUser,role:'editor'})).status,303);
 restoreSession(caseySession);
 assert.equal((await ui({action:'invite_accept',target_library:family})).status,303);
 assert.equal((await ui({action:'folder',library:family,folder:'Editor folder'})).status,303);
 assert.equal((await ui({action:'share',library:family,dir:'Editor folder'})).status,403);
 assert.equal((await ui({action:'delete',library:family,dir:'Legacy upgrade',file:'same.txt'})).status,403);
 assert.equal((await ui({action:'agent_setup',library:family,dir:'Editor folder'})).status,403);
 assert.equal((await scopedUpload(family,'Editor folder','draft.txt','editable')).status,200);
 assert.equal((await ui({action:'rename',library:family,dir:'Editor folder',file:'draft.txt',new_name:'draft revised'})).status,303);
 restoreSession(bobSession);
 assert(!(await request(libraryWeb(family,{dir:'Legacy upgrade'}))).text.includes('web-only'));
 assert.equal((await request(libraryWeb(family,{dir:'Legacy upgrade',download:'same.txt'}))).status,403);
 for(const options of [{},{part:0,version:'none'},{asset:'cover.png',version:'none'}]){
   const blocked='preview.php?'+new URLSearchParams({library:family,dir:'Legacy upgrade',book:'same.txt',...options});
   assert.equal((await request(blocked)).status,403);
 }
 assert.equal((await scopedUpload(family,'Legacy upgrade','not-web.txt','no')).status,403);
 function setupConfig(res) {
   assert.equal(res.status,200,res.json?.message);
   return JSON.parse(res.json.setup.match(/```json\n(.*?)\n```/s)[1]);
 }
 const agent=setupConfig(await ui({action:'agent_setup',library:family}));
 // Older request fields cannot change the new token's lifetime or scope.
 const another=setupConfig(await ui({action:'agent_setup',library:family,destination:'Legacy upgrade',name:'ignored',days:'1',scope:'folder'}));
 assert.notEqual(agent.token,another.token);
 assert.equal(agent.library_id,family);
 assert(agent.folders.includes('Legacy upgrade')&&agent.folders.includes('Editor folder'));
 assert(!agent.folders.includes('Share shelf'));
 const newState=readState(libState);
 const anotherRecord=newState.records[family].tokens[another.token.split('.')[1]];
 assert.equal(anotherRecord.expires-anotherRecord.created,90*86400);
 assert.equal(anotherRecord.name,'');
 assert(!fs.readFileSync(libState,'utf8').includes(agent.token));
 const bearer=token=>({authorization:'Bearer '+token});
 const verify=token=>request('api.php?action=verify',{headers:bearer(token)});
 const verified=await verify(agent.token);
 assert.equal(verified.json.directory,null);
 assert.equal(verified.json.can_create_directory,true);
 assert.deepEqual(verified.json.folders,agent.folders);
 assert.equal((await upload(agent.token,'Legacy upgrade',[['agent-only.txt','agent upload worked']])).status,200);
 assert.equal((await upload(agent.token,'Legacy upgrade',[['agent-only.txt','agent upload worked']])).status,409);
 assert.equal((await upload(agent.token,'Agent 新建',[['new.txt','automatically created']])).status,200);
 assert((await verify(agent.token)).json.folders.includes('Agent 新建'));
 assert.equal((await upload(agent.token,undefined,[['agent-root.txt','root fallback']])).status,200);
 assert(fs.existsSync(path.join(data,'books',librarian,'agent-root.txt')));
 assert(!fs.existsSync(path.join(data,'books','bob','Agent 新建')));
 assert.equal((await upload(agent.token,'../alice',[['wrong.txt','must not escape']])).status,400);
 assert.equal((await ui({action:'folder',library:family,folder:'Another folder'})).status,403);
 assert.equal((await request(url({library:family,download:'Legacy upgrade/same.txt'}),{headers:bearer(agent.token)})).status,401);
 assert.equal((await ui({action:'agent_revoke',library:family,token_id:agent.token.split('.')[1]})).status,303);
 assert.equal((await verify(agent.token)).status,401);
 assert.equal((await verify(another.token)).status,200);
 const expiring=setupConfig(await ui({action:'agent_setup',library:family}));
 const expiryState=readState(libState);
 const expiringId=expiring.token.split('.')[1];
 expiryState.records[family].tokens[expiringId].expires=1;
 fs.writeFileSync(libState,JSON.stringify(expiryState));
 assert.equal((await verify(expiring.token)).status,401);
 assert.equal((await upload(expiring.token,'Expired test',[['not-saved.txt','expired']])).status,401);
 assert(!fs.existsSync(path.join(data,'books',librarian,'Expired test')));
 const renewed=setupConfig(await ui({action:'agent_setup',library:family}));
 assert.equal(renewed.library_id,expiring.library_id);
 assert.notEqual(renewed.token,expiring.token);
 assert.equal((await verify(renewed.token)).status,200);


 // A pre-upgrade fixed-folder token retains its restriction and cannot list folders.
 const oldScopedState=readState(libState), oldScoped=crypto.randomBytes(32).toString('hex'), oldId=crypto.randomBytes(12).toString('hex');
 oldScopedState.records[family].tokens[oldId]={...anotherRecord,agent_connection:false,whole:false,mkdir:false,dir:'Legacy upgrade',
   identity:fs.readFileSync(path.join(data,'books',librarian,'Legacy upgrade','.opds-category'),'utf8'),
   digest:crypto.createHash('sha256').update(oldScoped).digest('hex')};
 fs.writeFileSync(libState,JSON.stringify(oldScopedState));
 const legacyScopedToken='opds1.'+oldId+'.'+oldScoped;
 const legacyCheck=await verify(legacyScopedToken);
 assert.equal(legacyCheck.status,200);
 assert.equal(legacyCheck.json.directory,'Legacy upgrade');
 assert.equal(legacyCheck.json.folders,undefined);
 assert.equal((await upload(legacyScopedToken,'Agent 新建',[['wrong.txt','not allowed']])).status,403);

 restoreSession(ownerSession);
 const auto=setupConfig(await ui({action:'agent_setup',library:family}));
 assert.equal((await upload(auto.token,'new by agent',[['yes.txt','created only in family']])).status,200);
 assert(!fs.existsSync(path.join(data,'books','alice','new by agent')));
 assert.equal((await ui({action:'member_remove',library:family,member:'bob'})).status,303);
 assert.equal((await verify(another.token)).status,401);
 restoreSession(bobSession);
 assert.equal((await request(libraryWeb(family))).status,403);
 assert.equal((await request('up.php')).status,200);
 assert.equal((await request(url({s:modernKey,download:'Legacy upgrade/agent-only.txt'}),{headers:{cookie:''}})).text,'agent upload worked');
 pass('named invitations, mandatory multi-library picker, isolated WEB and OPDS permissions, scoped uploads and independent anonymous access');

 restoreSession(ownerSession);
 assert.equal((await ui({action:'member_invite',library:family,member:'bob',role:'reader'})).status,303);
 restoreSession(bobSession);
 assert.equal((await ui({action:'invite_accept',target_library:family})).status,303);
 assert.equal((await request(libraryWeb(family,{dir:'Legacy upgrade',download:'same.txt'}))).text,'only in shared library');
 assert.equal((await ui({action:'library_rename',library:family,title:'Not the owner'})).status,403);
 assert.equal((await ui({action:'library_archive',library:family})).status,403);
 assert.equal((await verify(auto.token)).status,200);
 restoreSession(ownerSession);
 assert.equal((await ui({action:'library_rename',library:family,title:'家庭书库 · 周末精选'})).status,303);
 assert((await request('up.php')).text.includes('家庭书库 · 周末精选'));
 assert.equal((await ui({action:'library_archive',library:family})).status,303);
 assert.equal((await verify(auto.token)).status,401);
 assert.equal((await request(url({s:modernKey}),{headers:{cookie:''}})).status,410);
 assert.equal((await ui({action:'library_restore',target_library:family})).status,303);
 assert.equal((await request(url({s:modernKey}),{headers:{cookie:''}})).status,410);
 assert.equal((await request(libraryWeb(family,{dir:'Legacy upgrade',download:'same.txt'}))).text,'only in shared library');
 assert.equal((await request(url({s:legacyKey,download:'Legacy upgrade/same.txt'}),{headers:{cookie:''}})).text,'kept in the original library');
 const audit=JSON.parse(cli('rbac-audit'));
 assert(audit.some(e=>e.event==='member.accepted'&&e.library===family));
 assert(audit.some(e=>e.event==='library_archive'&&e.actor===librarian));
 assert(!JSON.stringify(audit).includes(auto.token));
 pass('one personal library per account, fixed ownership, archive/restore and secret-free audit');

 assert.equal((await ui({action:'account_invite',username:'notallowed',operation:'create'})).status,403);
 assert(!fs.existsSync(path.join(data,'books','notallowed')));
 await switchUser('alice');
 assert((await request('up.php')).text.includes('id="accounts-dialog"'));
 const webAccount=async (username,operation='create')=>ui({action:'account_invite',username,operation});
 const readLink=res=>{assert.equal(res.status,200);return res.text.match(/id="account-activation-url" readonly value="([^"]+)"/)[1].replaceAll('&amp;','&');};
 const first=readLink(await webAccount('ellen'));
 assert(fs.existsSync(path.join(data,'books','ellen')));
 assert.equal(readState(path.join(data,'conf','users.json')).records.ellen.state,'pending');
 assert.equal((await webAccount('ellen')).status,409);
 assert.equal((await webAccount('alice','renew')).status,409);
 const second=readLink(await webAccount('ellen','renew'));
 assert.notEqual(first,second);
 cookies.clear();
 assert.equal((await activate('ellen',first)).status,403);
 assert.equal((await activate('ellen',second)).status,303);
 assert.equal((await activate('ellen',second)).status,403);
 assert.equal((await opds('ellen')).status,200);
 assert.equal(readState(path.join(data,'conf','users.json')).records.ellen.site_admin,undefined);
 cli('grant-site-admin',librarian);
 restoreSession(ownerSession);
 assert((await request('up.php')).text.includes('id="accounts-dialog"'));
 cli('revoke-site-admin',librarian);
 assert.equal((await webAccount('notallowed')).status,403);
 cli('grant-site-admin',librarian);
 pass('site admin web onboarding, one-time links, renewals and immediate permission revocation');
 fs.rmSync(path.join(data,'conf','.rate.json'),{force:true});
 await switchUser('ellen');
 const ellenSession=savedSession();
 const ellenLibrary='p-ellen';
 assert.equal((await ui({action:'folder',library:ellenLibrary,folder:'Shared'})).status,303);
 assert.equal((await scopedUpload(ellenLibrary,'Shared','retained.txt','keep this book')).status,200);
 const ellenToken=setupConfig(await ui({action:'agent_setup',library:ellenLibrary,destination:'Shared'})).token;
 assert.equal((await ui({action:'share',library:ellenLibrary,dir:'Shared'})).status,303);
 const ellenShare=(await request(libraryWeb(ellenLibrary,{dir:'Shared'}))).text.match(/\?s=([1-9]{8}-[A-Z0-9]{4})/)[1];
 assert.equal((await request(url({s:ellenShare}))).status,200);
 assert.equal((await webAccount('ellen','disable')).status,403);
 await switchUser('alice');
 const adminSession=savedSession();
 assert.equal((await webAccount('alice','disable')).status,403);
 assert.equal((await webAccount(librarian,'disable')).status,403);
 assert.equal((await webAccount('ellen','disable')).status,303);
 assert((await request('up.php?accounts=1')).text.includes('ellen was disabled.'));
 restoreSession(ellenSession);
 assert((await request('up.php')).text.includes('Your reading room'));
 assert.equal((await opds('ellen')).status,401);
 assert.equal((await verify(ellenToken)).status,401);
 assert.equal((await request(url({s:ellenShare}))).status,410);
 assert.equal(fs.readFileSync(path.join(data,'books','ellen','Shared','retained.txt'),'utf8'),'keep this book');
 restoreSession(adminSession);
 const recover=readLink(await webAccount('ellen','restore'));
 assert.equal((await opds('ellen')).status,401);
 assert.equal((await activate('ellen',recover,'restored-ellen-password')).status,303);
 assert.equal((await opds('ellen')).status,401);
 assert.equal((await request(url({download:'Shared/retained.txt'}),{headers:auth('ellen','restored-ellen-password')})).text,'keep this book');
 assert.equal((await verify(ellenToken)).status,401);
 assert.equal((await request(url({s:ellenShare}))).status,410);
 pass('site-wide disable interrupts sessions, API and OPDS; restore retains files without reviving old credentials or links');


 if(process.env.PLAYWRIGHT_MODULE && process.env.CHROME_BIN){
   const {chromium}=await import(process.env.PLAYWRIGHT_MODULE);
   const browser=await chromium.launch({executablePath:process.env.CHROME_BIN,args:['--no-sandbox']});
   try {
     // Previous workflows share the same localhost IP; reset the isolated rate fixture.
     fs.rmSync(path.join(data,'conf','.rate.json'),{force:true});
     const ctx=await browser.newContext({viewport:{width:1280,height:850},ignoreHTTPSErrors:true,locale:'zh-CN',permissions:['clipboard-read','clipboard-write']});
     const page=await ctx.newPage();
     const errors=[]; page.on('pageerror',e=>errors.push(e.message));
     await page.goto(base+'up.php');
     await page.getByLabel('用户名').fill(librarian); await page.getByLabel('密码',{exact:true}).fill(password);
     await page.getByRole('button',{name:'登录',exact:true}).click();
     await page.getByRole('heading',{name:'选择书库',exact:true}).waitFor();
     if(process.env.RBAC_SCREENSHOT_DIR) await page.screenshot({path:path.join(process.env.RBAC_SCREENSHOT_DIR,'01-选择书库.png')});
     await page.getByRole('link',{name:/家庭书库 · 周末精选/}).click();
     await page.getByRole('heading',{name:'家庭书库 · 周末精选',exact:true}).waitFor();
     await page.getByRole('link',{name:'切换书库'}).waitFor();
     await page.getByLabel('账号菜单').click();
     await page.getByLabel('你在当前书库的角色').getByText('所有者',{exact:true}).waitFor();
     assert.equal(await page.getByRole('button',{name:'新建书库',exact:true}).count(),0);
     await page.getByRole('button',{name:'连接Agent'}).click();
     const compound=page.locator('#agent-setup');
     assert.equal(await compound.locator('select,input:not([type=hidden]),details').count(),0);
     assert.equal(await compound.getByRole('button').count(),1);
     if(process.env.RBAC_SCREENSHOT_DIR) await page.screenshot({path:path.join(process.env.RBAC_SCREENSHOT_DIR,'02-一键安装Skill.png')});
     await compound.getByRole('button',{name:'复制完整 Agent 配置'}).click();
     await page.getByText('已复制，粘贴给 Agent 即可。').waitFor();
     const text=await page.evaluate(()=>navigator.clipboard.readText());
     assert.match(text,/opds1\.[a-f0-9]{24}\.[a-f0-9]{64}/);
     const copied=JSON.parse(text.match(/```json\s*([^\n]+)/)[1]);
     assert.equal(copied.endpoint,base+'api.php');
     assert(copied.folders.includes('Legacy upgrade'));
     assert(text.includes('HTTP 401')&&text.includes('「连接Agent」→「复制完整 Agent 配置」'));
     assert(text.includes('never resend a successful file'));
     assert(!copied.folders.includes('Share shelf'));
     assert(text.includes('~/.personal-opds-upload/profiles.json')&&text.includes('Authorization: Bearer <token>'));
     const check=await verify(copied.token);
     assert.equal(check.status,200);
     for(const key of ['library_id','expires_at'])assert.equal(check.json[key],copied[key]);
     assert.deepEqual(check.json.folders,copied.folders);
     assert.equal(check.json.can_create_directory,true);
     await page.locator('#tools-dialog').getByLabel('关闭').click();
     await page.waitForLoadState();
     await page.getByLabel('账号菜单').click();
     await page.getByRole('button',{name:'连接Agent'}).click();
     const management=page.locator('#tools-dialog details').filter({hasText:'管理 Agent 连接'});
     assert.equal(await management.getAttribute('open'),null);
     await management.locator('summary').click();
     const connection=management.locator('.token-row').filter({hasText:copied.token.split('.')[1].slice(0,8)});
     page.once('dialog',dlg=>dlg.accept());
     await connection.getByRole('button',{name:'撤销'}).click();
     await page.waitForLoadState();
     assert.equal((await verify(copied.token)).status,401);
     assert.deepEqual(errors,[]);
     pass('Chinese Agent-only setup copies a verified profile and keeps scoped revocation in one collapsed panel');
     await page.goto(base+libraryWeb(family));
     const account=page.getByLabel('账号菜单');
     const members=page.locator('#members-dialog');
     const settings=page.locator('#library-settings-dialog');
     await account.click(); await page.getByRole('button',{name:'书库成员',exact:true}).click();
     await members.getByRole('tab',{name:/成员/}).waitFor();
     if(process.env.RBAC_SCREENSHOT_DIR) await page.screenshot({path:path.join(process.env.RBAC_SCREENSHOT_DIR,'03-成员管理.png')});
     assert.equal(await members.getByText('归档书库').count(),0);
     assert.equal(await members.getByText('本库成员令牌').count(),0);
     await members.getByLabel('casey 的操作').click();
     await members.getByRole('button',{name:'更换角色'}).click();
     const edit=page.locator('#edit-role-dialog');
     assert.equal(await edit.locator('input[value=editor]').isChecked(),true);
     await edit.locator('input[value=reader]').check();
     assert.equal(await edit.locator('input:checked').count(),1);
     await edit.getByRole('button',{name:'保存角色'}).click();
     await members.locator('.member-line').filter({hasText:'casey'}).getByText('阅读者',{exact:true}).waitFor();
     await page.setViewportSize({width:390,height:844});
     await members.getByRole('button',{name:'邀请成员'}).click();
     const invite=page.locator('#invite-member-dialog');
     await invite.getByLabel('用户名').fill('alice');
     await invite.locator('input[value=agent_upload]').check();
     if(process.env.RBAC_SCREENSHOT_DIR) await page.screenshot({path:path.join(process.env.RBAC_SCREENSHOT_DIR,'04-手机邀请成员.png')});
     await invite.getByRole('button',{name:'发送邀请'}).click();
     await members.getByRole('tab',{name:/邀请记录/}).waitFor();
     assert.equal(await members.getByRole('tab',{name:/邀请记录/}).getAttribute('aria-selected'),'true');
     const row=members.locator('.invitation-entry').filter({hasText:'alice'});
     await row.getByRole('button',{name:'复制邀请链接'}).click();
     await row.getByText('已复制。',{exact:true}).waitFor();
     const inviteLink=await page.evaluate(()=>navigator.clipboard.readText());
     assert.match(inviteLink,/target=p-dana&invitation=[a-f0-9]{32}$/);
     const guest=await browser.newPage({ignoreHTTPSErrors:true});
     try {
       await guest.goto(inviteLink);
       await guest.getByRole('heading',{name:'Library invitation'}).waitFor();
       assert.equal(await guest.getByRole('button',{name:'Accept invitation'}).count(),0);
       await guest.getByLabel('Username').fill('alice');
       await guest.getByLabel('Password',{exact:true}).fill(password);
       await guest.getByRole('button',{name:'Sign in'}).click();
       await guest.getByRole('button',{name:'Accept invitation'}).click();
       await guest.getByText('Invitation accepted.',{exact:true}).waitFor();
       assert.equal((await guest.goto(inviteLink)).status(),410);
     } finally {await guest.close();}
     await row.getByText('待接受',{exact:true}).waitFor();
     const beforeRefresh=page.url();
     await members.getByLabel('刷新邀请状态').click();
     await row.getByText('已接受',{exact:true}).waitFor();
     assert.equal(page.url(),beforeRefresh);
     assert.equal(await row.getByRole('button',{name:'复制邀请链接'}).count(),0);
     await members.getByRole('tab',{name:/^成员/}).click();
     await members.locator('#member-current').getByText('alice',{exact:true}).waitFor();
     await members.getByLabel('alice 的操作').click();
     page.once('dialog',dialog=>dialog.accept());
     await members.getByRole('button',{name:'移出书库'}).click();
     await members.getByText('alice',{exact:true}).waitFor({state:'hidden'});
     assert.equal(await members.locator('#member-current').getByText('alice',{exact:true}).count(),0);
     assert.equal((await opds('alice')).status,200);
     assert.equal((await opds('alice',{library:family})).status,403);
     await members.getByLabel('关闭').click();
     await account.click(); await page.getByRole('button',{name:'书库设置',exact:true}).click();
     const generalTab=settings.getByRole('tab',{name:'基本设置'});
     const archiveTab=settings.getByRole('tab',{name:'归档',exact:true});
     const titleField=settings.getByLabel('书库名称');
     await generalTab.waitFor();
     assert.equal(await generalTab.getAttribute('aria-selected'),'true');
     assert.equal(await settings.getByRole('button',{name:'归档书库'}).count(),0);
     const labelBox=await settings.locator('label[for=settings-library-name]').boundingBox();
     const titleBox=await titleField.boundingBox();
     assert(labelBox.y+labelBox.height<titleBox.y && Math.abs(labelBox.width-titleBox.width)<=1);
     if(process.env.RBAC_SCREENSHOT_DIR) await page.screenshot({path:path.join(process.env.RBAC_SCREENSHOT_DIR,'05-书库基本设置.png')});
     await generalTab.focus(); await page.keyboard.press('ArrowRight');
     assert.equal(await archiveTab.getAttribute('aria-selected'),'true');
     assert.equal(await titleField.isVisible(),false);
     const archiveButton=settings.getByRole('button',{name:'归档书库',exact:true});
     await archiveButton.waitFor();
     if(process.env.RBAC_SCREENSHOT_DIR) await page.screenshot({path:path.join(process.env.RBAC_SCREENSHOT_DIR,'06-书库归档设置.png')});
     const archiveConfirmation=page.waitForEvent('dialog').then(async prompt=>{
       assert.match(prompt.message(),/归档/);await prompt.dismiss();
     });
     await archiveButton.click();await archiveConfirmation;
     await generalTab.click();
     await titleField.fill('   ');
     await settings.getByRole('button',{name:'保存名称'}).click();
     await settings.getByRole('alert').waitFor();
     assert.equal(await generalTab.getAttribute('aria-selected'),'true');
     assert.equal(await settings.getByText('转让所有权').count(),0);
     await settings.getByLabel('关闭').click();
     await page.goto(base+libraryWeb(tech));
     await account.click();
     const currentRole=page.getByLabel('你在当前书库的角色');
     await currentRole.getByText(thirdUser+' 的书库',{exact:true}).waitFor();
     await currentRole.getByText('阅读者',{exact:true}).waitFor();
     await page.getByRole('button',{name:'站点账号',exact:true}).click();
     const accountDialog=page.locator('#accounts-dialog');
     await accountDialog.locator('.account-record').filter({hasText:'ellen'}).getByText('已激活',{exact:true}).waitFor();
     await accountDialog.getByLabel('用户名').fill('frank');
     await accountDialog.getByRole('button',{name:'创建账号并生成链接'}).click();
     await accountDialog.getByRole('button',{name:'复制激活链接'}).click();
     assert.match(await page.evaluate(()=>navigator.clipboard.readText()),/account=frank&activate=[a-f0-9]{64}$/);
     const accountRow=accountDialog.locator('.account-record').filter({hasText:'frank'});
     page.once('dialog',dialog=>dialog.accept());
     await accountRow.getByRole('button',{name:'禁用账号'}).click();
     await accountRow.getByText('已禁用',{exact:true}).waitFor();
     await accountRow.getByRole('button',{name:'恢复账号'}).click();
     await accountRow.getByText('待激活',{exact:true}).waitFor();
     await accountDialog.getByRole('button',{name:'复制激活链接'}).waitFor();

     assert.deepEqual(errors,[]);
     pass('Chinese desktop/mobile member tabs, single-role editing and invitations, separate library settings');
   } finally { await browser.close(); }
 }
 {
 const dir='Online reader checks', fixture=path.join(temp,'readable.epub');
 const png='iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j2ZkAAAAASUVORK5CYII=';
 execFileSync(php,['-r',`
    $z=new ZipArchive();$z->open($argv[1],ZipArchive::CREATE);
    $z->addFromString("mimetype","application/epub+zip");$z->setCompressionName("mimetype",ZipArchive::CM_STORE);
    $z->addFromString("META-INF/container.xml",'<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="book.opf" media-type="application/oebps-package+xml"/></rootfiles></container>');
    $z->addFromString("book.opf",'<package><metadata/><manifest>
    <item id="intro" href="read/one.xhtml" media-type="application/xhtml+xml"/>
    <item id="second" href="read/two.xhtml" media-type="application/xhtml+xml"/>
    <item id="cover" href="cover.png" media-type="image/png"/>
    <item id="nav" href="nav.xhtml" properties="nav" media-type="application/xhtml+xml"/>
    </manifest><spine><itemref idref="intro"/><itemref idref="second"/></spine></package>');
    $nav='';$subsections='';
    for ($i=1;$i<=32;$i++) {
      $nav.='<li><a href="read/two.xhtml#sub-'.$i.'">Subsection '.$i.'</a></li>';
      $subsections.='<h3 id="sub-'.$i.'">Topic '.$i.'</h3>'.str_repeat('<p>Topic reading text.</p>',12);
    }
    $z->addFromString("nav.xhtml",'<html><body><nav epub:type="toc"><ol><li><a href="read/one.xhtml">Opening pages</a></li><li><a href="read/two.xhtml#return-here">Second chapter</a></li>'.$nav.'</ol></nav></body></html>');
    $z->addFromString("read/one.xhtml",'<html><body><h2>Opening text</h2><p>First chapter.</p>
    <a href="two.xhtml#return-here">Go to chapter two</a><img src="../cover.png" alt="Book image" onload="alert(1)">
    <iframe src="https://example.invalid/frame"></iframe><script>alert(1)</script>
    <img src="https://example.invalid/image"><a href="https://example.invalid/">External</a></body></html>');
    $z->addFromString("read/two.xhtml",'<html><body><h2 id="return-here">The second chapter</h2>'.
    str_repeat('<p>This chapter has enough text to scroll and test saved progress on reload.</p>',60).$subsections.'</body></html>');
    $z->addFromString("other.bin",random_bytes(4*1024*1024));$z->setCompressionName("other.bin",ZipArchive::CM_STORE);
    $z->addFromString("cover.png",base64_decode($argv[2]));$z->close();
 `,fixture,png]);
 fs.rmSync(path.join(data,'conf','.rate.json'),{force:true});cookies.clear();
 assert.equal((await ui({action:'login',username:'alice',password})).status,303);
 const readerToken=getLegacyToken('alice');
 const text='回到上次阅读的位置。Welcome to the test book.\n'.repeat(25000);
 const txtGB=Buffer.from([0xd6,0xd0,0xce,0xc4,0x0a]);
 assert.equal((await upload(readerToken,dir,[['readable.epub',fs.readFileSync(fixture)],['long.txt',text],['gbk.txt',txtGB]])).status,200);
 const previewURL=(file,params={})=>'preview.php?'+new URLSearchParams({library:'p-alice',dir,book:file,...params});
 const shelfURL='up.php?'+new URLSearchParams({library:'p-alice',dir});
 const getConfig=page=>JSON.parse(page.text.match(/data-config="([^"]+)"/)[1].replace(/&quot;/g,'"').replace(/&amp;/g,'&'));
 const readerPage=await request(previewURL('readable.epub'));
 assert.equal(readerPage.status,200,readerPage.text.slice(0,900));
 assert(!readerPage.text.includes('Opening text')); // no book payload in the HTML shell
 const readerApi=getConfig(readerPage).url;
 const first=await request(readerApi+'&part=0');
 assert.equal(first.status,200,first.text);assert(first.json.html.includes('Opening text'));
 assert(!/The second chapter|example\.invalid|onload=|<script|<iframe/.test(first.json.html));
 assert(first.text.length<2500);assert(fs.statSync(fixture).size>4*1024*1024);
 assert.equal((await request(readerApi+'&part=1')).json.count,2);
 assert.equal((await request(readerApi+'&toc=1')).json.toc[1][1],'return-here');
 assert.equal((await request(readerApi+'&asset=cover.png')).headers['content-type'],'image/png');
 assert.equal((await request(readerApi+'&asset=other.bin')).status,404);
 const signedInReader=savedSession();
 assert.equal((await request(readerApi+'&part=0',{headers:{cookie:''}})).status,401);
 assert.equal((await request(readerApi+'&asset=cover.png',{headers:{cookie:'',...auth('alice',password)}})).status,401);
 restoreSession(signedInReader);
 assert.equal((await request(previewURL('../private.txt'))).status,400);
 assert.equal((await request(previewURL('readable.epub',{version:'bad',part:0}))).status,409);
 assert.match((await request(shelfURL)).text,/class="book-name" href="preview\.php/);
 const txtApi=getConfig(await request(previewURL('long.txt'))).url;
 const utf=await request(txtApi+'&part=0');assert.equal(utf.status,200,utf.text.slice(0,400));
 assert(utf.json.total>1000000&&utf.json.next<26000);
 assert(Buffer.from(utf.json.bytes,'base64').toString().startsWith('回到上次阅读的位置'));
 assert.equal((await request(txtApi+'&part='+utf.json.next+'&encoding=utf-8')).json.offset,utf.json.next);
 const gb=await request(getConfig(await request(previewURL('gbk.txt'))).url+'&part=0');
 assert.equal(gb.json.encoding,'gb18030');assert.equal(new TextDecoder('gb18030').decode(Buffer.from(gb.json.bytes,'base64')),'中文\n');
 const seekGB=await request(getConfig(await request(previewURL('gbk.txt'))).url+'&part=1&direction=seek');
 assert.equal(seekGB.json.offset,2);
 assert.equal(new TextDecoder('gb18030').decode(Buffer.from(seekGB.json.bytes,'base64')),'文\n');
 const seekUTF=await request(txtApi+'&part=1&encoding=utf-8&direction=seek');
 assert.equal(seekUTF.json.offset,3);
 assert(Buffer.from(seekUTF.json.bytes,'base64').toString().startsWith('到上次'));
 const previousUTF=await request(txtApi+'&part='+utf.json.next+'&encoding=utf-8&direction=before');
 assert.equal(previousUTF.json.next,utf.json.next);
 assert.equal(previousUTF.json.bytes,utf.json.bytes);
 const endUTF=await request(txtApi+'&part='+utf.json.total+'&encoding=utf-8&direction=seek');
 assert.equal(endUTF.json.next,utf.json.total);
 pass('online reader authorization on every request, bounded first chapter/segment, protected EPUB images and TOC, UTF-8/GBK');

 if(process.env.PLAYWRIGHT_MODULE && process.env.CHROME_BIN){
   const {chromium}=await import(process.env.PLAYWRIGHT_MODULE);
   const browser=await chromium.launch({executablePath:process.env.CHROME_BIN,args:['--no-sandbox']});
   try {
     const ctx=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1200,height:800}});
     for(const cookie of cookies.values()){
         const [name,...v]=cookie.split('=');await ctx.addCookies([{name,value:v.join('='),url:base,secure:true}]);
     }
     const web=await ctx.newPage();const fetched=[];const errors=[];
     web.on('request',req=>fetched.push(req.url()));web.on('pageerror',err=>errors.push(err.message));
     await web.goto(base+shelfURL);
     await web.getByRole('link',{name:'readable',exact:true}).click();
     await web.getByText('Opening text',{exact:true}).waitFor();
     assert.equal(fetched.filter(u=>u.includes('&part=')).length,1);
     assert(!fetched.some(u=>u.includes('example.invalid')||u.includes('&toc=')));
     const checkImmersion=async (x,y)=>{
       const vp=web.locator('#viewport');
       const height=await vp.evaluate(async el=>{
         el.scrollTop=Math.min(el.scrollTop,Math.max(0,el.scrollHeight-el.clientHeight-250));
         await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
         return el.clientHeight;
       });
       await web.mouse.move(x,y);
       await web.mouse.wheel(0,170);
       await web.waitForFunction(()=>document.body.hasAttribute('data-header-hidden'));
       await web.waitForFunction(()=>getComputedStyle(document.querySelector('.reader-bar')).opacity==='0');
       assert.equal(await vp.evaluate(el=>el.clientHeight),height);
       assert(await web.locator('.contents-fab').isVisible());
       await web.mouse.click(x,y);
       await web.waitForFunction(()=>!document.body.hasAttribute('data-header-hidden'));
       await web.waitForFunction(()=>getComputedStyle(document.querySelector('.reader-bar')).opacity==='1');
       assert.equal(await vp.evaluate(el=>el.clientHeight),height);
     };
     const drawer=web.getByRole('dialog',{name:'Contents'});
     const contents=web.getByRole('button',{name:'Contents',exact:true});
     assert.equal(await web.locator('.reader-footer').count(),0);
     const fab=await contents.boundingBox();
     assert(fab.x<25&&fab.y+fab.height>770);
     await contents.click();
     await drawer.getByRole('button',{name:'Opening pages'}).waitFor();
     assert.equal(await drawer.getByRole('button',{name:'Opening pages'}).getAttribute('aria-current'),'location');
     await drawer.evaluate(el=>Promise.all(el.getAnimations().map(a=>a.finished)));
     assert(Math.abs((await drawer.boundingBox()).x)<1);
     await web.mouse.click(1000,370);
     await drawer.waitFor({state:'hidden'});
     assert.equal(await contents.getAttribute('aria-expanded'),'false');
     await contents.click();
     await drawer.getByRole('button',{name:'Second chapter'}).click();
     await web.getByText('The second chapter',{exact:true}).waitFor();
     await web.locator('#viewport').evaluate(v=>v.scrollTop=2200);await web.waitForTimeout(240);
     await web.reload();await web.getByText('The second chapter',{exact:true}).waitFor();
     assert((await web.locator('#viewport').evaluate(v=>v.scrollTop))>1500);
     await checkImmersion(600,380);
     await web.getByRole('button',{name:'Reading controls'}).click();
     await web.getByRole('button',{name:'Reading settings'}).click();
     await web.getByLabel('Theme').selectOption('warm');
     await web.getByLabel('Reading mode').selectOption('page');
     await web.getByRole('button',{name:'Close',exact:true}).click();
     await web.reload();await web.getByText('The second chapter',{exact:true}).waitFor();
     assert.equal(await web.locator('html').getAttribute('data-theme'),'warm');
     assert.equal(await web.locator('#reader').getAttribute('data-mode'),'page');
     await web.setViewportSize({width:390,height:844});
     await contents.click();
     await drawer.getByRole('button',{name:'Second chapter'}).waitFor();
     await drawer.evaluate(el=>Promise.all(el.getAnimations().map(a=>a.finished)));
     assert((await drawer.boundingBox()).width<390);
     await web.mouse.click(382,405);
     await drawer.waitFor({state:'hidden'});
     await contents.click();
     await web.keyboard.press('Escape');
     await drawer.waitFor({state:'hidden'});
     await web.locator('[data-book-anchor="sub-28"]').evaluate(heading=>heading.scrollIntoView({block:'start'}));
     const beforeDrawer=await web.locator('#viewport').evaluate(el=>el.scrollTop);
     await contents.click();
     const focused=drawer.getByRole('button',{name:'Subsection 28',exact:true});
     await focused.waitFor();
     await drawer.evaluate(el=>Promise.all(el.getAnimations().map(a=>a.finished)));
     assert.equal(await focused.getAttribute('aria-current'),'location');
     assert.equal(await drawer.locator('[aria-current]').count(),1);
     const scroller=drawer.locator('#chapters');
     const drawerBox=await scroller.boundingBox(), focusedBox=await focused.boundingBox();
     assert(focusedBox.y>=drawerBox.y&&focusedBox.y+focusedBox.height<=drawerBox.y+drawerBox.height);
     assert((await scroller.evaluate(el=>el.scrollTop))>300);
     assert.equal(await drawer.evaluate(el=>el.scrollTop),0);
     assert.equal(await web.locator('#viewport').evaluate(el=>el.scrollTop),beforeDrawer);

     // The selected heading is near the end of the XHTML: it cannot reach
     // the reading line. The requested destination must win before and after
     // a deliberately slow reload of that same EPUB spine item.
     let releaseChapter,forwarded;
     const waitChapter=new Promise(resolve=>{releaseChapter=resolve;});
     const chapterForwarded=new Promise(resolve=>{forwarded=resolve;});
     const chapterQuery=url=>url.pathname.endsWith('/preview.php')&&url.searchParams.get('part')==='1';
     const slowChapter=async route=>{await waitChapter;try{await route.continue();}finally{forwarded();}};
     await web.route(chapterQuery,slowChapter);
     try{
       await drawer.getByRole('button',{name:'Subsection 32',exact:true}).click();
       await drawer.waitFor({state:'hidden'});
       await contents.click();
       assert.equal(await drawer.locator('[aria-current]').innerText(),'Subsection 32','reopening during navigation must show the chosen section');
       assert(await web.locator('#book[aria-busy="true"]').count());
       releaseChapter();
       await web.locator('#book[aria-busy="false"]').waitFor();
       assert.equal(await drawer.locator('[aria-current]').innerText(),'Subsection 32','chapter load must keep the exact selection near the end');
     }finally{
       releaseChapter();
       await Promise.race([chapterForwarded,delay(3000)]);
       await web.unroute(chapterQuery,slowChapter);
     }
     await web.keyboard.press('Escape');
     await drawer.waitFor({state:'hidden'});
     await web.getByRole('link',{name:'Back to library'}).click();
     await web.getByRole('link',{name:'readable',exact:true}).waitFor();
     await web.setViewportSize({width:390,height:844});
     await web.getByRole('link',{name:'long',exact:true}).click();
     const blocks=web.locator('.text-segment'), viewport=web.locator('#viewport');
     await blocks.first().waitFor();
     assert.equal(await web.locator('.reader-footer').count(),0);
     assert((await blocks.first().textContent()).includes('回到上次阅读的位置'));
     assert.equal(await web.evaluate(()=>document.documentElement.scrollWidth),390);
     assert.equal(await blocks.count(),1);
     const position=web.getByRole('button',{name:'Go to position',exact:true});
     const positionDialog=web.getByRole('dialog',{name:'Go to position'});
     await viewport.evaluate(el=>el.scrollTop=el.scrollHeight-el.clientHeight*2);
     await blocks.nth(1).waitFor();
     const joined=await web.locator('.plain-text').textContent();
     await checkImmersion(200,420);
     assert.equal(joined,text.slice(0,joined.length),'chunk boundaries must not alter visible text');
     await position.click();
     await positionDialog.getByRole('slider',{name:'Reading position'}).fill('60');
     await positionDialog.getByText('60%',{exact:true}).waitFor();
     const sought=web.waitForResponse(response=>response.url().includes('direction=seek'));
     await positionDialog.getByRole('button',{name:'Jump to position'}).click();
     assert.equal((await (await sought).json()).offset>=Math.floor(Buffer.byteLength(text)*.60),true);
     await positionDialog.waitFor({state:'hidden'});
     await position.click();
     assert.equal(await positionDialog.getByRole('slider',{name:'Reading position'}).inputValue(),'60');
     await web.keyboard.press('Escape');
     await positionDialog.waitFor({state:'hidden'});
     await web.reload();
     await blocks.first().waitFor();
     await position.click();
     assert.equal(await positionDialog.getByRole('slider',{name:'Reading position'}).inputValue(),'60');
     await positionDialog.getByRole('button',{name:'Start of book'}).click();
     await positionDialog.waitFor({state:'hidden'});
     await position.click();
     assert.equal(await positionDialog.getByRole('slider',{name:'Reading position'}).inputValue(),'0');
     assert.deepEqual(errors,[]);
     pass('desktop/mobile EPUB drawer, current subsection centered on reopen, continuous TXT, percentage jump and resume, and header fades without layout movement');
   } finally { await browser.close(); }
 }
 if(process.env.PLAYWRIGHT_MODULE && process.env.OPDS_TEST_WEBKIT==='1'){
   const {webkit,devices}=await import(process.env.PLAYWRIGHT_MODULE);
   const browser=await webkit.launch();
   try{
     const ctx=await browser.newContext({...devices['iPhone 13'],ignoreHTTPSErrors:true});
     for(const cookie of cookies.values()){
       const [name,...v]=cookie.split('=');await ctx.addCookies([{name,value:v.join('='),url:base,secure:true}]);
     }
     const web=await ctx.newPage();
     await web.goto(base+previewURL('readable.epub'));
     await web.getByText('Opening text',{exact:true}).waitFor();
     const fab=web.getByRole('button',{name:'Contents',exact:true}), drawer=web.getByRole('dialog',{name:'Contents'});
     await fab.tap();
     await drawer.getByRole('button',{name:'Second chapter',exact:true}).tap();
     await drawer.waitFor({state:'hidden'});
     const heading=web.locator('[data-book-anchor="sub-28"]');
     await heading.evaluate(el=>el.scrollIntoView({block:'start'}));
     const reading=await web.locator('#viewport').evaluate(el=>el.scrollTop);
     for(let attempt=0;attempt<2;attempt++){
       await fab.tap();
       await web.waitForFunction(()=>{
         const scroller=document.querySelector('#chapters'), active=scroller.querySelector('[aria-current]');
         if(!active||active.textContent!=='Subsection 28'||scroller.scrollTop<300)return false;
         if(document.querySelector('#toc').getAnimations().some(a=>a.playState==='running'))return false;
         const view=scroller.getBoundingClientRect(), item=active.getBoundingClientRect();
         return item.top>=view.top&&item.bottom<=view.bottom;
       });
       assert.equal(await web.locator('#viewport').evaluate(el=>el.scrollTop),reading);
       assert.equal(await drawer.evaluate(el=>el.scrollTop),0);
       await drawer.locator('#chapters').evaluate(el=>el.scrollTop=0);
       await drawer.getByRole('button',{name:'Close',exact:true}).tap();
       await drawer.waitFor({state:'hidden'});
     }
     pass('iPhone-sized WebKit touch: a distant current EPUB section is visible on both opens after animation');
   }finally{await browser.close();}
 }
 {
   cookies.clear();
   const signedIn=await ui({action:'login',username:'alice',password});
   assert.equal(signedIn.status,303);
   const header=signedIn.headers['set-cookie'].find(value=>/^OPDS_LIBRARY=/.test(value)&&/Max-Age=25919[9][9]|Max-Age=2592000/.test(value));
   assert(header,'login cookie must persist for 30 days');
   assert.match(header,/path=\/library\/; secure; HttpOnly; SameSite=Strict/i);
   const cookie=cookies.get('OPDS_LIBRARY');
   const id=cookie.split('=')[1];
   const storage=path.join(data,'conf','web-sessions');
   const stateFile=path.join(storage,'sess_'+id);
   assert.equal(fs.statSync(storage).mode&0o777,0o700);
   assert.equal(fs.statSync(stateFile).mode&0o777,0o600);
   const original=fs.readFileSync(stateFile,'utf8');
   assert.match(original,/issued\|i:[0-9]+;/);
   const issuedAt=days=>{
     const timestamp=Math.floor(Date.now()/1000)-days*86400;
     fs.writeFileSync(stateFile,original.replace(/issued\|i:[0-9]+;/,'issued|i:'+timestamp+';'));
     fs.utimesSync(stateFile,timestamp,timestamp);
   };
   issuedAt(29);
   const dashboard=await request(shelfURL);
   assert(dashboard.text.includes('readable.epub'));
   assert(!dashboard.headers['set-cookie']?.some(h=>/Max-Age=259/.test(h)),'activity must not extend the deadline');
   assert.equal((await request(previewURL('long.txt'))).status,200);
   issuedAt(30);
   assert.equal((await request(previewURL('long.txt'))).status,401);
   assert(!(await request(shelfURL)).text.includes('readable.epub'));
   assert.equal((await ui({action:'login',username:'alice',password})).status,303);
   const revoked=cookies.get('OPDS_LIBRARY');
   const logout=await ui({action:'logout'});
   assert.equal(logout.status,303);
   assert(logout.headers['set-cookie'].some(value=>/OPDS_LIBRARY=.*Max-Age=0/i.test(value)));
   assert(!fs.existsSync(path.join(storage,'sess_'+revoked.split('=')[1])));
   assert.equal((await request(previewURL('long.txt'),{headers:{cookie:revoked}})).status,401);
   pass('30-day persistent web login, no idle expiry or sliding renewal, identical reader expiry and immediate logout revocation');
 }
 }
 {
 // Move the real PHP application without changing config.php or private data.
 fs.rmSync(path.join(data,'conf','.rate.json'),{force:true});
 const relocated=path.join(web,'opds');
 fs.renameSync(app,relocated);
 const moved=new URL('/opds/',base).href;
 cookies.clear();
 const signIn=await request(moved+'up.php');
 assert.equal(signIn.status,200);
 assert((signIn.headers['set-cookie']??[]).some(cookie=>/path=\/opds\//i.test(cookie)));
 const loginMoved=await post(moved+'up.php',{action:'login',csrf:csrf(signIn),username:'alice',password});
 assert.equal(loginMoved.status,303);
 assert.equal(loginMoved.headers.location,moved+'up.php');
 const shelf=await request(moved+'up.php');
 assert(shelf.text.includes('My personal library'));
 const xml=await request(moved+'index.php',{headers:{...auth('alice',password),host:'untrusted.example','x-forwarded-host':'untrusted.example','x-forwarded-prefix':'/wrong'}});
 assert.equal(xml.status,200); assert(xml.text.includes(moved+'index.php')); assert(!xml.text.includes('untrusted.example'));
 assert.equal((await request(moved+url({s:legacyKey,download:'Legacy upgrade/same.txt'}),{headers:{cookie:''}})).text,'kept in the original library');
 const setup=await post(moved+'up.php',{action:'agent_setup',csrf:csrf(shelf)});
 assert.equal(setup.status,200); assert(setup.json.setup.includes(moved+'api.php'));
 const created=await post(moved+'up.php',{action:'account_invite',csrf:csrf(shelf),username:'moveduser',operation:'create'});
 assert.equal(created.status,200); assert(created.text.includes(moved+'up.php?account=moveduser'));
 const cliLink=execFileSync(php,[path.join(relocated,'admin.php'),'invite','movedcli'],{encoding:'utf8',env:{...process.env,OPDS_BASE_URL:moved}}).trim();
 assert(cliLink.startsWith(moved+'up.php?account=movedcli'));
 if(process.env.PLAYWRIGHT_MODULE && process.env.CHROME_BIN){
   const {chromium}=await import(process.env.PLAYWRIGHT_MODULE);
   const browser=await chromium.launch({executablePath:process.env.CHROME_BIN,args:['--no-sandbox']});
   try {
     const ctx=await browser.newContext({ignoreHTTPSErrors:true});
     await ctx.addCookies([{name:'OPDS_LIBRARY',value:'old-install-cookie',domain:'localhost',path:'/library/',secure:true,httpOnly:true}]);
     const page=await ctx.newPage();
     await page.goto(moved+'up.php');
     await page.getByLabel('Username',{exact:true}).fill('alice');
     await page.getByLabel('Password',{exact:true}).fill(password);
     await page.getByRole('button',{name:'Sign in',exact:true}).click();
     await page.getByRole('heading',{name:'My personal library',exact:true}).waitFor();
     assert(page.url().startsWith(moved));
     assert((await ctx.cookies(moved)).some(cookie=>cookie.path==='/opds/'));
   } finally { await browser.close(); }
 }
 pass('physical relocation without configuration changes: browser login, cookies, feed, anonymous download, and issued links follow the new path');
 }
 console.log(`Passed ${results.length} integration suites.`);
} catch(e) {
 console.error(fs.readFileSync(path.join(temp,'php.log'),'utf8').split('\n').slice(-30).join('\n').replace(/((?:activate|s)=)[^&\s]+/g,'$1[redacted]'));
 throw e;
} finally {
 proxy.closeAllConnections();await new Promise(r=>proxy.close(r));
 try{process.kill(-server.pid,'SIGTERM');}catch{}
 fs.closeSync(log);fs.chmodSync(dataParent,0o700);fs.rmSync(temp,{recursive:true,force:true});
}
