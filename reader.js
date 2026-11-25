'use strict';
(() => {
 const $ = id => document.getElementById(id);
 const app=$('reader'), cfg=JSON.parse(app.dataset.config);
 const vp=$('viewport'), book=$('book'), status=$('status'), more=$('continue');
 const progress=$('progress'), previous=$('previous'), next=$('next');
 const prefix='personal-opds:reader:v1:'+location.pathname+':'+cfg.profile+':';
 const prefsKey=prefix+'settings', posKey=prefix+cfg.book;
 const read=key=>{try{return JSON.parse(localStorage.getItem(key))||{};}catch{return {};}};
 const write=(key,value)=>{try{localStorage.setItem(key,JSON.stringify(value));}catch{}};
 const prefs=read(prefsKey), saved=read(posKey);
 const txt=cfg.format==='txt';
 let encoding=['utf-8','gb18030'].includes(saved.encoding)?saved.encoding:'';
 let textChoice=['utf-8','gb18030'].includes(saved.textChoice)?saved.textChoice:'';
 let part=0, data=null, busy=false, requestNo=0, failed=null, closeTimer=0, saveTimer=0;
 const boundaries=new Map();
 const validPart=value=>Number.isSafeInteger(value)&&value>=0&&value<=100*1024*1024;
 if (txt&&Array.isArray(saved.boundaries)) for (const [start,end] of saved.boundaries.slice(-4096)) {
     if(validPart(start)&&validPart(end)&&end>start)boundaries.set(end,start);
 }
 const clamp=value=>Math.min(1,Math.max(0,Number(value)||0));
 const limit=()=>Math.max(0,vp.scrollHeight-vp.clientHeight);
 const scrollRatio=()=>limit()>0?clamp(vp.scrollTop/limit()):0;
 const format=(template,a,b)=>template.replace('%d',a).replace('%d',b);
 function position() {
     if(!data||busy||failed)return;
     write(posKey,{part,ratio:scrollRatio(),encoding,textChoice,boundaries:txt?[...boundaries].map(([end,start])=>[start,end]):undefined});
 }
 function applyPrefs() {
     document.documentElement.dataset.theme=$('theme').value;
     app.dataset.mode=$('mode').value;
     app.style.setProperty('--font',Number($('size').value)+'px');
     app.style.setProperty('--leading',$('spacing').value);
 }
 for (const id of ['size','spacing','theme','mode']) {
     const el=$(id);
     if(prefs[id]!=null){
         if(el instanceof HTMLSelectElement){if([...el.options].some(o=>o.value===prefs[id]))el.value=prefs[id];}
         else if(Number.isFinite(+prefs[id]))el.value=prefs[id];
     }
     el.addEventListener('input',()=>{
         const ratio=scrollRatio();
         prefs[id]=el.value;applyPrefs();
         vp.scrollTop=ratio*limit();
         write(prefsKey,prefs); position();
     });
 }
 applyPrefs();
 if(txt)$('encoding').value=textChoice;
 const prevPart=()=>txt?boundaries.get(part):part>0?part-1:undefined;
 const nextPart=()=>!data?undefined:txt?(data.next<data.total?data.next:undefined):(part+1<data.count?part+1:undefined);
 function displayProgress(){
     if(!data)return;
     const offset=limit()>0?scrollRatio():(nextPart()===undefined?1:0);
     const ratio=txt?(data.total?(part+(data.next-part)*offset)/data.total:1):(part+offset)/data.count;
     const percent=new Intl.NumberFormat(document.documentElement.lang,{style:'percent'}).format(clamp(ratio));
     progress.textContent=txt?percent:format(cfg.part,part+1,data.count)+' · '+percent;
     previous.disabled=busy||!!failed||(vp.scrollTop<1&&prevPart()===undefined);
     next.disabled=busy||!!failed||(vp.scrollTop>=limit()-1&&nextPart()===undefined);
     more.hidden=!!failed||nextPart()===undefined||app.dataset.mode==='page';
 }
 async function get(query){
     const response=await fetch(cfg.url+'&'+new URLSearchParams(query),{cache:'no-store',credentials:'same-origin'});
     let result;try{result=await response.json();}catch{throw new Error(cfg.failed);}
     if(!response.ok)throw new Error(result.error||cfg.failed);
     return result;
 }
 function jumpAnchor(fragment){
     if(!fragment)return false;
     const anchor=[...book.querySelectorAll('[data-book-anchor]')].find(el=>el.dataset.bookAnchor===fragment);
     if(!anchor)return false;
     anchor.scrollIntoView({block:'start'});return true;
 }
 async function load(target,ratio=0,fragment=''){
     const seq=++requestNo;
     clearTimeout(saveTimer);
     busy=true; failed=null;
     book.setAttribute('aria-busy','true');
     previous.disabled=next.disabled=true;more.hidden=true;
     $('reader-message').hidden=false;status.textContent=cfg.loading;$('retry').hidden=true;
     progress.textContent='';
     // Keep the old chapter on screen until the requested one returns.
     try {
         const result=await get({part:target,...(txt?{encoding:encoding||textChoice}:{})});
         if(seq!==requestNo)return;
         if(txt){
             const bytes=Uint8Array.from(atob(result.bytes),c=>c.charCodeAt(0));
             const decoded=new TextDecoder(result.encoding,{fatal:false}).decode(bytes);
             book.replaceChildren();
             const pre=document.createElement('div');pre.className='plain-text';pre.textContent=decoded;book.append(pre);
             encoding=result.encoding;
             if(result.next>result.offset)boundaries.set(result.next,result.offset);
             part=result.offset;
         }else{
             // Server output is rebuilt using a strict HTML and attribute allowlist.
             book.innerHTML=result.html;
             part=target;
         }
         data=result;
         $('reader-message').hidden=true;status.textContent='';
         busy=false;displayProgress();
         if(!jumpAnchor(fragment))vp.scrollTop=clamp(ratio)*limit();
         displayProgress();position();
     }catch(error){
         if(seq!==requestNo)return;
         failed=()=>load(target,ratio,fragment);
         status.textContent=error.message||cfg.failed;$('retry').hidden=false;
         busy=false;displayProgress();
     }finally{if(seq===requestNo)book.setAttribute('aria-busy','false');}
 }
 function step(dir){
     if(busy||!data)return;
     if(dir>0&&vp.scrollTop>=limit()-2){const n=nextPart();if(n!==undefined)load(n);return;}
     if(dir<0&&vp.scrollTop<=1){const p=prevPart();if(p!==undefined)load(p,1);return;}
     vp.scrollBy({top:dir*Math.max(96,vp.clientHeight-56),behavior:'instant'});
 }
 previous.addEventListener('click',()=>step(-1));next.addEventListener('click',()=>step(1));
 more.addEventListener('click',()=>{const n=nextPart();if(n!==undefined&&!busy)load(n);});
 $('retry').addEventListener('click',()=>failed?.());
 vp.addEventListener('scroll',()=>{
     if(busy)return;
     displayProgress();clearTimeout(saveTimer);saveTimer=setTimeout(position,180);
 },{passive:true});
 window.addEventListener('pagehide',position);
 document.addEventListener('visibilitychange',()=>{if(document.hidden)position();});
 vp.addEventListener('load',displayProgress,true);
 window.addEventListener('resize',displayProgress);
 function toolbar(open){
     clearTimeout(closeTimer);
     $('toolbar').hidden=!open;$('controls').setAttribute('aria-expanded',String(open));
     // Do not hide a toolbar while keyboard focus is within it.
     if(open)closeTimer=setTimeout(()=>{if(!$('toolbar').contains(document.activeElement))toolbar(false);},5500);
 }
 $('controls').addEventListener('click',()=>toolbar($('toolbar').hidden));
 vp.addEventListener('click',event=>{
     const link=event.target.closest('a[data-part]');
     if(link){
         event.preventDefault();
         const to=Number(link.dataset.part);
         if(to===part&&!busy)jumpAnchor(link.dataset.fragment);
         else load(to,0,link.dataset.fragment);
         return;
     }
     if(event.target.closest('button')||getSelection()?.toString())return;
     if(app.dataset.mode==='page'&&(event.clientX<innerWidth*.22||event.clientX>innerWidth*.78)){
         step(event.clientX<innerWidth*.22?-1:1);return;
     }
     toolbar($('toolbar').hidden);
 });
 document.addEventListener('keydown',event=>{
     if(event.altKey||event.ctrlKey||event.metaKey||event.defaultPrevented||document.querySelector('dialog[open]')||
         event.target.closest('input, select, textarea, button, a'))return;
     if(['ArrowLeft','ArrowRight','PageUp','PageDown'].includes(event.key)){
         event.preventDefault();step(['ArrowRight','PageDown'].includes(event.key)?1:-1);
     }
 });
 function addChapter(label,to,fragment=''){
     const item=document.createElement('button');item.type='button';item.textContent=label;
     if(to===part)item.setAttribute('aria-current','location');
     item.addEventListener('click',()=>{$('toc').close();load(to,0,fragment);});
     $('chapters').append(item);
 }
 let tocCache=null;
 $('contents').addEventListener('click',async()=>{
     $('toc').showModal();$('chapters').replaceChildren();
     if(txt){addChapter(cfg.start,0);return;}
     const message=document.createElement('p');message.textContent=cfg.loading;$('chapters').append(message);
     try{
         tocCache??=(await get({toc:1})).toc;
         $('chapters').replaceChildren();
         for(const [to,fragment,label] of tocCache)addChapter(label||format(cfg.part,to+1,data?.count||tocCache.length),to,fragment);
     }catch(error){message.textContent=error.message||cfg.failed;}
 });
 $('settings').addEventListener('click',()=>$('preferences').showModal());
 document.querySelectorAll('dialog .dialog-close').forEach(button=>button.addEventListener('click',()=>button.closest('dialog').close()));
 if(txt)$('encoding').addEventListener('change',()=>{
     textChoice=$('encoding').value;encoding='';boundaries.clear();$('preferences').close();load(0);
 });
 more.textContent=txt?cfg.section:cfg.chapter;
 load(validPart(saved.part)?saved.part:0,clamp(saved.ratio));
})();
