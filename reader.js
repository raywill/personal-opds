'use strict';
(() => {
 const $ = id => document.getElementById(id);
 const app=$('reader'), cfg=JSON.parse(app.dataset.config);
 const vp=$('viewport'), book=$('book'), status=$('status'), more=$('continue');
 const progress=$('progress');
 const toc=$('toc'), contents=$('contents');
 const prefix='personal-opds:reader:v1:'+location.pathname+':'+cfg.profile+':';
 const prefsKey=prefix+'settings', posKey=prefix+cfg.book;
 const read=key=>{try{return JSON.parse(localStorage.getItem(key))||{};}catch{return {};}};
 const write=(key,value)=>{try{localStorage.setItem(key,JSON.stringify(value));}catch{}};
 const prefs=read(prefsKey), saved=read(posKey);
 const byteReader=cfg.reader==='bytes';
 const validPart=value=>Number.isSafeInteger(value)&&value>=0&&value<=100*1024*1024;
 const clamp=value=>Math.min(1,Math.max(0,Number(value)||0));
 const limit=()=>Math.max(0,vp.scrollHeight-vp.clientHeight);
 const scrollRatio=()=>limit()>0?clamp(vp.scrollTop/limit()):0;
 const format=(template,a,b)=>template.replace('%d',a).replace('%d',b);
 function preferences(capture,restore){
     const apply=()=>{
         document.documentElement.dataset.theme=$('theme').value;
         app.dataset.mode=$('mode')?.value||'scroll';
         app.style.setProperty('--font',Number($('size').value)+'px');
         app.style.setProperty('--leading',$('spacing').value);
     };
     for(const id of ['size','spacing','theme','mode']){
         const el=$(id);if(!el)continue;
         if(prefs[id]!=null){
             if(el instanceof HTMLSelectElement){if([...el.options].some(o=>o.value===prefs[id]))el.value=prefs[id];}
             else if(Number.isFinite(+prefs[id]))el.value=prefs[id];
         }
         el.addEventListener('input',()=>{
             const spot=capture();
             prefs[id]=el.value;apply();restore(spot);write(prefsKey,prefs);
         });
     }
     apply();
 }
 async function get(query){
     const response=await fetch(cfg.url+'&'+new URLSearchParams(query),{cache:'no-store',credentials:'same-origin'});
     let result;try{result=await response.json();}catch{throw new Error(cfg.failed);}
     if(!response.ok)throw new Error(result.error||cfg.failed);
     return result;
 }
 let closeTimer=0;
 function toolbar(open){
     clearTimeout(closeTimer);
     $('toolbar').hidden=!open;$('controls').setAttribute('aria-expanded',String(open));
     // Do not hide a toolbar while keyboard focus is within it.
     if(open)closeTimer=setTimeout(()=>{if(!$('toolbar').contains(document.activeElement))toolbar(false);},5500);
 }
 $('controls').addEventListener('click',()=>toolbar($('toolbar').hidden));
 function immersiveHeader(){
     const header=document.querySelector('.reader-bar');
     let last=vp.scrollTop,down=0,gestureUntil=0;
     const show=()=>{delete document.body.dataset.headerHidden;down=0;};
     const measure=()=>document.body.style.setProperty('--reader-bar-height',header.offsetHeight+'px');
     if(window.ResizeObserver)new ResizeObserver(measure).observe(header);
     else window.addEventListener('resize',measure);
     measure();
     const gesture=()=>{gestureUntil=performance.now()+900;};
     for(const type of ['wheel','touchmove','pointerdown'])vp.addEventListener(type,gesture,{passive:true});
     document.addEventListener('keydown',event=>{
         if(['ArrowUp','ArrowDown','ArrowLeft','ArrowRight','PageUp','PageDown','Home','End',' '].includes(event.key))gesture();
     });
     header.addEventListener('focusin',show);
     vp.addEventListener('scroll',()=>{
         const y=vp.scrollTop, delta=y-last;last=y;
         if(performance.now()>gestureUntil){down=0;return;}
         if(y<8){show();return;}
         if(delta<=0){down=0;return;}
         down+=delta;
         if(down>=45&&!header.querySelector(':focus-visible')){
             document.body.dataset.headerHidden='';
             toolbar(false);
         }
     },{passive:true});
     vp.addEventListener('click',event=>{
         if(!document.body.hasAttribute('data-header-hidden')||
             event.target.closest('a,button,input,select,textarea,summary,[role=button]')||
             getSelection()?.toString())return;
         show();
     });
 }
 immersiveHeader();
 let closingToc=0;
 function finishTocClose(){
     clearTimeout(closingToc);closingToc=0;
     delete toc.dataset.closing;
     contents.setAttribute('aria-expanded','false');
     if(toc.open)toc.close();
 }
 function closeToc(){
     if(matchMedia('(prefers-reduced-motion: reduce)').matches){finishTocClose();return;}
     if(!toc.open||closingToc)return;
     toc.dataset.closing='';
     closingToc=setTimeout(finishTocClose,240);
 }
 toc.addEventListener('animationend',event=>{
     if(event.target===toc&&event.animationName==='reader-drawer-out')finishTocClose();
 });
 toc.addEventListener('close',()=>{
     if(toc.open)return;
     clearTimeout(closingToc);closingToc=0;delete toc.dataset.closing;
     contents.setAttribute('aria-expanded','false');
 });
 toc.addEventListener('cancel',event=>{event.preventDefault();closeToc();});
 toc.addEventListener('click',event=>{
     if(event.target!==toc)return;
     const box=toc.getBoundingClientRect();
     if(event.clientX<box.left||event.clientX>=box.right||event.clientY<box.top||event.clientY>=box.bottom)closeToc();
 });
 function showToc(){toc.showModal();contents.setAttribute('aria-expanded','true');}
 toc.querySelector('.dialog-close').addEventListener('click',closeToc);
 $('settings').addEventListener('click',()=>$('preferences').showModal());
 $('preferences').querySelector('.dialog-close').addEventListener('click',()=>$('preferences').close());
 function startTextReader(){
     const range=$('position-range'), value=$('position-value');
     const formatPercent=new Intl.NumberFormat(document.documentElement.lang,{style:'percent'});
     let selection=['utf-8','gb18030'].includes(saved.textChoice)?saved.textChoice:'';
     let encoding=['utf-8','gb18030'].includes(saved.encoding)?saved.encoding:selection;
     let sections=[],total=0,epoch=0,pending=false,retry=null,starting=false,saveTimer=0;
     $('encoding').value=selection;
     const segmentY=s=>s.node.getBoundingClientRect().top-vp.getBoundingClientRect().top+vp.scrollTop;
     function readLocation(){
         let section=sections[0],y=vp.scrollTop;
         if(!section)return null;
         for(const candidate of sections){if(segmentY(candidate)>y+.5)break;section=candidate;}
         const top=segmentY(section);
         const following=sections[sections.indexOf(section)+1];
         const bottom=following?segmentY(following):top+section.node.getBoundingClientRect().height;
         return {offset:section.offset,ratio:clamp((y-top)/Math.max(1,bottom-top)),next:section.next};
     }
     function saveText(){
         if(starting)return;
         const spot=readLocation();
         if(spot)write(posKey,{part:spot.offset,ratio:spot.ratio,encoding,textChoice:selection});
     }
     function fraction(){
         const spot=readLocation();
         if(!spot||!total)return 0;
         if(sections.at(-1).next===total&&limit()>2&&vp.scrollTop>=limit()-2)return 1;
         return clamp((spot.offset+spot.ratio*(spot.next-spot.offset))/total);
     }
     function sync(){
         progress.textContent=formatPercent.format(fraction());
         clearTimeout(saveTimer);saveTimer=setTimeout(saveText,180);
     }
     function textMessage(error){
         $('reader-message').hidden=!error;
         status.textContent=error||'';
         $('retry').hidden=!retry;
     }
     function sectionOf(data){
         const bytes=Uint8Array.from(atob(data.bytes),character=>character.charCodeAt(0));
         const node=document.createElement('span');
         node.className='text-segment';
         node.textContent=new TextDecoder(data.encoding,{ignoreBOM:data.offset!==0}).decode(bytes);
         return {node,offset:data.offset,next:data.next};
     }
     function restoreSpot(spot){
         if(!spot)return;
         const index=sections.findIndex(section=>section.offset===spot.offset);
         if(index<0)return;
         const section=sections[index],top=segmentY(section),after=sections[index+1];
         const height=after?segmentY(after)-top:section.node.getBoundingClientRect().height;
         vp.scrollTop=Math.max(0,top+height*clamp(spot.ratio));
     }
     function prune(direction){
         // Keep the loaded window small on long books, without discarding
         // any visible text. Trim only on the side opposite to scrolling.
         while(sections.length>8){
             if(direction==='before'){
                 const last=sections.at(-1);
                 if(segmentY(last)<vp.scrollTop+vp.clientHeight*2)break;
                 sections.pop().node.remove();
             }else{
                 const next=sections[1];
                 const before=segmentY(next);
                 if(before>vp.scrollTop-vp.clientHeight)break;
                 sections.shift().node.remove();
                 vp.scrollTop=Math.max(0,vp.scrollTop+segmentY(next)-before);
             }
         }
     }
     async function extend(direction){
         if(pending||retry||starting||!sections.length)return;
         const seq=epoch;
         const offset=direction==='before'?sections[0].offset:sections.at(-1).next;
         if(direction==='before'?offset===0:offset>=total)return;
         pending=true;
         try {
             const data=await get({part:offset,encoding,direction});
             if(seq!==epoch)return;
             const section=sectionOf(data);
             if(section.offset>=section.next||(direction==='before'?section.next!==offset:section.offset!==offset))
                 throw Error(cfg.failed);
             if(direction==='before'){
                 const first=sections[0], old=segmentY(first);
                 sections.unshift(section);book.prepend(section.node);vp.scrollTop+=segmentY(first)-old;
             }else{sections.push(section);book.append(section.node);}
             prune(direction);sync();
         }catch(error){
             if(seq!==epoch)return;
             retry=()=>{retry=null;textMessage('');extend(direction);};
             textMessage(error.message||cfg.failed);
         }finally{
             if(seq===epoch){pending=false;if(!retry)requestAnimationFrame(fill);}
         }
     }
     function fill(){
         if(pending||retry||starting||!sections.length)return;
         if(sections.at(-1).next<total&&limit()-vp.scrollTop<=vp.clientHeight*2)extend('');
         else if(sections[0].offset>0&&vp.scrollTop<=vp.clientHeight*1.25)extend('before');
     }
     async function openText(offset,{seek=false,ratio=0,end=false}={}){
         const seq=++epoch;
         pending=false;starting=true;retry=null;
         clearTimeout(saveTimer);
         textMessage(cfg.loading);
         book.setAttribute('aria-busy','true');
         try {
             const data=await get({part:offset,encoding,direction:seek?'seek':''});
             if(seq!==epoch)return;
             encoding=data.encoding;total=data.total;
             sections=[sectionOf(data)];book.replaceChildren(sections[0].node);
             textMessage('');
             vp.scrollTop=0;
             if(end)vp.scrollTop=limit();
             else if(ratio>0)restoreSpot({offset:data.offset,ratio});
             contents.disabled=false;
             starting=false;sync();saveText();requestAnimationFrame(fill);
         }catch(error){
             if(seq!==epoch)return;
             retry=()=>openText(offset,{seek,ratio,end});textMessage(error.message||cfg.failed);
         }finally{if(seq===epoch)book.setAttribute('aria-busy','false');}
     }
     function labelValue(){value.textContent=formatPercent.format(Number(range.value)/100);}
     function jump(fraction){
         closeToc();
         openText(Math.floor(fraction*total),{seek:true,end:fraction===1});
     }
     contents.addEventListener('click',()=>{
         range.value=String(Math.round(fraction()*100));labelValue();showToc();
     });
     range.addEventListener('input',labelValue);
     $('jump').addEventListener('click',()=>jump(Number(range.value)/100));
     $('jump-start').addEventListener('click',()=>jump(0));
     $('retry').addEventListener('click',()=>retry?.());
     $('encoding').addEventListener('change',()=>{
         selection=$('encoding').value;encoding=selection;$('preferences').close();openText(0);
     });
     preferences(()=>({spot:readLocation()}),state=>{restoreSpot(state.spot);sync();fill();});
     vp.addEventListener('scroll',()=>{if(!starting){sync();fill();}},{passive:true});
     window.addEventListener('resize',()=>{sync();fill();});
     window.addEventListener('pagehide',saveText);
     document.addEventListener('visibilitychange',()=>{if(document.hidden)saveText();});
     openText(validPart(saved.part)?saved.part:0,{ratio:clamp(saved.ratio)});
 }
 if(byteReader){startTextReader();return;}
 let chapterClient=null;
 async function chapterSource(query,onPreview){
     if(!cfg.client)return get(query);
     const permission=await get({check:1});
     if(permission.success!==true)throw new Error(cfg.failed);
     if(!chapterClient){
         chapterClient=import(cfg.client).then(module=>module.openReader(cfg)).catch(error=>{
             chapterClient=null;
             throw error;
         });
     }
     return (await chapterClient).read(query,onPreview);
 }
 let part=0,data=null,busy=false,requestNo=0,failed=null,saveTimer=0;
 let pendingLocation=null,selectedLocation=null;
 const prevPart=()=>part>0?part-1:undefined;
 const nextPart=()=>data&&part+1<data.count?part+1:undefined;
 function position(){
     if(data&&!busy&&!failed)write(posKey,{part,ratio:scrollRatio(),fragment:currentSelection()?.fragment});
 }
 preferences(scrollRatio,ratio=>{vp.scrollTop=ratio*limit();position();});
 function displayProgress(){
     if(!data)return;
     const offset=limit()>0?scrollRatio():(nextPart()===undefined?1:0);
     const percent=new Intl.NumberFormat(document.documentElement.lang,{style:'percent'}).format(clamp((part+offset)/data.count));
     progress.textContent=format(cfg.part,part+1,data.count)+' · '+percent;
     more.hidden=busy||!!failed||nextPart()===undefined;
 }
 function jumpAnchor(fragment){
     if(!fragment)return false;
     const anchor=[...book.querySelectorAll('[data-book-anchor]')].find(el=>el.dataset.bookAnchor===fragment);
     if(!anchor)return false;
     anchor.scrollIntoView({block:'start'});return true;
 }
 // Keep an explicit destination until the reader moves away from its
 // landing position. Near the end of a chapter the browser may not be able
 // to scroll the chosen heading all the way to the reading line.
 function currentSelection(){
     if(selectedLocation&&Math.abs(vp.scrollTop-selectedLocation.top)>12)selectedLocation=null;
     return selectedLocation;
 }
 function selectAnchor(to,fragment){
     if(!jumpAnchor(fragment))return false;
     selectedLocation={to,fragment,top:vp.scrollTop};
     return true;
 }
 async function load(target,ratio=0,fragment=''){
     const seq=++requestNo;
     clearTimeout(saveTimer);
     busy=true; failed=null;pendingLocation={to:target,fragment};
     book.setAttribute('aria-busy','true');
     more.hidden=true;
     $('reader-message').hidden=false;status.textContent=cfg.loading;$('retry').hidden=true;
     progress.textContent='';
     // Keep the old chapter on screen until the requested one returns.
     try {
         let paintedPrefix=false;
         const onPreview=!data&&target===0&&ratio===0&&!fragment?excerpt=>{
             if(seq!==requestNo)return;
             excerpt.mount(book);
             $('reader-message').hidden=true;status.textContent='';
             book.setAttribute('aria-busy','false');
             paintedPrefix=true;
         }:null;
         const result=await chapterSource({part:target},onPreview);
         if(seq!==requestNo)return;
         const prefixTop=paintedPrefix?vp.scrollTop:null;
         // Only the active chapter adopts its validated local raster blobs.
         if(typeof result.mount==='function')result.mount(book);
         else book.innerHTML=result.html;
         part=target;
         data=result;
         $('reader-message').hidden=true;status.textContent='';
         busy=false;displayProgress();
         pendingLocation=null;selectedLocation=null;
         if(!selectAnchor(target,fragment))vp.scrollTop=prefixTop===null?clamp(ratio)*limit():Math.min(prefixTop,limit());
         displayProgress();position();
         if(toc.open)highlightCurrentChapter();
     }catch(error){
         if(seq!==requestNo)return;
         pendingLocation=null;failed=()=>load(target,ratio,fragment);
         $('reader-message').hidden=false;status.textContent=error.message||cfg.failed;$('retry').hidden=false;
         busy=false;displayProgress();
         if(toc.open)highlightCurrentChapter();
     }finally{if(seq===requestNo)book.setAttribute('aria-busy','false');}
 }
 function step(dir){
     if(busy||!data)return;
     if(dir>0&&vp.scrollTop>=limit()-2){const n=nextPart();if(n!==undefined)load(n);return;}
     if(dir<0&&vp.scrollTop<=1){const p=prevPart();if(p!==undefined)load(p,1);return;}
     vp.scrollBy({top:dir*Math.max(96,vp.clientHeight-56),behavior:'instant'});
 }
 more.addEventListener('click',()=>{const n=nextPart();if(n!==undefined&&!busy)load(n);});
 $('retry').addEventListener('click',()=>failed?.());
 vp.addEventListener('scroll',()=>{
     if(busy)return;
     currentSelection();
     displayProgress();clearTimeout(saveTimer);saveTimer=setTimeout(position,180);
 },{passive:true});
 window.addEventListener('pagehide',position);
 document.addEventListener('visibilitychange',()=>{if(document.hidden)position();});
 vp.addEventListener('load',displayProgress,true);
 window.addEventListener('resize',displayProgress);
 vp.addEventListener('click',event=>{
     const link=event.target.closest('a[data-part]');
     if(link){
         event.preventDefault();
         const to=Number(link.dataset.part);
         if(to===part&&!busy){if(selectAnchor(to,link.dataset.fragment))position();}
         else load(to,0,link.dataset.fragment);
         return;
     }
     if(event.target.closest('button')||getSelection()?.toString())return;
     if(app.dataset.mode==='page'&&(event.clientX<innerWidth*.22||event.clientX>innerWidth*.78)){
         step(event.clientX<innerWidth*.22?-1:1);return;
     }
 });
 document.addEventListener('keydown',event=>{
     if(event.altKey||event.ctrlKey||event.metaKey||event.defaultPrevented||document.querySelector('dialog[open]')||
         event.target.closest('input, select, textarea, button, a'))return;
     if(['ArrowLeft','ArrowRight','PageUp','PageDown'].includes(event.key)){
         event.preventDefault();step(['ArrowRight','PageDown'].includes(event.key)?1:-1);
     }
 });
 const chapters=$('chapters');
 let tocCache=null,tocRequest=null,tocRows=[],visibleRow=null,autoCenter=false,centerFrame=0,openTimer=0;
 function centerChapter(){
     if(!toc.open||closingToc||!autoCenter||!visibleRow)return;
     const viewport=chapters.getBoundingClientRect(), row=visibleRow.getBoundingClientRect();
     chapters.scrollTop+=row.top-viewport.top-(chapters.clientHeight-row.height)/2;
 }
 function scheduleChapterCenter(){
     cancelAnimationFrame(centerFrame);
     centerFrame=requestAnimationFrame(()=>{centerFrame=requestAnimationFrame(centerChapter);});
 }
 // On touch browsers the modal can finish establishing its scroll position
 // after showModal(). Set the inner scroller again once the drawer is painted.
 toc.addEventListener('animationend',event=>{
     if(event.target===toc&&event.animationName==='reader-drawer-in')scheduleChapterCenter();
 });
 toc.addEventListener('close',()=>{
     if(toc.open)return;
     cancelAnimationFrame(centerFrame);clearTimeout(openTimer);autoCenter=false;
 });
 function stopChapterCenter(){autoCenter=false;}
 for(const type of ['wheel','touchmove','pointerdown','keydown'])
     chapters.addEventListener(type,stopChapterCenter,{passive:true});
 function addChapter(label,to,fragment=''){
     const item=document.createElement('button');item.type='button';item.textContent=label;
     item.addEventListener('click',()=>{if(closingToc)return;closeToc();load(to,0,fragment);});
     chapters.append(item);
     return {item,to,fragment};
 }
 function highlightCurrentChapter(){
     const destination=pendingLocation??currentSelection();
     const chapter=destination?.to??part;
     const same=tocRows.filter(row=>row.to===chapter);
     const exact=destination&&same.find(row=>row.fragment===destination.fragment);
     let active=exact??same.find(row=>!row.fragment)??same[0];
     if(!exact&&!pendingLocation&&same.length>1){
         const anchors=new Map();
         for(const node of book.querySelectorAll('[data-book-anchor]')){
             if(!anchors.has(node.dataset.bookAnchor))anchors.set(node.dataset.bookAnchor,node);
         }
         const viewport=vp.getBoundingClientRect();
         const readingLine=viewport.top+(document.querySelector('.reader-bar')?.offsetHeight||0)+28;
         let nearest=-Infinity;
         for(const row of same){
             const anchor=anchors.get(row.fragment);
             if(!anchor||!anchor.getClientRects().length)continue;
             const top=anchor.getBoundingClientRect().top;
             if(top<=readingLine&&top>=nearest){nearest=top;active=row;}
         }
     }
     chapters.querySelector('[aria-current]')?.removeAttribute('aria-current');
     active?.item.setAttribute('aria-current','location');
     // Some EPUBs omit a spine document from their TOC. Show the nearest
     // preceding entry in that case, without marking it as the current one.
     let prior=null;
     if(!active)for(const row of tocRows)if(row.to<chapter&&(!prior||row.to>=prior.to))prior=row;
     visibleRow=(active??prior??tocRows[0])?.item;
     centerChapter();
     scheduleChapterCenter();
 }
 contents.addEventListener('click',async()=>{
     if(toc.open)return;
     autoCenter=true;
     showToc();
     clearTimeout(openTimer);
     openTimer=setTimeout(centerChapter,260);
     if(tocRows.length){highlightCurrentChapter();return;}
     const message=document.createElement('p');message.textContent=cfg.loading;chapters.replaceChildren(message);
     try{
         tocRequest??=chapterSource({toc:1}).then(result=>result.toc).finally(()=>{tocRequest=null;});
         tocCache??=await tocRequest;
         if(!toc.open||closingToc)return;
         chapters.replaceChildren();
         tocRows=tocCache.map(([to,fragment,label])=>addChapter(label||format(cfg.part,to+1,data?.count||tocCache.length),to,fragment));
         highlightCurrentChapter();
     }catch(error){message.textContent=error.message||cfg.failed;}
 });
 load(validPart(saved.part)?saved.part:0,clamp(saved.ratio),typeof saved.fragment==='string'?saved.fragment:'');
})();
