// The worker has no browsing context. All reads go through the authorized
// same-origin source; book markup cannot fetch a URL or execute scripts.
function asset(name){
    const url=new URL(name,import.meta.url);
    url.search=new URL(import.meta.url).search;
    return import(url);
}
let parser,MOBI,BookSourceError,openSource;
const ready=Promise.all([asset('./linkedom-worker.js'),asset('./foliate-mobi.js'),asset('./source.js')]).then(([dom,mobi,source])=>{
    ({BookSourceError,openSource}=source);
    MOBI=mobi.MOBI;
    globalThis.DOMParser=dom.DOMParser;
    globalThis.document=dom.parseHTML('<!doctype html><html><body></body></html>').document;
    globalThis.XMLSerializer=class{serializeToString(node){return node.toString();}};
    parser=new dom.DOMParser();
});
ready.catch(()=>{}); // surfaced to the host through its request, not as an unhandled rejection

const tags=new Set('h1 h2 h3 h4 h5 h6 p div span section article strong b em i u s small sup sub blockquote pre code ul ol li dl dt dd table thead tbody tfoot tr th td figure figcaption ruby rt rp q abbr bdi bdo'.split(' '));
const discard=new Set('script style iframe object embed form input textarea select button template noscript math audio video source link meta base canvas title head'.split(' '));
const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
const maxChapter=4*1024*1024;
const maxImage=12*1024*1024;
let book,sections,visibleIndexes,toc,anchors,imageState;
function localLink(raw,part){
    if(typeof raw!=='string'||raw.length>512)return null;
    if(raw.startsWith('#')&&part!==undefined){
        try{return [part,decodeURIComponent(raw.slice(1))];}catch{return null;}
    }
    if(!/^(?:filepos:\d{1,12}|kindle:pos:fid:[0-9a-v]{1,8}:off:[0-9a-v]{1,8})$/i.test(raw))return null;
    try{
        const [original,location]=book.splitTOCHref(raw);
        const index=visibleIndexes.get(original);
        if(index===undefined)return null;
        if(typeof location==='string')return [index,location];
        const mark='opds-pos-'+location.fid+'-'+location.off;
        const chapterMarks=anchors.get(index)??new Map();
        if(chapterMarks.size<1024){chapterMarks.set(mark,raw);anchors.set(index,chapterMarks);}
        return [index,mark];
    }catch{return null;}
}
function makeToc(){
    const result=[],stack=[...(book.toc??[])].reverse();
    while(stack.length&&result.length<2000){
        const row=stack.pop();
        const target=localLink(row.href);
        if(target)result.push([...target,String(row.label??'').trim().slice(0,512)]);
        for(let i=(row.subitems?.length??0)-1;i>=0;i--)stack.push(row.subitems[i]);
    }
    return result.length?result:sections.map((_,i)=>[i,'','']);
}
function imageMime(bytes){
    const a=new Uint8Array(bytes,0,Math.min(bytes.byteLength,32));
    const is=(offset,values)=>values.every((value,i)=>a[offset+i]===value);
    if(is(0,[0xff,0xd8,0xff]))return 'image/jpeg';
    if(is(0,[137,80,78,71,13,10,26,10]))return 'image/png';
    if(is(0,[71,73,70,56])&&(a[4]===55||a[4]===57)&&a[5]===97)return 'image/gif';
    if(is(0,[82,73,70,70])&&is(8,[87,69,66,80]))return 'image/webp';
    if(is(4,[102,116,121,112])&&(is(8,[97,118,105,102])||is(8,[97,118,105,115])))return 'image/avif';
    if(is(0,[66,77])&&a.length>=26)return 'image/bmp';
    return null;
}
function imageIndex(node){
    const rec=node.getAttribute('recindex');
    const href=node.getAttribute('src')??node.getAttribute('href')??node.getAttribute('xlink:href')??'';
    const embed=href.match(/^kindle:embed:([0-9a-v]{1,8})(?:\?mime=[a-z0-9.+\/-]+)?$/i);
    const key=rec&&/^\d{1,8}$/.test(rec)?Number(rec):embed?parseInt(embed[1],32):0;
    return Number.isSafeInteger(key)&&key>=1&&key<=book.mobi.pdb.numRecords?key-1:null;
}
async function render(part,token){
    if(!Number.isInteger(part)||part<0||part>=sections.length)throw Error('Invalid chapter');
    imageState?.controller.abort();
    const chapter=await sanitize(await sections[part].readMarkup(),part);
    imageState={token,keys:chapter.images,budget:0,controller:new AbortController()};
    return {html:chapter.html,count:sections.length,imageToken:token};
}
async function sanitize(raw,part){
    if(typeof raw!=='string'||raw.length>maxChapter)throw Error('Chapter too large');
    const wrapped=/<(?:html|body)(?:\s|>)/i.test(raw)?raw:'<html><body>'+raw+'</body></html>';
    const doc=parser.parseFromString(wrapped,'text/html');
    const body=doc.querySelector('body')??doc.documentElement;
    if(!body)throw Error('Missing chapter body');
    const marks=new Map();
    for(const [anchor,href] of (part===undefined?[]:anchors.get(part)??[])){
        try{
            const resolved=await book.resolveHref(href);
            const node=resolved?.anchor?.(doc);
            if(node){const list=marks.get(node)??[];list.push(anchor);marks.set(node,list);}
        }catch{}
    }
    const images=new Set(),pieces=[];
    let visited=0,hasText=false;
    function appendImage(node){
        if(part===undefined)return;
        const key=imageIndex(node);
        if(key===null||(!images.has(key)&&images.size>=64))return;
        images.add(key);
        pieces.push('<img data-mobi-image="'+key+'" decoding="async" alt="'+escape(node.getAttribute('alt'))+'">');
    }
    async function visit(node,depth){
        if(++visited>100000)throw Error('Chapter too complex');
        if(depth>96)return;
        if(node.nodeType===3){if(node.nodeValue.trim())hasText=true;pieces.push(escape(node.nodeValue));return;}
        if(node.nodeType!==1)return;
        const tag=node.localName.toLowerCase();
        if(discard.has(tag))return;
        for(const mark of marks.get(node)??[])pieces.push('<span data-book-anchor="'+mark+'"></span>');
        if(tag==='img'||tag==='image'){appendImage(node);return;}
        if(tag==='br'||tag==='hr'){pieces.push('<'+tag+'>');return;}
        const name=node.getAttribute('id')||(tag==='a'?node.getAttribute('name'):'');
        const dir=node.getAttribute('dir');
        const attrs=(name&&name.length<=512?' data-book-anchor="'+escape(name)+'"':'')+(['ltr','rtl','auto'].includes(dir)?' dir="'+dir+'"':'');
        const pos=tag==='a'?node.getAttribute('filepos'):null;
        const link=tag==='a'&&part!==undefined?localLink(pos?'filepos:'+pos:node.getAttribute('href'),part):null;
        const use=link?'a':tags.has(tag)?tag:attrs?'span':'';
        if(use)pieces.push('<'+use+attrs+(link?' href="#" data-part="'+link[0]+'" data-fragment="'+escape(link[1])+'"':'')+'>');
        for(const child of node.childNodes)await visit(child,depth+1);
        if(use)pieces.push('</'+use+'>');
    }
    for(const mark of marks.get(body)??[])pieces.push('<span data-book-anchor="'+mark+'"></span>');
    for(const child of body.childNodes)await visit(child,0);
    if(part===undefined)return hasText?pieces.join(''):'';
    return {html:pieces.join(''),images};
}
async function getImage({token,key}){
    const state=imageState;
    if(state?.token!==token||!state.keys.delete(key)||state.budget>=24*1024*1024)return null;
    const bytes=await book.mobi.loadResource(key,state.controller.signal);
    if(state!==imageState||state.controller.signal.aborted)return null;
    const mime=bytes instanceof ArrayBuffer?imageMime(bytes):null;
    if(!mime||bytes.byteLength>maxImage||state.budget+bytes.byteLength>24*1024*1024)return null;
    state.budget+=bytes.byteLength;
    return {mime,bytes};
}
async function open({url,preview},id){
    const source=await openSource(url);
    const onPrefix=preview?async raw=>{
        const html=await sanitize(raw);
        if(!html)return false;
        self.postMessage({id,preview:html});
        return true;
    }:undefined;
    // Styles and fonts are not rendered by the shared reader; never inflate them.
    book=await new MOBI({unzlib:()=>{throw Error('Embedded fonts are not rendered');}})
        .open(source,{onPrefix,readingOnly:true});
    sections=[];visibleIndexes=new Map();anchors=new Map();
    for(const [i,section] of book.sections.entries()){
        if(typeof section.readMarkup!=='function'||section.size<=0)continue;
        visibleIndexes.set(i,sections.push(section)-1);
    }
    if(!sections.length||sections.length>2000)throw Error('No readable chapters');
    toc=makeToc();
}
let queue=Promise.resolve(),imageQueue=Promise.resolve();
self.onmessage=({data:{id,action,value}})=>{
    // A slow illustration must never delay the next chapter's text.
    if(action==='image'){
        imageQueue=imageQueue.then(async()=>{
            try{
                const image=await getImage(value);
                self.postMessage({id,ok:true,value:image},image?[image.bytes]:[]);
            }catch{self.postMessage({id,ok:true,value:null});}
        });
        return;
    }
    queue=queue.then(async()=>{
        try{
            await ready;
            if(action==='open'){await open(value,id);self.postMessage({id,ok:true,value:true});return;}
            if(!book)throw Error('Book not open');
            if(action==='toc'){self.postMessage({id,ok:true,value:toc});return;}
            if(action!=='part')throw Error('Unknown action');
            const chapter=await render(value,id);
            self.postMessage({id,ok:true,value:chapter});
        }catch(error){self.postMessage({id,ok:false,status:BookSourceError&&error instanceof BookSourceError?error.status:null});}
    });
};
