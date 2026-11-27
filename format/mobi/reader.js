const MAX_SOURCE=100*1024*1024;

// MOBI parsing runs outside the UI thread. The worker receives only the
// already-authorized book, not a token or a URL.
export async function openReader(cfg){
    const controller=new AbortController();
    const timer=setTimeout(()=>controller.abort(),45000);
    let source;
    try {
        const response=await fetch(cfg.url+'&source=1',{cache:'no-store',credentials:'same-origin',
            redirect:'error',signal:controller.signal});
        if(!response.ok){
            const failure=await response.json().catch(()=>null);
            throw new Error(failure?.error||cfg.failed);
        }
        const declared=response.headers.get('Content-Length');
        const length=declared===null?null:Number(declared);
        if(length!==null&&(!Number.isSafeInteger(length)||length<1||length>MAX_SOURCE))
            throw new Error(cfg.unsupported);
        source=await response.blob();
        if(source.size<1||source.size>MAX_SOURCE||(length!==null&&source.size!==length))
            throw new Error(cfg.failed);
    } catch(error) {
        if(error.name==='AbortError'||error instanceof TypeError)throw new Error(cfg.failed);
        throw error;
    } finally { clearTimeout(timer); }
    let worker=null,opening=null,sequence=0,urls=[];
    const pending=new Map();
    function stop(){
        worker?.terminate();worker=null;opening=null;
        for(const item of pending.values()){
            clearTimeout(item.timer);item.reject(new Error(cfg.unsupported));
        }
        pending.clear();
    }
    function call(action,value){
        return new Promise((resolve,reject)=>{
            const id=++sequence;
            const timer=setTimeout(stop,25000);
            pending.set(id,{resolve,reject,timer});
            worker.postMessage({id,action,value});
        });
    }
    async function ensure(){
        if(!opening){
            const path=new URL('./worker.js',import.meta.url);
            path.search=new URL(import.meta.url).search;
            worker=new Worker(path,{type:'module'});
            worker.addEventListener('error',stop);
            worker.onmessage=({data})=>{
                const item=pending.get(data.id);
                if(!item)return;
                clearTimeout(item.timer);pending.delete(data.id);
                if(data.ok)item.resolve(data.value);
                else item.reject(new Error(cfg.unsupported));
            };
            opening=call('open',source).catch(error=>{stop();throw error;});
        }
        return opening;
    }
    function cleanupUrls(){for(const url of urls)URL.revokeObjectURL(url);urls=[];}
    addEventListener('pagehide',event=>{if(!event.persisted){stop();cleanupUrls();}});
    return {async read(query){
        await ensure();
        if(query.toc)return {toc:await call('toc')};
        const data=await call('part',query.part);
        return {count:data.count,mount(container){
            cleanupUrls();
            const template=document.createElement('template');
            template.innerHTML=data.html;
            for(const image of template.content.querySelectorAll('img[data-mobi-image]')){
                const asset=data.images[Number(image.dataset.mobiImage)];
                if(!asset){image.remove();continue;}
                const src=URL.createObjectURL(new Blob([asset.bytes],{type:asset.mime}));
                urls.push(src);image.src=src;image.removeAttribute('data-mobi-image');
            }
            container.replaceChildren(template.content);
        }};
    }};
}
